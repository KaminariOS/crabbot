use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use crabbot_protocol::{
    AppendMessageRequest, AppendMessageResponse, CreateSessionRequest, CreateSessionResponse,
    GetSessionResponse, HealthResponse, ListMessagesResponse, ListSessionsResponse, LoginRequest,
    LoginResponse, Message, RealtimeBootstrapResponse, Session, WEBSOCKET_SCHEMA_VERSION,
};
use tokio::sync::RwLock;

const SESSION_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct AppState {
    pub service_name: String,
    pub realtime_websocket_url: String,
    store: Arc<RwLock<InMemoryStore>>,
}

#[derive(Debug, Clone)]
struct AuthSession {
    user_id: String,
    session_token: String,
    refresh_token: String,
    expires_at_unix_ms: u64,
}

#[derive(Default)]
struct InMemoryStore {
    next_session_id: u64,
    next_message_id: u64,
    next_auth_id: u64,
    auth_by_session_token: HashMap<String, AuthSession>,
    session_token_by_refresh_token: HashMap<String, String>,
    sessions_by_user: HashMap<String, Vec<Session>>,
    messages_by_session: HashMap<String, Vec<Message>>,
    sequence_by_user: HashMap<String, u64>,
}

#[derive(Debug, Clone)]
struct Authenticated {
    user_id: String,
    session_token: String,
}

pub fn router() -> Router {
    let state = AppState {
        service_name: "crabbot_api".to_string(),
        realtime_websocket_url: "wss://api.crabbot.local/realtime".to_string(),
        store: Arc::new(RwLock::new(InMemoryStore::default())),
    };

    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/sessions", get(list_sessions).post(create_session))
        .route("/sessions/{session_id}", get(get_session))
        .route(
            "/sessions/{session_id}/messages",
            get(list_messages).post(append_message),
        )
        .route("/realtime/bootstrap", get(realtime_bootstrap))
        .with_state(state)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn normalize_provider(provider: &str) -> String {
    let mut normalized = String::with_capacity(provider.len());
    for ch in provider.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
        } else {
            normalized.push('_');
        }
    }

    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let header = headers.get("authorization")?;
    let raw = header.to_str().ok()?;
    let token = raw.strip_prefix("Bearer ")?;
    if token.trim().is_empty() {
        None
    } else {
        Some(token.trim().to_string())
    }
}

fn next_sequence(store: &mut InMemoryStore, user_id: &str) -> u64 {
    let sequence = store
        .sequence_by_user
        .entry(user_id.to_string())
        .or_insert(0);
    *sequence += 1;
    *sequence
}

fn parse_if_match(headers: &HeaderMap) -> Result<Option<u64>, StatusCode> {
    let Some(value) = headers.get("if-match") else {
        return Ok(None);
    };
    let raw = value.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
    let parsed = raw
        .trim()
        .trim_matches('"')
        .parse::<u64>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Some(parsed))
}

async fn authenticate(headers: &HeaderMap, state: &AppState) -> Result<Authenticated, StatusCode> {
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let mut store = state.store.write().await;
    let auth = store
        .auth_by_session_token
        .get(&token)
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if auth.expires_at_unix_ms <= now_unix_ms() {
        store.auth_by_session_token.remove(&auth.session_token);
        store
            .session_token_by_refresh_token
            .remove(&auth.refresh_token);
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(Authenticated {
        user_id: auth.user_id,
        session_token: auth.session_token,
    })
}

fn issue_auth_session(store: &mut InMemoryStore, user_id: String) -> LoginResponse {
    store.next_auth_id += 1;
    let issued_id = store.next_auth_id;
    let session_token = format!("session_tok_{issued_id}");
    let refresh_token = format!("refresh_tok_{issued_id}");
    let expires_at_unix_ms = now_unix_ms() + SESSION_TOKEN_TTL.as_millis() as u64;
    let auth = AuthSession {
        user_id: user_id.clone(),
        session_token: session_token.clone(),
        refresh_token: refresh_token.clone(),
        expires_at_unix_ms,
    };

    store
        .session_token_by_refresh_token
        .insert(refresh_token.clone(), session_token.clone());
    store
        .auth_by_session_token
        .insert(session_token.clone(), auth);

    LoginResponse {
        user_id,
        session_token,
        refresh_token,
        expires_at_unix_ms,
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: state.service_name,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    if payload.provider.trim().is_empty() || payload.access_token.trim().is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user_id = format!("user_{}", normalize_provider(&payload.provider));
    let mut store = state.store.write().await;
    let response = issue_auth_session(&mut store, user_id);
    Ok(Json(response))
}

async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<LoginResponse>, StatusCode> {
    let refresh_token = bearer_token(&headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let mut store = state.store.write().await;

    let previous_session_token = store
        .session_token_by_refresh_token
        .remove(&refresh_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let previous_auth = store
        .auth_by_session_token
        .remove(&previous_session_token)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if previous_auth.expires_at_unix_ms <= now_unix_ms() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let response = issue_auth_session(&mut store, previous_auth.user_id);
    Ok(Json(response))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListSessionsResponse>, StatusCode> {
    let auth = authenticate(&headers, &state).await?;
    let store = state.store.read().await;
    let sessions = store
        .sessions_by_user
        .get(&auth.user_id)
        .cloned()
        .unwrap_or_default();

    Ok(Json(ListSessionsResponse {
        sessions,
        next_cursor: None,
    }))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), StatusCode> {
    let auth = authenticate(&headers, &state).await?;
    if payload.machine_id.trim().is_empty() || payload.title_ciphertext.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut store = state.store.write().await;
    store.next_session_id += 1;
    let now = now_unix_ms();
    let session = Session {
        session_id: format!("sess_{}", store.next_session_id),
        machine_id: payload.machine_id,
        state: "active".to_string(),
        optimistic_version: 1,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };

    store
        .sessions_by_user
        .entry(auth.user_id.clone())
        .or_default()
        .push(session.clone());
    store
        .messages_by_session
        .entry(session.session_id.clone())
        .or_default();
    next_sequence(&mut store, &auth.user_id);

    Ok((StatusCode::CREATED, Json(CreateSessionResponse { session })))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<GetSessionResponse>, StatusCode> {
    let auth = authenticate(&headers, &state).await?;
    let store = state.store.read().await;
    let session = store
        .sessions_by_user
        .get(&auth.user_id)
        .and_then(|sessions| {
            sessions
                .iter()
                .find(|session| session.session_id == session_id)
        })
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(GetSessionResponse { session }))
}

async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<ListMessagesResponse>, StatusCode> {
    let auth = authenticate(&headers, &state).await?;
    let store = state.store.read().await;
    let owns_session = store
        .sessions_by_user
        .get(&auth.user_id)
        .map(|sessions| {
            sessions
                .iter()
                .any(|session| session.session_id == session_id)
        })
        .unwrap_or(false);
    if !owns_session {
        return Err(StatusCode::NOT_FOUND);
    }

    let messages = store
        .messages_by_session
        .get(&session_id)
        .cloned()
        .unwrap_or_default();

    Ok(Json(ListMessagesResponse {
        session_id,
        messages,
        next_cursor: None,
    }))
}

async fn append_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(payload): Json<AppendMessageRequest>,
) -> Result<(StatusCode, Json<AppendMessageResponse>), StatusCode> {
    let expected_version = parse_if_match(&headers)?;
    let auth = authenticate(&headers, &state).await?;
    if payload.role.trim().is_empty() || payload.ciphertext.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut store = state.store.write().await;

    let next_version = {
        let sessions = store
            .sessions_by_user
            .get_mut(&auth.user_id)
            .ok_or(StatusCode::NOT_FOUND)?;
        let session = sessions
            .iter_mut()
            .find(|session| session.session_id == session_id)
            .ok_or(StatusCode::NOT_FOUND)?;

        if let Some(version) = expected_version {
            if version != session.optimistic_version {
                return Err(StatusCode::CONFLICT);
            }
        }

        session.optimistic_version += 1;
        session.updated_at_unix_ms = now_unix_ms();
        session.optimistic_version
    };

    let message_id = if let Some(client_message_id) = payload.client_message_id {
        client_message_id
    } else {
        store.next_message_id += 1;
        format!("msg_{}", store.next_message_id)
    };

    let message = Message {
        message_id,
        session_id: session_id.clone(),
        role: payload.role,
        ciphertext: payload.ciphertext,
        optimistic_version: next_version,
        created_at_unix_ms: now_unix_ms(),
    };

    store
        .messages_by_session
        .entry(session_id)
        .or_default()
        .push(message.clone());
    next_sequence(&mut store, &auth.user_id);

    Ok((StatusCode::CREATED, Json(AppendMessageResponse { message })))
}

async fn realtime_bootstrap(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RealtimeBootstrapResponse>, StatusCode> {
    let auth = authenticate(&headers, &state).await?;
    let store = state.store.read().await;
    let last_sequence = *store.sequence_by_user.get(&auth.user_id).unwrap_or(&0);

    Ok(Json(RealtimeBootstrapResponse {
        websocket_url: state.realtime_websocket_url,
        session_token: auth.session_token,
        heartbeat_interval_ms: 15_000,
        last_sequence,
        schema_version: WEBSOCKET_SCHEMA_VERSION,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde::de::DeserializeOwned;
    use tower::ServiceExt;

    async fn parse_json<T: DeserializeOwned>(response: axum::response::Response) -> T {
        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        serde_json::from_slice(&body).expect("parse json response")
    }

    async fn login(app: Router) -> LoginResponse {
        let payload = serde_json::json!({
            "provider": "github",
            "access_token": "gho_token",
        });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("build login request"),
            )
            .await
            .expect("login request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        parse_json(response).await
    }

    #[tokio::test]
    async fn health_endpoint_returns_ok_payload() {
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build health request"),
            )
            .await
            .expect("health request should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let parsed: HealthResponse = parse_json(response).await;
        assert_eq!(parsed.status, "ok");
        assert_eq!(parsed.service, "crabbot_api");
    }

    #[tokio::test]
    async fn login_rejects_empty_access_token() {
        let payload = serde_json::json!({
            "provider": "github",
            "access_token": "",
        });

        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("build login request"),
            )
            .await
            .expect("login request should succeed");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn sessions_require_auth_and_persist_created_session() {
        let app = router();
        let login = login(app.clone()).await;

        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/sessions")
                    .body(Body::empty())
                    .expect("build unauthorized request"),
            )
            .await
            .expect("request should succeed");
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let payload = serde_json::json!({
            "machine_id": "machine_abc",
            "title_ciphertext": "encrypted:title",
        });

        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sessions")
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("build create request"),
            )
            .await
            .expect("create session should succeed");
        assert_eq!(created.status(), StatusCode::CREATED);
        let created_payload: CreateSessionResponse = parse_json(created).await;

        let listed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/sessions")
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .body(Body::empty())
                    .expect("build list request"),
            )
            .await
            .expect("list sessions should succeed");
        assert_eq!(listed.status(), StatusCode::OK);
        let listed_payload: ListSessionsResponse = parse_json(listed).await;
        assert_eq!(listed_payload.sessions.len(), 1);
        assert_eq!(
            listed_payload.sessions[0].session_id,
            created_payload.session.session_id
        );
    }

    #[tokio::test]
    async fn refresh_rotates_tokens_and_invalidates_previous_session_token() {
        let app = router();
        let login = login(app.clone()).await;

        let refreshed = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .header("authorization", format!("Bearer {}", login.refresh_token))
                    .body(Body::empty())
                    .expect("build refresh request"),
            )
            .await
            .expect("refresh request should succeed");
        assert_eq!(refreshed.status(), StatusCode::OK);
        let refreshed_payload: LoginResponse = parse_json(refreshed).await;
        assert_ne!(refreshed_payload.session_token, login.session_token);

        let old_token_request = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/sessions")
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .body(Body::empty())
                    .expect("build old token request"),
            )
            .await
            .expect("old token request should succeed");
        assert_eq!(old_token_request.status(), StatusCode::UNAUTHORIZED);

        let new_token_request = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/sessions")
                    .header(
                        "authorization",
                        format!("Bearer {}", refreshed_payload.session_token),
                    )
                    .body(Body::empty())
                    .expect("build new token request"),
            )
            .await
            .expect("new token request should succeed");
        assert_eq!(new_token_request.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn append_message_uses_if_match_and_updates_realtime_sequence() {
        let app = router();
        let login = login(app.clone()).await;

        let create_payload = serde_json::json!({
            "machine_id": "machine_abc",
            "title_ciphertext": "encrypted:title",
        });
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sessions")
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .header("content-type", "application/json")
                    .body(Body::from(create_payload.to_string()))
                    .expect("build create request"),
            )
            .await
            .expect("create request should succeed");
        let created_payload: CreateSessionResponse = parse_json(created).await;
        let session_id = created_payload.session.session_id;

        let append_payload = serde_json::json!({
            "role": "user",
            "ciphertext": "encrypted:new-message",
            "client_message_id": "msg_client_1",
        });
        let appended = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/sessions/{session_id}/messages"))
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .header("if-match", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(append_payload.to_string()))
                    .expect("build append request"),
            )
            .await
            .expect("append request should succeed");
        assert_eq!(appended.status(), StatusCode::CREATED);
        let appended_payload: AppendMessageResponse = parse_json(appended).await;
        assert_eq!(appended_payload.message.optimistic_version, 2);

        let stale_append = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/sessions/{session_id}/messages"))
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .header("if-match", "1")
                    .header("content-type", "application/json")
                    .body(Body::from(append_payload.to_string()))
                    .expect("build stale append request"),
            )
            .await
            .expect("stale append request should succeed");
        assert_eq!(stale_append.status(), StatusCode::CONFLICT);

        let bootstrap = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/realtime/bootstrap")
                    .header("authorization", format!("Bearer {}", login.session_token))
                    .body(Body::empty())
                    .expect("build realtime bootstrap request"),
            )
            .await
            .expect("realtime bootstrap request should succeed");
        assert_eq!(bootstrap.status(), StatusCode::OK);
        let bootstrap_payload: RealtimeBootstrapResponse = parse_json(bootstrap).await;
        assert_eq!(bootstrap_payload.last_sequence, 2);
        assert_eq!(bootstrap_payload.schema_version, WEBSOCKET_SCHEMA_VERSION);
    }
}
