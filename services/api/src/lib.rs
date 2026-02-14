use std::{
    collections::HashMap,
    env,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{
        Path, Query, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use crabbot_protocol::{
    ApiEvent, AppendMessageRequest, AppendMessageResponse, CreateSessionRequest,
    CreateSessionResponse, GetSessionResponse, HealthResponse, ListMessagesResponse,
    ListSessionsResponse, LoginRequest, LoginResponse, Message, MessageAppended,
    RealtimeBootstrapResponse, Session, SessionCreated, WEBSOCKET_SCHEMA_VERSION,
    WebSocketEnvelope,
};
use futures_util::StreamExt;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};

const SESSION_TOKEN_TTL: Duration = Duration::from_secs(60 * 60);
const REALTIME_CHANNEL_CAPACITY: usize = 256;
const EVENT_LOG_LIMIT: usize = 512;
const JWT_SECRET_ENV: &str = "CRABBOT_JWT_SECRET";
const JWT_DEFAULT_DEV_SECRET: &str = "crabbot-dev-secret-change-me";

#[derive(Clone)]
pub struct AppState {
    pub service_name: String,
    pub realtime_websocket_url: String,
    jwt_secret: String,
    store: Arc<RwLock<InMemoryStore>>,
}

#[derive(Debug, Clone)]
struct AuthSession {
    user_id: String,
    token_id: String,
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
    event_log_by_user: HashMap<String, Vec<WebSocketEnvelope>>,
    realtime_by_user: HashMap<String, broadcast::Sender<WebSocketEnvelope>>,
}

#[derive(Debug, Clone)]
struct Authenticated {
    user_id: String,
    session_token: String,
}

#[derive(Debug, Deserialize)]
struct RealtimeQuery {
    session_token: Option<String>,
    since_sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,
    exp: u64,
    iat: u64,
    jti: String,
}

pub fn router() -> Router {
    let state = AppState {
        service_name: "crabbot_api".to_string(),
        realtime_websocket_url: "wss://api.crabbot.local/realtime".to_string(),
        jwt_secret: env::var(JWT_SECRET_ENV).unwrap_or_else(|_| JWT_DEFAULT_DEV_SECRET.to_string()),
        store: Arc::new(RwLock::new(InMemoryStore::default())),
    };

    router_with_state(state)
}

fn router_with_state(state: AppState) -> Router {
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
        .route("/realtime", get(realtime_websocket))
        .with_state(state)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_unix_s() -> u64 {
    now_unix_ms() / 1_000
}

fn encoding_key(secret: &str) -> EncodingKey {
    EncodingKey::from_secret(secret.as_bytes())
}

fn decoding_key(secret: &str) -> DecodingKey {
    DecodingKey::from_secret(secret.as_bytes())
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

fn create_broadcaster() -> broadcast::Sender<WebSocketEnvelope> {
    let (sender, _receiver) = broadcast::channel(REALTIME_CHANNEL_CAPACITY);
    sender
}

fn push_event(store: &mut InMemoryStore, user_id: &str, event: ApiEvent) -> u64 {
    let sequence = next_sequence(store, user_id);
    let envelope = WebSocketEnvelope {
        schema_version: WEBSOCKET_SCHEMA_VERSION,
        sequence,
        event,
    };

    {
        let events = store
            .event_log_by_user
            .entry(user_id.to_string())
            .or_default();
        events.push(envelope.clone());
        if events.len() > EVENT_LOG_LIMIT {
            let drop_count = events.len() - EVENT_LOG_LIMIT;
            events.drain(0..drop_count);
        }
    }

    let broadcaster = store
        .realtime_by_user
        .entry(user_id.to_string())
        .or_insert_with(create_broadcaster)
        .clone();
    let _ = broadcaster.send(envelope);

    sequence
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
    authenticate_token(token, state).await
}

async fn authenticate_token(token: String, state: &AppState) -> Result<Authenticated, StatusCode> {
    let claims = decode::<JwtClaims>(
        &token,
        &decoding_key(&state.jwt_secret),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?
    .claims;

    let mut store = state.store.write().await;
    let auth = store
        .auth_by_session_token
        .get(&token)
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if auth.expires_at_unix_ms <= now_unix_ms()
        || claims.sub != auth.user_id
        || claims.jti != auth.token_id
    {
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

fn issue_auth_session(
    store: &mut InMemoryStore,
    jwt_secret: &str,
    user_id: String,
) -> Result<LoginResponse, StatusCode> {
    store.next_auth_id += 1;
    let issued_id = store.next_auth_id;
    let token_id = format!("auth_{issued_id}");
    let now_unix_s = now_unix_s();
    let expires_at_unix_ms = now_unix_ms() + SESSION_TOKEN_TTL.as_millis() as u64;
    let claims = JwtClaims {
        sub: user_id.clone(),
        exp: expires_at_unix_ms / 1_000,
        iat: now_unix_s,
        jti: token_id.clone(),
    };
    let session_token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &encoding_key(jwt_secret),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let refresh_token = format!("refresh_tok_{issued_id}");
    let auth = AuthSession {
        user_id: user_id.clone(),
        token_id,
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

    Ok(LoginResponse {
        user_id,
        session_token,
        refresh_token,
        expires_at_unix_ms,
    })
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
    let response = issue_auth_session(&mut store, &state.jwt_secret, user_id)?;
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

    let response = issue_auth_session(&mut store, &state.jwt_secret, previous_auth.user_id)?;
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
    push_event(
        &mut store,
        &auth.user_id,
        ApiEvent::SessionCreated(SessionCreated {
            session_id: session.session_id.clone(),
            machine_id: session.machine_id.clone(),
            created_at_unix_ms: session.created_at_unix_ms,
        }),
    );

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
    push_event(
        &mut store,
        &auth.user_id,
        ApiEvent::MessageAppended(MessageAppended {
            session_id: message.session_id.clone(),
            message_id: message.message_id.clone(),
            role: message.role.clone(),
            ciphertext: message.ciphertext.clone(),
        }),
    );

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

async fn realtime_websocket(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RealtimeQuery>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, StatusCode> {
    let token = query
        .session_token
        .or_else(|| bearer_token(&headers))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let auth = authenticate_token(token, &state).await?;
    let since_sequence = query.since_sequence.unwrap_or(0);

    Ok(ws.on_upgrade(move |socket| realtime_socket(socket, state, auth.user_id, since_sequence)))
}

async fn realtime_socket(
    mut socket: WebSocket,
    state: AppState,
    user_id: String,
    since_sequence: u64,
) {
    let (backlog, mut receiver) = {
        let mut store = state.store.write().await;
        let backlog = store
            .event_log_by_user
            .get(&user_id)
            .map(|events| {
                events
                    .iter()
                    .filter(|event| event.sequence > since_sequence)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let receiver = store
            .realtime_by_user
            .entry(user_id)
            .or_insert_with(create_broadcaster)
            .subscribe();
        (backlog, receiver)
    };

    for envelope in backlog {
        if send_envelope(&mut socket, &envelope).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            inbound = socket.next() => {
                match inbound {
                    Some(Ok(WsMessage::Close(_))) | None => break,
                    Some(Ok(WsMessage::Ping(payload))) => {
                        if socket.send(WsMessage::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
            outbound = receiver.recv() => {
                match outbound {
                    Ok(envelope) => {
                        if send_envelope(&mut socket, &envelope).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Client should reconnect with since_sequence to replay missed events.
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn send_envelope(socket: &mut WebSocket, envelope: &WebSocketEnvelope) -> Result<(), ()> {
    let payload = serde_json::to_string(envelope).map_err(|_| ())?;
    socket
        .send(WsMessage::Text(payload.into()))
        .await
        .map_err(|_| ())
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
    use tokio::task::JoinHandle;
    use tokio::time::timeout;
    use tokio_tungstenite::{
        MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message as TungsteniteMessage,
    };
    use tower::ServiceExt;

    type ClientWsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

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

    async fn create_session_for(app: Router, session_token: &str) -> CreateSessionResponse {
        let payload = serde_json::json!({
            "machine_id": "machine_abc",
            "title_ciphertext": "encrypted:title",
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sessions")
                    .header("authorization", format!("Bearer {session_token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("build create session request"),
            )
            .await
            .expect("create session request should succeed");
        assert_eq!(response.status(), StatusCode::CREATED);
        parse_json(response).await
    }

    async fn append_message_for(
        app: Router,
        session_token: &str,
        session_id: &str,
        client_message_id: &str,
        if_match: Option<u64>,
    ) -> axum::response::Response {
        let payload = serde_json::json!({
            "role": "user",
            "ciphertext": "encrypted:new-message",
            "client_message_id": client_message_id,
        });

        let mut builder = Request::builder()
            .method("POST")
            .uri(format!("/sessions/{session_id}/messages"))
            .header("authorization", format!("Bearer {session_token}"))
            .header("content-type", "application/json");
        if let Some(version) = if_match {
            builder = builder.header("if-match", version.to_string());
        }

        app.oneshot(
            builder
                .body(Body::from(payload.to_string()))
                .expect("build append request"),
        )
        .await
        .expect("append request should succeed")
    }

    async fn spawn_server(app: Router) -> (std::net::SocketAddr, JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("resolve local address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test server should run");
        });
        (addr, task)
    }

    async fn next_ws_envelope(stream: &mut ClientWsStream) -> WebSocketEnvelope {
        let message = timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("websocket receive should not timeout")
            .expect("websocket stream should produce message")
            .expect("websocket message should be valid");

        match message {
            TungsteniteMessage::Text(text) => {
                serde_json::from_str(text.as_str()).expect("parse websocket envelope")
            }
            other => panic!("expected text websocket message, got {other:?}"),
        }
    }

    fn test_state() -> AppState {
        AppState {
            service_name: "crabbot_api".to_string(),
            realtime_websocket_url: "ws://127.0.0.1/realtime".to_string(),
            jwt_secret: JWT_DEFAULT_DEV_SECRET.to_string(),
            store: Arc::new(RwLock::new(InMemoryStore::default())),
        }
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
    async fn login_issues_jwt_access_token_and_tampering_is_rejected() {
        let app = router();
        let login = login(app.clone()).await;
        assert_eq!(login.session_token.split('.').count(), 3);

        let tampered = format!("{}x", login.session_token);
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/sessions")
                    .header("authorization", format!("Bearer {tampered}"))
                    .body(Body::empty())
                    .expect("build tampered token request"),
            )
            .await
            .expect("tampered token request should complete");

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

        let created_payload = create_session_for(app.clone(), &login.session_token).await;

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

        let created_payload = create_session_for(app.clone(), &login.session_token).await;
        let session_id = created_payload.session.session_id;

        let appended = append_message_for(
            app.clone(),
            &login.session_token,
            &session_id,
            "msg_client_1",
            Some(1),
        )
        .await;
        assert_eq!(appended.status(), StatusCode::CREATED);
        let appended_payload: AppendMessageResponse = parse_json(appended).await;
        assert_eq!(appended_payload.message.optimistic_version, 2);

        let stale_append = append_message_for(
            app.clone(),
            &login.session_token,
            &session_id,
            "msg_client_1",
            Some(1),
        )
        .await;
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

    #[tokio::test]
    async fn realtime_websocket_replays_backlog_and_resumes_from_since_sequence() {
        let state = test_state();
        let app = router_with_state(state.clone());
        let login = login(app.clone()).await;
        let created_payload = create_session_for(app.clone(), &login.session_token).await;
        let session_id = created_payload.session.session_id;

        let append = append_message_for(
            app.clone(),
            &login.session_token,
            &session_id,
            "msg_client_1",
            Some(1),
        )
        .await;
        assert_eq!(append.status(), StatusCode::CREATED);

        let (addr, server_task) = spawn_server(router_with_state(state)).await;

        let first_url = format!(
            "ws://{addr}/realtime?session_token={}&since_sequence=0",
            login.session_token
        );
        let (mut first_stream, _response) = connect_async(first_url)
            .await
            .expect("open first websocket connection");

        let first_event = next_ws_envelope(&mut first_stream).await;
        assert_eq!(first_event.sequence, 1);
        assert!(matches!(first_event.event, ApiEvent::SessionCreated(_)));

        let second_event = next_ws_envelope(&mut first_stream).await;
        assert_eq!(second_event.sequence, 2);
        match second_event.event {
            ApiEvent::MessageAppended(event) => {
                assert_eq!(event.message_id, "msg_client_1");
            }
            other => panic!("expected message_appended event, got {other:?}"),
        }

        first_stream
            .close(None)
            .await
            .expect("close first websocket");

        let append_after_disconnect = append_message_for(
            app,
            &login.session_token,
            &session_id,
            "msg_client_2",
            Some(2),
        )
        .await;
        assert_eq!(append_after_disconnect.status(), StatusCode::CREATED);

        let replay_url = format!(
            "ws://{addr}/realtime?session_token={}&since_sequence=2",
            login.session_token
        );
        let (mut replay_stream, _response) = connect_async(replay_url)
            .await
            .expect("open replay websocket connection");

        let replay_event = next_ws_envelope(&mut replay_stream).await;
        assert_eq!(replay_event.sequence, 3);
        match replay_event.event {
            ApiEvent::MessageAppended(event) => {
                assert_eq!(event.message_id, "msg_client_2");
            }
            other => panic!("expected message_appended replay event, got {other:?}"),
        }

        let no_extra = timeout(Duration::from_millis(200), replay_stream.next()).await;
        assert!(no_extra.is_err(), "unexpected extra backlog event");

        replay_stream
            .close(None)
            .await
            .expect("close replay websocket");
        server_task.abort();
    }
}
