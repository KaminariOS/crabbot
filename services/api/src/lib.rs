use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use crabbot_protocol::{
    AppendMessageRequest, AppendMessageResponse, CreateSessionRequest, CreateSessionResponse,
    GetSessionResponse, HealthResponse, ListMessagesResponse, ListSessionsResponse, LoginRequest,
    LoginResponse, Message, RealtimeBootstrapResponse, Session, WEBSOCKET_SCHEMA_VERSION,
};

#[derive(Clone)]
pub struct AppState {
    pub service_name: String,
}

pub fn router() -> Router {
    let state = AppState {
        service_name: "crabbot_api".to_string(),
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

fn stub_session(session_id: &str) -> Session {
    Session {
        session_id: session_id.to_string(),
        machine_id: "machine_stub".to_string(),
        state: "active".to_string(),
        optimistic_version: 1,
        created_at_unix_ms: 1_735_689_600_000,
        updated_at_unix_ms: 1_735_689_600_000,
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: state.service_name,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn login(Json(payload): Json<LoginRequest>) -> Result<Json<LoginResponse>, StatusCode> {
    if payload.access_token.trim().is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(Json(LoginResponse {
        user_id: "user_stub".to_string(),
        session_token: format!("stub_session_for_{}", payload.provider),
        refresh_token: "stub_refresh_token".to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
    }))
}

async fn refresh() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}

async fn list_sessions() -> Json<ListSessionsResponse> {
    Json(ListSessionsResponse {
        sessions: vec![stub_session("sess_stub_1")],
        next_cursor: None,
    })
}

async fn create_session(
    Json(payload): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<CreateSessionResponse>), StatusCode> {
    if payload.machine_id.trim().is_empty() || payload.title_ciphertext.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut session = stub_session("sess_stub_new");
    session.machine_id = payload.machine_id;

    Ok((StatusCode::CREATED, Json(CreateSessionResponse { session })))
}

async fn get_session(
    Path(session_id): Path<String>,
) -> Result<Json<GetSessionResponse>, StatusCode> {
    if session_id == "missing" {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(GetSessionResponse {
        session: stub_session(&session_id),
    }))
}

async fn list_messages(
    Path(session_id): Path<String>,
) -> Result<Json<ListMessagesResponse>, StatusCode> {
    if session_id == "missing" {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(ListMessagesResponse {
        session_id: session_id.clone(),
        messages: vec![Message {
            message_id: "msg_stub_1".to_string(),
            session_id,
            role: "user".to_string(),
            ciphertext: "encrypted:hello".to_string(),
            optimistic_version: 1,
            created_at_unix_ms: 1_735_689_600_000,
        }],
        next_cursor: None,
    }))
}

async fn append_message(
    Path(session_id): Path<String>,
    Json(payload): Json<AppendMessageRequest>,
) -> Result<(StatusCode, Json<AppendMessageResponse>), StatusCode> {
    if session_id == "missing" {
        return Err(StatusCode::NOT_FOUND);
    }
    if payload.role.trim().is_empty() || payload.ciphertext.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let message = Message {
        message_id: payload
            .client_message_id
            .unwrap_or_else(|| "msg_stub_appended".to_string()),
        session_id,
        role: payload.role,
        ciphertext: payload.ciphertext,
        optimistic_version: 2,
        created_at_unix_ms: 1_735_689_660_000,
    };

    Ok((StatusCode::CREATED, Json(AppendMessageResponse { message })))
}

async fn realtime_bootstrap() -> Json<RealtimeBootstrapResponse> {
    Json(RealtimeBootstrapResponse {
        websocket_url: "wss://api.crabbot.local/realtime".to_string(),
        session_token: "stub_realtime_token".to_string(),
        heartbeat_interval_ms: 15_000,
        last_sequence: 0,
        schema_version: WEBSOCKET_SCHEMA_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let parsed: HealthResponse = serde_json::from_slice(&body).expect("parse health payload");
        assert_eq!(parsed.status, "ok");
        assert_eq!(parsed.service, "crabbot_api");
    }

    #[tokio::test]
    async fn login_endpoint_returns_stub_credentials() {
        let payload = serde_json::json!({
            "provider": "github",
            "access_token": "gho_token",
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

        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let parsed: LoginResponse = serde_json::from_slice(&body).expect("parse login payload");
        assert_eq!(parsed.user_id, "user_stub");
        assert_eq!(parsed.session_token, "stub_session_for_github");
    }

    #[tokio::test]
    async fn refresh_endpoint_is_stubbed() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/refresh")
                    .body(Body::empty())
                    .expect("build refresh request"),
            )
            .await
            .expect("refresh request should succeed");

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn create_session_endpoint_returns_created_session() {
        let payload = serde_json::json!({
            "machine_id": "machine_abc",
            "title_ciphertext": "encrypted:title",
        });

        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sessions")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("build create session request"),
            )
            .await
            .expect("create session request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let parsed: CreateSessionResponse =
            serde_json::from_slice(&body).expect("parse create session payload");
        assert_eq!(parsed.session.machine_id, "machine_abc");
    }

    #[tokio::test]
    async fn append_message_endpoint_returns_created_message() {
        let payload = serde_json::json!({
            "role": "user",
            "ciphertext": "encrypted:new-message",
            "client_message_id": "msg_client_1"
        });

        let response = router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sessions/sess_stub_1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("build append message request"),
            )
            .await
            .expect("append message request should succeed");

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let parsed: AppendMessageResponse =
            serde_json::from_slice(&body).expect("parse append message payload");
        assert_eq!(parsed.message.message_id, "msg_client_1");
        assert_eq!(parsed.message.role, "user");
    }

    #[tokio::test]
    async fn realtime_bootstrap_returns_schema_version() {
        let response = router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/realtime/bootstrap")
                    .body(Body::empty())
                    .expect("build realtime bootstrap request"),
            )
            .await
            .expect("realtime bootstrap request should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        let body = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let parsed: RealtimeBootstrapResponse =
            serde_json::from_slice(&body).expect("parse realtime bootstrap payload");
        assert_eq!(parsed.schema_version, WEBSOCKET_SCHEMA_VERSION);
        assert_eq!(parsed.websocket_url, "wss://api.crabbot.local/realtime");
    }
}
