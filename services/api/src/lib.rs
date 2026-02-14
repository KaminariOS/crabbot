use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use crabbot_protocol::{HealthResponse, LoginRequest, LoginResponse};

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
        .with_state(state)
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
                    .unwrap(),
            )
            .await
            .expect("health request should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: HealthResponse = serde_json::from_slice(&body).unwrap();
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
                    .unwrap(),
            )
            .await
            .expect("login request should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let parsed: LoginResponse = serde_json::from_slice(&body).unwrap();
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
                    .unwrap(),
            )
            .await
            .expect("refresh request should succeed");

        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
