use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use crabbot_protocol::{
    DAEMON_STREAM_SCHEMA_VERSION, DaemonApprovalRequired, DaemonSessionState,
    DaemonSessionStatusResponse, DaemonStartSessionRequest, DaemonStreamEnvelope,
    DaemonStreamEvent, DaemonTurnCompleted, DaemonTurnStreamDelta, HealthResponse, Heartbeat,
};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:8788";

#[derive(Clone, Default)]
struct AppState {
    sessions: Arc<RwLock<HashMap<String, DaemonSessionStatusResponse>>>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let bind = env::var("CRABBOT_DAEMON_BIND").unwrap_or_else(|_| DEFAULT_DAEMON_BIND.to_string());
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid CRABBOT_DAEMON_BIND address: {bind}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind daemon listener at {addr}"))?;
    axum::serve(listener, router())
        .await
        .context("serve daemon router")
}

fn router() -> Router {
    router_with_state(AppState::default())
}

fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/sessions/start", post(start_session))
        .route("/v1/sessions/{session_id}/resume", post(resume_session))
        .route(
            "/v1/sessions/{session_id}/interrupt",
            post(interrupt_session),
        )
        .route("/v1/sessions/{session_id}/status", get(session_status))
        .route("/v1/sessions/{session_id}/stream", get(session_stream))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "crabbot_daemon".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn build_session_status(
    session_id: String,
    state: &str,
    last_event: &str,
) -> DaemonSessionStatusResponse {
    DaemonSessionStatusResponse {
        session_id,
        state: state.to_string(),
        last_event: last_event.to_string(),
        updated_at_unix_ms: now_unix_ms(),
    }
}

async fn start_session(
    State(state): State<AppState>,
    Json(payload): Json<DaemonStartSessionRequest>,
) -> Result<(StatusCode, Json<DaemonSessionStatusResponse>), StatusCode> {
    if payload
        .session_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let session_id = payload
        .session_id
        .unwrap_or_else(|| format!("sess_daemon_{}", now_unix_ms()));
    let session = build_session_status(session_id.clone(), "active", "started");
    let mut sessions = state.sessions.write().await;
    sessions.insert(session_id, session.clone());
    Ok((StatusCode::CREATED, Json(session)))
}

async fn mutate_session_state(
    state: &AppState,
    session_id: &str,
    next_state: &str,
    last_event: &str,
) -> Result<DaemonSessionStatusResponse, StatusCode> {
    let mut sessions = state.sessions.write().await;
    let session = sessions.get_mut(session_id).ok_or(StatusCode::NOT_FOUND)?;
    session.state = next_state.to_string();
    session.last_event = last_event.to_string();
    session.updated_at_unix_ms = now_unix_ms();
    Ok(session.clone())
}

async fn resume_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<DaemonSessionStatusResponse>, StatusCode> {
    let response = mutate_session_state(&state, &session_id, "active", "resumed").await?;
    Ok(Json(response))
}

async fn interrupt_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<DaemonSessionStatusResponse>, StatusCode> {
    let response = mutate_session_state(&state, &session_id, "interrupted", "interrupted").await?;
    Ok(Json(response))
}

async fn session_status(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<DaemonSessionStatusResponse>, StatusCode> {
    let sessions = state.sessions.read().await;
    let session = sessions
        .get(&session_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(session))
}

async fn session_stream(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;
    let session = sessions
        .get(&session_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    drop(sessions);

    let now = now_unix_ms();
    let turn_id = format!("turn_{session_id}_1");
    let lines = [
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id: session_id.clone(),
            sequence: 1,
            event: DaemonStreamEvent::SessionState(DaemonSessionState {
                state: session.state.clone(),
            }),
        },
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id: session_id.clone(),
            sequence: 2,
            event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                turn_id: turn_id.clone(),
                delta: "daemon stream connected".to_string(),
            }),
        },
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id: session_id.clone(),
            sequence: 3,
            event: DaemonStreamEvent::ApprovalRequired(DaemonApprovalRequired {
                turn_id: turn_id.clone(),
                approval_id: format!("approval_{session_id}_1"),
                action_kind: "shell_command".to_string(),
                prompt: "Allow running ls -la in workspace?".to_string(),
            }),
        },
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id: session_id.clone(),
            sequence: 4,
            event: DaemonStreamEvent::Heartbeat(Heartbeat { unix_ms: now }),
        },
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id,
            sequence: 5,
            event: DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
                turn_id,
                output_summary: format!("last event: {}", session.last_event),
            }),
        },
    ]
    .into_iter()
    .map(|event| serde_json::to_string(&event).expect("serialize daemon stream event"))
    .collect::<Vec<_>>()
    .join("\n");

    let payload = format!("{lines}\n");
    Ok((
        [
            ("content-type", "application/x-ndjson"),
            ("cache-control", "no-store"),
            ("x-crabbot-daemon-stream", "1"),
        ],
        payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn read_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("parse json body")
    }

    #[tokio::test]
    async fn session_control_endpoints_round_trip() {
        let app = router();
        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonStartSessionRequest {
                            session_id: Some("sess_daemon_test".to_string()),
                        })
                        .expect("serialize start request"),
                    ))
                    .expect("build start request"),
            )
            .await
            .expect("route start request");
        assert_eq!(start_response.status(), StatusCode::CREATED);
        let start_json = read_json(start_response).await;
        assert_eq!(start_json["session_id"], "sess_daemon_test");
        assert_eq!(start_json["state"], "active");
        assert_eq!(start_json["last_event"], "started");

        let interrupt_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/sess_daemon_test/interrupt")
                    .body(Body::empty())
                    .expect("build interrupt request"),
            )
            .await
            .expect("route interrupt request");
        assert_eq!(interrupt_response.status(), StatusCode::OK);
        let interrupt_json = read_json(interrupt_response).await;
        assert_eq!(interrupt_json["state"], "interrupted");

        let resume_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/sess_daemon_test/resume")
                    .body(Body::empty())
                    .expect("build resume request"),
            )
            .await
            .expect("route resume request");
        assert_eq!(resume_response.status(), StatusCode::OK);
        let resume_json = read_json(resume_response).await;
        assert_eq!(resume_json["state"], "active");
        assert_eq!(resume_json["last_event"], "resumed");

        let status_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_test/status")
                    .body(Body::empty())
                    .expect("build status request"),
            )
            .await
            .expect("route status request");
        assert_eq!(status_response.status(), StatusCode::OK);
        let status_json = read_json(status_response).await;
        assert_eq!(status_json["state"], "active");
        assert_eq!(status_json["last_event"], "resumed");
    }

    #[tokio::test]
    async fn stream_endpoint_returns_ndjson_envelopes() {
        let app = router();
        let _start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonStartSessionRequest {
                            session_id: Some("sess_daemon_stream".to_string()),
                        })
                        .expect("serialize start request"),
                    ))
                    .expect("build start request"),
            )
            .await
            .expect("route start request");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_stream/stream")
                    .body(Body::empty())
                    .expect("build stream request"),
            )
            .await
            .expect("route stream request");

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 5);
        let first: DaemonStreamEnvelope =
            serde_json::from_str(lines[0]).expect("parse first stream line");
        assert_eq!(first.session_id, "sess_daemon_stream");
        assert_eq!(first.sequence, 1);
        let approval: DaemonStreamEnvelope =
            serde_json::from_str(lines[2]).expect("parse approval stream line");
        assert_eq!(
            approval.event,
            DaemonStreamEvent::ApprovalRequired(DaemonApprovalRequired {
                turn_id: "turn_sess_daemon_stream_1".to_string(),
                approval_id: "approval_sess_daemon_stream_1".to_string(),
                action_kind: "shell_command".to_string(),
                prompt: "Allow running ls -la in workspace?".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn health_endpoint_reports_daemon_service() {
        let app = router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route request");

        assert_eq!(response.status(), StatusCode::OK);
        let value = read_json(response).await;
        assert_eq!(value["service"], json!("crabbot_daemon"));
    }
}
