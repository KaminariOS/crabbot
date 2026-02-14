use anyhow::Context;
use axum::{Router, extract::Path, response::IntoResponse, routing::get};
use crabbot_protocol::{
    DAEMON_STREAM_SCHEMA_VERSION, DaemonSessionState, DaemonStreamEnvelope, DaemonStreamEvent,
    DaemonTurnCompleted, DaemonTurnStreamDelta, HealthResponse, Heartbeat,
};
use serde_json::json;
use std::{
    env,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:8788";

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
    Router::new()
        .route("/health", get(health))
        .route("/v1/sessions/{session_id}/stream", get(session_stream))
}

async fn health() -> axum::Json<HealthResponse> {
    axum::Json(HealthResponse {
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

async fn session_stream(Path(session_id): Path<String>) -> impl IntoResponse {
    let now = now_unix_ms();
    let turn_id = format!("turn_{session_id}_1");
    let lines = [
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id: session_id.clone(),
            sequence: 1,
            event: DaemonStreamEvent::SessionState(DaemonSessionState {
                state: "active".to_string(),
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
            event: DaemonStreamEvent::Heartbeat(Heartbeat { unix_ms: now }),
        },
        DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id,
            sequence: 4,
            event: DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
                turn_id,
                output_summary: "daemon stream closed".to_string(),
            }),
        },
    ]
    .into_iter()
    .map(|event| serde_json::to_string(&event).expect("serialize daemon stream event"))
    .collect::<Vec<_>>()
    .join("\n");

    let payload = format!("{lines}\n");
    (
        [
            ("content-type", "application/x-ndjson"),
            ("cache-control", "no-store"),
            ("x-crabbot-daemon-stream", "1"),
        ],
        payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn stream_endpoint_returns_ndjson_envelopes() {
        let app = router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_test/stream")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route request");

        assert_eq!(response.status(), 200);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4);
        let first: DaemonStreamEnvelope =
            serde_json::from_str(lines[0]).expect("parse first stream line");
        assert_eq!(first.session_id, "sess_daemon_test");
        assert_eq!(first.sequence, 1);
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

        assert_eq!(response.status(), 200);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("parse health");
        assert_eq!(value["service"], json!("crabbot_daemon"));
    }
}
