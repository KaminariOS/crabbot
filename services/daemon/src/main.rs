use anyhow::Context;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::extract::WebSocketUpgrade;
use axum::extract::ws::CloseFrame as AxumCloseFrame;
use axum::extract::ws::Message as AxumWsMessage;
use axum::extract::ws::Utf8Bytes;
use axum::extract::ws::WebSocket;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::routing::post;
use crabbot_protocol::HealthResponse;
use futures_util::SinkExt;
use futures_util::StreamExt;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::process::Child;
use std::process::Command;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use tokio::sync::RwLock;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as UpstreamWsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame as UpstreamCloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as UpstreamCloseCode;

const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:8788";
const DEFAULT_CODEX_BIN: &str = "codex";
static APPROVAL_NOTIFY_ARGV: OnceLock<Option<Vec<String>>> = OnceLock::new();

#[derive(Clone)]
struct AppState {
    ws_relay: Arc<WebSocketRelayState>,
    push_notifications: Arc<PushNotificationState>,
}

struct SpawnedAppServer {
    child: Mutex<Child>,
}

impl Drop for SpawnedAppServer {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone)]
struct WebSocketRelayState {
    upstream_endpoint: String,
    _spawned_app_server: Option<Arc<SpawnedAppServer>>,
}

#[derive(Debug, Deserialize)]
struct PushRegistrationRequest {
    token: String,
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct PushRegistrationResponse {
    ok: bool,
}

#[derive(Debug, Clone)]
struct PushRegistration {
    token: String,
    session_id: Option<String>,
}

#[derive(Debug)]
struct PushNotificationState {
    registrations: Arc<RwLock<HashMap<String, PushRegistration>>>,
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
    let state = AppState::from_env(&bind)?;
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid CRABBOT_DAEMON_BIND address: {bind}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind daemon listener at {addr}"))?;
    axum::serve(listener, router_with_state(state))
        .await
        .context("serve daemon router")
}

fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/", get(app_server_ws_proxy))
        .route("/health", get(health))
        .route("/v1/notifications/register", post(register_push_token))
        .with_state(state)
}

impl AppState {
    fn from_env(daemon_bind: &str) -> anyhow::Result<Self> {
        Ok(Self {
            ws_relay: Arc::new(WebSocketRelayState::from_env(daemon_bind)?),
            push_notifications: Arc::new(PushNotificationState::new()),
        })
    }
}

impl WebSocketRelayState {
    fn from_env(daemon_bind: &str) -> anyhow::Result<Self> {
        let upstream_endpoint = match env::var("CRABBOT_CODEX_APP_SERVER_ENDPOINT") {
            Ok(value) => value,
            Err(_) => derive_upstream_endpoint_from_daemon_bind(daemon_bind)?,
        };
        ensure_distinct_daemon_and_upstream(daemon_bind, &upstream_endpoint)?;
        let spawn_upstream = env_flag("CRABBOT_DAEMON_SPAWN_CODEX_APP_SERVER", true);
        let spawned_app_server = if spawn_upstream {
            let codex_bin =
                env::var("CRABBOT_CODEX_BIN").unwrap_or_else(|_| DEFAULT_CODEX_BIN.to_string());
            let child = Command::new(&codex_bin)
                .arg("app-server")
                .arg("--listen")
                .arg(&upstream_endpoint)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| {
                    format!("spawn `{codex_bin} app-server --listen {upstream_endpoint}`")
                })?;
            Some(Arc::new(SpawnedAppServer {
                child: Mutex::new(child),
            }))
        } else {
            None
        };

        Ok(Self {
            upstream_endpoint,
            _spawned_app_server: spawned_app_server,
        })
    }
}

fn derive_upstream_endpoint_from_daemon_bind(daemon_bind: &str) -> anyhow::Result<String> {
    let mut daemon_addr = daemon_bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid CRABBOT_DAEMON_BIND address: {daemon_bind}"))?;
    let daemon_port = daemon_addr.port();
    let upstream_port = daemon_port.checked_add(1).with_context(|| {
        format!("cannot derive upstream endpoint from daemon port {daemon_port}")
    })?;
    daemon_addr.set_port(upstream_port);
    Ok(format!("ws://{daemon_addr}"))
}

fn ensure_distinct_daemon_and_upstream(
    daemon_bind: &str,
    upstream_endpoint: &str,
) -> anyhow::Result<()> {
    let daemon_addr = daemon_bind
        .parse::<SocketAddr>()
        .with_context(|| format!("invalid CRABBOT_DAEMON_BIND address: {daemon_bind}"))?;
    if let Some(upstream_addr) = parse_ws_socket_addr(upstream_endpoint)
        && daemon_addr == upstream_addr
    {
        anyhow::bail!(
            "invalid websocket relay configuration: daemon bind `{daemon_bind}` and upstream `{upstream_endpoint}` resolve to the same socket"
        );
    }
    Ok(())
}

fn parse_ws_socket_addr(endpoint: &str) -> Option<SocketAddr> {
    endpoint
        .strip_prefix("ws://")
        .and_then(|rest| rest.parse::<SocketAddr>().ok())
}

fn env_flag(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

async fn app_server_ws_proxy(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let upstream_endpoint = state.ws_relay.upstream_endpoint.clone();
    let upstream_headers = sanitize_upstream_ws_headers(&headers);
    ws.on_upgrade(move |client_socket| async move {
        if let Err(error) =
            proxy_websocket_connection(client_socket, upstream_endpoint, upstream_headers).await
        {
            eprintln!("warning: websocket relay session ended with error: {error:#}");
        }
    })
}

fn sanitize_upstream_ws_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_ascii_lowercase();
        if matches!(
            key.as_str(),
            "connection"
                | "upgrade"
                | "host"
                | "sec-websocket-key"
                | "sec-websocket-version"
                | "sec-websocket-extensions"
        ) {
            continue;
        }
        out.insert(name.clone(), value.clone());
    }
    out
}

async fn proxy_websocket_connection(
    client_socket: WebSocket,
    upstream_endpoint: String,
    upstream_headers: HeaderMap,
) -> anyhow::Result<()> {
    let mut request = upstream_endpoint
        .as_str()
        .into_client_request()
        .context("build upstream websocket request")?;
    request.headers_mut().extend(upstream_headers);
    request.headers_mut().remove("Sec-WebSocket-Extensions");

    let (upstream_socket, _) = connect_async(request)
        .await
        .context("connect upstream websocket app-server")?;

    let (mut client_sender, mut client_receiver) = client_socket.split();
    let (mut upstream_sender, mut upstream_receiver) = upstream_socket.split();

    let client_to_upstream = async {
        while let Some(message) = client_receiver.next().await {
            let message = message.context("read message from websocket client")?;
            let mapped = map_client_to_upstream_message(message);
            upstream_sender
                .send(mapped)
                .await
                .context("forward message to upstream websocket")?;
        }
        anyhow::Ok(())
    };

    let upstream_to_client = async {
        while let Some(message) = upstream_receiver.next().await {
            let message = message.context("read message from upstream websocket")?;
            maybe_notify_user_for_ws_approval_request(&message);
            let Some(mapped) = map_upstream_to_client_message(message) else {
                continue;
            };
            client_sender
                .send(mapped)
                .await
                .context("forward message to websocket client")?;
        }
        anyhow::Ok(())
    };

    tokio::select! {
        result = client_to_upstream => result,
        result = upstream_to_client => result,
    }
}

fn map_client_to_upstream_message(message: AxumWsMessage) -> UpstreamWsMessage {
    match message {
        AxumWsMessage::Text(text) => UpstreamWsMessage::Text(text.to_string().into()),
        AxumWsMessage::Binary(binary) => UpstreamWsMessage::Binary(binary),
        AxumWsMessage::Ping(payload) => UpstreamWsMessage::Ping(payload),
        AxumWsMessage::Pong(payload) => UpstreamWsMessage::Pong(payload),
        AxumWsMessage::Close(frame) => {
            let mapped = frame.map(|f| UpstreamCloseFrame {
                code: UpstreamCloseCode::from(f.code),
                reason: f.reason.to_string().into(),
            });
            UpstreamWsMessage::Close(mapped)
        }
    }
}

fn map_upstream_to_client_message(message: UpstreamWsMessage) -> Option<AxumWsMessage> {
    match message {
        UpstreamWsMessage::Text(text) => {
            Some(AxumWsMessage::Text(Utf8Bytes::from(text.to_string())))
        }
        UpstreamWsMessage::Binary(binary) => Some(AxumWsMessage::Binary(binary)),
        UpstreamWsMessage::Ping(payload) => Some(AxumWsMessage::Ping(payload)),
        UpstreamWsMessage::Pong(payload) => Some(AxumWsMessage::Pong(payload)),
        UpstreamWsMessage::Close(frame) => {
            let mapped = frame.map(|f| AxumCloseFrame {
                code: u16::from(f.code),
                reason: Utf8Bytes::from(f.reason.to_string()),
            });
            Some(AxumWsMessage::Close(mapped))
        }
        UpstreamWsMessage::Frame(_) => None,
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let device_token_registered = state.push_notifications.has_registrations().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "crabbot_daemon".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        device_token_registered: Some(device_token_registered),
    })
}

#[derive(serde::Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ApprovalNotification {
    #[serde(rename_all = "kebab-case")]
    ApprovalRequired {
        turn_id: String,
        approval_id: String,
        action_kind: String,
        prompt: String,
    },
}

fn maybe_notify_user_for_ws_approval_request(message: &UpstreamWsMessage) {
    let UpstreamWsMessage::Text(text) = message else {
        return;
    };
    let Some(payload) = approval_notify_json_from_ws_request(text.as_ref()) else {
        return;
    };
    let Some(argv) = approval_notify_argv() else {
        return;
    };
    let Some(mut command) = command_from_argv(argv) else {
        return;
    };
    let spawn_result = command
        .arg(payload)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if let Err(error) = spawn_result {
        eprintln!("warning: failed to run approval notification command: {error}");
    }
}

fn approval_notify_json_from_ws_request(raw: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let method = value.get("method")?.as_str()?;
    if !method.starts_with("item/") || !method.ends_with("/requestApproval") {
        return None;
    }
    let params = value.get("params")?.as_object()?;
    let turn_id = params.get("turnId")?.as_str()?.to_string();
    let approval_id = params
        .get("approvalId")
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .or_else(|| {
            value.get("id").map(|id| match id {
                serde_json::Value::String(value) => value.clone(),
                other => other.to_string(),
            })
        })?;
    let prompt = params
        .get("reason")
        .and_then(|value| value.as_str())
        .unwrap_or("Approval required before continuing this action")
        .to_string();

    serde_json::to_string(&ApprovalNotification::ApprovalRequired {
        turn_id,
        approval_id,
        action_kind: method.to_string(),
        prompt,
    })
    .ok()
}

fn command_from_argv(argv: &[String]) -> Option<Command> {
    let (program, args) = argv.split_first()?;
    if program.is_empty() {
        return None;
    }
    let mut command = Command::new(program);
    command.args(args);
    Some(command)
}

fn approval_notify_argv() -> Option<&'static [String]> {
    APPROVAL_NOTIFY_ARGV
        .get_or_init(load_notify_argv_from_codex_config)
        .as_deref()
}

fn load_notify_argv_from_codex_config() -> Option<Vec<String>> {
    let config_path = codex_config_path()?;
    let raw = match std::fs::read_to_string(&config_path) {
        Ok(raw) => raw,
        Err(error) => {
            eprintln!(
                "warning: failed to read codex config `{}` for notify command: {error}",
                config_path.display()
            );
            return None;
        }
    };
    parse_notify_argv_from_toml(&raw)
}

fn codex_config_path() -> Option<std::path::PathBuf> {
    if let Some(codex_home) = env::var_os("CODEX_HOME") {
        return Some(std::path::PathBuf::from(codex_home).join("config.toml"));
    }
    env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| home.join(".codex/config.toml"))
}

fn parse_notify_argv_from_toml(raw: &str) -> Option<Vec<String>> {
    let parsed: toml::Value = match toml::from_str(raw) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("warning: failed to parse codex config TOML for notify command: {error}");
            return None;
        }
    };
    let notify = parsed.get("notify")?.as_array()?;
    let argv = notify
        .iter()
        .map(|value| value.as_str().map(ToString::to_string))
        .collect::<Option<Vec<_>>>()?;
    let (program, _) = argv.split_first()?;
    if program.is_empty() {
        return None;
    }
    Some(argv)
}

impl PushNotificationState {
    fn new() -> Self {
        Self {
            registrations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn register(&self, request: PushRegistrationRequest) {
        let token = request.token;
        let session_id = request.session_id;
        let mut registrations = self.registrations.write().await;
        let previous = registrations.insert(
            token.clone(),
            PushRegistration {
                token,
                session_id: session_id.clone(),
            },
        );
        if previous.is_none() {
            let session_label = session_id.as_deref().unwrap_or("all");
            eprintln!("info: device token registered (session_id={session_label})");
        }
    }

    async fn has_registrations(&self) -> bool {
        let registrations = self.registrations.read().await;
        registrations.values().any(|registration| {
            !registration.token.trim().is_empty() || registration.session_id.is_some()
        })
    }
}

async fn register_push_token(
    State(state): State<AppState>,
    Json(payload): Json<PushRegistrationRequest>,
) -> Result<(StatusCode, Json<PushRegistrationResponse>), StatusCode> {
    if payload.token.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    state.push_notifications.register(payload).await;
    Ok((StatusCode::OK, Json(PushRegistrationResponse { ok: true })))
}
