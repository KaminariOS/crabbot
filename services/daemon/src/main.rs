use anyhow::Context;
use axum::Json;
use axum::Router;
use axum::extract::Path;
use axum::extract::Query;
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
use crabbot_codex_app_server::CodexAppServerClient;
use crabbot_codex_app_server::CodexServerEvent;
use crabbot_codex_app_server::InitializeRequest;
use crabbot_codex_app_server::RuntimeEvent;
use crabbot_codex_app_server::SessionLifecycleState;
use crabbot_protocol::DAEMON_STREAM_SCHEMA_VERSION;
use crabbot_protocol::DaemonApprovalRequired;
use crabbot_protocol::DaemonPromptRequest;
use crabbot_protocol::DaemonPromptResponse;
use crabbot_protocol::DaemonSessionState;
use crabbot_protocol::DaemonSessionStatusResponse;
use crabbot_protocol::DaemonStartSessionRequest;
use crabbot_protocol::DaemonStreamEnvelope;
use crabbot_protocol::DaemonStreamEvent;
use crabbot_protocol::DaemonTurnCompleted;
use crabbot_protocol::DaemonTurnStreamDelta;
use crabbot_protocol::HealthResponse;
use futures_util::SinkExt;
use futures_util::StreamExt;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use reqwest::Client;
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
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use tokio::sync::RwLock;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as UpstreamWsMessage;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::CloseFrame as UpstreamCloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode as UpstreamCloseCode;

const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:8788";
const DEFAULT_CODEX_APP_SERVER_ENDPOINT: &str = "ws://127.0.0.1:8789";
const CODEX_PROTOCOL_VERSION: &str = "2026-02-14";
const DAEMON_RUNTIME_USER_ID: &str = "daemon_local_user";
const DEFAULT_CODEX_BIN: &str = "codex";
const DEFAULT_FCM_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
static APPROVAL_NOTIFY_ARGV: OnceLock<Option<Vec<String>>> = OnceLock::new();

#[derive(Clone)]
struct AppState {
    sessions: Arc<RwLock<HashMap<String, SessionRuntime>>>,
    codex_client: CodexAppServerClient,
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

#[derive(Debug, Clone)]
struct SessionRuntime {
    status: DaemonSessionStatusResponse,
    codex_session_id: String,
    codex_thread_id: String,
    active_turn_id: Option<String>,
    next_sequence: u64,
    events: Vec<DaemonStreamEnvelope>,
    last_user_prompt: Option<String>,
    turn_buffers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    since_sequence: Option<u64>,
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
    client: Client,
    service_account: Option<FcmServiceAccount>,
    registrations: Arc<RwLock<HashMap<String, PushRegistration>>>,
}

#[derive(Debug, Clone)]
struct FcmServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(Debug, Deserialize)]
struct FcmServiceAccountFile {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: Option<String>,
}

#[derive(Debug, Serialize)]
struct FcmJwtClaims {
    iss: String,
    sub: String,
    aud: String,
    scope: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
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

#[cfg(test)]
fn router() -> Router {
    router_with_state(
        AppState::for_endpoint(DEFAULT_CODEX_APP_SERVER_ENDPOINT)
            .expect("default codex app server endpoint must be valid"),
    )
}

fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/", get(app_server_ws_proxy))
        .route("/health", get(health))
        .route("/v1/sessions/start", post(start_session))
        .route("/v1/sessions/{session_id}/resume", post(resume_session))
        .route(
            "/v1/sessions/{session_id}/interrupt",
            post(interrupt_session),
        )
        .route("/v1/sessions/{session_id}/prompt", post(prompt_session))
        .route("/v1/sessions/{session_id}/status", get(session_status))
        .route("/v1/sessions/{session_id}/stream", get(session_stream))
        .route("/v1/notifications/register", post(register_push_token))
        .with_state(state)
}

impl AppState {
    fn from_env(daemon_bind: &str) -> anyhow::Result<Self> {
        let ws_relay = WebSocketRelayState::from_env(daemon_bind)?;
        let codex_client =
            CodexAppServerClient::new(&ws_relay.upstream_endpoint).with_context(|| {
                format!(
                    "initialize codex app server client for {}",
                    ws_relay.upstream_endpoint
                )
            })?;
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            codex_client,
            ws_relay: Arc::new(ws_relay),
            push_notifications: Arc::new(PushNotificationState::from_env()),
        })
    }

    #[cfg(test)]
    fn for_endpoint(endpoint: &str) -> anyhow::Result<Self> {
        let codex_client = CodexAppServerClient::new(endpoint)
            .with_context(|| format!("initialize codex app server client for {endpoint}"))?;
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            codex_client,
            ws_relay: Arc::new(WebSocketRelayState {
                upstream_endpoint: endpoint.to_string(),
                _spawned_app_server: None,
            }),
            push_notifications: Arc::new(PushNotificationState::disabled()),
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn ensure_codex_initialized(client: &CodexAppServerClient) -> Result<(), StatusCode> {
    client
        .initialize(InitializeRequest {
            client_name: "crabbot-daemon".to_string(),
            protocol_version: CODEX_PROTOCOL_VERSION.to_string(),
        })
        .await
        .map(|_| ())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn daemon_state_from_codex(state: SessionLifecycleState) -> &'static str {
    match state {
        SessionLifecycleState::Active => "active",
        SessionLifecycleState::Interrupted => "interrupted",
        SessionLifecycleState::Closed => "interrupted",
    }
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

fn push_event(state: &AppState, runtime: &mut SessionRuntime, event: DaemonStreamEvent) -> u64 {
    maybe_notify_user_for_approval(&event);

    match &event {
        DaemonStreamEvent::TurnStreamDelta(payload) => {
            runtime
                .turn_buffers
                .entry(payload.turn_id.clone())
                .or_default()
                .push_str(&payload.delta);
        }
        DaemonStreamEvent::TurnCompleted(payload) => {
            let response = runtime
                .turn_buffers
                .remove(&payload.turn_id)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| payload.output_summary.clone());
            let title = runtime
                .last_user_prompt
                .as_deref()
                .map(truncate_for_notification)
                .unwrap_or_else(|| runtime.status.session_id.clone());
            state.push_notifications.notify_turn_completed(
                &runtime.status.session_id,
                &title,
                &response,
            );
        }
        DaemonStreamEvent::ApprovalRequired(payload) => {
            let title = runtime
                .last_user_prompt
                .as_deref()
                .map(truncate_for_notification)
                .unwrap_or_else(|| runtime.status.session_id.clone());
            let body = format!("Approval required: {}", payload.action_kind);
            state.push_notifications.notify_approval_required(
                &runtime.status.session_id,
                &title,
                &body,
            );
        }
        DaemonStreamEvent::SessionState(_) | DaemonStreamEvent::Heartbeat(_) => {}
    }

    runtime.next_sequence += 1;
    let sequence = runtime.next_sequence;
    let envelope = DaemonStreamEnvelope {
        schema_version: DAEMON_STREAM_SCHEMA_VERSION,
        session_id: runtime.status.session_id.clone(),
        sequence,
        event: event.clone(),
    };
    runtime.events.push(envelope);

    if let DaemonStreamEvent::SessionState(payload) = event {
        runtime.status.state = payload.state;
        runtime.status.updated_at_unix_ms = now_unix_ms();
    }

    sequence
}

fn maybe_notify_user_for_approval(event: &DaemonStreamEvent) {
    let Some(payload) = legacy_approval_notify_json(event) else {
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

fn legacy_approval_notify_json(event: &DaemonStreamEvent) -> Option<String> {
    match event {
        DaemonStreamEvent::ApprovalRequired(payload) => {
            serde_json::to_string(&ApprovalNotification::ApprovalRequired {
                turn_id: payload.turn_id.clone(),
                approval_id: payload.approval_id.clone(),
                action_kind: payload.action_kind.clone(),
                prompt: payload.prompt.clone(),
            })
            .ok()
        }
        _ => None,
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
    fn from_env() -> Self {
        Self {
            client: Client::new(),
            service_account: load_fcm_service_account_from_env(),
            registrations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn disabled() -> Self {
        Self {
            client: Client::new(),
            service_account: None,
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
        !self.registrations.read().await.is_empty()
    }

    fn notify_turn_completed(&self, session_id: &str, title: &str, body: &str) {
        self.notify(session_id, title, body, "turn_completed");
    }

    fn notify_approval_required(&self, session_id: &str, title: &str, body: &str) {
        self.notify(session_id, title, body, "approval_required");
    }

    fn notify(&self, session_id: &str, title: &str, body: &str, kind: &str) {
        let Some(service_account) = self.service_account.clone() else {
            return;
        };
        let session_id = session_id.to_string();
        let title = truncate_for_notification(title);
        let body = truncate_for_notification(body);
        let kind = kind.to_string();
        let client = self.client.clone();
        let registrations = self.registrations.clone();

        tokio::spawn(async move {
            let access_token = match fetch_fcm_access_token(&client, &service_account).await {
                Some(token) => token,
                None => return,
            };
            let endpoint = format!(
                "https://fcm.googleapis.com/v1/projects/{}/messages:send",
                service_account.project_id
            );

            let targets = {
                let registrations = registrations.read().await;
                registrations
                    .values()
                    .filter(|registration| {
                        registration
                            .session_id
                            .as_deref()
                            .is_none_or(|value| value == session_id.as_str())
                    })
                    .map(|registration| registration.token.clone())
                    .collect::<Vec<_>>()
            };

            for token in targets {
                let payload = serde_json::json!({
                    "message": {
                        "token": token,
                        "notification": {
                            "title": title,
                            "body": body
                        },
                        "android": {
                            "priority": "high",
                            "notification": {
                                "sound": "default",
                                "channel_id": "high-priority"
                            }
                        },
                        "data": {
                            "session_id": session_id,
                            "kind": kind
                        }
                    }
                });

                let response = client
                    .post(&endpoint)
                    .bearer_auth(&access_token)
                    .header("Content-Type", "application/json")
                    .json(&payload)
                    .send()
                    .await;

                match response {
                    Ok(resp) if resp.status().is_success() => {}
                    Ok(resp) => {
                        eprintln!(
                            "warning: fcm v1 push failed with status {} for session {}",
                            resp.status(),
                            session_id
                        );
                    }
                    Err(error) => {
                        eprintln!(
                            "warning: fcm v1 push request failed for session {}: {}",
                            session_id, error
                        );
                    }
                }
            }
        });
    }
}

fn truncate_for_notification(text: &str) -> String {
    let normalized = text.trim();
    if normalized.len() <= 160 {
        return normalized.to_string();
    }
    format!("{}…", normalized.chars().take(159).collect::<String>())
}

fn load_fcm_service_account_from_env() -> Option<FcmServiceAccount> {
    let raw = if let Ok(path) = env::var("CRABBOT_FCM_SERVICE_ACCOUNT_JSON_PATH") {
        match std::fs::read_to_string(&path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "warning: failed to read CRABBOT_FCM_SERVICE_ACCOUNT_JSON_PATH `{path}`: {error}"
                );
                return None;
            }
        }
    } else {
        match env::var("CRABBOT_FCM_SERVICE_ACCOUNT_JSON") {
            Ok(value) => value,
            Err(_) => return None,
        }
    };

    let parsed: FcmServiceAccountFile = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("warning: failed to parse FCM service account json: {error}");
            return None;
        }
    };

    let token_uri = parsed
        .token_uri
        .unwrap_or_else(|| DEFAULT_FCM_TOKEN_URI.to_string());
    if parsed.project_id.trim().is_empty()
        || parsed.client_email.trim().is_empty()
        || parsed.private_key.trim().is_empty()
    {
        return None;
    }

    Some(FcmServiceAccount {
        project_id: parsed.project_id,
        client_email: parsed.client_email,
        private_key: parsed.private_key,
        token_uri,
    })
}

async fn fetch_fcm_access_token(client: &Client, account: &FcmServiceAccount) -> Option<String> {
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    let claims = FcmJwtClaims {
        iss: account.client_email.clone(),
        sub: account.client_email.clone(),
        aud: account.token_uri.clone(),
        scope: FCM_SCOPE.to_string(),
        iat: now_secs.saturating_sub(5),
        exp: now_secs.saturating_add(3500),
    };
    let key = EncodingKey::from_rsa_pem(account.private_key.as_bytes()).ok()?;
    let assertion = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key).ok()?;

    let response = client
        .post(&account.token_uri)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", assertion.as_str()),
        ])
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        eprintln!(
            "warning: failed to acquire fcm access token, status {}",
            response.status()
        );
        return None;
    }
    let parsed: OAuthTokenResponse = response.json().await.ok()?;
    if parsed.access_token.trim().is_empty() {
        return None;
    }
    Some(parsed.access_token)
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

fn split_for_stream(text: &str, chunk_size: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let chars = text.chars().collect::<Vec<_>>();
    let mut chunks = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let end = (index + chunk_size).min(chars.len());
        chunks.push(chars[index..end].iter().collect::<String>());
        index = end;
    }
    chunks
}

fn runtime_event_to_daemon_event(event: RuntimeEvent) -> Option<DaemonStreamEvent> {
    match event {
        RuntimeEvent::TurnStarted { .. } => None,
        RuntimeEvent::TurnOutputDelta { turn_id, delta, .. } => {
            Some(DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                turn_id,
                delta,
            }))
        }
        RuntimeEvent::TurnCompleted {
            turn_id,
            output_message_id,
            ..
        } => Some(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
            turn_id,
            output_summary: format!("complete ({output_message_id})"),
        })),
        RuntimeEvent::TurnInterrupted {
            turn_id, reason, ..
        } => Some(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
            turn_id,
            output_summary: format!("interrupted: {reason}"),
        })),
        RuntimeEvent::TurnAborted {
            turn_id, reason, ..
        } => Some(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
            turn_id,
            output_summary: format!("aborted: {reason}"),
        })),
        RuntimeEvent::ActionApprovalRequired {
            turn_id,
            approval_id,
            action,
            ..
        } => Some(DaemonStreamEvent::ApprovalRequired(
            DaemonApprovalRequired {
                turn_id,
                approval_id,
                action_kind: action,
                prompt: "Approval required before continuing this action".to_string(),
            },
        )),
    }
}

fn synthesize_assistant_output(prompt: &str) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return "Please share a concrete request.".to_string();
    }
    let normalized = trimmed.to_ascii_lowercase();
    if matches!(normalized.as_str(), "hi" | "hello" | "hey") {
        return "Hi. Ready when you are.".to_string();
    }
    if normalized.ends_with('?') || normalized.starts_with("why ") || normalized.starts_with("how ")
    {
        return format!(
            "You asked: {trimmed}\nI can give a precise answer once full Codex model execution is connected."
        );
    }

    format!("You said: {trimmed}")
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
    ensure_codex_initialized(&state.codex_client).await?;
    let codex_session = state
        .codex_client
        .create_session(DAEMON_RUNTIME_USER_ID)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let codex_thread = state
        .codex_client
        .create_thread(&codex_session.session_id, &format!("daemon-{session_id}"))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status = build_session_status(session_id.clone(), "active", "started");
    let mut runtime = SessionRuntime {
        status,
        codex_session_id: codex_session.session_id,
        codex_thread_id: codex_thread.thread_id,
        active_turn_id: None,
        next_sequence: 0,
        events: Vec::new(),
        last_user_prompt: None,
        turn_buffers: HashMap::new(),
    };
    push_event(
        &state,
        &mut runtime,
        DaemonStreamEvent::SessionState(DaemonSessionState {
            state: "active".to_string(),
        }),
    );

    let session = runtime.status.clone();
    let mut sessions = state.sessions.write().await;
    sessions.insert(session_id, runtime);
    Ok((StatusCode::CREATED, Json(session)))
}

async fn mutate_session_state(
    state: &AppState,
    session_id: &str,
    next_state: &str,
    last_event: &str,
) -> Result<DaemonSessionStatusResponse, StatusCode> {
    ensure_codex_initialized(&state.codex_client).await?;
    let (codex_session_id, codex_thread_id, active_turn_id) = {
        let sessions = state.sessions.read().await;
        let runtime = sessions.get(session_id).ok_or(StatusCode::NOT_FOUND)?;
        (
            runtime.codex_session_id.clone(),
            runtime.codex_thread_id.clone(),
            runtime.active_turn_id.clone(),
        )
    };

    let codex_state = match next_state {
        "active" => state
            .codex_client
            .resume_session(&codex_session_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        "interrupted" => {
            if let Some(turn_id) = active_turn_id.as_deref() {
                let _ = state
                    .codex_client
                    .interrupt_turn(
                        &codex_session_id,
                        &codex_thread_id,
                        turn_id,
                        "session_interrupt",
                    )
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            state
                .codex_client
                .interrupt_session(&codex_session_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let mut sessions = state.sessions.write().await;
    let runtime = sessions.get_mut(session_id).ok_or(StatusCode::NOT_FOUND)?;
    runtime.status.state = daemon_state_from_codex(codex_state.state).to_string();
    runtime.status.last_event = last_event.to_string();
    runtime.status.updated_at_unix_ms = now_unix_ms();
    if next_state == "interrupted" {
        runtime.active_turn_id = None;
    }
    push_event(
        &state,
        runtime,
        DaemonStreamEvent::SessionState(DaemonSessionState {
            state: runtime.status.state.clone(),
        }),
    );
    Ok(runtime.status.clone())
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
    let runtime = sessions.get(&session_id).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(runtime.status.clone()))
}

async fn session_stream(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Query(query): Query<StreamQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;
    let runtime = sessions.get(&session_id).ok_or(StatusCode::NOT_FOUND)?;
    let since = query.since_sequence.unwrap_or(0);
    let lines = runtime
        .events
        .iter()
        .filter(|event| event.sequence > since)
        .cloned()
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

async fn prompt_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(payload): Json<DaemonPromptRequest>,
) -> Result<(StatusCode, Json<DaemonPromptResponse>), StatusCode> {
    if payload.prompt.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (daemon_state, codex_session_id, codex_thread_id) = {
        let sessions = state.sessions.read().await;
        let runtime = sessions.get(&session_id).ok_or(StatusCode::NOT_FOUND)?;
        (
            runtime.status.state.clone(),
            runtime.codex_session_id.clone(),
            runtime.codex_thread_id.clone(),
        )
    };
    if daemon_state != "active" {
        return Err(StatusCode::CONFLICT);
    }

    ensure_codex_initialized(&state.codex_client).await?;
    let turn = state
        .codex_client
        .start_turn(&codex_session_id, &codex_thread_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let turn_id = turn.turn_id.clone();

    let mut mapped_events = Vec::new();
    let started = CodexAppServerClient::map_server_event(CodexServerEvent::TurnStarted {
        session_id: codex_session_id.clone(),
        thread_id: codex_thread_id.clone(),
        turn_id: turn_id.clone(),
    });
    if let Some(event) = runtime_event_to_daemon_event(started) {
        mapped_events.push(event);
    }

    let assistant_output = synthesize_assistant_output(&payload.prompt);
    for chunk in split_for_stream(&assistant_output, 32) {
        let _ = state
            .codex_client
            .append_turn_delta(&codex_session_id, &codex_thread_id, &turn_id, &chunk)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let delta_event = CodexAppServerClient::map_server_event(CodexServerEvent::TurnDelta {
            session_id: codex_session_id.clone(),
            thread_id: codex_thread_id.clone(),
            turn_id: turn_id.clone(),
            delta: chunk,
        });
        if let Some(event) = runtime_event_to_daemon_event(delta_event) {
            mapped_events.push(event);
        }
    }

    if payload.prompt.to_ascii_lowercase().contains("approve") {
        let approval_event =
            CodexAppServerClient::map_server_event(CodexServerEvent::ApprovalRequired {
                session_id: codex_session_id.clone(),
                thread_id: codex_thread_id.clone(),
                turn_id: turn_id.clone(),
                approval_id: format!("approval_{session_id}_{turn_id}"),
                action: "shell_command".to_string(),
            });
        if let Some(event) = runtime_event_to_daemon_event(approval_event) {
            mapped_events.push(event);
        }
    }

    let output_message_id = format!("msg_{turn_id}");
    let _ = state
        .codex_client
        .complete_turn(
            &codex_session_id,
            &codex_thread_id,
            &turn_id,
            &output_message_id,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let completed = CodexAppServerClient::map_server_event(CodexServerEvent::TurnCompleted {
        session_id: codex_session_id,
        thread_id: codex_thread_id,
        turn_id: turn_id.clone(),
        output_message_id,
    });
    if let Some(event) = runtime_event_to_daemon_event(completed) {
        mapped_events.push(event);
    }

    let mut sessions = state.sessions.write().await;
    let runtime = sessions.get_mut(&session_id).ok_or(StatusCode::NOT_FOUND)?;
    if runtime.status.state != "active" {
        return Err(StatusCode::CONFLICT);
    }
    runtime.active_turn_id = Some(turn_id.clone());
    runtime.last_user_prompt = Some(payload.prompt.clone());
    for mapped in mapped_events {
        push_event(&state, runtime, mapped);
    }
    runtime.active_turn_id = None;
    runtime.status.last_event = "turn_completed".to_string();
    runtime.status.updated_at_unix_ms = now_unix_ms();

    let response = DaemonPromptResponse {
        session_id,
        turn_id,
        state: runtime.status.state.clone(),
        last_event: runtime.status.last_event.clone(),
        updated_at_unix_ms: runtime.status.updated_at_unix_ms,
        last_sequence: runtime.next_sequence,
    };
    Ok((StatusCode::ACCEPTED, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use serde_json::json;
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
        assert_eq!(lines.len(), 1);
        let first: DaemonStreamEnvelope =
            serde_json::from_str(lines[0]).expect("parse first stream line");
        assert_eq!(first.session_id, "sess_daemon_stream");
        assert_eq!(first.sequence, 1);
        assert_eq!(
            first.event,
            DaemonStreamEvent::SessionState(DaemonSessionState {
                state: "active".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn prompt_endpoint_emits_turn_events_and_stream_filtering() {
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
                            session_id: Some("sess_daemon_prompt".to_string()),
                        })
                        .expect("serialize start request"),
                    ))
                    .expect("build start request"),
            )
            .await
            .expect("route start request");

        let prompt_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/sess_daemon_prompt/prompt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonPromptRequest {
                            prompt: "ship it".to_string(),
                        })
                        .expect("serialize prompt request"),
                    ))
                    .expect("build prompt request"),
            )
            .await
            .expect("route prompt request");
        assert_eq!(prompt_response.status(), StatusCode::ACCEPTED);
        let prompt_json = read_json(prompt_response).await;
        assert_eq!(prompt_json["session_id"], "sess_daemon_prompt");
        assert_eq!(prompt_json["state"], "active");
        assert_eq!(prompt_json["last_event"], "turn_completed");

        let all_events_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_prompt/stream")
                    .body(Body::empty())
                    .expect("build stream request"),
            )
            .await
            .expect("route stream request");
        assert_eq!(all_events_response.status(), StatusCode::OK);
        let all_bytes = all_events_response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let all_body = String::from_utf8(all_bytes.to_vec()).expect("utf8 body");
        let all_lines = all_body.lines().collect::<Vec<_>>();
        assert!(all_lines.len() >= 3);

        let completion: DaemonStreamEnvelope =
            serde_json::from_str(all_lines[all_lines.len() - 1]).expect("parse completion line");
        match completion.event {
            DaemonStreamEvent::TurnCompleted(payload) => {
                assert!(payload.turn_id.starts_with("turn_"));
                assert!(payload.output_summary.starts_with("complete (msg_turn_"));
            }
            _ => panic!("expected turn completed event"),
        }

        let filtered_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_prompt/stream?since_sequence=2")
                    .body(Body::empty())
                    .expect("build filtered stream request"),
            )
            .await
            .expect("route filtered stream request");
        assert_eq!(filtered_response.status(), StatusCode::OK);
        let filtered_bytes = filtered_response
            .into_body()
            .collect()
            .await
            .expect("collect filtered body")
            .to_bytes();
        let filtered_body = String::from_utf8(filtered_bytes.to_vec()).expect("utf8 body");
        let filtered_lines = filtered_body.lines().collect::<Vec<_>>();
        assert!(!filtered_lines.is_empty());
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
        assert_eq!(value["device_token_registered"], json!(false));
    }

    #[test]
    fn derive_upstream_endpoint_uses_daemon_port_plus_one() {
        let endpoint =
            derive_upstream_endpoint_from_daemon_bind("127.0.0.1:8788").expect("derive endpoint");
        assert_eq!(endpoint, "ws://127.0.0.1:8789");
    }

    #[test]
    fn distinct_daemon_and_upstream_rejects_same_socket() {
        let error = ensure_distinct_daemon_and_upstream("127.0.0.1:8765", "ws://127.0.0.1:8765")
            .expect_err("same socket should be rejected");
        assert!(
            error.to_string().contains("resolve to the same socket"),
            "expected same-socket error, got: {error:#}"
        );
    }

    #[test]
    fn distinct_daemon_and_upstream_allows_different_socket() {
        ensure_distinct_daemon_and_upstream("127.0.0.1:8765", "ws://127.0.0.1:8766")
            .expect("different sockets should be allowed");
    }

    #[test]
    fn approval_notification_only_for_approval_events() {
        let payload = legacy_approval_notify_json(&DaemonStreamEvent::ApprovalRequired(
            DaemonApprovalRequired {
                turn_id: "turn_1".to_string(),
                approval_id: "approval_1".to_string(),
                action_kind: "shell_command".to_string(),
                prompt: "approve?".to_string(),
            },
        ))
        .expect("approval event should generate payload");
        let parsed: serde_json::Value = serde_json::from_str(&payload).expect("valid json");
        assert_eq!(parsed["type"], "approval-required");
        assert_eq!(parsed["approval-id"], "approval_1");

        assert!(
            legacy_approval_notify_json(&DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
                turn_id: "turn_1".to_string(),
                output_summary: "done".to_string(),
            }))
            .is_none()
        );
    }

    #[test]
    fn approval_notification_parses_ws_request_approval_message() {
        let payload = approval_notify_json_from_ws_request(
            r#"{
                "jsonrpc":"2.0",
                "id":42,
                "method":"item/commandExecution/requestApproval",
                "params":{
                    "threadId":"thread_1",
                    "turnId":"turn_1",
                    "approvalId":"approval_1",
                    "reason":"needs approval"
                }
            }"#,
        )
        .expect("ws request should generate payload");
        let parsed: serde_json::Value = serde_json::from_str(&payload).expect("valid json");
        assert_eq!(parsed["type"], "approval-required");
        assert_eq!(parsed["turn-id"], "turn_1");
        assert_eq!(parsed["approval-id"], "approval_1");
        assert_eq!(
            parsed["action-kind"],
            "item/commandExecution/requestApproval"
        );
        assert_eq!(parsed["prompt"], "needs approval");
    }

    #[test]
    fn approval_notification_ignores_non_approval_ws_messages() {
        assert!(
            approval_notify_json_from_ws_request(
                r#"{"jsonrpc":"2.0","method":"turn/started","params":{"turnId":"turn_1"}}"#
            )
            .is_none()
        );
    }

    #[test]
    fn parse_notify_argv_from_toml_parses_notify_array() {
        let argv = parse_notify_argv_from_toml(r#"notify = ["uv", "run", "/tmp/notify.py"]"#)
            .expect("notify argv should parse");
        assert_eq!(
            argv,
            vec![
                "uv".to_string(),
                "run".to_string(),
                "/tmp/notify.py".to_string()
            ]
        );
    }

    #[test]
    fn parse_notify_argv_from_toml_rejects_invalid_values() {
        assert!(parse_notify_argv_from_toml("").is_none());
        assert!(parse_notify_argv_from_toml("notify = []").is_none());
        assert!(parse_notify_argv_from_toml(r#"notify = [""]"#).is_none());
        assert!(parse_notify_argv_from_toml("notify = [1]").is_none());
    }
}
