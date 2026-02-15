use anyhow::{Context, Result, anyhow, bail};
use crabbot_protocol::{
    DaemonPromptRequest, DaemonPromptResponse, DaemonRpcNotification, DaemonRpcRequest,
    DaemonRpcRequestResponse, DaemonRpcRespondRequest, DaemonRpcStreamEnvelope,
    DaemonRpcStreamEvent, DaemonSessionStatusResponse, DaemonStartSessionRequest,
    DaemonStreamEnvelope, DaemonStreamEvent, HealthResponse,
};
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const TUI_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TUI_EVENT_WAIT_STEP: Duration = Duration::from_millis(50);
const TUI_STREAM_REQUEST_TIMEOUT: Duration = Duration::from_millis(600);
const DAEMON_PROMPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const TUI_COMPOSER_PROMPT: &str = "\u{203a} ";
const TUI_COMPOSER_PLACEHOLDER: &str = "Ask Crabbot to do anything";
const TUI_SLASH_PICKER_MAX_ROWS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRuntimeState {
    pub state: SessionStatus,
    pub updated_at_unix_ms: u64,
    pub last_event: String,
    #[serde(default)]
    pub last_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub api_endpoint: String,
    pub daemon_endpoint: String,
    pub auth_token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:8787".to_string(),
            daemon_endpoint: "http://127.0.0.1:8788".to_string(),
            auth_token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliState {
    pub sessions: BTreeMap<String, SessionRuntimeState>,
    pub config: CliConfig,
    #[serde(default)]
    pub last_thread_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TuiArgs {
    pub thread_id: Option<String>,
}

pub enum CommandOutput {
    Json(Value),
    Text(String),
}

#[derive(Debug, Default, Clone)]
struct ConfigSetArgs {
    api_endpoint: Option<String>,
    daemon_endpoint: Option<String>,
    auth_token: Option<String>,
    clear_auth_token: bool,
}

mod slash_command;
pub mod tui;

pub(crate) use tui::color;
pub use tui::handle_attach_tui_interactive;
pub use tui::handle_tui;
pub(crate) use tui::terminal_palette;
fn truncate_for_width(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    let mut truncated = text.chars().take(width - 3).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn persist_latest_session_state_from_stream(
    state: &mut CliState,
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
) -> Result<()> {
    let Some(last_sequence) = stream_events.last().map(|event| event.sequence) else {
        return Ok(());
    };
    let latest_state = stream_events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            DaemonStreamEvent::SessionState(payload) => Some(payload.state.clone()),
            _ => None,
        });

    if let Some(runtime) = state.sessions.get_mut(session_id) {
        if let Some(next_state) = latest_state {
            runtime.state = parse_session_status(&next_state)?;
            runtime.last_event = "attached".to_string();
        }
        runtime.updated_at_unix_ms = now_unix_ms();
        runtime.last_sequence = runtime.last_sequence.max(last_sequence);
        return Ok(());
    }

    if let Some(next_state) = latest_state {
        state.sessions.insert(
            session_id.to_string(),
            SessionRuntimeState {
                state: parse_session_status(&next_state)?,
                updated_at_unix_ms: now_unix_ms(),
                last_event: "attached".to_string(),
                last_sequence,
            },
        );
    }
    Ok(())
}

fn handle_config_show(state: &CliState) -> Value {
    json!({
        "ok": true,
        "config": state.config,
    })
}

fn handle_config_set(args: ConfigSetArgs, state: &mut CliState) -> Result<Value> {
    let mut changed = false;

    if let Some(api_endpoint) = args.api_endpoint {
        if api_endpoint.trim().is_empty() {
            bail!("api_endpoint cannot be empty");
        }
        state.config.api_endpoint = api_endpoint;
        changed = true;
    }

    if let Some(daemon_endpoint) = args.daemon_endpoint {
        if daemon_endpoint.trim().is_empty() {
            bail!("daemon_endpoint cannot be empty");
        }
        state.config.daemon_endpoint = daemon_endpoint;
        changed = true;
    }

    if let Some(auth_token) = args.auth_token {
        if auth_token.trim().is_empty() {
            bail!("auth_token cannot be empty");
        }
        state.config.auth_token = Some(auth_token);
        changed = true;
    }

    if args.clear_auth_token {
        state.config.auth_token = None;
        changed = true;
    }

    if !changed {
        bail!("no config fields were provided");
    }

    Ok(json!({
        "ok": true,
        "action": "config_set",
        "config": state.config,
    }))
}

fn parse_session_status(state: &str) -> Result<SessionStatus> {
    match state {
        "active" => Ok(SessionStatus::Active),
        "interrupted" => Ok(SessionStatus::Interrupted),
        other => bail!("unsupported daemon session state: {other}"),
    }
}

fn persist_daemon_session(
    state: &mut CliState,
    daemon_session: &DaemonSessionStatusResponse,
) -> Result<()> {
    let state_value = parse_session_status(&daemon_session.state)?;
    let last_sequence = state
        .sessions
        .get(&daemon_session.session_id)
        .map(|runtime| runtime.last_sequence)
        .unwrap_or(0);
    state.sessions.insert(
        daemon_session.session_id.clone(),
        SessionRuntimeState {
            state: state_value,
            updated_at_unix_ms: daemon_session.updated_at_unix_ms,
            last_event: daemon_session.last_event.clone(),
            last_sequence,
        },
    );
    Ok(())
}

fn http_client_with_timeout(timeout: Duration) -> Result<Client> {
    Client::builder()
        .timeout(timeout)
        .build()
        .context("build http client")
}

fn http_client() -> Result<Client> {
    http_client_with_timeout(Duration::from_secs(5))
}

fn endpoint_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn apply_auth(
    request: reqwest::blocking::RequestBuilder,
    auth_token: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    if let Some(token) = auth_token {
        if !token.trim().is_empty() {
            return request.bearer_auth(token);
        }
    }
    request
}

fn fetch_api_health(api_endpoint: &str, auth_token: Option<&str>) -> Result<HealthResponse> {
    let client = http_client()?;
    let url = endpoint_url(api_endpoint, "/health");
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request api health")?
        .error_for_status()
        .context("api health returned error status")?;
    response
        .json::<HealthResponse>()
        .context("parse api health response")
}

fn health_http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .context("build health-check http client")
}

fn daemon_is_healthy(daemon_endpoint: &str, auth_token: Option<&str>) -> bool {
    let client = match health_http_client() {
        Ok(client) => client,
        Err(_) => return false,
    };
    let url = endpoint_url(daemon_endpoint, "/health");
    let response = match apply_auth(client.get(url), auth_token).send() {
        Ok(response) => response,
        Err(_) => return false,
    };
    if !response.status().is_success() {
        return false;
    }

    response
        .json::<HealthResponse>()
        .map(|health| health.status == "ok")
        .unwrap_or(false)
}

fn ensure_daemon_ready(state: &CliState) -> Result<()> {
    if daemon_is_healthy(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
    ) {
        return Ok(());
    }

    auto_start_daemon_process()?;

    for _ in 0..20 {
        if daemon_is_healthy(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
        ) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(150));
    }

    bail!(
        "daemon is not healthy at {}; run `cargo run -p crabbot_daemon` or set CRABBOT_DAEMON_BIN",
        state.config.daemon_endpoint
    )
}

fn auto_start_daemon_process() -> Result<()> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = env::var_os("CRABBOT_DAEMON_BIN") {
        if !PathBuf::from(&explicit).as_os_str().is_empty() {
            candidates.push(PathBuf::from(explicit));
        }
    }

    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join("crabbot_daemon"));
        }
    }
    candidates.push(PathBuf::from("crabbot_daemon"));

    let mut last_error: Option<anyhow::Error> = None;
    for candidate in candidates {
        match spawn_daemon_process(&candidate) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }

    if spawn_daemon_via_cargo().is_ok() {
        return Ok(());
    }

    match last_error {
        Some(error) => Err(error),
        None => bail!("unable to auto-start daemon"),
    }
}

fn spawn_daemon_process(binary: &Path) -> Result<()> {
    let mut command = Command::new(binary);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(bind) = env::var_os("CRABBOT_DAEMON_BIND") {
        command.env("CRABBOT_DAEMON_BIND", bind);
    }

    command
        .spawn()
        .with_context(|| format!("auto-start daemon via {}", binary.display()))?;
    Ok(())
}

fn spawn_daemon_via_cargo() -> Result<()> {
    if !Path::new("Cargo.toml").exists() {
        bail!("Cargo.toml not found in current working directory");
    }

    Command::new("cargo")
        .args(["run", "-p", "crabbot_daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("auto-start daemon via cargo run -p crabbot_daemon")?;
    Ok(())
}

fn daemon_start_session(
    daemon_endpoint: &str,
    session_id: Option<String>,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let url = endpoint_url(daemon_endpoint, "/v1/sessions/start");
    let response = apply_auth(client.post(url), auth_token)
        .json(&DaemonStartSessionRequest { session_id })
        .send()
        .context("request daemon session start")?
        .error_for_status()
        .context("daemon session start returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon start response")
}

fn daemon_resume_session(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/resume");
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.post(url), auth_token)
        .send()
        .context("request daemon session resume")?
        .error_for_status()
        .context("daemon session resume returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon resume response")
}

fn daemon_interrupt_session(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/interrupt");
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.post(url), auth_token)
        .send()
        .context("request daemon session interrupt")?
        .error_for_status()
        .context("daemon session interrupt returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon interrupt response")
}

fn daemon_prompt_session(
    daemon_endpoint: &str,
    session_id: &str,
    text: &str,
    auth_token: Option<&str>,
) -> Result<DaemonPromptResponse> {
    let path = format!("/v1/sessions/{session_id}/prompt");
    let url = endpoint_url(daemon_endpoint, &path);
    let request = DaemonPromptRequest {
        prompt: text.to_string(),
    };

    let response = send_daemon_prompt_request(&url, &request, auth_token).with_context(|| {
        format!("request daemon prompt (session={session_id}, endpoint={daemon_endpoint})")
    })?;
    if response.status() == StatusCode::NOT_FOUND {
        daemon_start_session(daemon_endpoint, Some(session_id.to_string()), auth_token)
            .with_context(|| format!("recover missing daemon session {session_id}"))?;
        let retry = send_daemon_prompt_request(&url, &request, auth_token).with_context(|| {
            format!("retry daemon prompt after session recovery (session={session_id})")
        })?;
        return parse_daemon_prompt_response(retry);
    }

    parse_daemon_prompt_response(response)
}

fn send_daemon_prompt_request(
    url: &str,
    request: &DaemonPromptRequest,
    auth_token: Option<&str>,
) -> Result<Response> {
    let client = http_client_with_timeout(DAEMON_PROMPT_REQUEST_TIMEOUT)?;
    apply_auth(client.post(url.to_string()), auth_token)
        .json(request)
        .send()
        .context("send daemon prompt request")
}

fn parse_daemon_prompt_response(response: Response) -> Result<DaemonPromptResponse> {
    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .ok()
            .map(|text| text.trim().to_string())
            .unwrap_or_default();
        if body.is_empty() {
            bail!("daemon prompt returned HTTP {status}");
        }
        bail!(
            "daemon prompt returned HTTP {status}: {}",
            truncate_for_width(&body, 200)
        );
    }

    response
        .json::<DaemonPromptResponse>()
        .context("parse daemon prompt response")
}

fn daemon_get_session_status(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/status");
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon session status")?
        .error_for_status()
        .context("daemon session status returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon status response")
}

fn daemon_app_server_rpc_request(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<DaemonRpcRequestResponse> {
    let client = http_client_with_timeout(DAEMON_PROMPT_REQUEST_TIMEOUT)?;
    let url = endpoint_url(daemon_endpoint, "/v2/app-server/request");
    let response = apply_auth(client.post(url), auth_token)
        .json(&DaemonRpcRequest {
            method: method.to_string(),
            params,
        })
        .send()
        .context("request daemon app-server rpc")?
        .error_for_status()
        .context("daemon app-server rpc returned error status")?;
    response
        .json::<DaemonRpcRequestResponse>()
        .context("parse daemon app-server rpc response")
}

fn daemon_app_server_rpc_respond(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    request_id: Value,
    result: Value,
) -> Result<()> {
    let client = http_client_with_timeout(DAEMON_PROMPT_REQUEST_TIMEOUT)?;
    let url = endpoint_url(daemon_endpoint, "/v2/app-server/respond");
    apply_auth(client.post(url), auth_token)
        .json(&DaemonRpcRespondRequest { request_id, result })
        .send()
        .context("respond daemon app-server request")?
        .error_for_status()
        .context("daemon app-server respond returned error status")?;
    Ok(())
}

fn fetch_daemon_app_server_stream(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    let client = http_client_with_timeout(TUI_STREAM_REQUEST_TIMEOUT)?;
    let mut path = "/v2/app-server/stream".to_string();
    if let Some(since_sequence) = since_sequence {
        path.push_str(&format!("?since_sequence={since_sequence}"));
    }
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon app-server stream")?;
    let body = response
        .error_for_status()
        .context("daemon app-server stream returned error status")?
        .text()
        .context("read daemon app-server stream body")?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<DaemonRpcStreamEnvelope>(line)
                .context("parse daemon app-server stream line")
        })
        .collect::<Result<Vec<_>>>()
}

fn request_id_key_for_cli(request_id: &Value) -> String {
    serde_json::to_string(request_id).unwrap_or_else(|_| request_id.to_string())
}

fn extract_thread_id_from_rpc_result(result: &Value) -> Option<String> {
    result
        .get("thread")
        .and_then(|thread| thread.get("id"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

#[derive(Debug)]
enum DaemonStreamFetchResult {
    Stream(Vec<DaemonStreamEnvelope>),
    NotFound,
}

fn fetch_daemon_stream(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
) -> Result<DaemonStreamFetchResult> {
    fetch_daemon_stream_with_timeout(
        daemon_endpoint,
        session_id,
        auth_token,
        since_sequence,
        Duration::from_secs(5),
    )
}

fn fetch_daemon_stream_with_timeout(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
    timeout: Duration,
) -> Result<DaemonStreamFetchResult> {
    let client = http_client_with_timeout(timeout)?;
    let mut path = format!("/v1/sessions/{session_id}/stream");
    if let Some(since_sequence) = since_sequence {
        path.push_str(&format!("?since_sequence={since_sequence}"));
    }
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon stream")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(DaemonStreamFetchResult::NotFound);
    }
    let body = response
        .error_for_status()
        .context("daemon stream returned error status")?
        .text()
        .context("read daemon stream body")?;

    let stream_events = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<DaemonStreamEnvelope>(line).context("parse daemon stream line")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DaemonStreamFetchResult::Stream(stream_events))
}

fn latest_cached_session_id(state: &CliState) -> Option<String> {
    state
        .sessions
        .iter()
        .max_by_key(|(_, value)| value.updated_at_unix_ms)
        .map(|(key, _)| key.clone())
}

fn cached_last_sequence(state: &CliState, session_id: &str) -> Option<u64> {
    state
        .sessions
        .get(session_id)
        .map(|runtime| runtime.last_sequence)
}

fn render_attach_tui(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    daemon_endpoint: &str,
) -> String {
    render_attach_tui_with_columns_and_fallback(
        session_id,
        stream_events,
        daemon_endpoint,
        terminal_columns(),
        None,
    )
}

#[cfg(test)]
fn render_attach_tui_with_columns(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    daemon_endpoint: &str,
    columns: usize,
) -> String {
    render_attach_tui_with_columns_and_fallback(
        session_id,
        stream_events,
        daemon_endpoint,
        columns,
        None,
    )
}

fn render_attach_tui_with_columns_and_fallback(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    daemon_endpoint: &str,
    columns: usize,
    fallback_state: Option<&str>,
) -> String {
    let mut output = String::new();
    let mut latest_state = fallback_state.unwrap_or("unknown").to_string();
    let mut previous_state: Option<String> = None;

    for envelope in stream_events {
        match &envelope.event {
            DaemonStreamEvent::SessionState(payload) => {
                if previous_state.as_deref() != Some(payload.state.as_str()) {
                    if payload.state == "interrupted" {
                        if !output.is_empty() && !output.ends_with('\n') {
                            output.push('\n');
                        }
                        output.push_str(&format!(
                            "[session interrupted] resume with: crabbot codex resume --session-id {session_id}\n"
                        ));
                    }

                    if previous_state.as_deref() == Some("interrupted")
                        && payload.state.as_str() == "active"
                    {
                        output.push_str("[session resumed] stream is active again\n");
                    }
                }
                latest_state = payload.state.clone();
                previous_state = Some(payload.state.clone());
            }
            DaemonStreamEvent::TurnStreamDelta(payload) => output.push_str(&payload.delta),
            DaemonStreamEvent::TurnCompleted(payload) => {
                if !output.is_empty() && !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str(&format!(
                    "[turn {} complete] {}\n",
                    payload.turn_id, payload.output_summary
                ));
            }
            DaemonStreamEvent::ApprovalRequired(payload) => {
                if !output.is_empty() && !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str(&format!(
                    "[approval required] id={} action={}\n",
                    payload.approval_id, payload.action_kind
                ));
                output.push_str(&format!("prompt: {}\n", payload.prompt));
                output.push_str(&format!(
                    "after approval, resume with: crabbot codex resume --session-id {session_id}\n"
                ));
            }
            DaemonStreamEvent::Heartbeat(_) => {}
        }
    }

    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }

    let last_sequence = stream_events
        .last()
        .map(|event| event.sequence)
        .unwrap_or(0);
    let footer = build_attach_footer(
        session_id,
        &latest_state,
        stream_events.len(),
        last_sequence,
        daemon_endpoint,
        columns,
    );

    let separator_width = columns.clamp(24, 80);
    output.push_str(&"-".repeat(separator_width));
    output.push('\n');
    output.push_str(&footer);
    output
}

fn cached_session_state_label<'a>(state: &'a CliState, session_id: &str) -> Option<&'a str> {
    state
        .sessions
        .get(session_id)
        .map(|runtime| match runtime.state {
            SessionStatus::Active => "active",
            SessionStatus::Interrupted => "interrupted",
        })
}

fn terminal_columns() -> usize {
    env::var("COLUMNS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|columns| *columns > 0)
        .unwrap_or(100)
}

fn build_attach_footer(
    session_id: &str,
    state: &str,
    received_events: usize,
    last_sequence: u64,
    daemon_endpoint: &str,
    columns: usize,
) -> String {
    let full = format!(
        "session={session_id} state={state} events={received_events} seq={last_sequence} daemon={daemon_endpoint}"
    );
    if full.len() <= columns {
        return full;
    }

    format!("session={session_id} state={state} events={received_events} seq={last_sequence}")
}

fn resolve_state_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("CRABBOT_CLI_STATE_PATH") {
        let candidate = PathBuf::from(path);
        if !candidate.as_os_str().is_empty() {
            return Ok(candidate);
        }
    }

    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".crabbot").join("cli-state.json"))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
