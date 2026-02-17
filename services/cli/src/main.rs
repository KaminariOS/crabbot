use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use crabbot_protocol::DaemonPromptRequest;
use crabbot_protocol::DaemonPromptResponse;
use crabbot_protocol::DaemonRpcNotification;
use crabbot_protocol::DaemonRpcRequest;
use crabbot_protocol::DaemonRpcRequestResponse;
use crabbot_protocol::DaemonRpcRespondRequest;
use crabbot_protocol::DaemonRpcServerRequest;
use crabbot_protocol::DaemonRpcStreamEnvelope;
use crabbot_protocol::DaemonRpcStreamEvent;
use crabbot_protocol::DaemonSessionStatusResponse;
use crabbot_protocol::DaemonStartSessionRequest;
use crabbot_protocol::DaemonStreamEnvelope;
use crabbot_protocol::DaemonStreamEvent;
use crabbot_protocol::HealthResponse;
use crossterm::event::DisableBracketedPaste;
use crossterm::event::EnableBracketedPaste;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use crossterm::event::{self};
use crossterm::execute;
use crossterm::terminal::EnterAlternateScreen;
use crossterm::terminal::LeaveAlternateScreen;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use reqwest::StatusCode;
use reqwest::blocking::Client;
use reqwest::blocking::Response;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::IsTerminal;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const TUI_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TUI_EVENT_WAIT_STEP: Duration = Duration::from_millis(50);
const TUI_STREAM_REQUEST_TIMEOUT: Duration = Duration::from_millis(600);
const DAEMON_PROMPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const TUI_COMPOSER_PROMPT: &str = "\u{203a} ";
const TUI_COMPOSER_PLACEHOLDER: &str = "Ask Crabbot to do anything";
const TUI_SLASH_PICKER_MAX_ROWS: usize = 4;

#[derive(Debug, Parser)]
#[command(name = "crabbot", about = "Crabbot Linux CLI")]
struct Cli {
    #[command(subcommand)]
    command: TopLevelCommand,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    Codex(CodexCommand),
}

#[derive(Debug, Args)]
struct CodexCommand {
    #[command(subcommand)]
    command: Option<CodexSubcommand>,
}

#[derive(Debug, Subcommand)]
enum CodexSubcommand {
    Start(StartArgs),
    Prompt(PromptArgs),
    Resume(SessionArgs),
    Interrupt(SessionArgs),
    Status(StatusArgs),
    Tui(TuiArgs),
    Attach(AttachArgs),
    Config(ConfigCommand),
}

#[derive(Debug, Args)]
struct StartArgs {
    #[arg(long)]
    session_id: Option<String>,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[arg(long)]
    session_id: String,
}

#[derive(Debug, Args)]
struct PromptArgs {
    #[arg(long)]
    session_id: String,
    #[arg(long)]
    text: String,
}

#[derive(Debug, Args)]
struct AttachArgs {
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long, default_value_t = false)]
    tui: bool,
}

#[derive(Debug, Args)]
struct TuiArgs {
    #[arg(long)]
    thread_id: Option<String>,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[arg(long)]
    session_id: Option<String>,
    #[arg(long, default_value_t = false)]
    check_api: bool,
}

#[derive(Debug, Args)]
struct ConfigCommand {
    #[command(subcommand)]
    command: ConfigSubcommand,
}

#[derive(Debug, Subcommand)]
enum ConfigSubcommand {
    Show,
    Set(ConfigSetArgs),
}

#[derive(Debug, Args)]
struct ConfigSetArgs {
    #[arg(long)]
    api_endpoint: Option<String>,
    #[arg(long)]
    daemon_endpoint: Option<String>,
    #[arg(long)]
    auth_token: Option<String>,
    #[arg(long, default_value_t = false)]
    clear_auth_token: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SessionStatus {
    Active,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRuntimeState {
    state: SessionStatus,
    updated_at_unix_ms: u64,
    last_event: String,
    #[serde(default)]
    last_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CliConfig {
    api_endpoint: String,
    daemon_endpoint: String,
    auth_token: Option<String>,
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
struct CliState {
    sessions: BTreeMap<String, SessionRuntimeState>,
    config: CliConfig,
    #[serde(default)]
    last_thread_id: Option<String>,
}

enum CommandOutput {
    Json(Value),
    Text(String),
}

impl CommandOutput {
    fn into_string(self) -> Result<String> {
        match self {
            Self::Json(value) => {
                serde_json::to_string_pretty(&value).context("serialize cli output")
            }
            Self::Text(value) => Ok(value),
        }
    }
}

fn convert_state_to_tui(state: &CliState) -> Result<crabbot_tui::CliState> {
    let value = serde_json::to_value(state).context("serialize cli state for tui crate")?;
    serde_json::from_value(value).context("deserialize cli state into tui crate state")
}

fn convert_state_from_tui(state: crabbot_tui::CliState) -> Result<CliState> {
    let value = serde_json::to_value(state).context("serialize tui crate state for cli")?;
    serde_json::from_value(value).context("deserialize tui crate state into cli state")
}

fn convert_output_from_tui(output: crabbot_tui::CommandOutput) -> CommandOutput {
    match output {
        crabbot_tui::CommandOutput::Json(value) => CommandOutput::Json(value),
        crabbot_tui::CommandOutput::Text(value) => CommandOutput::Text(value),
    }
}

fn handle_tui_with_crate(args: TuiArgs, state: &mut CliState) -> Result<CommandOutput> {
    let mut tui_state = convert_state_to_tui(state)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("initialize tokio runtime for tui")?;
    let output = runtime.block_on(async {
        crabbot_tui::handle_tui(
            crabbot_tui::TuiArgs {
                thread_id: args.thread_id,
            },
            &mut tui_state,
        )
    })?;
    *state = convert_state_from_tui(tui_state)?;
    Ok(convert_output_from_tui(output))
}

fn handle_attach_tui_interactive_with_crate(
    session_id: String,
    initial_events: Vec<DaemonStreamEnvelope>,
    state: &mut CliState,
) -> Result<CommandOutput> {
    let mut tui_state = convert_state_to_tui(state)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("initialize tokio runtime for attach tui")?;
    let output = runtime.block_on(async {
        crabbot_tui::handle_attach_tui_interactive(session_id, initial_events, &mut tui_state)
    })?;
    *state = convert_state_from_tui(tui_state)?;
    Ok(convert_output_from_tui(output))
}

fn main() {
    if let Err(error) = run(Cli::parse()) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let state_path = resolve_state_path()?;
    let output = run_with_state_path(cli, &state_path)?;
    println!("{output}");
    Ok(())
}

fn run_with_state_path(cli: Cli, state_path: &Path) -> Result<String> {
    match cli.command {
        TopLevelCommand::Codex(command) => run_codex(command, state_path),
    }
}

fn run_codex(command: CodexCommand, state_path: &Path) -> Result<String> {
    let mut state = load_state(state_path)?;
    let mut should_persist = false;

    let output = match command.command {
        Some(CodexSubcommand::Start(args)) => {
            should_persist = true;
            handle_start(args, &mut state).map(CommandOutput::Json)
        }
        Some(CodexSubcommand::Prompt(args)) => {
            should_persist = true;
            handle_prompt(args, &mut state).map(CommandOutput::Json)
        }
        Some(CodexSubcommand::Resume(args)) => {
            should_persist = true;
            handle_resume(args, &mut state).map(CommandOutput::Json)
        }
        Some(CodexSubcommand::Interrupt(args)) => {
            should_persist = true;
            handle_interrupt(args, &mut state).map(CommandOutput::Json)
        }
        Some(CodexSubcommand::Status(args)) => {
            should_persist = args.session_id.is_some();
            handle_status(args, &mut state).map(CommandOutput::Json)
        }
        Some(CodexSubcommand::Tui(args)) => {
            should_persist = true;
            handle_tui_with_crate(args, &mut state)
        }
        Some(CodexSubcommand::Attach(args)) => {
            should_persist = true;
            handle_attach(args, &mut state)
        }
        Some(CodexSubcommand::Config(command)) => match command.command {
            ConfigSubcommand::Show => Ok(CommandOutput::Json(handle_config_show(&state))),
            ConfigSubcommand::Set(args) => {
                should_persist = true;
                handle_config_set(args, &mut state).map(CommandOutput::Json)
            }
        },
        None => {
            should_persist = true;
            handle_codex_default(&mut state)
        }
    }?;

    if should_persist {
        save_state(state_path, &state)?;
    }

    output.into_string()
}

fn handle_codex_default(state: &mut CliState) -> Result<CommandOutput> {
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        ensure_daemon_ready(state)?;
        let daemon_session = daemon_start_session(
            &state.config.daemon_endpoint,
            None,
            state.config.auth_token.as_deref(),
        )?;
        persist_daemon_session(state, &daemon_session)?;
        return handle_attach(
            AttachArgs {
                session_id: Some(daemon_session.session_id),
                tui: true,
            },
            state,
        );
    }
    handle_tui_with_crate(
        TuiArgs {
            // Leave this empty so TUI can treat persisted `last_thread_id` as
            // cache (resume-or-start fallback), not as strict explicit input.
            thread_id: None,
        },
        state,
    )
}

fn handle_start(args: StartArgs, state: &mut CliState) -> Result<Value> {
    if args
        .session_id
        .as_deref()
        .is_some_and(|session_id| session_id.trim().is_empty())
    {
        bail!("session_id cannot be empty");
    }
    let daemon_session = daemon_start_session(
        &state.config.daemon_endpoint,
        args.session_id,
        state.config.auth_token.as_deref(),
    )?;
    persist_daemon_session(state, &daemon_session)?;

    Ok(json!({
        "ok": true,
        "action": "start",
        "session_id": daemon_session.session_id,
        "state": daemon_session.state,
        "last_event": daemon_session.last_event,
        "updated_at_unix_ms": daemon_session.updated_at_unix_ms,
        "daemon_endpoint": state.config.daemon_endpoint,
        "api_endpoint": state.config.api_endpoint,
    }))
}

fn handle_prompt(args: PromptArgs, state: &mut CliState) -> Result<Value> {
    if args.session_id.trim().is_empty() {
        bail!("session_id cannot be empty");
    }
    if args.text.trim().is_empty() {
        bail!("text cannot be empty");
    }

    let prompt = daemon_prompt_session(
        &state.config.daemon_endpoint,
        &args.session_id,
        &args.text,
        state.config.auth_token.as_deref(),
    )?;
    persist_daemon_session(
        state,
        &DaemonSessionStatusResponse {
            session_id: prompt.session_id.clone(),
            state: prompt.state.clone(),
            last_event: prompt.last_event.clone(),
            updated_at_unix_ms: prompt.updated_at_unix_ms,
        },
    )?;

    Ok(json!({
        "ok": true,
        "action": "prompt",
        "session_id": prompt.session_id,
        "turn_id": prompt.turn_id,
        "state": prompt.state,
        "last_event": prompt.last_event,
        "last_sequence": prompt.last_sequence,
        "updated_at_unix_ms": prompt.updated_at_unix_ms,
    }))
}

fn handle_resume(args: SessionArgs, state: &mut CliState) -> Result<Value> {
    if args.session_id.trim().is_empty() {
        bail!("session_id cannot be empty");
    }
    let daemon_session = daemon_resume_session(
        &state.config.daemon_endpoint,
        &args.session_id,
        state.config.auth_token.as_deref(),
    )?;
    persist_daemon_session(state, &daemon_session)?;

    Ok(json!({
        "ok": true,
        "action": "resume",
        "session_id": daemon_session.session_id,
        "state": daemon_session.state,
        "last_event": daemon_session.last_event,
        "updated_at_unix_ms": daemon_session.updated_at_unix_ms,
    }))
}

fn handle_interrupt(args: SessionArgs, state: &mut CliState) -> Result<Value> {
    if args.session_id.trim().is_empty() {
        bail!("session_id cannot be empty");
    }
    let daemon_session = daemon_interrupt_session(
        &state.config.daemon_endpoint,
        &args.session_id,
        state.config.auth_token.as_deref(),
    )?;
    persist_daemon_session(state, &daemon_session)?;

    Ok(json!({
        "ok": true,
        "action": "interrupt",
        "session_id": daemon_session.session_id,
        "state": daemon_session.state,
        "last_event": daemon_session.last_event,
        "updated_at_unix_ms": daemon_session.updated_at_unix_ms,
    }))
}

fn handle_status(args: StatusArgs, state: &mut CliState) -> Result<Value> {
    let api_health = if args.check_api {
        Some(fetch_api_health(
            &state.config.api_endpoint,
            state.config.auth_token.as_deref(),
        )?)
    } else {
        None
    };

    if let Some(session_id) = args.session_id {
        let daemon_session = daemon_get_session_status(
            &state.config.daemon_endpoint,
            &session_id,
            state.config.auth_token.as_deref(),
        )?;
        persist_daemon_session(state, &daemon_session)?;
        return Ok(json!({
            "ok": true,
            "session_id": daemon_session.session_id,
            "state": daemon_session.state,
            "updated_at_unix_ms": daemon_session.updated_at_unix_ms,
            "last_event": daemon_session.last_event,
            "daemon_endpoint": state.config.daemon_endpoint,
            "api_endpoint": state.config.api_endpoint,
            "api_health": api_health,
        }));
    }

    Ok(json!({
        "ok": true,
        "sessions": state.sessions,
        "daemon_endpoint": state.config.daemon_endpoint,
        "api_endpoint": state.config.api_endpoint,
        "api_health": api_health,
    }))
}

fn handle_attach(args: AttachArgs, state: &mut CliState) -> Result<CommandOutput> {
    let auth_token = state.config.auth_token.clone();
    let is_interactive_tui = args.tui && io::stdin().is_terminal() && io::stdout().is_terminal();
    let session_id_was_provided = args.session_id.is_some();
    let mut created_session = false;
    let mut session_id = if let Some(session_id) = args.session_id {
        if session_id.trim().is_empty() {
            bail!("session_id cannot be empty");
        }
        session_id
    } else if let Some(session_id) = latest_cached_session_id(state) {
        session_id
    } else {
        let daemon_session =
            daemon_start_session(&state.config.daemon_endpoint, None, auth_token.as_deref())?;
        created_session = true;
        let session_id = daemon_session.session_id.clone();
        persist_daemon_session(state, &daemon_session)?;
        session_id
    };
    let initial_since_sequence = if is_interactive_tui {
        cached_last_sequence(state, &session_id).filter(|sequence| *sequence > 0)
    } else {
        None
    };
    let should_skip_initial_backlog = is_interactive_tui
        && !session_id_was_provided
        && !created_session
        && initial_since_sequence.is_none();

    let mut stream_not_found = false;
    let mut stream_events = match fetch_daemon_stream(
        &state.config.daemon_endpoint,
        &session_id,
        auth_token.as_deref(),
        initial_since_sequence,
    )? {
        DaemonStreamFetchResult::Stream(events) => events,
        DaemonStreamFetchResult::NotFound => {
            stream_not_found = true;
            Vec::new()
        }
    };
    if stream_not_found {
        let daemon_session = daemon_start_session(
            &state.config.daemon_endpoint,
            Some(session_id.clone()),
            auth_token.as_deref(),
        )?;
        created_session = true;
        session_id = daemon_session.session_id.clone();
        persist_daemon_session(state, &daemon_session)?;
        stream_events = match fetch_daemon_stream(
            &state.config.daemon_endpoint,
            &session_id,
            auth_token.as_deref(),
            None,
        )? {
            DaemonStreamFetchResult::Stream(events) => events,
            DaemonStreamFetchResult::NotFound => {
                bail!("daemon stream not found after creating session: {session_id}")
            }
        };
    }
    persist_latest_session_state_from_stream(state, &session_id, &stream_events)?;
    if should_skip_initial_backlog {
        stream_events.clear();
    }
    let received_events = stream_events.len();
    let last_sequence = stream_events
        .last()
        .map(|event| event.sequence)
        .unwrap_or(0);

    let json_output = json!({
        "ok": true,
        "action": "attach",
        "session_id": session_id.clone(),
        "stream_events": stream_events,
        "received_events": received_events,
        "last_sequence": last_sequence,
        "created_session": created_session,
        "daemon_endpoint": state.config.daemon_endpoint,
    });

    if args.tui {
        if is_interactive_tui {
            return handle_attach_tui_interactive_with_crate(session_id, stream_events, state);
        }
        return Ok(CommandOutput::Text(render_attach_tui(
            &session_id,
            &stream_events,
            &state.config.daemon_endpoint,
        )));
    }

    Ok(CommandOutput::Json(json_output))
}

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

fn load_state(path: &Path) -> Result<CliState> {
    if !path.exists() {
        return Ok(CliState::default());
    }

    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let state = serde_json::from_str(&raw)
        .with_context(|| format!("parse state json from {}", path.display()))?;
    Ok(state)
}

fn save_state(path: &Path, state: &CliState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create state dir {}", parent.display()))?;
    }
    let data = serde_json::to_vec_pretty(state).context("serialize state json")?;
    fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabbot_protocol::DAEMON_STREAM_SCHEMA_VERSION;
    use crabbot_protocol::DaemonApprovalRequired;
    use crabbot_protocol::DaemonSessionState;
    use crabbot_protocol::DaemonStreamEvent;
    use crabbot_protocol::DaemonTurnStreamDelta;
    use crabbot_protocol::Heartbeat;
    use std::io::Read;
    use std::io::Write;
    use std::net::TcpListener;
    use std::thread::JoinHandle;
    use tempfile::TempDir;

    fn temp_state_path() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("state.json");
        (dir, path)
    }

    fn run_json(cli: Cli, state_path: &Path) -> Value {
        let output = run_with_state_path(cli, state_path).expect("run command");
        serde_json::from_str(&output).expect("parse command output")
    }

    #[derive(Debug)]
    struct MockExpectation {
        request_line: String,
        status_line: String,
        content_type: String,
        body: String,
        auth_token: Option<String>,
    }

    fn assert_auth_header(request: &str, auth_token: Option<&str>) {
        let auth_line = request
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("authorization:"));
        match auth_token {
            Some(token) => {
                let actual = auth_line.expect("missing authorization header");
                assert_eq!(actual, format!("authorization: Bearer {token}"));
            }
            None => assert!(
                auth_line.is_none(),
                "unexpected authorization header: {auth_line:?}"
            ),
        }
    }

    fn spawn_mock_get_server(
        expected_path: &str,
        expected_auth_token: Option<&str>,
        content_type: &str,
        body: String,
    ) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock server local addr");
        let expected_request_line = format!("GET {expected_path} HTTP/1.1");
        let content_type = content_type.to_string();
        let expected_auth_token = expected_auth_token.map(|token| token.to_string());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock request");
            let mut buffer = [0_u8; 8 * 1024];
            let read = stream.read(&mut buffer).expect("read request");
            let request = String::from_utf8_lossy(&buffer[..read]);
            let first_line = request.lines().next().unwrap_or_default();
            assert_eq!(first_line, expected_request_line);
            assert_auth_header(&request, expected_auth_token.as_deref());

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
            stream.flush().expect("flush response");
        });

        (format!("http://{addr}"), handle)
    }

    fn spawn_mock_sequence_server(expectations: Vec<MockExpectation>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock sequence server");
        let addr = listener.local_addr().expect("mock server local addr");
        let handle = std::thread::spawn(move || {
            for expectation in expectations {
                let (mut stream, _) = listener.accept().expect("accept mock request");
                let mut buffer = [0_u8; 8 * 1024];
                let read = stream.read(&mut buffer).expect("read request");
                let request = String::from_utf8_lossy(&buffer[..read]);
                let first_line = request.lines().next().unwrap_or_default();
                assert_eq!(first_line, expectation.request_line);
                assert_auth_header(&request, expectation.auth_token.as_deref());

                let response = format!(
                    "{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    expectation.status_line,
                    expectation.content_type,
                    expectation.body.len(),
                    expectation.body,
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("write response");
                stream.flush().expect("flush response");
            }
        });

        (format!("http://{addr}"), handle)
    }

    #[test]
    fn start_interrupt_resume_and_status_roundtrip() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_m5";
        let (daemon_endpoint, daemon_handle) = spawn_mock_sequence_server(vec![
            MockExpectation {
                request_line: "POST /v1/sessions/start HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 201 Created".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_cli_1","state":"active","last_event":"started","updated_at_unix_ms":10}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "POST /v1/sessions/sess_cli_1/interrupt HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_cli_1","state":"interrupted","last_event":"interrupted","updated_at_unix_ms":20}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "POST /v1/sessions/sess_cli_1/resume HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_cli_1","state":"active","last_event":"resumed","updated_at_unix_ms":30}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "GET /v1/sessions/sess_cli_1/status HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_cli_1","state":"active","last_event":"resumed","updated_at_unix_ms":31}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
        ]);

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let start = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Start(StartArgs {
                        session_id: Some("sess_cli_1".to_string()),
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(start["ok"], true);
        assert_eq!(start["state"], "active");

        let interrupt = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Interrupt(SessionArgs {
                        session_id: "sess_cli_1".to_string(),
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(interrupt["state"], "interrupted");

        let resume = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Resume(SessionArgs {
                        session_id: "sess_cli_1".to_string(),
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(resume["state"], "active");

        let status = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Status(StatusArgs {
                        session_id: Some("sess_cli_1".to_string()),
                        check_api: false,
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(status["state"], "active");
        assert_eq!(status["last_event"], "resumed");
        assert_eq!(status["updated_at_unix_ms"], 31);
        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn prompt_command_posts_text_and_returns_turn_metadata() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_prompt";
        let (daemon_endpoint, daemon_handle) = spawn_mock_sequence_server(vec![
            MockExpectation {
                request_line: "POST /v1/sessions/sess_cli_prompt/prompt HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 202 Accepted".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_cli_prompt","turn_id":"turn_sess_cli_prompt_1","state":"active","last_event":"turn_completed","updated_at_unix_ms":99,"last_sequence":4}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
        ]);

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let prompt = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Prompt(PromptArgs {
                        session_id: "sess_cli_prompt".to_string(),
                        text: "ship it".to_string(),
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(prompt["ok"], true);
        assert_eq!(prompt["action"], "prompt");
        assert_eq!(prompt["turn_id"], "turn_sess_cli_prompt_1");
        assert_eq!(prompt["last_sequence"], 4);
        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn config_set_and_show_roundtrip() {
        let (_dir, state_path) = temp_state_path();

        let set = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: Some("https://api.crabbot.local".to_string()),
                            daemon_endpoint: Some("https://daemon.crabbot.local".to_string()),
                            auth_token: Some("token_123".to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(set["ok"], true);
        assert_eq!(set["config"]["api_endpoint"], "https://api.crabbot.local");

        let show = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Show,
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(
            show["config"]["daemon_endpoint"],
            "https://daemon.crabbot.local"
        );
        assert_eq!(show["config"]["auth_token"], "token_123");
    }

    #[test]
    fn attach_uses_daemon_stream_and_status_can_check_api_health() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_attach";

        let daemon_events = vec![
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_attach".to_string(),
                sequence: 1,
                event: DaemonStreamEvent::SessionState(DaemonSessionState {
                    state: "active".to_string(),
                }),
            },
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_attach".to_string(),
                sequence: 2,
                event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                    turn_id: "turn_1".to_string(),
                    delta: "hello from daemon".to_string(),
                }),
            },
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_attach".to_string(),
                sequence: 3,
                event: DaemonStreamEvent::Heartbeat(Heartbeat { unix_ms: 123 }),
            },
        ];
        let daemon_body = daemon_events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize daemon event"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let (daemon_endpoint, daemon_handle) = spawn_mock_get_server(
            "/v1/sessions/sess_cli_attach/stream",
            Some(auth_token),
            "application/x-ndjson",
            daemon_body,
        );
        let (api_endpoint, api_handle) = spawn_mock_get_server(
            "/health",
            Some(auth_token),
            "application/json",
            r#"{"status":"ok","service":"mock_api","version":"1.2.3"}"#.to_string(),
        );

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: Some(api_endpoint),
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let attach = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Attach(AttachArgs {
                        session_id: Some("sess_cli_attach".to_string()),
                        tui: false,
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(attach["ok"], true);
        assert_eq!(attach["received_events"], 3);
        assert_eq!(attach["last_sequence"], 3);
        assert_eq!(attach["created_session"], false);
        assert_eq!(attach["stream_events"][0]["event"]["type"], "session_state");

        let status = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Status(StatusArgs {
                        session_id: None,
                        check_api: true,
                    })),
                }),
            },
            &state_path,
        );
        assert_eq!(status["ok"], true);
        assert_eq!(status["api_health"]["service"], "mock_api");
        assert_eq!(status["sessions"]["sess_cli_attach"]["state"], "active");
        assert_eq!(
            status["sessions"]["sess_cli_attach"]["last_event"],
            "attached"
        );

        daemon_handle.join().expect("join daemon mock thread");
        api_handle.join().expect("join api mock thread");
    }

    #[test]
    fn attach_without_session_id_uses_latest_cached_session() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_attach_latest";
        let daemon_body = format!(
            "{}\n",
            serde_json::to_string(&DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_latest".to_string(),
                sequence: 7,
                event: DaemonStreamEvent::SessionState(DaemonSessionState {
                    state: "active".to_string(),
                }),
            })
            .expect("serialize daemon event")
        );
        let (daemon_endpoint, daemon_handle) = spawn_mock_get_server(
            "/v1/sessions/sess_latest/stream",
            Some(auth_token),
            "application/x-ndjson",
            daemon_body,
        );

        save_state(
            &state_path,
            &CliState {
                sessions: BTreeMap::from([
                    (
                        "sess_old".to_string(),
                        SessionRuntimeState {
                            state: SessionStatus::Active,
                            updated_at_unix_ms: 10,
                            last_event: "attached".to_string(),
                            last_sequence: 0,
                        },
                    ),
                    (
                        "sess_latest".to_string(),
                        SessionRuntimeState {
                            state: SessionStatus::Active,
                            updated_at_unix_ms: 20,
                            last_event: "attached".to_string(),
                            last_sequence: 0,
                        },
                    ),
                ]),
                config: CliConfig {
                    api_endpoint: "http://127.0.0.1:8787".to_string(),
                    daemon_endpoint,
                    auth_token: Some(auth_token.to_string()),
                },
                last_thread_id: None,
            },
        )
        .expect("seed cli state");

        let attach = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Attach(AttachArgs {
                        session_id: None,
                        tui: false,
                    })),
                }),
            },
            &state_path,
        );

        assert_eq!(attach["ok"], true);
        assert_eq!(attach["session_id"], "sess_latest");
        assert_eq!(attach["created_session"], false);
        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn attach_without_session_id_creates_new_session_when_cache_empty() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_attach_create";
        let daemon_body = format!(
            "{}\n",
            serde_json::to_string(&DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_auto_1".to_string(),
                sequence: 1,
                event: DaemonStreamEvent::SessionState(DaemonSessionState {
                    state: "active".to_string(),
                }),
            })
            .expect("serialize daemon event")
        );
        let (daemon_endpoint, daemon_handle) = spawn_mock_sequence_server(vec![
            MockExpectation {
                request_line: "POST /v1/sessions/start HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 201 Created".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_auto_1","state":"active","last_event":"started","updated_at_unix_ms":100}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "GET /v1/sessions/sess_auto_1/stream HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/x-ndjson".to_string(),
                body: daemon_body,
                auth_token: Some(auth_token.to_string()),
            },
        ]);

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let attach = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Attach(AttachArgs {
                        session_id: None,
                        tui: false,
                    })),
                }),
            },
            &state_path,
        );

        assert_eq!(attach["ok"], true);
        assert_eq!(attach["session_id"], "sess_auto_1");
        assert_eq!(attach["created_session"], true);
        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn attach_recreates_missing_session_on_404() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_attach_recreate";
        let daemon_body = format!(
            "{}\n",
            serde_json::to_string(&DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_missing".to_string(),
                sequence: 1,
                event: DaemonStreamEvent::SessionState(DaemonSessionState {
                    state: "active".to_string(),
                }),
            })
            .expect("serialize daemon event")
        );
        let (daemon_endpoint, daemon_handle) = spawn_mock_sequence_server(vec![
            MockExpectation {
                request_line: "GET /v1/sessions/sess_missing/stream HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 404 Not Found".to_string(),
                content_type: "text/plain".to_string(),
                body: "not found".to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "POST /v1/sessions/start HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 201 Created".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_missing","state":"active","last_event":"started","updated_at_unix_ms":101}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "GET /v1/sessions/sess_missing/stream HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/x-ndjson".to_string(),
                body: daemon_body,
                auth_token: Some(auth_token.to_string()),
            },
        ]);

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let attach = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Attach(AttachArgs {
                        session_id: Some("sess_missing".to_string()),
                        tui: false,
                    })),
                }),
            },
            &state_path,
        );

        assert_eq!(attach["ok"], true);
        assert_eq!(attach["session_id"], "sess_missing");
        assert_eq!(attach["created_session"], true);
        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn attach_tui_renders_stream_and_footer() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_attach_tui";

        let daemon_events = vec![
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_tui".to_string(),
                sequence: 1,
                event: DaemonStreamEvent::SessionState(DaemonSessionState {
                    state: "active".to_string(),
                }),
            },
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_tui".to_string(),
                sequence: 2,
                event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                    turn_id: "turn_1".to_string(),
                    delta: "hello ".to_string(),
                }),
            },
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_tui".to_string(),
                sequence: 3,
                event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                    turn_id: "turn_1".to_string(),
                    delta: "world".to_string(),
                }),
            },
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_cli_tui".to_string(),
                sequence: 4,
                event: DaemonStreamEvent::TurnCompleted(crabbot_protocol::DaemonTurnCompleted {
                    turn_id: "turn_1".to_string(),
                    output_summary: "done".to_string(),
                }),
            },
        ];
        let daemon_body = daemon_events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize daemon event"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let (daemon_endpoint, daemon_handle) = spawn_mock_get_server(
            "/v1/sessions/sess_cli_tui/stream",
            Some(auth_token),
            "application/x-ndjson",
            daemon_body,
        );

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint.clone()),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let output = run_with_state_path(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Attach(AttachArgs {
                        session_id: Some("sess_cli_tui".to_string()),
                        tui: true,
                    })),
                }),
            },
            &state_path,
        )
        .expect("run attach tui");

        assert!(output.contains("hello world"));
        assert!(output.contains("[turn turn_1 complete] done"));
        assert!(output.contains("session=sess_cli_tui state=active events=4 seq=4"));
        assert!(output.contains(&format!("daemon={daemon_endpoint}")));

        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn codex_default_runs_tui_attach_flow() {
        let (_dir, state_path) = temp_state_path();
        let auth_token = "token_cli_default";
        let daemon_events = vec![
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_default".to_string(),
                sequence: 1,
                event: DaemonStreamEvent::SessionState(DaemonSessionState {
                    state: "active".to_string(),
                }),
            },
            DaemonStreamEnvelope {
                schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                session_id: "sess_default".to_string(),
                sequence: 2,
                event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                    turn_id: "turn_default".to_string(),
                    delta: "hello default".to_string(),
                }),
            },
        ];
        let daemon_body = daemon_events
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize daemon event"))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";

        let (daemon_endpoint, daemon_handle) = spawn_mock_sequence_server(vec![
            MockExpectation {
                request_line: "GET /health HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"status":"ok","service":"crabbot_daemon","version":"0.1.0"}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "POST /v1/sessions/start HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 201 Created".to_string(),
                content_type: "application/json".to_string(),
                body: r#"{"session_id":"sess_default","state":"active","last_event":"started","updated_at_unix_ms":220}"#
                    .to_string(),
                auth_token: Some(auth_token.to_string()),
            },
            MockExpectation {
                request_line: "GET /v1/sessions/sess_default/stream HTTP/1.1".to_string(),
                status_line: "HTTP/1.1 200 OK".to_string(),
                content_type: "application/x-ndjson".to_string(),
                body: daemon_body,
                auth_token: Some(auth_token.to_string()),
            },
        ]);

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: Some(CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    })),
                }),
            },
            &state_path,
        );

        let output = run_with_state_path(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand { command: None }),
            },
            &state_path,
        )
        .expect("run codex default command");

        assert!(output.contains("hello default"));
        assert!(output.contains("session=sess_default state=active events=2 seq=2"));
        daemon_handle.join().expect("join daemon mock thread");
    }

    #[test]
    fn attach_footer_compacts_for_narrow_terminal_width() {
        let wide = build_attach_footer("sess_1", "active", 12, 42, "http://127.0.0.1:8788", 160);
        assert!(wide.contains("daemon=http://127.0.0.1:8788"));

        let narrow = build_attach_footer("sess_1", "active", 12, 42, "http://127.0.0.1:8788", 48);
        assert!(!narrow.contains("daemon="));
        assert!(narrow.contains("session=sess_1 state=active events=12 seq=42"));
    }

    #[test]
    fn attach_tui_shows_approval_and_resume_recovery_hints() {
        let output = render_attach_tui(
            "sess_recover",
            &[
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_recover".to_string(),
                    sequence: 1,
                    event: DaemonStreamEvent::SessionState(DaemonSessionState {
                        state: "active".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_recover".to_string(),
                    sequence: 2,
                    event: DaemonStreamEvent::ApprovalRequired(DaemonApprovalRequired {
                        turn_id: "turn_recover_1".to_string(),
                        approval_id: "approval_recover_1".to_string(),
                        action_kind: "shell_command".to_string(),
                        prompt: "Allow cat Cargo.toml?".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_recover".to_string(),
                    sequence: 3,
                    event: DaemonStreamEvent::SessionState(DaemonSessionState {
                        state: "interrupted".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_recover".to_string(),
                    sequence: 4,
                    event: DaemonStreamEvent::SessionState(DaemonSessionState {
                        state: "active".to_string(),
                    }),
                },
            ],
            "http://127.0.0.1:8788",
        );

        assert!(output.contains("[approval required] id=approval_recover_1 action=shell_command"));
        assert!(output.contains("prompt: Allow cat Cargo.toml?"));
        assert!(output.contains(
            "after approval, resume with: crabbot codex resume --session-id sess_recover"
        ));
        assert!(output.contains(
            "[session interrupted] resume with: crabbot codex resume --session-id sess_recover"
        ));
        assert!(output.contains("[session resumed] stream is active again"));
    }

    #[test]
    fn attach_tui_output_matches_golden_fixture() {
        let output = render_attach_tui_with_columns(
            "sess_golden",
            &[
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 1,
                    event: DaemonStreamEvent::SessionState(DaemonSessionState {
                        state: "active".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 2,
                    event: DaemonStreamEvent::ApprovalRequired(DaemonApprovalRequired {
                        turn_id: "turn_golden_1".to_string(),
                        approval_id: "approval_golden_1".to_string(),
                        action_kind: "shell_command".to_string(),
                        prompt: "Allow ls -la?".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 3,
                    event: DaemonStreamEvent::SessionState(DaemonSessionState {
                        state: "interrupted".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 4,
                    event: DaemonStreamEvent::SessionState(DaemonSessionState {
                        state: "active".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 5,
                    event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                        turn_id: "turn_golden_1".to_string(),
                        delta: "Hello, ".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 6,
                    event: DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                        turn_id: "turn_golden_1".to_string(),
                        delta: "world!".to_string(),
                    }),
                },
                DaemonStreamEnvelope {
                    schema_version: DAEMON_STREAM_SCHEMA_VERSION,
                    session_id: "sess_golden".to_string(),
                    sequence: 7,
                    event: DaemonStreamEvent::TurnCompleted(
                        crabbot_protocol::DaemonTurnCompleted {
                            turn_id: "turn_golden_1".to_string(),
                            output_summary: "done".to_string(),
                        },
                    ),
                },
            ],
            "http://127.0.0.1:8788",
            24,
        );

        let expected = include_str!("../tests/golden/attach_tui_output.txt").trim_end_matches('\n');
        assert_eq!(output, expected);
    }
}
