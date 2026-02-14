use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use crabbot_protocol::{
    DaemonSessionStatusResponse, DaemonStartSessionRequest, DaemonStreamEnvelope,
    DaemonStreamEvent, HealthResponse,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

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
    command: CodexSubcommand,
}

#[derive(Debug, Subcommand)]
enum CodexSubcommand {
    Start(StartArgs),
    Resume(SessionArgs),
    Interrupt(SessionArgs),
    Status(StatusArgs),
    Attach(SessionArgs),
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
        CodexSubcommand::Start(args) => {
            should_persist = true;
            handle_start(args, &mut state)
        }
        CodexSubcommand::Resume(args) => {
            should_persist = true;
            handle_resume(args, &mut state)
        }
        CodexSubcommand::Interrupt(args) => {
            should_persist = true;
            handle_interrupt(args, &mut state)
        }
        CodexSubcommand::Status(args) => {
            should_persist = args.session_id.is_some();
            handle_status(args, &mut state)
        }
        CodexSubcommand::Attach(args) => {
            should_persist = true;
            handle_attach(args, &mut state)
        }
        CodexSubcommand::Config(command) => match command.command {
            ConfigSubcommand::Show => Ok(handle_config_show(&state)),
            ConfigSubcommand::Set(args) => {
                should_persist = true;
                handle_config_set(args, &mut state)
            }
        },
    }?;

    if should_persist {
        save_state(state_path, &state)?;
    }

    serde_json::to_string_pretty(&output).context("serialize cli output")
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

fn handle_attach(args: SessionArgs, state: &mut CliState) -> Result<Value> {
    if args.session_id.trim().is_empty() {
        bail!("session_id cannot be empty");
    }

    let stream_events = fetch_daemon_stream(
        &state.config.daemon_endpoint,
        &args.session_id,
        state.config.auth_token.as_deref(),
    )?;
    if let Some(latest_state) = stream_events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            DaemonStreamEvent::SessionState(payload) => Some(payload.state.clone()),
            _ => None,
        })
    {
        persist_daemon_session(
            state,
            &DaemonSessionStatusResponse {
                session_id: args.session_id.clone(),
                state: latest_state,
                last_event: "attached".to_string(),
                updated_at_unix_ms: now_unix_ms(),
            },
        )?;
    }
    let received_events = stream_events.len();
    let last_sequence = stream_events
        .last()
        .map(|event| event.sequence)
        .unwrap_or(0);

    Ok(json!({
        "ok": true,
        "action": "attach",
        "session_id": args.session_id,
        "stream_events": stream_events,
        "received_events": received_events,
        "last_sequence": last_sequence,
        "daemon_endpoint": state.config.daemon_endpoint,
    }))
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
    state.sessions.insert(
        daemon_session.session_id.clone(),
        SessionRuntimeState {
            state: state_value,
            updated_at_unix_ms: daemon_session.updated_at_unix_ms,
            last_event: daemon_session.last_event.clone(),
        },
    );
    Ok(())
}

fn http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build http client")
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

fn fetch_daemon_stream(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<Vec<DaemonStreamEnvelope>> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/stream");
    let url = endpoint_url(daemon_endpoint, &path);
    let body = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon stream")?
        .error_for_status()
        .context("daemon stream returned error status")?
        .text()
        .context("read daemon stream body")?;

    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<DaemonStreamEnvelope>(line).context("parse daemon stream line")
        })
        .collect()
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
    use crabbot_protocol::{
        DAEMON_STREAM_SCHEMA_VERSION, DaemonSessionState, DaemonStreamEvent, DaemonTurnStreamDelta,
        Heartbeat,
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread::JoinHandle,
    };
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
                    command: CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: None,
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    }),
                }),
            },
            &state_path,
        );

        let start = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Start(StartArgs {
                        session_id: Some("sess_cli_1".to_string()),
                    }),
                }),
            },
            &state_path,
        );
        assert_eq!(start["ok"], true);
        assert_eq!(start["state"], "active");

        let interrupt = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Interrupt(SessionArgs {
                        session_id: "sess_cli_1".to_string(),
                    }),
                }),
            },
            &state_path,
        );
        assert_eq!(interrupt["state"], "interrupted");

        let resume = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Resume(SessionArgs {
                        session_id: "sess_cli_1".to_string(),
                    }),
                }),
            },
            &state_path,
        );
        assert_eq!(resume["state"], "active");

        let status = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Status(StatusArgs {
                        session_id: Some("sess_cli_1".to_string()),
                        check_api: false,
                    }),
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
    fn config_set_and_show_roundtrip() {
        let (_dir, state_path) = temp_state_path();

        let set = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: Some("https://api.crabbot.local".to_string()),
                            daemon_endpoint: Some("https://daemon.crabbot.local".to_string()),
                            auth_token: Some("token_123".to_string()),
                            clear_auth_token: false,
                        }),
                    }),
                }),
            },
            &state_path,
        );
        assert_eq!(set["ok"], true);
        assert_eq!(set["config"]["api_endpoint"], "https://api.crabbot.local");

        let show = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Show,
                    }),
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
                    command: CodexSubcommand::Config(ConfigCommand {
                        command: ConfigSubcommand::Set(ConfigSetArgs {
                            api_endpoint: Some(api_endpoint),
                            daemon_endpoint: Some(daemon_endpoint),
                            auth_token: Some(auth_token.to_string()),
                            clear_auth_token: false,
                        }),
                    }),
                }),
            },
            &state_path,
        );

        let attach = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Attach(SessionArgs {
                        session_id: "sess_cli_attach".to_string(),
                    }),
                }),
            },
            &state_path,
        );
        assert_eq!(attach["ok"], true);
        assert_eq!(attach["received_events"], 3);
        assert_eq!(attach["last_sequence"], 3);
        assert_eq!(attach["stream_events"][0]["event"]["type"], "session_state");

        let status = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Status(StatusArgs {
                        session_id: None,
                        check_api: true,
                    }),
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
}
