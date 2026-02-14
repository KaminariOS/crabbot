use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
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
        CodexSubcommand::Status(args) => handle_status(args, &state),
        CodexSubcommand::Attach(args) => handle_attach(args, &state),
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
    let now = now_unix_ms();
    let session_id = args
        .session_id
        .unwrap_or_else(|| format!("sess_local_{now}"));
    if session_id.trim().is_empty() {
        bail!("session_id cannot be empty");
    }

    state.sessions.insert(
        session_id.clone(),
        SessionRuntimeState {
            state: SessionStatus::Active,
            updated_at_unix_ms: now,
            last_event: "started".to_string(),
        },
    );

    Ok(json!({
        "ok": true,
        "action": "start",
        "session_id": session_id,
        "state": "active",
        "daemon_endpoint": state.config.daemon_endpoint,
        "api_endpoint": state.config.api_endpoint,
    }))
}

fn handle_resume(args: SessionArgs, state: &mut CliState) -> Result<Value> {
    let session = state
        .sessions
        .get_mut(&args.session_id)
        .ok_or_else(|| anyhow!("session not found: {}", args.session_id))?;
    session.state = SessionStatus::Active;
    session.updated_at_unix_ms = now_unix_ms();
    session.last_event = "resumed".to_string();

    Ok(json!({
        "ok": true,
        "action": "resume",
        "session_id": args.session_id,
        "state": "active",
    }))
}

fn handle_interrupt(args: SessionArgs, state: &mut CliState) -> Result<Value> {
    let session = state
        .sessions
        .get_mut(&args.session_id)
        .ok_or_else(|| anyhow!("session not found: {}", args.session_id))?;
    session.state = SessionStatus::Interrupted;
    session.updated_at_unix_ms = now_unix_ms();
    session.last_event = "interrupted".to_string();

    Ok(json!({
        "ok": true,
        "action": "interrupt",
        "session_id": args.session_id,
        "state": "interrupted",
    }))
}

fn handle_status(args: StatusArgs, state: &CliState) -> Result<Value> {
    if let Some(session_id) = args.session_id {
        let session = state
            .sessions
            .get(&session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        return Ok(json!({
            "ok": true,
            "session_id": session_id,
            "state": session.state,
            "updated_at_unix_ms": session.updated_at_unix_ms,
            "last_event": session.last_event,
            "daemon_endpoint": state.config.daemon_endpoint,
            "api_endpoint": state.config.api_endpoint,
        }));
    }

    Ok(json!({
        "ok": true,
        "sessions": state.sessions,
        "daemon_endpoint": state.config.daemon_endpoint,
        "api_endpoint": state.config.api_endpoint,
    }))
}

fn handle_attach(args: SessionArgs, state: &CliState) -> Result<Value> {
    let session = state
        .sessions
        .get(&args.session_id)
        .ok_or_else(|| anyhow!("session not found: {}", args.session_id))?;
    Ok(json!({
        "ok": true,
        "action": "attach",
        "session_id": args.session_id,
        "mirrored_state": session.state,
        "last_event": session.last_event,
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

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn start_interrupt_resume_and_status_roundtrip() {
        let (_dir, state_path) = temp_state_path();

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
                    }),
                }),
            },
            &state_path,
        );
        assert_eq!(status["state"], "active");
        assert_eq!(status["last_event"], "resumed");
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
    fn attach_reflects_session_state() {
        let (_dir, state_path) = temp_state_path();

        let _ = run_json(
            Cli {
                command: TopLevelCommand::Codex(CodexCommand {
                    command: CodexSubcommand::Start(StartArgs {
                        session_id: Some("sess_cli_attach".to_string()),
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
        assert_eq!(attach["mirrored_state"], "active");
    }
}
