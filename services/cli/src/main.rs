use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use clap::ArgAction;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use crabbot_protocol::DaemonPromptRequest;
use crabbot_protocol::DaemonPromptResponse;
use crabbot_protocol::DaemonSessionStatusResponse;
use crabbot_protocol::DaemonStartSessionRequest;
use crabbot_protocol::DaemonStreamEnvelope;
use crabbot_protocol::DaemonStreamEvent;
use crabbot_protocol::HealthResponse;
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
use std::io::Read;
use std::io::{self};
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::thread;
use std::time::Duration;
use supports_color::Stream;

const DAEMON_PROMPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

mod daemon_commands;
use daemon_commands::run_daemon;

#[cfg(test)]
mod test_helpers;
#[cfg(test)]
use test_helpers::*;

#[derive(Debug, Parser)]
#[command(
    name = "crab",
    about = "Crabbot Linux CLI",
    disable_version_flag = true,
    subcommand_negates_reqs = true,
    override_usage = "crab [OPTIONS] [PROMPT]\n       crab [OPTIONS] <COMMAND> [ARGS]"
)]
struct Cli {
    /// Print version
    #[arg(short = 'V', long = "version", action = ArgAction::SetTrue)]
    version: bool,

    #[command(flatten)]
    interactive: InteractiveArgs,

    #[command(subcommand)]
    command: Option<TopLevelCommand>,
}

#[derive(Debug, Subcommand)]
enum TopLevelCommand {
    /// Resume a previous interactive session (picker by default; use --last to continue the most recent).
    Resume(ResumeCommand),
    /// Fork a previous interactive session (picker by default; use --last to fork the most recent).
    Fork(ForkCommand),
    /// Manage the local Codex app-server daemon.
    Daemon(DaemonCommand),
    /// Legacy compatibility subcommand.
    #[command(hide = true)]
    Codex(CodexCommand),
}

#[derive(Debug, Args)]
struct DaemonCommand {
    #[command(subcommand)]
    command: DaemonSubcommand,
}

#[derive(Debug, Subcommand)]
enum DaemonSubcommand {
    /// Start `crabbot_daemon` in the background.
    Up(DaemonUpArgs),
    /// Stop the background daemon.
    Down,
    /// Restart the background daemon.
    Restart(DaemonUpArgs),
    /// Show daemon process and health status.
    Status,
    /// Show daemon logs (follows by default).
    Logs(DaemonLogsArgs),
}

#[derive(Debug, Args, Clone)]
struct DaemonUpArgs {
    /// Bind daemon to Tailscale IPv4.
    #[arg(long, default_value_t = false, conflicts_with_all = ["lan", "local", "bind_all"])]
    tailscale: bool,
    /// Bind daemon to LAN IPv4 (default).
    #[arg(long, default_value_t = false, conflicts_with_all = ["tailscale", "local", "bind_all"])]
    lan: bool,
    /// Bind daemon to localhost.
    #[arg(long, default_value_t = false, conflicts_with_all = ["tailscale", "lan", "bind_all"])]
    local: bool,
    /// Bind daemon to all interfaces (0.0.0.0).
    #[arg(long = "all", default_value_t = false, conflicts_with_all = ["tailscale", "lan", "local"])]
    bind_all: bool,
    /// Override daemon listen port.
    #[arg(long)]
    port: Option<u16>,
}

#[derive(Debug, Args)]
struct DaemonLogsArgs {
    /// Number of lines to show before following.
    #[arg(long, default_value_t = 200)]
    tail: usize,
    /// Print and exit without following.
    #[arg(long, default_value_t = false)]
    no_follow: bool,
}

#[derive(Debug, Args, Clone)]
struct InteractiveArgs {
    /// Optional user prompt to start the session.
    #[arg(value_name = "PROMPT", value_hint = clap::ValueHint::Other)]
    prompt: Option<String>,

    /// Optional image(s) to attach to the initial prompt.
    #[arg(
        long = "image",
        short = 'i',
        value_name = "FILE",
        value_delimiter = ',',
        num_args = 1..
    )]
    images: Vec<PathBuf>,

    /// Override a configuration value from `~/.codex/config.toml`.
    #[arg(
        short = 'c',
        long = "config",
        value_name = "key=value",
        action = ArgAction::Append
    )]
    config: Vec<String>,

    /// Enable a feature (repeatable). Equivalent to `-c features.<name>=true`.
    #[arg(long = "enable", value_name = "FEATURE", action = ArgAction::Append)]
    enable: Vec<String>,

    /// Disable a feature (repeatable). Equivalent to `-c features.<name>=false`.
    #[arg(long = "disable", value_name = "FEATURE", action = ArgAction::Append)]
    disable: Vec<String>,

    /// Model the agent should use.
    #[arg(long, short = 'm')]
    model: Option<String>,

    /// Configuration profile from config.toml to specify default options.
    #[arg(long = "profile", short = 'p')]
    profile: Option<String>,

    /// Select the sandbox policy to use when executing model-generated shell commands.
    #[arg(long = "sandbox", short = 's')]
    sandbox_mode: Option<crabbot_tui::SandboxModeCliArg>,

    /// Configure when the model requires human approval before executing a command.
    #[arg(long = "ask-for-approval", short = 'a')]
    approval_policy: Option<crabbot_tui::ApprovalModeCliArg>,

    /// Convenience alias for low-friction sandboxed automatic execution (-a on-request, --sandbox workspace-write).
    #[arg(long = "full-auto", default_value_t = false)]
    full_auto: bool,

    /// Skip all confirmation prompts and execute commands without sandboxing.
    #[arg(
        long = "dangerously-bypass-approvals-and-sandbox",
        alias = "yolo",
        default_value_t = false,
        conflicts_with_all = ["approval_policy", "full_auto"]
    )]
    dangerously_bypass_approvals_and_sandbox: bool,

    /// Tell the agent to use the specified directory as its working root.
    #[arg(long = "cd", short = 'C', value_name = "DIR")]
    cwd: Option<PathBuf>,

    /// Enable live web search.
    #[arg(long = "search", default_value_t = false)]
    search: bool,

    /// Additional directories that should be writable alongside the primary workspace.
    #[arg(long = "add-dir", value_name = "DIR", value_hint = clap::ValueHint::DirPath)]
    add_dir: Vec<PathBuf>,

    /// Disable alternate screen mode.
    #[arg(long = "no-alt-screen", default_value_t = false)]
    no_alt_screen: bool,
}

#[derive(Debug, Args, Clone)]
struct ResumeCommand {
    /// Conversation/session id (UUID) or thread name.
    #[arg(value_name = "SESSION_ID")]
    session_id: Option<String>,
    /// Continue the most recent session without showing the picker.
    #[arg(long = "last", default_value_t = false)]
    last: bool,
    /// Show all sessions (disables cwd filtering and shows CWD column).
    #[arg(long = "all", default_value_t = false)]
    all: bool,
    #[command(flatten)]
    interactive: InteractiveArgs,
}

#[derive(Debug, Args, Clone)]
struct ForkCommand {
    /// Conversation/session id (UUID) or thread name to fork.
    #[arg(value_name = "SESSION_ID")]
    session_id: Option<String>,
    /// Fork the most recent session without showing the picker.
    #[arg(long = "last", default_value_t = false, conflicts_with = "session_id")]
    last: bool,
    /// Show all sessions (disables cwd filtering and shows CWD column).
    #[arg(long = "all", default_value_t = false)]
    all: bool,
    #[command(flatten)]
    interactive: InteractiveArgs,
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
    #[arg(skip)]
    fork_mode: bool,
    #[arg(skip)]
    resume_last: bool,
    #[arg(skip)]
    fork_last: bool,
    #[arg(long, default_value_t = false)]
    no_alt_screen: bool,
    #[arg(skip)]
    startup_picker: Option<crabbot_tui::StartupPicker>,
    #[arg(skip)]
    startup_picker_show_all: bool,
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
    #[serde(alias = "app_server_endpoint", default = "default_daemon_endpoint")]
    daemon_endpoint: String,
    auth_token: Option<String>,
}

fn default_daemon_endpoint() -> String {
    "ws://127.0.0.1:8765".to_string()
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:8787".to_string(),
            daemon_endpoint: default_daemon_endpoint(),
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

fn handle_tui_with_crate(
    args: TuiArgs,
    interactive: Option<&InteractiveArgs>,
    state: &mut CliState,
) -> Result<CommandOutput> {
    if env::var("TERM")
        .map(|term| term.eq_ignore_ascii_case("dumb"))
        .unwrap_or(false)
    {
        if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
            bail!(
                "TERM is set to \"dumb\". Refusing to start the interactive TUI because no terminal is available for a confirmation prompt (stdin/stderr is not a TTY). Run in a supported terminal or unset TERM."
            );
        }
        eprintln!(
            "WARNING: TERM is set to \"dumb\". Crabbot's interactive TUI may not work in this terminal."
        );
        eprintln!("Continue anyway? [y/N]: ");
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let answer = input.trim();
        let accepted = answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes");
        if !accepted {
            bail!(
                "Refusing to start the interactive TUI because TERM is set to \"dumb\". Run in a supported terminal or unset TERM."
            );
        }
    }

    crabbot_tui::set_daemon_connection_raw(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("initialize tokio runtime for tui")?;
    let exit_info = runtime.block_on(async {
        let (
            prompt,
            images,
            model,
            config_profile,
            sandbox_mode,
            approval_policy,
            full_auto,
            dangerously_bypass_approvals_and_sandbox,
            cwd,
            web_search,
            add_dir,
            config_overrides,
        ) = if let Some(interactive) = interactive {
            (
                interactive
                    .prompt
                    .clone()
                    .map(|value| value.replace("\r\n", "\n").replace('\r', "\n")),
                interactive.images.clone(),
                interactive.model.clone(),
                interactive.profile.clone(),
                interactive.sandbox_mode,
                interactive.approval_policy,
                interactive.full_auto,
                interactive.dangerously_bypass_approvals_and_sandbox,
                interactive.cwd.clone(),
                interactive.search,
                interactive.add_dir.clone(),
                tui_config_overrides_from_interactive(Some(interactive)),
            )
        } else {
            (
                None,
                Vec::new(),
                None,
                None,
                None,
                None,
                false,
                false,
                None,
                false,
                Vec::new(),
                crabbot_tui::CliConfigOverrides::default(),
            )
        };
        crabbot_tui::run_main(
            crabbot_tui::Cli {
                prompt,
                images,
                resume_picker: matches!(
                    args.startup_picker,
                    Some(crabbot_tui::StartupPicker::Resume)
                ),
                resume_last: args.resume_last,
                resume_session_id: if args.fork_mode {
                    None
                } else {
                    args.thread_id.clone()
                },
                resume_show_all: args.startup_picker_show_all
                    && matches!(
                        args.startup_picker,
                        Some(crabbot_tui::StartupPicker::Resume)
                    ),
                fork_picker: matches!(args.startup_picker, Some(crabbot_tui::StartupPicker::Fork)),
                fork_last: args.fork_last,
                fork_session_id: if args.fork_mode {
                    args.thread_id.clone()
                } else {
                    None
                },
                fork_show_all: args.startup_picker_show_all
                    && matches!(args.startup_picker, Some(crabbot_tui::StartupPicker::Fork)),
                model,
                oss: false,
                oss_provider: None,
                config_profile,
                sandbox_mode,
                approval_policy,
                full_auto,
                dangerously_bypass_approvals_and_sandbox,
                cwd,
                web_search,
                add_dir,
                no_alt_screen: args.no_alt_screen,
                config_overrides,
            },
            None,
        )
        .await
    })?;
    let token_usage = exit_info.token_usage;
    let thread_id = exit_info.thread_id;
    let thread_name = exit_info.thread_name;
    state.last_thread_id = thread_id.map(|id| id.to_string());
    let mut lines = Vec::new();
    if !token_usage.is_zero() {
        lines.push(crabbot_tui::protocol::FinalOutput::from(token_usage).to_string());
        if let Some(command) = crabbot_tui::util::resume_command(thread_name.as_deref(), thread_id)
        {
            let command = if supports_color::on(Stream::Stdout).is_some() {
                format!("\u{1b}[36m{command}\u{1b}[39m")
            } else {
                command
            };
            lines.push(format!("To continue this session, run {command}"));
        }
    }
    Ok(CommandOutput::Text(lines.join("\n")))
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
        crabbot_tui::handle_attach_tui_interactive(session_id, initial_events, &mut tui_state).await
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
    let Cli {
        version,
        interactive,
        command,
    } = cli;

    if version {
        return Ok(version_output());
    }

    let mut state = load_state(state_path)?;
    let (output, should_persist) = match command {
        None => (run_interactive_default(interactive, &mut state), true),
        Some(TopLevelCommand::Resume(command)) => {
            (run_resume_command(command, interactive, &mut state), true)
        }
        Some(TopLevelCommand::Fork(command)) => {
            (run_fork_command(command, interactive, &mut state), true)
        }
        Some(TopLevelCommand::Daemon(command)) => {
            return run_daemon(command, state_path);
        }
        Some(TopLevelCommand::Codex(command)) => {
            return run_codex(command, state_path);
        }
    };
    let output = output?;

    if should_persist {
        save_state(state_path, &state)?;
    }

    output.into_string()
}

fn version_output() -> String {
    let crabbot = env!("CARGO_PKG_VERSION");
    let codex = detect_codex_version().unwrap_or_else(|| "unavailable".to_string());
    format!("crabbot {crabbot}\ncodex {codex}")
}

fn detect_codex_version() -> Option<String> {
    let output = Command::new("codex").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    if let Some(stripped) = line.strip_prefix("codex ") {
        return Some(stripped.to_string());
    }
    Some(line.to_string())
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
            handle_tui_with_crate(args, None, &mut state)
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

fn run_interactive_default(args: InteractiveArgs, state: &mut CliState) -> Result<CommandOutput> {
    ensure_daemon_ready(state)?;
    handle_tui_with_crate(
        TuiArgs {
            thread_id: None,
            fork_mode: false,
            resume_last: false,
            fork_last: false,
            no_alt_screen: args.no_alt_screen,
            startup_picker: None,
            startup_picker_show_all: false,
        },
        Some(&args),
        state,
    )
}

fn merge_interactive_args(mut root: InteractiveArgs, sub: InteractiveArgs) -> InteractiveArgs {
    if let Some(prompt) = sub.prompt {
        root.prompt = Some(prompt);
    }
    if !sub.images.is_empty() {
        root.images = sub.images;
    }
    root.config.extend(sub.config);
    root.enable.extend(sub.enable);
    root.disable.extend(sub.disable);
    if let Some(model) = sub.model {
        root.model = Some(model);
    }
    if let Some(profile) = sub.profile {
        root.profile = Some(profile);
    }
    if let Some(mode) = sub.sandbox_mode {
        root.sandbox_mode = Some(mode);
    }
    if let Some(policy) = sub.approval_policy {
        root.approval_policy = Some(policy);
    }
    root.full_auto = root.full_auto || sub.full_auto;
    root.dangerously_bypass_approvals_and_sandbox = root.dangerously_bypass_approvals_and_sandbox
        || sub.dangerously_bypass_approvals_and_sandbox;
    if let Some(cwd) = sub.cwd {
        root.cwd = Some(cwd);
    }
    root.search = root.search || sub.search;
    if !sub.add_dir.is_empty() {
        root.add_dir.extend(sub.add_dir);
    }
    root.no_alt_screen = root.no_alt_screen || sub.no_alt_screen;
    root
}

fn tui_config_overrides_from_interactive(
    interactive: Option<&InteractiveArgs>,
) -> crabbot_tui::CliConfigOverrides {
    let mut overrides = crabbot_tui::CliConfigOverrides::default();
    let Some(interactive) = interactive else {
        return overrides;
    };
    overrides.raw_overrides.extend(interactive.config.clone());
    overrides.raw_overrides.extend(
        interactive
            .enable
            .iter()
            .map(|feature| format!("features.{feature}=true")),
    );
    overrides.raw_overrides.extend(
        interactive
            .disable
            .iter()
            .map(|feature| format!("features.{feature}=false")),
    );
    overrides
}

fn run_resume_command(
    command: ResumeCommand,
    root_interactive: InteractiveArgs,
    state: &mut CliState,
) -> Result<CommandOutput> {
    ensure_daemon_ready(state)?;
    let has_session_id = command.session_id.is_some();
    let interactive = merge_interactive_args(root_interactive, command.interactive);
    handle_tui_with_crate(
        TuiArgs {
            thread_id: command.session_id,
            fork_mode: false,
            resume_last: command.last,
            fork_last: false,
            no_alt_screen: interactive.no_alt_screen,
            startup_picker: if command.last || has_session_id {
                None
            } else {
                Some(crabbot_tui::StartupPicker::Resume)
            },
            startup_picker_show_all: command.all,
        },
        Some(&interactive),
        state,
    )
}

fn run_fork_command(
    command: ForkCommand,
    root_interactive: InteractiveArgs,
    state: &mut CliState,
) -> Result<CommandOutput> {
    ensure_daemon_ready(state)?;
    let has_session_id = command.session_id.is_some();
    let interactive = merge_interactive_args(root_interactive, command.interactive);
    handle_tui_with_crate(
        TuiArgs {
            thread_id: command.session_id,
            fork_mode: true,
            resume_last: false,
            fork_last: command.last,
            no_alt_screen: interactive.no_alt_screen,
            startup_picker: if command.last || has_session_id {
                None
            } else {
                Some(crabbot_tui::StartupPicker::Fork)
            },
            startup_picker_show_all: command.all,
        },
        Some(&interactive),
        state,
    )
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
            fork_mode: false,
            resume_last: false,
            fork_last: false,
            no_alt_screen: false,
            startup_picker: None,
            startup_picker_show_all: false,
        },
        None,
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
    let base = http_compatible_base_url(base);
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn http_compatible_base_url(base: &str) -> String {
    let trimmed = base.trim();
    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return format!("http://{rest}");
    }
    if let Some(rest) = trimmed.strip_prefix("wss://") {
        return format!("https://{rest}");
    }
    trimmed.to_string()
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
    if endpoint_uses_websocket_transport(daemon_endpoint) {
        return endpoint_has_open_listener(daemon_endpoint);
    }

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

fn endpoint_uses_websocket_transport(endpoint: &str) -> bool {
    let endpoint = endpoint.trim().to_ascii_lowercase();
    endpoint.starts_with("ws://") || endpoint.starts_with("wss://")
}

fn endpoint_has_open_listener(endpoint: &str) -> bool {
    let endpoint = endpoint.trim();
    let without_scheme = endpoint
        .strip_prefix("ws://")
        .or_else(|| endpoint.strip_prefix("wss://"))
        .or_else(|| endpoint.strip_prefix("http://"))
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let authority = without_scheme.split('/').next().unwrap_or_default().trim();
    if authority.is_empty() {
        return false;
    }

    let host_port = if authority.contains(':') {
        authority.to_string()
    } else if endpoint.starts_with("wss://") || endpoint.starts_with("https://") {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    };

    let mut addrs = match host_port.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(_) => return false,
    };
    let addr = match addrs.next() {
        Some(addr) => addr,
        None => return false,
    };

    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

fn ensure_daemon_ready(state: &CliState) -> Result<()> {
    if !endpoint_uses_websocket_transport(&state.config.daemon_endpoint) {
        if daemon_is_healthy(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
        ) {
            return Ok(());
        }
    } else {
        crabbot_tui::ensure_daemon_ready_raw(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
        )
        .with_context(|| {
            format!(
                "daemon is not reachable at {}; run `crab daemon up`",
                state.config.daemon_endpoint
            )
        })?;
        return Ok(());
    }

    // For HTTP endpoints, surface a useful message that keeps parity with WS endpoints.
    // The daemon HTTP API remains compatible with the websocket transport.
    crabbot_tui::ensure_daemon_ready_raw(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
    )
    .with_context(|| {
        format!(
            "daemon is not reachable at {}; run `crab daemon up`",
            state.config.daemon_endpoint
        )
    })
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
                            "[session interrupted] resume with: crab codex resume --session-id {session_id}\n"
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
                    "after approval, resume with: crab codex resume --session-id {session_id}\n"
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
    let mut state: CliState = serde_json::from_str(&raw)
        .with_context(|| format!("parse state json from {}", path.display()))?;
    state.config.daemon_endpoint = normalize_app_server_endpoint(&state.config.daemon_endpoint);
    Ok(state)
}

fn normalize_app_server_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim();
    if trimmed.eq_ignore_ascii_case("http://127.0.0.1:8788")
        || trimmed.eq_ignore_ascii_case("http://localhost:8788")
        || trimmed.eq_ignore_ascii_case("ws://127.0.0.1:8788")
        || trimmed.eq_ignore_ascii_case("ws://localhost:8788")
    {
        return "ws://127.0.0.1:8765".to_string();
    }
    endpoint.to_string()
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

    fn test_cli(command: TopLevelCommand) -> Cli {
        Cli {
            version: false,
            interactive: InteractiveArgs {
                prompt: None,
                images: vec![],
                config: vec![],
                enable: vec![],
                disable: vec![],
                model: None,
                profile: None,
                sandbox_mode: None,
                approval_policy: None,
                full_auto: false,
                dangerously_bypass_approvals_and_sandbox: false,
                cwd: None,
                search: false,
                add_dir: vec![],
                no_alt_screen: false,
            },
            command: Some(command),
        }
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: None,
                        daemon_endpoint: Some(daemon_endpoint),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let start = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Start(StartArgs {
                    session_id: Some("sess_cli_1".to_string()),
                })),
            })),
            &state_path,
        );
        assert_eq!(start["ok"], true);
        assert_eq!(start["state"], "active");

        let interrupt = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Interrupt(SessionArgs {
                    session_id: "sess_cli_1".to_string(),
                })),
            })),
            &state_path,
        );
        assert_eq!(interrupt["state"], "interrupted");

        let resume = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Resume(SessionArgs {
                    session_id: "sess_cli_1".to_string(),
                })),
            })),
            &state_path,
        );
        assert_eq!(resume["state"], "active");

        let status = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Status(StatusArgs {
                    session_id: Some("sess_cli_1".to_string()),
                    check_api: false,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: None,
                        daemon_endpoint: Some(daemon_endpoint),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let prompt = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Prompt(PromptArgs {
                    session_id: "sess_cli_prompt".to_string(),
                    text: "ship it".to_string(),
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: Some("https://api.crabbot.local".to_string()),
                        daemon_endpoint: Some("https://daemon.crabbot.local".to_string()),
                        auth_token: Some("token_123".to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );
        assert_eq!(set["ok"], true);
        assert_eq!(set["config"]["api_endpoint"], "https://api.crabbot.local");

        let show = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Show,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: Some(api_endpoint),
                        daemon_endpoint: Some(daemon_endpoint),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let attach = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Attach(AttachArgs {
                    session_id: Some("sess_cli_attach".to_string()),
                    tui: false,
                })),
            })),
            &state_path,
        );
        assert_eq!(attach["ok"], true);
        assert_eq!(attach["received_events"], 3);
        assert_eq!(attach["last_sequence"], 3);
        assert_eq!(attach["created_session"], false);
        assert_eq!(attach["stream_events"][0]["event"]["type"], "session_state");

        let status = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Status(StatusArgs {
                    session_id: None,
                    check_api: true,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Attach(AttachArgs {
                    session_id: None,
                    tui: false,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: None,
                        daemon_endpoint: Some(daemon_endpoint),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let attach = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Attach(AttachArgs {
                    session_id: None,
                    tui: false,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: None,
                        daemon_endpoint: Some(daemon_endpoint),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let attach = run_json(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Attach(AttachArgs {
                    session_id: Some("sess_missing".to_string()),
                    tui: false,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: None,
                        daemon_endpoint: Some(daemon_endpoint.clone()),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let output = run_with_state_path(
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Attach(AttachArgs {
                    session_id: Some("sess_cli_tui".to_string()),
                    tui: true,
                })),
            })),
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
            test_cli(TopLevelCommand::Codex(CodexCommand {
                command: Some(CodexSubcommand::Config(ConfigCommand {
                    command: ConfigSubcommand::Set(ConfigSetArgs {
                        api_endpoint: None,
                        daemon_endpoint: Some(daemon_endpoint),
                        auth_token: Some(auth_token.to_string()),
                        clear_auth_token: false,
                    }),
                })),
            })),
            &state_path,
        );

        let output = run_with_state_path(
            test_cli(TopLevelCommand::Codex(CodexCommand { command: None })),
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
    fn websocket_url_for_daemon_endpoint_maps_http_schemes() {
        assert_eq!(
            daemon_commands::websocket_url_for_daemon_endpoint_for_test("http://127.0.0.1:8765"),
            "ws://127.0.0.1:8765"
        );
        assert_eq!(
            daemon_commands::websocket_url_for_daemon_endpoint_for_test(
                "https://daemon.crabbot.local"
            ),
            "wss://daemon.crabbot.local"
        );
        assert_eq!(
            daemon_commands::websocket_url_for_daemon_endpoint_for_test("ws://127.0.0.1:8765"),
            "ws://127.0.0.1:8765"
        );
        assert_eq!(
            daemon_commands::websocket_url_for_daemon_endpoint_for_test(
                "wss://daemon.crabbot.local"
            ),
            "wss://daemon.crabbot.local"
        );
    }

    #[test]
    fn format_daemon_websocket_qr_output_includes_url_and_qr_body() {
        let output =
            daemon_commands::format_daemon_websocket_qr_output_for_test("ws://127.0.0.1:8765");
        assert!(output.contains("websocket_url: ws://127.0.0.1:8765"));
        assert!(output.contains("qr:"));
        assert!(!output.contains("(qr unavailable:"));
        assert!(output.lines().count() > 3);
    }

    #[test]
    fn replace_endpoint_host_preserves_scheme_port_and_path() {
        assert_eq!(
            daemon_commands::replace_endpoint_host_for_test(
                "ws://127.0.0.1:8765/v1/sessions",
                "100.64.0.2"
            ),
            Some("ws://100.64.0.2:8765/v1/sessions".to_string())
        );
        assert_eq!(
            daemon_commands::replace_endpoint_host_for_test("https://localhost:443", "100.64.0.2"),
            Some("https://100.64.0.2:443".to_string())
        );
    }

    #[test]
    fn replace_endpoint_port_preserves_scheme_host_and_path() {
        assert_eq!(
            daemon_commands::replace_endpoint_port_for_test(
                "ws://127.0.0.1:8765/v1/sessions",
                9000
            ),
            Some("ws://127.0.0.1:9000/v1/sessions".to_string())
        );
        assert_eq!(
            daemon_commands::replace_endpoint_port_for_test("https://localhost:443", 8443),
            Some("https://localhost:8443".to_string())
        );
    }

    #[test]
    fn endpoint_host_is_local_detects_local_hosts() {
        assert!(daemon_commands::endpoint_host_is_local_for_test(
            "ws://127.0.0.1:8765"
        ));
        assert!(daemon_commands::endpoint_host_is_local_for_test(
            "ws://localhost:8765"
        ));
        assert!(!daemon_commands::endpoint_host_is_local_for_test(
            "ws://100.64.0.2:8765"
        ));
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
