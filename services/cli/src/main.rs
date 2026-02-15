use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use crabbot_protocol::{
    DaemonPromptRequest, DaemonPromptResponse, DaemonRpcNotification, DaemonRpcRequest,
    DaemonRpcRequestResponse, DaemonRpcRespondRequest, DaemonRpcServerRequest,
    DaemonRpcStreamEnvelope, DaemonRpcStreamEvent, DaemonSessionStatusResponse,
    DaemonStartSessionRequest, DaemonStreamEnvelope, DaemonStreamEvent, HealthResponse,
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
use reqwest::blocking::Client;
use reqwest::blocking::Response;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
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

struct TuiSlashCommand {
    command: &'static str,
    description: &'static str,
    hide_in_empty_picker: bool,
    requires_collaboration_modes: bool,
    requires_connectors: bool,
    requires_personality: bool,
    requires_windows_degraded_sandbox: bool,
    windows_only: bool,
    debug_only: bool,
}

const TUI_SLASH_COMMANDS: &[TuiSlashCommand] = &[
    TuiSlashCommand {
        command: "model",
        description: "choose what model and reasoning effort to use",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "approvals",
        description: "choose what Codex is allowed to do",
        hide_in_empty_picker: true,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "permissions",
        description: "choose what Codex is allowed to do",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "setup-default-sandbox",
        description: "set up elevated agent sandbox",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: true,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "sandbox-add-read-dir",
        description: "let sandbox read a directory: /sandbox-add-read-dir <absolute_path>",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: true,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "experimental",
        description: "toggle experimental features",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "skills",
        description: "use skills to improve how Codex performs specific tasks",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "review",
        description: "review my current changes and find issues",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "rename",
        description: "rename the current thread",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "new",
        description: "start a new chat during a conversation",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "resume",
        description: "resume a saved chat",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "fork",
        description: "fork the current chat",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "init",
        description: "create an AGENTS.md file with instructions for Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "compact",
        description: "summarize conversation to prevent hitting the context limit",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "plan",
        description: "switch to Plan mode",
        hide_in_empty_picker: false,
        requires_collaboration_modes: true,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "collab",
        description: "change collaboration mode (experimental)",
        hide_in_empty_picker: false,
        requires_collaboration_modes: true,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "agent",
        description: "switch the active agent thread",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "diff",
        description: "show git diff (including untracked files)",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "mention",
        description: "mention a file",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "status",
        description: "show current session configuration and token usage",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "debug-config",
        description: "show config layers and requirement sources for debugging",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "statusline",
        description: "configure which items appear in the status line",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "mcp",
        description: "list configured MCP tools",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "apps",
        description: "manage apps",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: true,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "logout",
        description: "log out of Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "quit",
        description: "exit Codex",
        hide_in_empty_picker: true,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "exit",
        description: "exit Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "feedback",
        description: "send logs to maintainers",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "rollout",
        description: "print the rollout file path",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: true,
    },
    TuiSlashCommand {
        command: "ps",
        description: "list background terminals",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "clean",
        description: "stop all background terminals",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "personality",
        description: "choose a communication style for Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: true,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "test-approval",
        description: "test approval request",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: true,
    },
    TuiSlashCommand {
        command: "debug-m-drop",
        description: "DO NOT USE",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "debug-m-update",
        description: "DO NOT USE",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
];

const TUI_COLLABORATION_MODES_ENABLED: bool = false;
const TUI_CONNECTORS_ENABLED: bool = false;
const TUI_PERSONALITY_COMMAND_ENABLED: bool = false;
const TUI_WINDOWS_DEGRADED_SANDBOX_ACTIVE: bool = false;

fn slash_command_visible_in_picker(command: &TuiSlashCommand) -> bool {
    if command.windows_only && !cfg!(target_os = "windows") {
        return false;
    }
    if command.debug_only && !cfg!(debug_assertions) {
        return false;
    }
    if command.requires_collaboration_modes && !TUI_COLLABORATION_MODES_ENABLED {
        return false;
    }
    if command.requires_connectors && !TUI_CONNECTORS_ENABLED {
        return false;
    }
    if command.requires_personality && !TUI_PERSONALITY_COMMAND_ENABLED {
        return false;
    }
    if command.requires_windows_degraded_sandbox && !TUI_WINDOWS_DEGRADED_SANDBOX_ACTIVE {
        return false;
    }
    true
}

fn filtered_slash_commands(query: &str) -> Vec<&'static TuiSlashCommand> {
    let builtins: Vec<&'static TuiSlashCommand> = TUI_SLASH_COMMANDS
        .iter()
        .filter(|command| slash_command_visible_in_picker(command))
        .collect();
    let filter = query.trim();
    if filter.is_empty() {
        return builtins
            .into_iter()
            .filter(|command| !command.hide_in_empty_picker)
            .collect();
    }

    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    let filter_lower = filter.to_ascii_lowercase();
    for command in builtins {
        let command_lower = command.command.to_ascii_lowercase();
        if command_lower == filter_lower {
            exact.push(command);
        } else if command_lower.starts_with(&filter_lower) {
            prefix.push(command);
        }
    }
    exact.extend(prefix);
    exact
}

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
            handle_tui(args, &mut state)
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
    handle_tui(
        TuiArgs {
            thread_id: state.last_thread_id.clone(),
        },
        state,
    )
}

fn handle_tui(args: TuiArgs, state: &mut CliState) -> Result<CommandOutput> {
    ensure_daemon_ready(state)?;
    let mut thread_id = args.thread_id.or_else(|| state.last_thread_id.clone());
    if thread_id.is_none() {
        let response = daemon_app_server_rpc_request(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
            "thread/start",
            json!({
                "approvalPolicy": "on-request"
            }),
        )?;
        thread_id = extract_thread_id_from_rpc_result(&response.result);
    }
    let Some(thread_id) = thread_id else {
        bail!("failed to initialize app-server thread");
    };
    state.last_thread_id = Some(thread_id.clone());

    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        return handle_tui_interactive(thread_id, state);
    }

    Ok(CommandOutput::Json(json!({
        "ok": true,
        "action": "tui",
        "thread_id": thread_id,
        "daemon_endpoint": state.config.daemon_endpoint,
    })))
}

fn handle_tui_interactive(thread_id: String, state: &mut CliState) -> Result<CommandOutput> {
    let mut ui = LiveAttachTui::new(thread_id.clone(), "active".to_string());
    ui.status_message = Some("connected to daemon app-server bridge".to_string());
    let _ = poll_app_server_tui_stream_updates(state, &mut ui);

    enable_raw_mode().context("enable raw mode for app-server tui")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)
        .context("enter alternate screen for app-server tui")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create app-server tui terminal")?;
    terminal.clear().context("clear app-server tui terminal")?;

    let loop_result = run_app_server_tui_loop(&mut terminal, &mut ui, state);

    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    let _ = terminal.show_cursor();

    loop_result?;
    state.last_thread_id = Some(ui.session_id.clone());
    Ok(CommandOutput::Text(format!(
        "thread={} detached",
        ui.session_id
    )))
}

fn run_app_server_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ui: &mut LiveAttachTui,
    state: &mut CliState,
) -> Result<()> {
    loop {
        ui.draw(terminal)?;
        let mut should_redraw = false;

        if event::poll(TUI_EVENT_WAIT_STEP).context("poll app-server tui input event")? {
            let event = event::read().context("read app-server tui input event")?;
            if let Event::Key(key_event) = event {
                if key_event.kind != KeyEventKind::Press {
                    continue;
                }
                match handle_app_server_tui_key_event(key_event, state, ui)? {
                    LiveTuiAction::Continue => {}
                    LiveTuiAction::Detach => return Ok(()),
                }
                should_redraw = true;
            }
        }

        if poll_app_server_tui_stream_updates(state, ui)? {
            should_redraw = true;
        }

        if !should_redraw {
            thread::sleep(TUI_STREAM_POLL_INTERVAL);
        }
    }
}

fn handle_app_server_tui_key_event(
    key: crossterm::event::KeyEvent,
    state: &mut CliState,
    ui: &mut LiveAttachTui,
) -> Result<LiveTuiAction> {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Ok(LiveTuiAction::Detach);
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ui.clear_input();
        }
        KeyCode::Up => {
            if ui.slash_picker_is_active() {
                ui.slash_picker_move_up();
            } else {
                ui.history_prev();
            }
        }
        KeyCode::Down => {
            if ui.slash_picker_is_active() {
                ui.slash_picker_move_down();
            } else {
                ui.history_next();
            }
        }
        KeyCode::Left => ui.move_input_cursor_left(),
        KeyCode::Right => ui.move_input_cursor_right(),
        KeyCode::Home => ui.move_input_cursor_home(),
        KeyCode::End => ui.move_input_cursor_end(),
        KeyCode::Enter => {
            if ui.should_apply_slash_picker_on_enter() {
                let _ = ui.apply_selected_slash_entry();
                return Ok(LiveTuiAction::Continue);
            }
            if handle_app_server_tui_submit(state, ui)? {
                return Ok(LiveTuiAction::Detach);
            }
        }
        KeyCode::Backspace => {
            ui.input_backspace();
        }
        KeyCode::Delete => {
            ui.input_delete();
        }
        KeyCode::Tab => {
            if ui.slash_picker_is_active() {
                let _ = ui.apply_selected_slash_entry();
            } else {
                ui.input_insert_char('\t');
            }
        }
        KeyCode::Char(ch) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                ui.input_insert_char(ch);
            }
        }
        _ => {}
    }
    Ok(LiveTuiAction::Continue)
}

fn handle_app_server_tui_submit(state: &mut CliState, ui: &mut LiveAttachTui) -> Result<bool> {
    let input = ui.take_input();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    ui.remember_history_entry(trimmed);

    match trimmed {
        "/exit" | "/quit" => return Ok(true),
        "/status" => {
            ui.status_message = Some(format!(
                "thread={} approvals={} seq={}",
                ui.session_id,
                ui.pending_approvals.len(),
                ui.last_sequence
            ));
            return Ok(false);
        }
        "/refresh" => {
            ui.status_message = Some("refreshing stream...".to_string());
            return Ok(false);
        }
        "/new" => {
            let response = daemon_app_server_rpc_request(
                &state.config.daemon_endpoint,
                state.config.auth_token.as_deref(),
                "thread/start",
                json!({
                    "approvalPolicy": "on-request"
                }),
            )?;
            let Some(thread_id) = extract_thread_id_from_rpc_result(&response.result) else {
                bail!("thread/start did not return thread id");
            };
            ui.session_id = thread_id.clone();
            ui.active_turn_id = None;
            ui.pending_approvals.clear();
            ui.push_line(&format!("[thread switched] {thread_id}"));
            ui.status_message = Some("started new thread".to_string());
            state.last_thread_id = Some(thread_id);
            return Ok(false);
        }
        _ => {}
    }

    if trimmed == "/interrupt" {
        if let Some(turn_id) = ui.active_turn_id.clone() {
            let _ = daemon_app_server_rpc_request(
                &state.config.daemon_endpoint,
                state.config.auth_token.as_deref(),
                "turn/interrupt",
                json!({
                    "threadId": ui.session_id,
                    "turnId": turn_id,
                }),
            )?;
            ui.status_message = Some("interrupt requested".to_string());
        } else {
            ui.status_message = Some("no running turn".to_string());
        }
        return Ok(false);
    }

    if trimmed == "/resume" {
        let response = daemon_app_server_rpc_request(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
            "thread/resume",
            json!({
                "threadId": ui.session_id,
            }),
        )?;
        if let Some(thread_id) = extract_thread_id_from_rpc_result(&response.result) {
            ui.session_id = thread_id.clone();
            state.last_thread_id = Some(thread_id);
            ui.status_message = Some("thread resumed".to_string());
        } else {
            ui.status_message = Some("resume returned no thread id".to_string());
        }
        return Ok(false);
    }

    if let Some(rest) = trimmed.strip_prefix("/approve") {
        return handle_app_server_approval_decision(state, ui, rest.trim(), true).map(|_| false);
    }
    if let Some(rest) = trimmed.strip_prefix("/deny") {
        return handle_app_server_approval_decision(state, ui, rest.trim(), false).map(|_| false);
    }

    ui.push_user_prompt(trimmed);
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "turn/start",
        json!({
            "threadId": ui.session_id,
            "input": [
                {
                    "type": "text",
                    "text": trimmed,
                    "textElements": []
                }
            ]
        }),
    )?;
    if let Some(turn_id) = response
        .result
        .get("turn")
        .and_then(|turn| turn.get("id"))
        .and_then(Value::as_str)
    {
        ui.active_turn_id = Some(turn_id.to_string());
    }
    ui.status_message = Some("waiting for response...".to_string());
    Ok(false)
}

fn handle_app_server_approval_decision(
    state: &mut CliState,
    ui: &mut LiveAttachTui,
    arg: &str,
    approve: bool,
) -> Result<()> {
    let approval_key = if arg.is_empty() {
        ui.pending_approvals.keys().next_back().cloned()
    } else {
        Some(arg.to_string())
    }
    .ok_or_else(|| anyhow!("no pending approval request"))?;
    let Some(request) = ui.pending_approvals.remove(&approval_key) else {
        bail!("pending approval id not found: {approval_key}");
    };
    daemon_app_server_rpc_respond(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        request.request_id,
        json!({
            "decision": if approve { "accept" } else { "decline" }
        }),
    )?;
    ui.status_message = Some(format!(
        "{} request {}",
        if approve { "approved" } else { "denied" },
        approval_key
    ));
    Ok(())
}

fn poll_app_server_tui_stream_updates(state: &CliState, ui: &mut LiveAttachTui) -> Result<bool> {
    let events = fetch_daemon_app_server_stream(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        Some(ui.last_sequence),
    )?;
    if events.is_empty() {
        return Ok(false);
    }
    ui.apply_rpc_stream_events(&events);
    Ok(true)
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
            return handle_attach_tui_interactive(session_id, stream_events, state);
        }
        return Ok(CommandOutput::Text(render_attach_tui(
            &session_id,
            &stream_events,
            &state.config.daemon_endpoint,
        )));
    }

    Ok(CommandOutput::Json(json_output))
}

fn handle_attach_tui_interactive(
    session_id: String,
    initial_events: Vec<DaemonStreamEnvelope>,
    state: &mut CliState,
) -> Result<CommandOutput> {
    let mut ui = LiveAttachTui::new(
        session_id.clone(),
        cached_session_state_label(state, &session_id)
            .unwrap_or("unknown")
            .to_string(),
    );
    ui.apply_stream_events(&initial_events);

    enable_raw_mode().context("enable raw mode for attach tui")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)
        .context("enter alternate screen for attach tui")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("create attach tui terminal")?;
    terminal.clear().context("clear attach tui terminal")?;

    let loop_result = run_attach_tui_loop(&mut terminal, &mut ui, state);

    let _ = disable_raw_mode();
    let _ = execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    );
    let _ = terminal.show_cursor();

    loop_result?;
    Ok(CommandOutput::Text(format!(
        "session={session_id} detached"
    )))
}

struct InFlightPrompt {
    prompt: String,
    submitted_at: Instant,
    handle: thread::JoinHandle<Result<DaemonPromptResponse>>,
}

struct LiveAttachTui {
    session_id: String,
    transcript: String,
    input: String,
    input_cursor: usize,
    command_history: Vec<String>,
    history_index: Option<usize>,
    latest_state: String,
    previous_state: Option<String>,
    received_events: usize,
    last_sequence: u64,
    status_message: Option<String>,
    active_turn_id: Option<String>,
    pending_prompt: Option<InFlightPrompt>,
    pending_approvals: BTreeMap<String, DaemonRpcServerRequest>,
    slash_picker_index: usize,
}

impl LiveAttachTui {
    fn new(session_id: String, latest_state: String) -> Self {
        Self {
            session_id,
            transcript: String::new(),
            input: String::new(),
            input_cursor: 0,
            command_history: Vec::new(),
            history_index: None,
            latest_state,
            previous_state: None,
            received_events: 0,
            last_sequence: 0,
            status_message: None,
            active_turn_id: None,
            pending_prompt: None,
            pending_approvals: BTreeMap::new(),
            slash_picker_index: 0,
        }
    }

    fn apply_stream_events(&mut self, stream_events: &[DaemonStreamEnvelope]) {
        for envelope in stream_events {
            self.received_events += 1;
            self.last_sequence = envelope.sequence;
            match &envelope.event {
                DaemonStreamEvent::SessionState(payload) => {
                    if self.previous_state.as_deref() != Some(payload.state.as_str()) {
                        if payload.state == "interrupted" {
                            self.push_line(&format!(
                                "[session interrupted] resume with: crabbot codex resume --session-id {}",
                                self.session_id
                            ));
                        } else if self.previous_state.as_deref() == Some("interrupted")
                            && payload.state == "active"
                        {
                            self.push_line("[session resumed] stream is active again");
                        }
                    }
                    self.latest_state = payload.state.clone();
                    self.previous_state = Some(payload.state.clone());
                }
                DaemonStreamEvent::TurnStreamDelta(payload) => {
                    let is_new_turn =
                        self.active_turn_id.as_deref() != Some(payload.turn_id.as_str());
                    if is_new_turn {
                        self.active_turn_id = Some(payload.turn_id.clone());
                    }
                    let delta = if is_new_turn {
                        payload
                            .delta
                            .strip_prefix("Assistant: ")
                            .unwrap_or(&payload.delta)
                    } else {
                        &payload.delta
                    };
                    self.append_assistant_delta(delta);
                }
                DaemonStreamEvent::TurnCompleted(payload) => {
                    self.active_turn_id = None;
                    if !self.transcript.is_empty() && !self.transcript.ends_with('\n') {
                        self.transcript.push('\n');
                    }
                    let _ = payload;
                    self.status_message = None;
                }
                DaemonStreamEvent::ApprovalRequired(payload) => {
                    self.push_line(&format!(
                        "[approval required] id={} action={}",
                        payload.approval_id, payload.action_kind
                    ));
                    self.push_line(&format!("prompt: {}", payload.prompt));
                    self.push_line(&format!(
                        "after approval, resume with: crabbot codex resume --session-id {}",
                        self.session_id
                    ));
                }
                DaemonStreamEvent::Heartbeat(_) => {}
            }
        }
    }

    fn apply_rpc_stream_events(&mut self, stream_events: &[DaemonRpcStreamEnvelope]) {
        for envelope in stream_events {
            self.received_events += 1;
            self.last_sequence = envelope.sequence;
            match &envelope.event {
                DaemonRpcStreamEvent::Notification(notification) => {
                    self.apply_rpc_notification(notification);
                }
                DaemonRpcStreamEvent::ServerRequest(request) => {
                    let key = request_id_key_for_cli(&request.request_id);
                    self.pending_approvals.insert(key.clone(), request.clone());
                    self.push_line(&format!(
                        "[approval required] request_id={key} method={}",
                        request.method
                    ));
                    if let Some(reason) = request.params.get("reason").and_then(Value::as_str) {
                        self.push_line(&format!("reason: {reason}"));
                    }
                }
                DaemonRpcStreamEvent::DecodeError(error) => {
                    self.push_line(&format!("[daemon rpc decode error] {}", error.message));
                }
            }
        }
    }

    fn apply_rpc_notification(&mut self, notification: &DaemonRpcNotification) {
        match notification.method.as_str() {
            "thread/started" => {
                if let Some(thread_id) = notification
                    .params
                    .get("thread")
                    .and_then(|thread| thread.get("id"))
                    .and_then(Value::as_str)
                {
                    self.session_id = thread_id.to_string();
                    self.push_line(&format!("[thread started] {thread_id}"));
                }
            }
            "turn/started" => {
                if let Some(turn_id) = notification
                    .params
                    .get("turn")
                    .and_then(|turn| turn.get("id"))
                    .and_then(Value::as_str)
                {
                    self.active_turn_id = Some(turn_id.to_string());
                    self.status_message = Some("running turn...".to_string());
                }
            }
            "item/agentMessage/delta" => {
                if let Some(delta) = notification.params.get("delta").and_then(Value::as_str) {
                    self.append_assistant_delta(delta);
                }
            }
            "item/completed" => {
                if let Some(item_type) = notification
                    .params
                    .get("item")
                    .and_then(|item| item.get("type"))
                    .and_then(Value::as_str)
                    && item_type == "agent_message"
                    && let Some(text) = notification
                        .params
                        .get("item")
                        .and_then(|item| item.get("text"))
                        .and_then(Value::as_str)
                {
                    self.append_assistant_delta(text);
                }
            }
            "turn/completed" => {
                self.active_turn_id = None;
                self.status_message = None;
                if !self.transcript.is_empty() && !self.transcript.ends_with('\n') {
                    self.transcript.push('\n');
                }
            }
            _ => {}
        }
    }

    fn push_line(&mut self, line: &str) {
        if !self.transcript.is_empty() && !self.transcript.ends_with('\n') {
            self.transcript.push('\n');
        }
        self.transcript.push_str(line);
        self.transcript.push('\n');
    }

    fn push_user_prompt(&mut self, prompt: &str) {
        if !self.transcript.is_empty() && !self.transcript.ends_with("\n\n") {
            if !self.transcript.ends_with('\n') {
                self.transcript.push('\n');
            }
            self.transcript.push('\n');
        }
        self.transcript.push_str(&format!("\u{203a} {prompt}\n\n"));
    }

    fn append_assistant_delta(&mut self, delta: &str) {
        if delta.is_empty() {
            return;
        }

        if !delta.starts_with([' ', '\n', '\t'])
            && let (Some(previous), Some(next)) =
                (self.transcript.chars().last(), delta.chars().next())
            && (previous.is_alphanumeric() && next.is_alphanumeric()
                || matches!(previous, '.' | '!' | '?' | ':' | ';' | ',') && next.is_alphanumeric())
        {
            self.transcript.push(' ');
        }

        self.transcript.push_str(delta);
    }

    fn input_insert_str(&mut self, text: &str) {
        if self.input_cursor == self.input.len() {
            self.input.push_str(text);
            self.input_cursor = self.input.len();
            self.sync_slash_picker();
            return;
        }
        self.input.insert_str(self.input_cursor, text);
        self.input_cursor += text.len();
        self.sync_slash_picker();
    }

    fn input_insert_char(&mut self, ch: char) {
        if self.input_cursor == self.input.len() {
            self.input.push(ch);
            self.input_cursor = self.input.len();
            self.sync_slash_picker();
            return;
        }
        self.input.insert(self.input_cursor, ch);
        self.input_cursor += ch.len_utf8();
        self.sync_slash_picker();
    }

    fn input_backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        let previous = previous_char_boundary(&self.input, self.input_cursor);
        self.input.drain(previous..self.input_cursor);
        self.input_cursor = previous;
        self.sync_slash_picker();
    }

    fn input_delete(&mut self) {
        if self.input_cursor >= self.input.len() {
            return;
        }
        let next = next_char_boundary(&self.input, self.input_cursor);
        self.input.drain(self.input_cursor..next);
        self.sync_slash_picker();
    }

    fn move_input_cursor_left(&mut self) {
        self.input_cursor = previous_char_boundary(&self.input, self.input_cursor);
    }

    fn move_input_cursor_right(&mut self) {
        self.input_cursor = next_char_boundary(&self.input, self.input_cursor);
    }

    fn move_input_cursor_home(&mut self) {
        self.input_cursor = 0;
    }

    fn move_input_cursor_end(&mut self) {
        self.input_cursor = self.input.len();
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.input_cursor = 0;
        self.sync_slash_picker();
    }

    fn replace_input(&mut self, text: String) {
        self.input = text;
        self.input_cursor = self.input.len();
        self.sync_slash_picker();
    }

    fn take_input(&mut self) -> String {
        self.history_index = None;
        self.input_cursor = 0;
        let taken = std::mem::take(&mut self.input);
        self.sync_slash_picker();
        taken
    }

    fn remember_history_entry(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        if self
            .command_history
            .last()
            .is_some_and(|entry| entry == text)
        {
            return;
        }
        self.command_history.push(text.to_string());
        self.history_index = None;
    }

    fn history_prev(&mut self) {
        if self.command_history.is_empty() {
            return;
        }
        let next_index = match self.history_index {
            Some(index) if index > 0 => index - 1,
            Some(index) => index,
            None => self.command_history.len().saturating_sub(1),
        };
        self.history_index = Some(next_index);
        self.replace_input(self.command_history[next_index].clone());
    }

    fn history_next(&mut self) {
        let Some(index) = self.history_index else {
            return;
        };
        if index + 1 >= self.command_history.len() {
            self.history_index = None;
            self.clear_input();
            return;
        }
        let next_index = index + 1;
        self.history_index = Some(next_index);
        self.replace_input(self.command_history[next_index].clone());
    }

    fn has_pending_prompt(&self) -> bool {
        self.pending_prompt.is_some()
    }

    fn start_prompt_request(
        &mut self,
        daemon_endpoint: String,
        auth_token: Option<String>,
        prompt: String,
    ) -> Result<()> {
        if self.pending_prompt.is_some() {
            bail!("a prompt is already running");
        }

        let session_id = self.session_id.clone();
        let request_prompt = prompt.clone();
        let handle = thread::spawn(move || {
            daemon_prompt_session(
                &daemon_endpoint,
                &session_id,
                &request_prompt,
                auth_token.as_deref(),
            )
        });

        self.pending_prompt = Some(InFlightPrompt {
            prompt,
            submitted_at: Instant::now(),
            handle,
        });
        self.status_message = Some("waiting for assistant response...".to_string());
        Ok(())
    }

    fn take_finished_prompt(&mut self) -> Option<InFlightPrompt> {
        if self
            .pending_prompt
            .as_ref()
            .is_some_and(|pending| pending.handle.is_finished())
        {
            return self.pending_prompt.take();
        }
        None
    }

    fn input_view(&self, width: usize) -> (String, usize, usize) {
        let prompt_width = TUI_COMPOSER_PROMPT.chars().count();
        if width == 0 {
            return (String::new(), 0, 0);
        }
        if width <= prompt_width {
            return (String::new(), width - 1, 0);
        }

        let input_width = width - prompt_width;
        let cursor_chars = self.input[..self.input_cursor].chars().count();
        let offset = if cursor_chars >= input_width {
            cursor_chars - (input_width - 1)
        } else {
            0
        };
        let visible = self.input.chars().skip(offset).take(input_width).collect();
        let cursor_col = (prompt_width + cursor_chars.saturating_sub(offset)).min(width - 1);
        (visible, cursor_col, offset)
    }

    fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|frame| {
            let slash_picker_lines = self.slash_picker_lines(frame.area().width as usize);
            let slash_picker_height = slash_picker_lines.len() as u16;
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(1),
                    Constraint::Length(slash_picker_height),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(frame.area());

            let history = self.transcript.clone();
            let history_lines = history.lines().count().max(1) as u16;
            let scroll = history_lines.saturating_sub(chunks[0].height);
            frame.render_widget(
                Paragraph::new(history)
                    .wrap(Wrap { trim: false })
                    .scroll((scroll, 0)),
                chunks[0],
            );

            if slash_picker_height > 0 {
                frame.render_widget(
                    Paragraph::new(slash_picker_lines).style(self.composer_row_style()),
                    chunks[1],
                );
            }

            let input_chunk_index = if slash_picker_height > 0 { 2 } else { 1 };
            let footer_chunk_index = if slash_picker_height > 0 { 3 } else { 2 };

            let input_width = chunks[input_chunk_index].width as usize;
            let (visible_input, cursor_col, offset) = self.input_view(input_width);
            let input_line = self.input_line(visible_input, offset, input_width);
            frame.render_widget(
                Paragraph::new(input_line).style(self.composer_row_style()),
                chunks[input_chunk_index],
            );

            frame.render_widget(
                Paragraph::new(
                    Line::from(self.footer_line_text(chunks[footer_chunk_index].width as usize))
                        .dim(),
                ),
                chunks[footer_chunk_index],
            );

            let cursor_x = chunks[input_chunk_index]
                .x
                .saturating_add(cursor_col.try_into().unwrap_or(u16::MAX));
            frame.set_cursor_position((cursor_x, chunks[input_chunk_index].y));
        })?;
        Ok(())
    }

    fn input_line(
        &self,
        visible_input: String,
        offset: usize,
        input_width: usize,
    ) -> Line<'static> {
        if visible_input.is_empty() {
            let placeholder_width = input_width.saturating_sub(TUI_COMPOSER_PROMPT.chars().count());
            let placeholder = truncate_for_width(TUI_COMPOSER_PLACEHOLDER, placeholder_width);
            return Line::from(vec![
                Span::raw(TUI_COMPOSER_PROMPT.to_string()),
                Span::raw(placeholder).dim(),
            ]);
        }

        if offset == 0 {
            let mut chars = visible_input.chars();
            if let Some(first) = chars.next() {
                let first_len = first.len_utf8();
                let rest = visible_input[first_len..].to_string();
                if let Some(style) = self.special_token_style(first) {
                    return Line::from(vec![
                        Span::raw(TUI_COMPOSER_PROMPT.to_string()),
                        Span::raw(first.to_string()).style(style),
                        Span::raw(rest),
                    ]);
                }
            }
        }

        Line::from(format!("{TUI_COMPOSER_PROMPT}{visible_input}"))
    }

    fn footer_line_text(&self, width: usize) -> String {
        let left = if let Some(pending) = &self.pending_prompt {
            let elapsed = pending.submitted_at.elapsed().as_secs_f32();
            format!("  esc to interrupt ({elapsed:.1}s)")
        } else if let Some(status) = &self.status_message {
            format!("  {}", status.trim())
        } else if let Some(left_hint) = self.live_input_hint() {
            left_hint
        } else if self.latest_state == "interrupted" {
            "  interrupted \u{2022} /resume to continue".to_string()
        } else {
            "  ? for shortcuts".to_string()
        };

        let context_left = self.context_left_percent();
        let right = if width >= 36 {
            format!("{context_left}% context left")
        } else {
            format!("{context_left}%")
        };
        align_left_right(&left, &right, width)
    }

    fn context_left_percent(&self) -> usize {
        let consumed = (self.received_events / 12).min(99);
        100_usize.saturating_sub(consumed)
    }

    fn composer_row_style(&self) -> Style {
        if env::var("COLORTERM")
            .map(|value| value.contains("truecolor"))
            .unwrap_or(false)
        {
            Style::default().bg(Color::Rgb(38, 42, 46))
        } else {
            Style::default().bg(Color::DarkGray)
        }
    }

    fn special_token_style(&self, token: char) -> Option<Style> {
        let style = match token {
            '!' => Style::default().fg(Color::Yellow).bold(),
            '@' => Style::default().fg(Color::Cyan).bold(),
            '$' => Style::default().fg(Color::Magenta).bold(),
            '/' => Style::default().fg(Color::Green).bold(),
            _ => return None,
        };
        Some(style)
    }

    fn slash_picker_query(&self) -> Option<String> {
        let trimmed = self.input.trim_start();
        if !trimmed.starts_with('/') {
            return None;
        }
        let stripped = trimmed.trim_start_matches('/');
        let token = stripped.trim_start();
        Some(token.split_whitespace().next().unwrap_or("").to_string())
    }

    fn slash_picker_entries(&self) -> Vec<&'static TuiSlashCommand> {
        let Some(query) = self.slash_picker_query() else {
            return Vec::new();
        };
        filtered_slash_commands(&query)
    }

    fn slash_picker_is_active(&self) -> bool {
        !self.slash_picker_entries().is_empty()
    }

    fn sync_slash_picker(&mut self) {
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
        } else if self.slash_picker_index >= len {
            self.slash_picker_index = len - 1;
        }
    }

    fn slash_picker_move_up(&mut self) {
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
            return;
        }
        if self.slash_picker_index == 0 {
            self.slash_picker_index = len - 1;
        } else {
            self.slash_picker_index = self.slash_picker_index.saturating_sub(1);
        }
    }

    fn slash_picker_move_down(&mut self) {
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
            return;
        }
        self.slash_picker_index = (self.slash_picker_index + 1) % len;
    }

    fn selected_slash_entry(&self) -> Option<&'static TuiSlashCommand> {
        let entries = self.slash_picker_entries();
        let selected = self.slash_picker_index.min(entries.len().saturating_sub(1));
        entries.get(selected).copied()
    }

    fn apply_selected_slash_entry(&mut self) -> bool {
        let Some(selected) = self.selected_slash_entry() else {
            return false;
        };
        self.replace_input(format!("/{}", selected.command));
        true
    }

    fn should_apply_slash_picker_on_enter(&self) -> bool {
        if !self.slash_picker_is_active() {
            return false;
        }
        let Some(selected) = self.selected_slash_entry() else {
            return false;
        };
        self.input.trim() != format!("/{}", selected.command)
    }

    fn slash_picker_lines(&self, width: usize) -> Vec<Line<'static>> {
        let entries = self.slash_picker_entries();
        if entries.is_empty() || width == 0 {
            return Vec::new();
        }

        let selected = self.slash_picker_index.min(entries.len().saturating_sub(1));
        let total = entries.len();
        let visible = total.min(TUI_SLASH_PICKER_MAX_ROWS);
        let start = selected.saturating_sub(visible.saturating_sub(1));
        let end = (start + visible).min(total);

        let command_col_width = entries[start..end]
            .iter()
            .map(|entry| entry.command.len() + 1)
            .max()
            .unwrap_or(12)
            .clamp(12, 30);
        let command_budget = command_col_width.saturating_sub(1);
        let mut lines = Vec::with_capacity(end.saturating_sub(start));
        for (index, entry) in entries[start..end].iter().enumerate() {
            let absolute = start + index;
            let is_selected = absolute == selected;
            let prefix = if is_selected { "› " } else { "  " };
            let command = truncate_for_width(entry.command, command_budget);
            let command_display = format!("/{command}");
            let description = truncate_for_width(
                entry.description,
                width.saturating_sub(command_col_width + 4),
            );

            let mut line = Line::from(vec![
                Span::raw(prefix),
                Span::raw(format!("{command_display:<command_col_width$}")),
                Span::raw(description).dim(),
            ]);
            if is_selected {
                line = line.style(Style::default().fg(Color::Green));
            }
            lines.push(line);
        }
        lines
    }

    fn live_input_hint(&self) -> Option<String> {
        if let Some(selected) = self.selected_slash_entry() {
            return Some(format!(
                "  {} \u{2022} {}",
                format!("/{}", selected.command),
                selected.description
            ));
        }
        match self.input.trim_start().chars().next() {
            Some('!') => Some("  ! shell command mode".to_string()),
            Some('@') => Some("  @ file mention mode".to_string()),
            Some('$') => Some("  $ variable/prompt mode".to_string()),
            Some('/') => Some("  / command mode".to_string()),
            _ => None,
        }
    }
}

fn previous_char_boundary(text: &str, index: usize) -> usize {
    if index == 0 {
        return 0;
    }
    text[..index]
        .char_indices()
        .last()
        .map(|(position, _)| position)
        .unwrap_or(0)
}

fn next_char_boundary(text: &str, index: usize) -> usize {
    if index >= text.len() {
        return text.len();
    }
    index
        + text[index..]
            .chars()
            .next()
            .map(|ch| ch.len_utf8())
            .unwrap_or(0)
}

fn run_attach_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ui: &mut LiveAttachTui,
    state: &mut CliState,
) -> Result<()> {
    let mut next_poll = Instant::now();
    let mut needs_redraw = true;
    loop {
        match poll_live_tui_prompt_completion(state, ui) {
            Ok(changed) => {
                if changed {
                    needs_redraw = true;
                }
            }
            Err(error) => {
                ui.status_message = Some(format!("prompt failed: {}", error_chain_summary(&error)));
                needs_redraw = true;
            }
        }

        if needs_redraw {
            ui.draw(terminal)?;
            needs_redraw = false;
        }

        let now = Instant::now();
        if now >= next_poll {
            match poll_live_tui_stream_updates(state, ui) {
                Ok(changed) => {
                    if changed {
                        needs_redraw = true;
                    }
                }
                Err(error) => {
                    ui.status_message = Some(format!(
                        "stream poll failed: {}",
                        error_chain_summary(&error)
                    ));
                    needs_redraw = true;
                }
            }
            next_poll = now + TUI_STREAM_POLL_INTERVAL;
        }

        if !event::poll(TUI_EVENT_WAIT_STEP).context("poll attach tui events")? {
            continue;
        }

        match event::read().context("read attach tui event")? {
            Event::Key(key) if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) => {
                let action = handle_live_tui_key_event(key, state, ui);
                match action {
                    Ok(LiveTuiAction::Detach) => break,
                    Ok(LiveTuiAction::Continue) => {
                        needs_redraw = true;
                        next_poll = Instant::now();
                    }
                    Err(error) => {
                        ui.status_message =
                            Some(format!("command failed: {}", error_chain_summary(&error)));
                        needs_redraw = true;
                    }
                }
            }
            Event::Paste(pasted) => {
                ui.input_insert_str(&pasted);
                needs_redraw = true;
            }
            Event::Resize(_, _) => {
                needs_redraw = true;
            }
            _ => {}
        }
    }
    Ok(())
}

enum LiveTuiAction {
    Continue,
    Detach,
}

fn handle_live_tui_key_event(
    key: crossterm::event::KeyEvent,
    state: &mut CliState,
    ui: &mut LiveAttachTui,
) -> Result<LiveTuiAction> {
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Ok(LiveTuiAction::Detach);
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ui.clear_input();
        }
        KeyCode::Up => {
            if ui.slash_picker_is_active() {
                ui.slash_picker_move_up();
            } else {
                ui.history_prev();
            }
        }
        KeyCode::Down => {
            if ui.slash_picker_is_active() {
                ui.slash_picker_move_down();
            } else {
                ui.history_next();
            }
        }
        KeyCode::Left => ui.move_input_cursor_left(),
        KeyCode::Right => ui.move_input_cursor_right(),
        KeyCode::Home => ui.move_input_cursor_home(),
        KeyCode::End => ui.move_input_cursor_end(),
        KeyCode::Enter => {
            if ui.should_apply_slash_picker_on_enter() {
                let _ = ui.apply_selected_slash_entry();
                return Ok(LiveTuiAction::Continue);
            }
            let input = ui.take_input();
            return handle_live_tui_submit(state, ui, input);
        }
        KeyCode::Backspace => {
            ui.input_backspace();
        }
        KeyCode::Delete => {
            ui.input_delete();
        }
        KeyCode::Tab => {
            if ui.slash_picker_is_active() {
                let _ = ui.apply_selected_slash_entry();
            } else {
                ui.input_insert_char('\t');
            }
        }
        KeyCode::Char(ch) => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                ui.input_insert_char(ch);
            }
        }
        _ => {}
    }
    Ok(LiveTuiAction::Continue)
}

fn handle_live_tui_submit(
    state: &mut CliState,
    ui: &mut LiveAttachTui,
    input: String,
) -> Result<LiveTuiAction> {
    let command = input.trim();
    if command.is_empty() || command == "/refresh" {
        let _ = poll_live_tui_stream_updates(state, ui)?;
        return Ok(LiveTuiAction::Continue);
    }

    if command == "/exit" || command == "/quit" {
        return Ok(LiveTuiAction::Detach);
    }

    if command == "/status" {
        let status = daemon_get_session_status(
            &state.config.daemon_endpoint,
            &ui.session_id,
            state.config.auth_token.as_deref(),
        )?;
        persist_daemon_session(state, &status)?;
        ui.latest_state = status.state.clone();
        ui.status_message = Some(format!(
            "state={} last_event={} updated_at_unix_ms={}",
            status.state, status.last_event, status.updated_at_unix_ms
        ));
        let _ = poll_live_tui_stream_updates(state, ui)?;
        return Ok(LiveTuiAction::Continue);
    }

    if command == "/interrupt" {
        let status = daemon_interrupt_session(
            &state.config.daemon_endpoint,
            &ui.session_id,
            state.config.auth_token.as_deref(),
        )?;
        persist_daemon_session(state, &status)?;
        ui.latest_state = status.state.clone();
        ui.status_message = Some("session interrupted".to_string());
        let _ = poll_live_tui_stream_updates(state, ui)?;
        return Ok(LiveTuiAction::Continue);
    }

    if command == "/resume" {
        let status = daemon_resume_session(
            &state.config.daemon_endpoint,
            &ui.session_id,
            state.config.auth_token.as_deref(),
        )?;
        persist_daemon_session(state, &status)?;
        ui.latest_state = status.state.clone();
        ui.status_message = Some("session resumed".to_string());
        let _ = poll_live_tui_stream_updates(state, ui)?;
        return Ok(LiveTuiAction::Continue);
    }

    if command.starts_with('/') {
        ui.status_message = Some(format!("unknown command: {command}"));
        return Ok(LiveTuiAction::Continue);
    }

    if ui.has_pending_prompt() {
        ui.status_message =
            Some("wait for current response before sending another prompt".to_string());
        ui.replace_input(input);
        return Ok(LiveTuiAction::Continue);
    }

    ensure_daemon_ready(state).context("daemon unavailable before prompt submit")?;

    ui.push_user_prompt(command);
    ui.remember_history_entry(command);

    ui.start_prompt_request(
        state.config.daemon_endpoint.clone(),
        state.config.auth_token.clone(),
        command.to_string(),
    )?;
    Ok(LiveTuiAction::Continue)
}

fn poll_live_tui_prompt_completion(state: &mut CliState, ui: &mut LiveAttachTui) -> Result<bool> {
    let Some(pending) = ui.take_finished_prompt() else {
        return Ok(false);
    };

    let prompt_text = pending.prompt;
    let result = pending
        .handle
        .join()
        .map_err(|_| anyhow!("prompt worker thread panicked"))?;
    let prompt = result?;

    persist_daemon_session(
        state,
        &DaemonSessionStatusResponse {
            session_id: prompt.session_id.clone(),
            state: prompt.state.clone(),
            last_event: prompt.last_event.clone(),
            updated_at_unix_ms: prompt.updated_at_unix_ms,
        },
    )?;
    ui.latest_state = prompt.state.clone();
    if prompt.state != "active" {
        ui.status_message = Some(format!("session state: {}", prompt.state));
    } else {
        ui.status_message = Some(format!("response received for: {prompt_text}"));
    }

    match poll_live_tui_stream_updates(state, ui) {
        Ok(_) => {}
        Err(error) => {
            ui.status_message = Some(format!(
                "stream poll failed after prompt: {}",
                error_chain_summary(&error)
            ));
        }
    }
    Ok(true)
}

fn poll_live_tui_stream_updates(state: &mut CliState, ui: &mut LiveAttachTui) -> Result<bool> {
    let stream_events = match fetch_daemon_stream_with_timeout(
        &state.config.daemon_endpoint,
        &ui.session_id,
        state.config.auth_token.as_deref(),
        Some(ui.last_sequence),
        TUI_STREAM_REQUEST_TIMEOUT,
    )? {
        DaemonStreamFetchResult::Stream(events) => events,
        DaemonStreamFetchResult::NotFound => {
            bail!("session stream not found for session: {}", ui.session_id)
        }
    };

    if stream_events.is_empty() {
        return Ok(false);
    }

    ui.apply_stream_events(&stream_events);
    persist_latest_session_state_from_stream(state, &ui.session_id, &stream_events)?;
    if let Some(cached_state) = cached_session_state_label(state, &ui.session_id) {
        ui.latest_state = cached_state.to_string();
    }
    Ok(true)
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

fn error_chain_summary(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(|cause| cause.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

fn align_left_right(left: &str, right: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }

    let left = truncate_for_width(left, width);
    let right = truncate_for_width(right, width);
    let left_width = left.chars().count();
    let right_width = right.chars().count();

    if left_width + right_width + 1 <= width {
        let spacing = width.saturating_sub(left_width + right_width);
        return format!("{left}{}{right}", " ".repeat(spacing));
    }

    if right_width + 1 >= width {
        return truncate_for_width(&right, width);
    }

    let left_budget = width.saturating_sub(right_width + 1);
    let left_truncated = truncate_for_width(&left, left_budget);
    format!("{left_truncated} {right}")
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
    use crabbot_protocol::{
        DAEMON_STREAM_SCHEMA_VERSION, DaemonApprovalRequired, DaemonSessionState,
        DaemonStreamEvent, DaemonTurnStreamDelta, Heartbeat,
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

    #[test]
    fn live_tui_input_editing_respects_cursor_boundaries() {
        let mut ui = LiveAttachTui::new("sess_input".to_string(), "active".to_string());

        ui.input_insert_str("hello");
        ui.move_input_cursor_left();
        ui.move_input_cursor_left();
        ui.input_insert_char('X');
        assert_eq!(ui.input, "helXlo");

        ui.input_delete();
        assert_eq!(ui.input, "helXo");

        ui.input_backspace();
        assert_eq!(ui.input, "helo");

        ui.move_input_cursor_home();
        ui.input_insert_char('[');
        ui.move_input_cursor_end();
        ui.input_insert_char(']');
        assert_eq!(ui.input, "[helo]");
    }

    #[test]
    fn live_tui_history_navigation_replays_previous_entries() {
        let mut ui = LiveAttachTui::new("sess_history".to_string(), "active".to_string());
        ui.remember_history_entry("first");
        ui.remember_history_entry("second");

        ui.history_prev();
        assert_eq!(ui.input, "second");

        ui.history_prev();
        assert_eq!(ui.input, "first");

        ui.history_next();
        assert_eq!(ui.input, "second");

        ui.history_next();
        assert_eq!(ui.input, "");
    }

    #[test]
    fn live_tui_slash_picker_opens_and_filters_commands() {
        let mut ui = LiveAttachTui::new("sess_picker".to_string(), "active".to_string());
        ui.input_insert_char('/');
        assert!(ui.slash_picker_is_active());
        assert_eq!(
            ui.selected_slash_entry().map(|entry| entry.command),
            Some("model")
        );

        ui.input_insert_str("re");
        let filtered = ui
            .slash_picker_entries()
            .iter()
            .map(|entry| entry.command)
            .collect::<Vec<_>>();
        assert_eq!(filtered, vec!["review", "rename", "resume"]);
    }

    #[test]
    fn live_tui_slash_picker_selection_applies_command() {
        let mut ui = LiveAttachTui::new("sess_picker_select".to_string(), "active".to_string());
        ui.input_insert_char('/');
        ui.slash_picker_move_down();
        assert_eq!(
            ui.selected_slash_entry().map(|entry| entry.command),
            Some("permissions")
        );
        assert!(ui.should_apply_slash_picker_on_enter());
        assert!(ui.apply_selected_slash_entry());
        assert_eq!(ui.input, "/permissions");
        assert!(!ui.should_apply_slash_picker_on_enter());
    }

    #[test]
    fn live_tui_special_token_hints_match_native_modes() {
        let mut ui = LiveAttachTui::new("sess_tokens".to_string(), "active".to_string());

        ui.replace_input("!ls -la".to_string());
        assert_eq!(
            ui.live_input_hint().as_deref(),
            Some("  ! shell command mode")
        );

        ui.replace_input("@src/main.rs".to_string());
        assert_eq!(
            ui.live_input_hint().as_deref(),
            Some("  @ file mention mode")
        );

        ui.replace_input("$VAR".to_string());
        assert_eq!(
            ui.live_input_hint().as_deref(),
            Some("  $ variable/prompt mode")
        );
    }
}
