use super::*;

use crate::app_event::AppEvent as WidgetAppEvent;
use crate::app_event_sender::AppEventSender as WidgetAppEventSender;
use crate::bottom_pane::InputResult;
use crate::chatwidget::ChatWidget;
use crate::chatwidget::LiveAttachTui;
pub(super) use crate::core_compat::AppEvent;
pub(super) use crate::core_compat::AppEventSender;
pub(super) use crate::core_compat::AppExitInfo;
pub(super) use crate::core_compat::ExitMode;
pub(super) use crate::core_compat::ExitReason;
pub(super) use crate::core_compat::LiveTuiAction;
pub(super) use crate::core_compat::interrupt_turn;
pub(super) use crate::core_compat::respond_to_approval;
pub(super) use crate::core_compat::resume_thread;
pub(super) use crate::core_compat::set_thread_name;
pub(super) use crate::core_compat::start_thread;
pub(super) use crate::core_compat::start_turn_with_elements;
pub(super) use crate::core_compat::stream_events;
use crate::exec_cell::CommandOutput as ExecCommandOutput;
use crate::exec_cell::new_active_exec_command;
use crate::file_search::FileSearchManager;
use crate::get_git_diff::get_git_diff;
use crate::slash_command::SlashCommand;
use crate::slash_commands::find_builtin_command;
use codex_core::protocol::ExecCommandSource;

// ---------------------------------------------------------------------------
// App struct — mirrors upstream `app::App` but backed by app-server transport
// ---------------------------------------------------------------------------

/// Top-level application state for the TUI.
///
/// Mirrors upstream `App` from `app.rs` in structure: owns the `ChatWidget`,
/// tracks the active thread, and drives the terminal event loop. All backend
/// calls go through `core_compat` instead of `codex-core`.
pub(crate) struct App {
    /// The active chat widget.
    widget: ChatWidget,
    /// Shared CLI state (app-server endpoint, sessions, auth).
    state: CliState,
    /// ID of the active app-server thread.
    thread_id: String,
    /// Internal app event sender (upstream-style dispatch seam).
    app_event_tx: AppEventSender,
    /// Internal app event receiver.
    app_event_rx: std::sync::mpsc::Receiver<AppEvent>,
    /// Widget event receiver (bottom pane + file search).
    widget_event_rx: tokio::sync::mpsc::UnboundedReceiver<WidgetAppEvent>,
    /// Upstream-style @file search manager.
    file_search: FileSearchManager,
    /// Runtime status data used by `/status` card rendering.
    status_runtime: StatusRuntime,
}

#[derive(Default)]
struct StatusRuntime {
    token_info: Option<codex_core::protocol::TokenUsageInfo>,
    total_token_usage: codex_core::protocol::TokenUsage,
    rate_limit_snapshots_by_limit_id:
        std::collections::BTreeMap<String, crate::status::RateLimitSnapshotDisplay>,
    thread_name: Option<String>,
    session_model: Option<String>,
    session_reasoning_effort: Option<codex_protocol::openai_models::ReasoningEffort>,
}

struct DrainResult {
    redraw: bool,
    detach: bool,
}

impl App {
    /// Create a new `App` for an interactive TUI session.
    ///
    /// Mirrors upstream `App::run()` initialization: ensures the app-server is
    /// ready, starts or reuses a thread, and creates the initial `ChatWidget`.
    pub(crate) fn new(args: TuiArgs, mut state: CliState) -> Result<Self> {
        ensure_app_server_ready(&state)?;
        let (thread_id, status_message) =
            resolve_initial_thread_id(&state, args.thread_id, state.last_thread_id.clone())?;
        state.last_thread_id = Some(thread_id.clone());

        let mut widget = ChatWidget::new(thread_id.clone());
        let mut status_runtime = StatusRuntime::default();
        widget.ui_mut().set_status_message(Some(status_message));
        match stream_events(&state, widget.ui_mut().last_sequence) {
            Ok(events) => {
                if !events.is_empty() {
                    status_runtime.apply_stream_events(&events);
                    widget.ui_mut().apply_rpc_stream_events(&events);
                }
            }
            Err(err) => {
                widget.ui_mut().set_status_message(Some(format!(
                    "connected; initial stream sync failed: {}",
                    err
                )));
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let (widget_tx, widget_rx) = tokio::sync::mpsc::unbounded_channel();
        let widget_sender = WidgetAppEventSender::new(widget_tx);
        let search_dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let file_search = FileSearchManager::new(search_dir, widget_sender);
        if let Ok(skills) = fetch_skills_for_cwd(&state)
            && !skills.is_empty()
        {
            widget.ui_mut().set_skills(Some(skills));
        }
        if let Ok(connectors) = fetch_connectors(&state)
            && !connectors.connectors.is_empty()
        {
            widget.ui_mut().set_connectors_snapshot(Some(connectors));
        }

        Ok(Self {
            widget,
            state,
            thread_id,
            app_event_tx: AppEventSender::new(tx),
            app_event_rx: rx,
            widget_event_rx: widget_rx,
            file_search,
            status_runtime,
        })
    }

    /// Create an `App` that attaches to an existing app-server session.
    pub(crate) fn attach(
        session_id: String,
        initial_events: Vec<DaemonStreamEnvelope>,
        mut state: CliState,
    ) -> Result<Self> {
        let mut widget = ChatWidget::new(session_id.clone());
        let status_runtime = StatusRuntime::default();
        {
            let ui = widget.ui_mut();
            ui.latest_state = cached_session_state_label(&state, &session_id)
                .unwrap_or("unknown")
                .to_string();
            ui.apply_stream_events(&initial_events);
            ui.set_status_message(Some("attached to app-server websocket".to_string()));
        }
        state.last_thread_id = Some(session_id.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        let (widget_tx, widget_rx) = tokio::sync::mpsc::unbounded_channel();
        let widget_sender = WidgetAppEventSender::new(widget_tx);
        let search_dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let file_search = FileSearchManager::new(search_dir, widget_sender);
        if let Ok(skills) = fetch_skills_for_cwd(&state)
            && !skills.is_empty()
        {
            widget.ui_mut().set_skills(Some(skills));
        }
        if let Ok(connectors) = fetch_connectors(&state)
            && !connectors.connectors.is_empty()
        {
            widget.ui_mut().set_connectors_snapshot(Some(connectors));
        }

        Ok(Self {
            widget,
            state,
            thread_id: session_id,
            app_event_tx: AppEventSender::new(tx),
            app_event_rx: rx,
            widget_event_rx: widget_rx,
            file_search,
            status_runtime,
        })
    }

    /// Run the interactive TUI event loop.
    ///
    /// This mirrors upstream `App::run()` — sets up the terminal, enters the
    /// main loop, then restores the terminal on exit.
    pub(crate) fn run(&mut self) -> Result<AppExitInfo> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Ok(AppExitInfo {
                thread_id: Some(self.thread_id.clone()),
                exit_reason: ExitReason::UserRequested,
            });
        }

        let terminal = crate::tui::init().context("initialize tui terminal")?;
        let mut tui = crate::tui::Tui::new(terminal);
        let loop_result = self.event_loop(&mut tui);
        let _ = crate::tui::restore();

        loop_result?;
        self.state.last_thread_id = Some(self.widget.session_id().to_string());

        Ok(AppExitInfo {
            thread_id: Some(self.widget.session_id().to_string()),
            exit_reason: ExitReason::UserRequested,
        })
    }

    /// Consume the `App`, returning the final `CliState` so the caller can
    /// persist it.
    pub(crate) fn into_state(self) -> CliState {
        self.state
    }

    // -----------------------------------------------------------------------
    // Event loop — mirrors upstream `App::run()` main loop body
    // -----------------------------------------------------------------------

    fn event_loop(&mut self, tui: &mut crate::tui::Tui) -> Result<()> {
        loop {
            let _ = self.widget.ui_mut().flush_bottom_pane_paste_burst_if_due();
            let in_paste_burst = self.widget.ui_mut().bottom_pane_is_in_paste_burst();
            let _ = self.widget.ui_mut().commit_assistant_stream_tick();
            let width = tui.terminal.size()?.width;
            let desired_height = self.widget.desired_height(width);
            tui.draw(desired_height, |frame| {
                self.widget.render(frame.area(), frame.buffer_mut());
                if let Some((x, y)) = self.widget.cursor_pos(frame.area()) {
                    frame.set_cursor_position((x, y));
                }
            })?;
            let mut should_redraw = false;

            // Poll terminal for input events.
            if event::poll(TUI_EVENT_WAIT_STEP).context("poll tui input event")? {
                let app_event = match event::read().context("read tui input event")? {
                    Event::Key(key_event) => {
                        if key_event.kind != KeyEventKind::Press {
                            continue;
                        }
                        AppEvent::Key(key_event)
                    }
                    Event::Mouse(mouse_event) => AppEvent::Mouse(mouse_event),
                    Event::Paste(pasted) => AppEvent::Paste(pasted),
                    Event::Resize(_, _) => AppEvent::Resize,
                    _ => continue,
                };

                match self.handle_event(app_event)? {
                    LiveTuiAction::Continue => {}
                    LiveTuiAction::Detach => return Ok(()),
                }
                should_redraw = true;
            }

            let drained = self.drain_pending_app_events()?;
            if drained.detach {
                return Ok(());
            }
            should_redraw |= drained.redraw;

            // Tick: poll stream for app-server events.
            match self.handle_event(AppEvent::Tick)? {
                LiveTuiAction::Continue => {}
                LiveTuiAction::Detach => return Ok(()),
            }
            let drained = self.drain_pending_app_events()?;
            if drained.detach {
                return Ok(());
            }
            should_redraw |= drained.redraw;

            if !should_redraw {
                if in_paste_burst {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                thread::sleep(TUI_STREAM_POLL_INTERVAL);
            }
        }
    }

    fn drain_pending_app_events(&mut self) -> Result<DrainResult> {
        let mut handled_any = false;
        while let Ok(app_event) = self.app_event_rx.try_recv() {
            match self.handle_event(app_event)? {
                LiveTuiAction::Continue => {}
                LiveTuiAction::Detach => {
                    return Ok(DrainResult {
                        redraw: handled_any,
                        detach: true,
                    });
                }
            }
            handled_any = true;
        }
        Ok(DrainResult {
            redraw: handled_any,
            detach: false,
        })
    }

    fn switch_to_thread(&mut self, thread_id: String, status_message: &str, announce_switch: bool) {
        let ui = self.widget.ui_mut();
        let previous_thread = ui.session_id.clone();
        let changed = previous_thread != thread_id;
        ui.session_id = thread_id.clone();
        ui.active_turn_id = None;
        if changed {
            ui.pending_approvals.clear();
        }
        if announce_switch && changed {
            ui.push_line(&format!("[thread switched] {thread_id}"));
        }
        ui.set_status_message(Some(status_message.to_string()));
        self.state.last_thread_id = Some(thread_id.clone());
        self.thread_id = thread_id;
    }

    // -----------------------------------------------------------------------
    // Event handling — mirrors upstream `App::handle_event()`
    // -----------------------------------------------------------------------

    /// Process a single `AppEvent` and return the action the loop should take.
    ///
    /// This is the central dispatch point, mirroring upstream's enormous
    /// `handle_event`. Currently handles the essential events; additional
    /// upstream event types will be added incrementally.
    fn handle_event(&mut self, event: AppEvent) -> Result<LiveTuiAction> {
        match event {
            AppEvent::Key(key_event) => self.handle_key_event(key_event),
            AppEvent::Mouse(mouse_event) => {
                self.widget.ui_mut().handle_mouse_event(mouse_event);
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Paste(pasted) => {
                // Mirror upstream textarea behavior: normalize CR to LF for pasted text.
                let pasted = pasted.replace('\r', "\n");
                self.widget.ui_mut().handle_bottom_pane_paste(pasted);
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Resize => Ok(LiveTuiAction::Continue),
            AppEvent::Tick => {
                let since_sequence = self.widget.ui_mut().last_sequence;
                match stream_events(&self.state, since_sequence) {
                    Ok(envelopes) => {
                        if !envelopes.is_empty() {
                            self.app_event_tx.send(AppEvent::StreamUpdate(envelopes));
                        }
                    }
                    Err(err) => {
                        self.widget
                            .ui_mut()
                            .set_status_message(Some(format!("stream poll failed: {err}")));
                    }
                }
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::SubmitInput {
                text,
                text_elements,
                mention_bindings,
            } => self.handle_submit(&text, text_elements, mention_bindings),
            AppEvent::StartTurn {
                text,
                text_elements,
                mention_bindings,
            } => {
                let ui = self.widget.ui_mut();
                ui.push_user_prompt(&text, text_elements.clone());
                if let Some(turn_id) = start_turn_with_elements(
                    &self.state,
                    &ui.session_id,
                    &text,
                    text_elements,
                    mention_bindings,
                )? {
                    ui.active_turn_id = Some(turn_id);
                }
                ui.set_status_message(Some("waiting for response...".to_string()));
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::NewSession => {
                let thread_id = start_thread(&self.state)?;
                self.switch_to_thread(thread_id, "started new thread", true);
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Interrupt => {
                let ui = self.widget.ui_mut();
                if let Some(turn_id) = ui.active_turn_id.clone() {
                    interrupt_turn(&self.state, &ui.session_id, &turn_id)?;
                    ui.set_status_message(Some("interrupt requested".to_string()));
                } else {
                    ui.set_status_message(Some("no running turn".to_string()));
                }
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::ShowStatus => {
                self.emit_status_summary();
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::RefreshStream => {
                self.widget
                    .ui_mut()
                    .set_status_message(Some("refreshing stream...".to_string()));
                self.app_event_tx.send(AppEvent::Tick);
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::ResumeSession => {
                self.open_resume_picker()?;
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::ApprovalDecision { arg, approve } => {
                handle_app_server_approval_decision(
                    &mut self.state,
                    self.widget.ui_mut(),
                    &arg,
                    approve,
                )?;
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Exit(_mode) => Ok(LiveTuiAction::Detach),
            AppEvent::StreamUpdate(envelopes) => {
                self.status_runtime.apply_stream_events(&envelopes);
                self.widget.ui_mut().apply_rpc_stream_events(&envelopes);
                Ok(LiveTuiAction::Continue)
            }
        }
    }

    /// Handle a key press event — mirrors upstream `App::handle_key_event`.
    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) -> Result<LiveTuiAction> {
        let mut queued_submit: Option<(String, Vec<codex_protocol::user_input::TextElement>)> =
            None;
        let mut queued_command: Option<(
            SlashCommand,
            Option<String>,
            Vec<codex_protocol::user_input::TextElement>,
        )> = None;
        if key.code == KeyCode::PageUp {
            self.widget.ui_mut().scroll_history_page_up();
            return Ok(LiveTuiAction::Continue);
        }
        if key.code == KeyCode::PageDown {
            self.widget.ui_mut().scroll_history_page_down();
            return Ok(LiveTuiAction::Continue);
        }
        let pending_widget_events = {
            let ui = self.widget.ui_mut();
            if key.code == KeyCode::Esc && ui.shortcuts_overlay_visible() {
                ui.hide_shortcuts_overlay();
                return Ok(LiveTuiAction::Continue);
            }
            match key.code {
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.app_event_tx.send(AppEvent::Exit(ExitMode::Immediate));
                    return Ok(LiveTuiAction::Continue);
                }
                KeyCode::Char('?') => {
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT)
                        && ui.bottom_pane_composer_text().trim().is_empty()
                    {
                        ui.toggle_shortcuts_overlay();
                    } else {
                        match ui.handle_bottom_pane_key_event(key) {
                            InputResult::Submitted {
                                text,
                                text_elements,
                            }
                            | InputResult::Queued {
                                text,
                                text_elements,
                            } => {
                                queued_submit = Some((text, text_elements));
                            }
                            InputResult::Command(cmd) => {
                                queued_command = Some((cmd, None, Vec::new()));
                            }
                            InputResult::CommandWithArgs(cmd, args, text_elements) => {
                                queued_command = Some((cmd, Some(args), text_elements));
                            }
                            InputResult::None => {}
                        }
                    }
                }
                _ => match ui.handle_bottom_pane_key_event(key) {
                    InputResult::Submitted {
                        text,
                        text_elements,
                    }
                    | InputResult::Queued {
                        text,
                        text_elements,
                    } => {
                        queued_submit = Some((text, text_elements));
                    }
                    InputResult::Command(cmd) => {
                        queued_command = Some((cmd, None, Vec::new()));
                    }
                    InputResult::CommandWithArgs(cmd, args, text_elements) => {
                        queued_command = Some((cmd, Some(args), text_elements));
                    }
                    InputResult::None => {}
                },
            }
            ui.drain_bottom_pane_events()
        };
        for event in pending_widget_events {
            match event {
                WidgetAppEvent::CodexOp(codex_core::protocol::Op::Interrupt) => {
                    self.app_event_tx.send(AppEvent::Interrupt);
                }
                WidgetAppEvent::InsertHistoryCell(cell) => {
                    self.widget.ui_mut().add_history_cell(cell);
                }
                WidgetAppEvent::StartFileSearch(query) => {
                    self.file_search.on_user_query(query);
                }
                WidgetAppEvent::FileSearchResult { query, matches } => {
                    self.widget
                        .ui_mut()
                        .apply_file_search_result(query, matches);
                }
                WidgetAppEvent::OpenResumePicker => {
                    self.open_resume_picker()?;
                }
                WidgetAppEvent::SelectAgentThread(thread_id) => {
                    let selected_thread_id = thread_id.to_string();
                    if let Some(resumed_thread_id) =
                        resume_thread(&self.state, &selected_thread_id)?
                    {
                        self.switch_to_thread(resumed_thread_id, "thread resumed", false);
                    } else {
                        self.widget
                            .ui_mut()
                            .set_status_message(Some("resume returned no thread id".to_string()));
                    }
                }
                WidgetAppEvent::StatusLineSetup { .. } => {
                    self.widget
                        .ui_mut()
                        .set_status_message(Some("status line updated".to_string()));
                }
                WidgetAppEvent::StatusLineSetupCancelled => {
                    self.widget
                        .ui_mut()
                        .set_status_message(Some("status line setup cancelled".to_string()));
                }
                _ => {}
            }
        }

        while let Ok(event) = self.widget_event_rx.try_recv() {
            if let WidgetAppEvent::FileSearchResult { query, matches } = event {
                self.widget
                    .ui_mut()
                    .apply_file_search_result(query, matches);
            }
        }

        if let Some((cmd, args, text_elements)) = queued_command {
            self.dispatch_slash_command(cmd, args, text_elements)?;
        } else if let Some((input, text_elements)) = queued_submit {
            let mention_bindings = self
                .widget
                .ui_mut()
                .take_recent_submission_mention_bindings();
            self.app_event_tx.send(AppEvent::SubmitInput {
                text: input,
                text_elements,
                mention_bindings,
            });
        }
        Ok(LiveTuiAction::Continue)
    }

    fn dispatch_slash_command(
        &mut self,
        cmd: SlashCommand,
        args: Option<String>,
        text_elements: Vec<codex_protocol::user_input::TextElement>,
    ) -> Result<()> {
        let arg = args.unwrap_or_default();
        match cmd {
            SlashCommand::New => self.app_event_tx.send(AppEvent::NewSession),
            SlashCommand::Resume => self.open_resume_picker()?,
            SlashCommand::Status => self.emit_status_summary(),
            SlashCommand::Statusline => self.widget.ui_mut().open_status_line_setup(None),
            SlashCommand::DebugConfig => self
                .widget
                .ui_mut()
                .push_line("[info] /debug-config is not yet ported in app-server tui"),
            SlashCommand::Fork => self.app_event_tx.send(AppEvent::NewSession),
            SlashCommand::Init => {
                let init_target = std::env::current_dir()
                    .unwrap_or_else(|_| std::env::temp_dir())
                    .join("AGENTS.md");
                if init_target.exists() {
                    self.widget.ui_mut().push_line(
                        "AGENTS.md already exists here. Skipping /init to avoid overwriting it.",
                    );
                } else {
                    const INIT_PROMPT: &str = include_str!("../prompt_for_init_command.md");
                    self.app_event_tx.send(AppEvent::StartTurn {
                        text: INIT_PROMPT.to_string(),
                        text_elements: Vec::new(),
                        mention_bindings: Vec::new(),
                    });
                }
            }
            SlashCommand::Approvals | SlashCommand::Permissions => {
                let pending = self.widget.ui_mut().pending_approvals.len();
                self.widget
                    .ui_mut()
                    .push_line(&format!("Pending approvals: {pending}"));
            }
            SlashCommand::Review => {
                if arg.trim().is_empty() {
                    self.widget
                        .ui_mut()
                        .push_line("[info] /review popup is not yet ported in app-server tui");
                } else {
                    self.app_event_tx.send(AppEvent::StartTurn {
                        text: format!("/review {}", arg.trim()),
                        text_elements,
                        mention_bindings: Vec::new(),
                    });
                }
            }
            SlashCommand::Rename => {
                if arg.trim().is_empty() {
                    self.widget
                        .ui_mut()
                        .push_line("[info] usage: /rename <thread-name>");
                } else {
                    let thread_id = self.widget.ui_mut().session_id.clone();
                    set_thread_name(&self.state, &thread_id, arg.trim())?;
                    self.widget
                        .ui_mut()
                        .set_status_message(Some(format!("thread renamed to {}", arg.trim())));
                }
            }
            SlashCommand::SandboxReadRoot => {
                if arg.trim().is_empty() {
                    self.widget
                        .ui_mut()
                        .push_line("Usage: /sandbox-add-read-dir <absolute-directory-path>");
                } else {
                    self.widget.ui_mut().push_line(
                        "[info] /sandbox-add-read-dir is not yet ported in app-server tui",
                    );
                }
            }
            SlashCommand::Quit | SlashCommand::Exit => {
                self.app_event_tx.send(AppEvent::Exit(ExitMode::Immediate))
            }
            SlashCommand::Logout => {
                self.state.config.auth_token = None;
                self.widget
                    .ui_mut()
                    .push_line("Logged out from app-server auth token.");
                self.app_event_tx.send(AppEvent::Exit(ExitMode::Immediate));
            }
            SlashCommand::Mention => {
                self.widget.ui_mut().bottom_pane_insert_str("@");
            }
            SlashCommand::Diff => {
                let diff_text = run_diff_now();
                self.widget.ui_mut().push_line(&diff_text);
            }
            SlashCommand::Skills => match fetch_skills_for_cwd(&self.state) {
                Ok(skills) if skills.is_empty() => {
                    self.widget.ui_mut().push_line("No skills available.");
                }
                Ok(skills) => {
                    self.widget.ui_mut().push_line("Skills:");
                    for skill in skills {
                        self.widget.ui_mut().push_line(&format!(
                            "- {}{}",
                            skill.name,
                            if skill.description.is_empty() {
                                String::new()
                            } else {
                                format!(": {}", skill.description)
                            }
                        ));
                    }
                }
                Err(err) => self
                    .widget
                    .ui_mut()
                    .push_line(&format!("Failed to load skills: {err}")),
            },
            SlashCommand::Apps => match fetch_connectors(&self.state) {
                Ok(snapshot) if snapshot.connectors.is_empty() => {
                    self.widget.ui_mut().push_line("No apps available.");
                }
                Ok(snapshot) => {
                    self.widget.ui_mut().push_line("Apps:");
                    for app in snapshot.connectors {
                        self.widget.ui_mut().push_line(&format!(
                            "- {} ({}){}",
                            app.name,
                            app.id,
                            if app.is_enabled { "" } else { " [disabled]" }
                        ));
                    }
                }
                Err(err) => self
                    .widget
                    .ui_mut()
                    .push_line(&format!("Failed to load apps: {err}")),
            },
            SlashCommand::Ps => {
                self.widget.ui_mut().add_history_cell(Box::new(
                    crate::history_cell::new_unified_exec_processes_output(Vec::new()),
                ));
            }
            SlashCommand::Clean => {
                self.widget
                    .ui_mut()
                    .push_line("Stopping all background terminals.");
            }
            SlashCommand::Mcp => {
                self.widget
                    .ui_mut()
                    .add_history_cell(Box::new(crate::history_cell::empty_mcp_output()));
            }
            SlashCommand::Rollout => {
                let session_id = self.widget.ui_mut().session_id.clone();
                match fetch_rollout_path(&self.state, &session_id) {
                    Ok(Some(path)) => self
                        .widget
                        .ui_mut()
                        .push_line(&format!("Current rollout path: {path}")),
                    Ok(None) => self
                        .widget
                        .ui_mut()
                        .push_line("Rollout path is not available yet."),
                    Err(err) => self
                        .widget
                        .ui_mut()
                        .push_line(&format!("Failed to read rollout path: {err}")),
                }
            }
            _ => {
                let _ = arg;
                let _ = text_elements;
                self.widget.ui_mut().push_line(&format!(
                    "[info] /{} is not yet ported in app-server tui",
                    cmd.command()
                ));
            }
        }
        Ok(())
    }

    /// Handle submitted user input (from Enter key or programmatic submit).
    fn handle_submit(
        &mut self,
        input: &str,
        text_elements: Vec<codex_protocol::user_input::TextElement>,
        mention_bindings: Vec<crate::bottom_pane::MentionBinding>,
    ) -> Result<LiveTuiAction> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(LiveTuiAction::Continue);
        }
        if let Some(command) = input.strip_prefix('!') {
            self.run_user_shell_command(command.trim());
            return Ok(LiveTuiAction::Continue);
        }
        let ui = self.widget.ui_mut();
        ui.hide_shortcuts_overlay();
        ui.remember_history_entry(trimmed);

        match trimmed {
            "/exit" | "/quit" => {
                self.app_event_tx.send(AppEvent::Exit(ExitMode::Immediate));
                return Ok(LiveTuiAction::Continue);
            }
            "/status" => {
                self.emit_status_summary();
                return Ok(LiveTuiAction::Continue);
            }
            "/refresh" => {
                self.app_event_tx.send(AppEvent::RefreshStream);
                return Ok(LiveTuiAction::Continue);
            }
            "/new" => {
                self.app_event_tx.send(AppEvent::NewSession);
                return Ok(LiveTuiAction::Continue);
            }
            "/interrupt" => {
                self.app_event_tx.send(AppEvent::Interrupt);
                return Ok(LiveTuiAction::Continue);
            }
            "/resume" => {
                self.open_resume_picker()?;
                return Ok(LiveTuiAction::Continue);
            }
            _ => {}
        }

        if let Some(rest) = trimmed.strip_prefix("/approve") {
            self.app_event_tx.send(AppEvent::ApprovalDecision {
                arg: rest.trim().to_string(),
                approve: true,
            });
            return Ok(LiveTuiAction::Continue);
        }
        if let Some(rest) = trimmed.strip_prefix("/deny") {
            self.app_event_tx.send(AppEvent::ApprovalDecision {
                arg: rest.trim().to_string(),
                approve: false,
            });
            return Ok(LiveTuiAction::Continue);
        }

        if let Some(stripped) = trimmed.strip_prefix('/') {
            let mut parts = stripped.splitn(2, char::is_whitespace);
            let command = parts.next().unwrap_or_default();
            let args = parts.next().unwrap_or_default().trim().to_string();
            if let Some(cmd) = find_builtin_command(command, true, true, true, true) {
                let args = if args.is_empty() { None } else { Some(args) };
                self.dispatch_slash_command(cmd, args, text_elements)?;
                return Ok(LiveTuiAction::Continue);
            }
        }

        self.app_event_tx.send(AppEvent::StartTurn {
            text: input.to_string(),
            text_elements,
            mention_bindings,
        });
        Ok(LiveTuiAction::Continue)
    }

    fn run_user_shell_command(&mut self, command: &str) {
        if command.is_empty() {
            self.widget.ui_mut().set_status_message(Some(
                "prefix with ! to run a local shell command".to_string(),
            ));
            return;
        }
        let started = Instant::now();
        let call_id = format!("user-shell-{}", started.elapsed().as_nanos());
        let mut cell = new_active_exec_command(
            call_id.clone(),
            vec!["bash".to_string(), "-lc".to_string(), command.to_string()],
            Vec::new(),
            ExecCommandSource::UserShell,
            None,
            true,
        );
        let output = std::process::Command::new("bash")
            .arg("-lc")
            .arg(command)
            .current_dir(std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()))
            .output();
        match output {
            Ok(output) => {
                let exit_code = output.status.code().unwrap_or(1);
                let aggregated_output = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                cell.complete_call(
                    &call_id,
                    ExecCommandOutput {
                        exit_code,
                        aggregated_output: aggregated_output.clone(),
                        formatted_output: aggregated_output,
                    },
                    started.elapsed(),
                );
                self.widget.ui_mut().add_history_cell(Box::new(cell));
            }
            Err(err) => {
                cell.complete_call(
                    &call_id,
                    ExecCommandOutput {
                        exit_code: 1,
                        aggregated_output: format!("shell command failed: {err}"),
                        formatted_output: String::new(),
                    },
                    started.elapsed(),
                );
                self.widget.ui_mut().add_history_cell(Box::new(cell));
            }
        }
    }

    fn emit_status_summary(&mut self) {
        let mut config = crate::config::Config::default();
        config.cwd = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        self.status_runtime
            .refresh_from_server(&self.state, &mut config);
        let (auth_manager, plan_type) = self.status_runtime.read_account(&self.state);
        let token_info = self.status_runtime.token_info.as_ref();
        let token_usage = &self.status_runtime.total_token_usage;
        let rate_limits: Vec<crate::status::RateLimitSnapshotDisplay> = self
            .status_runtime
            .rate_limit_snapshots_by_limit_id
            .values()
            .cloned()
            .collect();
        let thread_id =
            codex_protocol::ThreadId::from_string(self.widget.ui_mut().session_id.clone())
                .ok()
                .map(Some)
                .unwrap_or(None);
        let model_name = config
            .model
            .clone()
            .or_else(|| self.status_runtime.session_model.clone())
            .unwrap_or_else(|| "gpt-5.3-codex".to_string());
        let reasoning_effort_override = Some(self.status_runtime.session_reasoning_effort);

        let cell = crate::status::new_status_output_with_rate_limits(
            &config,
            &auth_manager,
            token_info,
            token_usage,
            &thread_id,
            self.status_runtime.thread_name.clone(),
            None,
            rate_limits.as_slice(),
            plan_type,
            chrono::Local::now(),
            &model_name,
            Some("Default"),
            reasoning_effort_override,
        );
        self.widget.ui_mut().add_history_cell(Box::new(cell));
    }

    fn open_resume_picker(&mut self) -> Result<()> {
        let threads = fetch_resume_threads(&self.state)?;
        if threads.is_empty() {
            self.widget
                .ui_mut()
                .set_status_message(Some("no saved chats to resume".to_string()));
            return Ok(());
        }

        let current_session_id = self.widget.ui_mut().session_id.clone();
        let items = threads
            .into_iter()
            .filter_map(|thread| {
                let thread_id_text = thread.thread_id.clone();
                let thread_id =
                    codex_protocol::ThreadId::from_string(thread_id_text.clone()).ok()?;
                let display_name = thread
                    .thread_name
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or_else(|| thread_id_text.clone());
                let action: crate::bottom_pane::SelectionAction = Box::new(move |sender| {
                    sender.send(WidgetAppEvent::SelectAgentThread(thread_id.clone()));
                });
                Some(crate::bottom_pane::SelectionItem {
                    name: display_name,
                    description: Some(thread_id_text.clone()),
                    is_current: current_session_id == thread_id_text,
                    actions: vec![action],
                    dismiss_on_select: true,
                    ..Default::default()
                })
            })
            .collect::<Vec<_>>();

        if items.is_empty() {
            self.widget
                .ui_mut()
                .set_status_message(Some("no saved chats to resume".to_string()));
            return Ok(());
        }

        self.widget
            .ui_mut()
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                view_id: Some("resume-session-picker"),
                title: Some("Resume Chat".to_string()),
                subtitle: Some("Select a saved chat to resume.".to_string()),
                items,
                ..Default::default()
            });
        Ok(())
    }
}

impl StatusRuntime {
    fn apply_stream_events(&mut self, stream_events: &[DaemonRpcStreamEnvelope]) {
        for envelope in stream_events {
            let DaemonRpcStreamEvent::Notification(notification) = &envelope.event else {
                continue;
            };
            match notification.method.as_str() {
                "thread/name/updated" => {
                    self.thread_name = notification
                        .params
                        .get("thread")
                        .and_then(|thread| thread.get("name").or_else(|| thread.get("threadName")))
                        .or_else(|| notification.params.get("threadName"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                }
                "thread/tokenUsage/updated" => {
                    if let Some((token_info, total_usage)) =
                        parse_token_usage_updated(&notification.params)
                    {
                        self.token_info = Some(token_info);
                        self.total_token_usage = total_usage;
                    }
                }
                "account/rateLimits/updated" => {
                    if let Some(snapshot) = notification
                        .params
                        .get("rateLimits")
                        .or_else(|| notification.params.get("rate_limits"))
                    {
                        self.apply_rate_limit_snapshot(snapshot);
                    }
                }
                "codex/event/session_configured" | "session/configured" => {
                    self.session_model = notification
                        .params
                        .get("model")
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    self.session_reasoning_effort = parse_reasoning_effort(
                        notification
                            .params
                            .get("reasoningEffort")
                            .or_else(|| notification.params.get("reasoning_effort")),
                    );
                }
                _ => {}
            }
        }
    }

    fn refresh_from_server(&mut self, state: &CliState, config: &mut crate::config::Config) {
        if let Ok(response) = app_server_rpc_request(
            &state.config.app_server_endpoint,
            state.config.auth_token.as_deref(),
            "config/read",
            json!({
                "includeLayers": false,
                "cwd": config.cwd.display().to_string(),
            }),
        ) {
            if let Some(model) = response
                .result
                .get("config")
                .and_then(|cfg| cfg.get("model"))
                .and_then(Value::as_str)
            {
                config.model = Some(model.to_string());
            }
            if let Some(summary) = response
                .result
                .get("config")
                .and_then(|cfg| cfg.get("modelReasoningSummary"))
                .and_then(Value::as_str)
            {
                config.model_reasoning_summary = match summary.to_ascii_lowercase().as_str() {
                    "auto" => codex_core::config::ReasoningSummary::Auto,
                    "concise" => codex_core::config::ReasoningSummary::Concise,
                    "detailed" => codex_core::config::ReasoningSummary::Detailed,
                    _ => codex_core::config::ReasoningSummary::None,
                };
            }
            if let Some(reasoning_effort) = parse_reasoning_effort(
                response
                    .result
                    .get("config")
                    .and_then(|cfg| cfg.get("modelReasoningEffort")),
            ) {
                self.session_reasoning_effort = Some(reasoning_effort);
            }
        }

        if let Ok(response) = app_server_rpc_request(
            &state.config.app_server_endpoint,
            state.config.auth_token.as_deref(),
            "account/rateLimits/read",
            json!({}),
        ) {
            if let Some(by_limit_id) = response
                .result
                .get("rateLimitsByLimitId")
                .and_then(Value::as_object)
            {
                for snapshot in by_limit_id.values() {
                    self.apply_rate_limit_snapshot(snapshot);
                }
            } else if let Some(snapshot) = response
                .result
                .get("rateLimits")
                .or_else(|| response.result.get("rate_limits"))
            {
                self.apply_rate_limit_snapshot(snapshot);
            }
        }
    }

    fn read_account(
        &self,
        state: &CliState,
    ) -> (
        crate::AuthManager,
        Option<codex_protocol::account::PlanType>,
    ) {
        let Ok(response) = app_server_rpc_request(
            &state.config.app_server_endpoint,
            state.config.auth_token.as_deref(),
            "account/read",
            json!({
                "refreshToken": false
            }),
        ) else {
            return (crate::AuthManager::default(), None);
        };

        let Some(account) = response.result.get("account") else {
            return (crate::AuthManager::default(), None);
        };

        let account_type = account
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if account_type.eq_ignore_ascii_case("chatgpt") {
            let email = account
                .get("email")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let plan_type =
                parse_plan_type(account.get("planType").or_else(|| account.get("plan_type")));
            (crate::AuthManager::from_chatgpt_email(email), plan_type)
        } else if account_type.eq_ignore_ascii_case("apikey")
            || account_type.eq_ignore_ascii_case("api_key")
            || account_type.eq_ignore_ascii_case("apiKey")
        {
            (crate::AuthManager::from_api_key(), None)
        } else {
            (crate::AuthManager::default(), None)
        }
    }

    fn apply_rate_limit_snapshot(&mut self, snapshot: &Value) {
        let Some(parsed) = parse_rate_limit_snapshot(snapshot) else {
            return;
        };
        let limit_id = parsed
            .limit_id
            .clone()
            .unwrap_or_else(|| "codex".to_string());
        let limit_label = parsed
            .limit_name
            .clone()
            .unwrap_or_else(|| limit_id.clone());
        let display = crate::status::rate_limit_snapshot_display_for_limit(
            &parsed,
            limit_label,
            chrono::Local::now(),
        );
        self.rate_limit_snapshots_by_limit_id
            .insert(limit_id, display);
    }
}

fn parse_token_usage_updated(
    params: &Value,
) -> Option<(
    codex_core::protocol::TokenUsageInfo,
    codex_core::protocol::TokenUsage,
)> {
    let token_usage = params
        .get("tokenUsage")
        .or_else(|| params.get("token_usage"))?;
    let total = token_usage.get("total")?;
    let last = token_usage.get("last")?;

    let total_usage = parse_token_usage_breakdown(total);
    let last_usage = parse_token_usage_breakdown(last);
    let model_context_window = token_usage
        .get("modelContextWindow")
        .or_else(|| token_usage.get("model_context_window"))
        .and_then(Value::as_i64);

    Some((
        codex_core::protocol::TokenUsageInfo {
            last_token_usage: last_usage,
            model_context_window,
        },
        total_usage,
    ))
}

fn parse_token_usage_breakdown(value: &Value) -> codex_core::protocol::TokenUsage {
    codex_core::protocol::TokenUsage {
        total_tokens: value
            .get("totalTokens")
            .or_else(|| value.get("total_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        input_tokens: value
            .get("inputTokens")
            .or_else(|| value.get("input_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        cached_input_tokens: value
            .get("cachedInputTokens")
            .or_else(|| value.get("cached_input_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        output_tokens: value
            .get("outputTokens")
            .or_else(|| value.get("output_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
        reasoning_output_tokens: value
            .get("reasoningOutputTokens")
            .or_else(|| value.get("reasoning_output_tokens"))
            .and_then(Value::as_i64)
            .unwrap_or_default(),
    }
}

fn parse_rate_limit_snapshot(value: &Value) -> Option<codex_core::protocol::RateLimitSnapshot> {
    let primary = parse_rate_limit_window(value.get("primary"));
    let secondary = parse_rate_limit_window(value.get("secondary"));
    let credits = value.get("credits").and_then(|credits| {
        Some(codex_core::protocol::CreditsSnapshot {
            has_credits: credits
                .get("hasCredits")
                .or_else(|| credits.get("has_credits"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            unlimited: credits
                .get("unlimited")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            balance: credits
                .get("balance")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        })
    });

    Some(codex_core::protocol::RateLimitSnapshot {
        limit_id: value
            .get("limitId")
            .or_else(|| value.get("limit_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        limit_name: value
            .get("limitName")
            .or_else(|| value.get("limit_name"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        primary,
        secondary,
        credits,
    })
}

fn parse_rate_limit_window(value: Option<&Value>) -> Option<codex_core::protocol::RateLimitWindow> {
    let value = value?;
    let used_percent = value
        .get("usedPercent")
        .or_else(|| value.get("used_percent"))
        .and_then(Value::as_f64)
        .or_else(|| {
            value
                .get("usedPercent")
                .or_else(|| value.get("used_percent"))
                .and_then(Value::as_i64)
                .map(|v| v as f64)
        })
        .unwrap_or_default();

    Some(codex_core::protocol::RateLimitWindow {
        used_percent,
        resets_at: value
            .get("resetsAt")
            .or_else(|| value.get("resets_at"))
            .and_then(Value::as_i64),
        window_minutes: value
            .get("windowDurationMins")
            .or_else(|| value.get("windowMinutes"))
            .or_else(|| value.get("window_minutes"))
            .and_then(Value::as_i64),
    })
}

fn parse_reasoning_effort(
    value: Option<&Value>,
) -> Option<codex_protocol::openai_models::ReasoningEffort> {
    let raw = value.and_then(Value::as_str)?.to_ascii_lowercase();
    match raw.as_str() {
        "none" => Some(codex_protocol::openai_models::ReasoningEffort::None),
        "minimal" => Some(codex_protocol::openai_models::ReasoningEffort::Minimal),
        "low" => Some(codex_protocol::openai_models::ReasoningEffort::Low),
        "medium" => Some(codex_protocol::openai_models::ReasoningEffort::Medium),
        "high" => Some(codex_protocol::openai_models::ReasoningEffort::High),
        "xhigh" | "x_high" | "x-high" => {
            Some(codex_protocol::openai_models::ReasoningEffort::XHigh)
        }
        _ => None,
    }
}

fn parse_plan_type(value: Option<&Value>) -> Option<codex_protocol::account::PlanType> {
    let raw = value.and_then(Value::as_str)?.to_ascii_lowercase();
    match raw.as_str() {
        "free" => Some(codex_protocol::account::PlanType::Free),
        "go" => Some(codex_protocol::account::PlanType::Go),
        "plus" => Some(codex_protocol::account::PlanType::Plus),
        "pro" => Some(codex_protocol::account::PlanType::Pro),
        "team" => Some(codex_protocol::account::PlanType::Team),
        "business" => Some(codex_protocol::account::PlanType::Business),
        "enterprise" => Some(codex_protocol::account::PlanType::Enterprise),
        _ => None,
    }
}

fn resolve_initial_thread_id(
    state: &CliState,
    explicit_thread_id: Option<String>,
    cached_thread_id: Option<String>,
) -> Result<(String, String)> {
    if let Some(thread_id) = explicit_thread_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        let resumed = resume_thread(state, &thread_id).with_context(|| {
            format!("resume explicit thread id before tui startup: {thread_id}")
        })?;
        let resolved = resumed.unwrap_or(thread_id);
        return Ok((resolved, "connected to app-server websocket".to_string()));
    }

    if let Some(thread_id) = cached_thread_id
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        match resume_thread(state, &thread_id) {
            Ok(Some(resumed_thread_id)) => {
                return Ok((
                    resumed_thread_id,
                    "connected to app-server websocket".to_string(),
                ));
            }
            Ok(None) => {}
            Err(_) => {}
        }

        let new_thread_id = start_thread(state)?;
        return Ok((
            new_thread_id,
            "cached thread was unavailable; started a new thread".to_string(),
        ));
    }

    let thread_id = start_thread(state)?;
    Ok((thread_id, "connected to app-server websocket".to_string()))
}

// ---------------------------------------------------------------------------
// Public entry points — backward compatible with existing callers
// ---------------------------------------------------------------------------

pub fn handle_tui(args: TuiArgs, state: &mut CliState) -> Result<CommandOutput> {
    let mut app = App::new(args, state.clone())?;

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        *state = app.into_state();
        return Ok(CommandOutput::Json(json!({
            "ok": true,
            "action": "tui",
            "thread_id": state.last_thread_id,
            "app_server_endpoint": state.config.app_server_endpoint,
        })));
    }

    let exit_info = app.run()?;
    *state = app.into_state();
    Ok(CommandOutput::Text(format!(
        "thread={} detached",
        exit_info.thread_id.as_deref().unwrap_or("unknown")
    )))
}

pub fn handle_attach_tui_interactive(
    session_id: String,
    initial_events: Vec<DaemonStreamEnvelope>,
    state: &mut CliState,
) -> Result<CommandOutput> {
    let mut app = App::attach(session_id, initial_events, state.clone())?;
    let exit_info = app.run()?;
    *state = app.into_state();
    Ok(CommandOutput::Text(format!(
        "session={} detached",
        exit_info.thread_id.as_deref().unwrap_or("unknown")
    )))
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
    respond_to_approval(state, request.request_id, &request.method, approve)?;
    ui.set_status_message(Some(format!(
        "{} request {}",
        if approve { "approved" } else { "denied" },
        approval_key
    )));
    Ok(())
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn fetch_skills_for_cwd(state: &CliState) -> Result<Vec<codex_core::skills::model::SkillMetadata>> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "skills/list",
        json!({
            "cwds": [cwd],
            "forceReload": false
        }),
    )?;
    let mut out = Vec::new();
    let data = response
        .result
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in data {
        let Some(skills) = entry.get("skills").and_then(Value::as_array) else {
            continue;
        };
        for skill in skills {
            let Some(name) = skill.get("name").and_then(Value::as_str) else {
                continue;
            };
            let description = skill
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let path = skill
                .get("path")
                .and_then(Value::as_str)
                .map(PathBuf::from)
                .unwrap_or_default();
            out.push(codex_core::skills::model::SkillMetadata {
                name: name.to_string(),
                description,
                short_description: skill
                    .get("shortDescription")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                interface: None,
                path,
                scope: codex_core::protocol::SkillScope::User,
            });
        }
    }
    Ok(out)
}

fn fetch_connectors(state: &CliState) -> Result<crate::app_event::ConnectorsSnapshot> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "app/list",
        json!({}),
    )?;
    let connectors = response
        .result
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|app| {
            Some(codex_chatgpt::connectors::AppInfo {
                id: app.get("id")?.as_str()?.to_string(),
                name: app.get("name")?.as_str()?.to_string(),
                description: app
                    .get("description")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                logo_url: app
                    .get("logoUrl")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                logo_url_dark: app
                    .get("logoUrlDark")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                distribution_channel: app
                    .get("distributionChannel")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                install_url: app
                    .get("installUrl")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                is_accessible: app
                    .get("isAccessible")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                is_enabled: app
                    .get("isEnabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect();
    Ok(crate::app_event::ConnectorsSnapshot { connectors })
}

fn fetch_rollout_path(state: &CliState, thread_id: &str) -> Result<Option<String>> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/read",
        json!({
            "threadId": thread_id,
            "includeTurns": false,
        }),
    )?;
    Ok(response
        .result
        .get("thread")
        .and_then(|thread| thread.get("path"))
        .and_then(Value::as_str)
        .map(ToString::to_string))
}

struct ResumeThreadEntry {
    thread_id: String,
    thread_name: Option<String>,
}

fn fetch_resume_threads(state: &CliState) -> Result<Vec<ResumeThreadEntry>> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/list",
        json!({
            "sortKey": "updated_at",
            "limit": 50,
            "archived": false,
        }),
    )?;

    let Some(threads) = response.result.get("data").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };

    Ok(threads
        .iter()
        .filter_map(|thread| {
            let thread_id = thread.get("id").and_then(Value::as_str)?.to_string();
            let thread_name = thread
                .get("threadName")
                .or_else(|| thread.get("name"))
                .and_then(Value::as_str)
                .map(ToString::to_string);
            Some(ResumeThreadEntry {
                thread_id,
                thread_name,
            })
        })
        .collect())
}

fn run_diff_now() -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        return "failed to initialize runtime for /diff".to_string();
    };
    match runtime.block_on(get_git_diff()) {
        Ok((is_git_repo, text)) => {
            if is_git_repo {
                text
            } else {
                "`/diff` — _not inside a git repository_".to_string()
            }
        }
        Err(err) => format!("Failed to compute diff: {err}"),
    }
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

pub(crate) fn align_left_right(left: &str, right: &str, width: usize) -> String {
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

#[cfg(test)]
mod tests {
    use super::App;
    use super::AppEventSender;
    use super::CliState;
    use super::LiveTuiAction;
    use crate::app_event_sender::AppEventSender as WidgetAppEventSender;
    use crate::bottom_pane::MentionBinding;
    use crate::chatwidget::ChatWidget;
    use crate::file_search::FileSearchManager;
    use crossterm::event::KeyCode;
    use crossterm::event::KeyEvent;
    use crossterm::event::KeyModifiers;

    fn make_test_app() -> App {
        let widget = ChatWidget::new("sess_test".to_string());
        let state = CliState::default();
        let (tx, rx) = std::sync::mpsc::channel();
        let (widget_tx, widget_rx) = tokio::sync::mpsc::unbounded_channel();
        let widget_sender = WidgetAppEventSender::new(widget_tx);
        let file_search = FileSearchManager::new(std::env::temp_dir(), widget_sender);

        App {
            widget,
            state,
            thread_id: "sess_test".to_string(),
            app_event_tx: AppEventSender::new(tx),
            app_event_rx: rx,
            widget_event_rx: widget_rx,
            file_search,
        }
    }

    #[test]
    fn handle_submit_status_sets_visible_status_message() {
        let mut app = make_test_app();
        let action = app
            .handle_submit("/status", Vec::new(), Vec::<MentionBinding>::new())
            .expect("status submit should not fail");
        assert!(matches!(action, LiveTuiAction::Continue));
        let status = app
            .widget
            .ui_mut()
            .status_message
            .clone()
            .expect("status message should be set");
        assert!(status.contains("thread=sess_test"), "status={status}");
    }

    #[test]
    fn handle_key_event_status_command_dispatches_from_composer() {
        let mut app = make_test_app();
        app.widget.ui_mut().bottom_pane_insert_str("/status");
        let enter = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = app
            .handle_key_event(enter)
            .expect("handle key event should succeed");
        assert!(matches!(action, LiveTuiAction::Continue));
        let status = app
            .widget
            .ui_mut()
            .status_message
            .clone()
            .expect("status message should be set");
        assert!(status.contains("thread=sess_test"), "status={status}");
    }

    use super::LiveAttachTui;

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
