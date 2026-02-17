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
pub(super) use crate::core_compat::fork_thread;
pub(super) use crate::core_compat::interrupt_turn;
pub(super) use crate::core_compat::respond_to_approval;
pub(super) use crate::core_compat::resume_thread;
pub(super) use crate::core_compat::set_thread_name;
pub(super) use crate::core_compat::start_thread;
pub(super) use crate::core_compat::start_turn_with_elements_and_collaboration;
pub(super) use crate::core_compat::stream_events;
use crate::exec_cell::CommandOutput as ExecCommandOutput;
use crate::exec_cell::new_active_exec_command;
use crate::file_search::FileSearchManager;
use crate::get_git_diff::get_git_diff;
use crate::history_cell::SessionHeaderHistoryCell;
use crate::slash_command::SlashCommand;
use crate::slash_commands::find_builtin_command;
use crate::version::CODEX_CLI_VERSION;
use codex_core::protocol::ExecCommandSource;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

const COMMIT_ANIMATION_TICK: Duration = crate::tui::TARGET_FRAME_INTERVAL;

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
    /// Widget event sender (used for app-driven widget events like commit ticks).
    widget_event_tx: WidgetAppEventSender,
    /// Upstream-style @file search manager.
    file_search: FileSearchManager,
    /// Runtime status data used by `/status` card rendering.
    status_runtime: StatusRuntime,
    /// One-shot guard used while switching threads.
    pending_thread_switch_clear: bool,
    /// Controls the animation thread that sends commit tick events.
    commit_anim_running: Arc<AtomicBool>,
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
        if !widget.ui_mut().has_history_cells() {
            let model = status_runtime
                .session_model
                .clone()
                .unwrap_or_else(|| "gpt-5.3-codex".to_string());
            widget
                .ui_mut()
                .add_history_cell(Box::new(SessionHeaderHistoryCell::new(
                    model,
                    status_runtime.session_reasoning_effort,
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
                    CODEX_CLI_VERSION,
                )));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let (widget_tx, widget_rx) = tokio::sync::mpsc::unbounded_channel();
        let widget_sender = WidgetAppEventSender::new(widget_tx);
        let search_dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let file_search = FileSearchManager::new(search_dir, widget_sender.clone());
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
            widget_event_tx: widget_sender.clone(),
            file_search,
            status_runtime,
            pending_thread_switch_clear: false,
            commit_anim_running: Arc::new(AtomicBool::new(false)),
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
        if !widget.ui_mut().has_history_cells() {
            widget
                .ui_mut()
                .add_history_cell(Box::new(SessionHeaderHistoryCell::new(
                    "gpt-5.3-codex".to_string(),
                    None,
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
                    CODEX_CLI_VERSION,
                )));
        }
        state.last_thread_id = Some(session_id.clone());
        let (tx, rx) = std::sync::mpsc::channel();
        let (widget_tx, widget_rx) = tokio::sync::mpsc::unbounded_channel();
        let widget_sender = WidgetAppEventSender::new(widget_tx);
        let search_dir = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let file_search = FileSearchManager::new(search_dir, widget_sender.clone());
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
            widget_event_tx: widget_sender.clone(),
            file_search,
            status_runtime,
            pending_thread_switch_clear: false,
            commit_anim_running: Arc::new(AtomicBool::new(false)),
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
        let _ = tui.enter_alt_screen();
        let loop_result = self.event_loop(&mut tui);
        let _ = tui.leave_alt_screen();
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
            if self.pending_thread_switch_clear {
                tui.terminal.clear_scrollback()?;
                tui.terminal.clear()?;
                self.pending_thread_switch_clear = false;
            }
            let _ = self.widget.ui_mut().flush_bottom_pane_paste_burst_if_due();
            let in_paste_burst = self.widget.ui_mut().bottom_pane_is_in_paste_burst();
            let _ = self.widget.ui_mut().commit_assistant_stream_tick();
            let history_width = tui.terminal.size()?.width;
            let new_history_lines = self
                .widget
                .ui_mut()
                .take_new_history_lines_for_scrollback(history_width);
            if !new_history_lines.is_empty() {
                tui.insert_history_lines(new_history_lines);
            }
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
        let previous_thread = self.widget.ui_mut().session_id.clone();
        let changed = previous_thread != thread_id;

        if changed {
            self.widget
                .ui_mut()
                .reset_for_thread_switch(thread_id.clone());
            self.status_runtime = StatusRuntime::default();
            self.pending_thread_switch_clear = true;
            if let Ok(events) = stream_events(&self.state, 0)
                && !events.is_empty()
            {
                self.status_runtime.apply_stream_events(&events);
                self.widget.ui_mut().apply_rpc_stream_events(&events);
            }
            let model = self
                .status_runtime
                .session_model
                .clone()
                .unwrap_or_else(|| "gpt-5.3-codex".to_string());
            self.widget
                .ui_mut()
                .add_history_cell(Box::new(SessionHeaderHistoryCell::new(
                    model,
                    self.status_runtime.session_reasoning_effort,
                    std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
                    CODEX_CLI_VERSION,
                )));
        }

        if announce_switch && changed {
            self.widget
                .ui_mut()
                .push_line(&format!("[thread switched] {thread_id}"));
        }
        self.widget
            .ui_mut()
            .set_status_message(Some(status_message.to_string()));
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
                let selected_mask = self.widget.ui_mut().active_collaboration_mask();
                let session_model = self
                    .status_runtime
                    .session_model
                    .clone()
                    .or_else(|| fetch_current_model_from_config(&self.state));
                let session_effort = self.status_runtime.session_reasoning_effort;
                let collaboration_mode =
                    collaboration_mode_from_mask(selected_mask, session_model, session_effort);
                let ui = self.widget.ui_mut();
                ui.push_user_prompt(&text, text_elements.clone());
                if let Some(turn_id) = start_turn_with_elements_and_collaboration(
                    &self.state,
                    &ui.session_id,
                    &text,
                    text_elements,
                    mention_bindings,
                    collaboration_mode,
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
        let mut queued_external_editor_launch = false;
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
                KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    if !ui.shortcuts_overlay_visible() && ui.bottom_pane_no_modal_or_popup_active()
                    {
                        queued_external_editor_launch = true;
                    }
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
            self.handle_widget_app_event(event)?;
        }

        while let Ok(event) = self.widget_event_rx.try_recv() {
            self.handle_widget_app_event(event)?;
        }

        if queued_external_editor_launch {
            self.handle_widget_app_event(WidgetAppEvent::LaunchExternalEditor)?;
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

    fn handle_widget_app_event(&mut self, event: WidgetAppEvent) -> Result<()> {
        match event {
            WidgetAppEvent::CodexEvent(event) => {
                self.widget.ui_mut().apply_codex_event(event);
            }
            WidgetAppEvent::FatalExitRequest(message) => {
                self.widget
                    .ui_mut()
                    .add_history_cell(Box::new(crate::history_cell::new_error_event(message)));
                self.app_event_tx.send(AppEvent::Exit(ExitMode::Immediate));
            }
            WidgetAppEvent::CodexOp(op) => self.handle_widget_op(op)?,
            WidgetAppEvent::OpenAgentPicker => {
                self.open_agent_picker()?;
            }
            WidgetAppEvent::InsertHistoryCell(cell) => {
                self.widget.ui_mut().add_history_cell(cell);
            }
            WidgetAppEvent::ApplyThreadRollback { num_turns } => {
                self.widget
                    .ui_mut()
                    .apply_non_pending_thread_rollback(num_turns);
            }
            WidgetAppEvent::StartCommitAnimation => {
                if self
                    .commit_anim_running
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    let tx = self.widget_event_tx.clone();
                    let running = self.commit_anim_running.clone();
                    thread::spawn(move || {
                        while running.load(Ordering::Relaxed) {
                            thread::sleep(COMMIT_ANIMATION_TICK);
                            tx.send(WidgetAppEvent::CommitTick);
                        }
                    });
                }
            }
            WidgetAppEvent::StopCommitAnimation => {
                self.commit_anim_running.store(false, Ordering::Release);
            }
            WidgetAppEvent::CommitTick => {
                self.widget.ui_mut().on_commit_tick();
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
            WidgetAppEvent::OpenApprovalsPopup | WidgetAppEvent::OpenPermissionsPopup => {
                self.open_permissions_picker()?;
            }
            WidgetAppEvent::OpenSkillsList => {
                self.widget.ui_mut().bottom_pane_insert_str("$");
            }
            WidgetAppEvent::OpenManageSkillsPopup => {
                self.open_manage_skills_popup()?;
            }
            WidgetAppEvent::OpenReviewBranchPicker(cwd) => {
                self.open_review_branch_picker(&cwd);
            }
            WidgetAppEvent::OpenReviewCommitPicker(cwd) => {
                self.open_review_commit_picker(&cwd);
            }
            WidgetAppEvent::OpenReviewCustomPrompt => {
                self.widget.ui_mut().show_review_custom_prompt();
            }
            WidgetAppEvent::StartReviewUncommitted => {
                self.start_review_uncommitted()?;
            }
            WidgetAppEvent::StartReviewBaseBranch { branch } => {
                self.start_review_base_branch(&branch)?;
            }
            WidgetAppEvent::StartReviewCommit { sha, title } => {
                self.start_review_commit(&sha, title.as_deref())?;
            }
            WidgetAppEvent::StartReviewCustomInstructions(instructions) => {
                self.start_review_custom(&instructions)?;
            }
            WidgetAppEvent::ForkCurrentSession => {
                let active_thread_id = self.widget.ui_mut().session_id.clone();
                if let Some(forked_thread_id) = fork_thread(&self.state, &active_thread_id)? {
                    self.switch_to_thread(forked_thread_id, "thread forked", true);
                } else {
                    self.widget
                        .ui_mut()
                        .set_status_message(Some("fork returned no thread id".to_string()));
                }
            }
            WidgetAppEvent::SelectAgentThread(thread_id) => {
                let selected_thread_id = thread_id.to_string();
                if let Some(resumed_thread_id) = resume_thread(&self.state, &selected_thread_id)? {
                    self.switch_to_thread(resumed_thread_id, "thread resumed", false);
                } else {
                    self.widget
                        .ui_mut()
                        .set_status_message(Some("resume returned no thread id".to_string()));
                }
            }
            WidgetAppEvent::UpdateModel(model) => {
                self.apply_model_selection(model)?;
            }
            WidgetAppEvent::UpdateReasoningEffort(effort) => {
                self.apply_reasoning_effort_selection(effort)?;
            }
            WidgetAppEvent::UpdateAskForApprovalPolicy(policy) => {
                self.apply_approval_policy_selection(policy)?;
            }
            WidgetAppEvent::UpdateSandboxPolicy(policy) => {
                self.apply_sandbox_policy_selection(policy)?;
            }
            WidgetAppEvent::UpdatePersonality(personality) => {
                self.apply_personality_selection(personality)?;
            }
            WidgetAppEvent::UpdateCollaborationMode(mask) => {
                self.widget.ui_mut().set_collaboration_mask(mask);
                self.widget
                    .ui_mut()
                    .set_status_message(Some("collaboration mode updated".to_string()));
            }
            WidgetAppEvent::UpdateFeatureFlags { updates } => {
                self.apply_feature_flags(updates)?;
            }
            WidgetAppEvent::SetSkillEnabled { path, enabled } => {
                self.apply_skill_enabled(path, enabled)?;
            }
            WidgetAppEvent::SetAppEnabled { id, enabled } => {
                self.apply_app_enabled(id, enabled)?;
            }
            WidgetAppEvent::ManageSkillsClosed => {
                self.widget
                    .ui_mut()
                    .set_status_message(Some("skill settings updated".to_string()));
            }
            WidgetAppEvent::OpenFeedbackConsent { category } => {
                let rollout_path = self.widget.ui_mut().rollout_path();
                self.widget
                    .ui_mut()
                    .open_feedback_consent(category, rollout_path);
            }
            WidgetAppEvent::OpenFeedbackNote {
                category,
                include_logs,
            } => {
                let rollout_path = self.widget.ui_mut().rollout_path();
                self.widget
                    .ui_mut()
                    .open_feedback_note(category, include_logs, rollout_path);
            }
            WidgetAppEvent::OpenReasoningPopup { model } => {
                self.widget.ui_mut().open_reasoning_popup(model);
            }
            WidgetAppEvent::OpenAllModelsPopup { models } => {
                self.widget.ui_mut().open_all_models_popup(models);
            }
            WidgetAppEvent::OpenFullAccessConfirmation {
                preset,
                return_to_permissions,
            } => {
                self.widget
                    .ui_mut()
                    .open_full_access_confirmation(preset, return_to_permissions);
            }
            WidgetAppEvent::SubmitUserMessageWithMode {
                text,
                collaboration_mode,
            } => {
                let session_model = self
                    .status_runtime
                    .session_model
                    .clone()
                    .or_else(|| fetch_current_model_from_config(&self.state));
                let session_effort = self.status_runtime.session_reasoning_effort;
                let collaboration_mode = collaboration_mode_from_mask(
                    Some(collaboration_mode),
                    session_model,
                    session_effort,
                );
                let ui = self.widget.ui_mut();
                ui.push_user_prompt(&text, Vec::new());
                if let Some(turn_id) = start_turn_with_elements_and_collaboration(
                    &self.state,
                    &ui.session_id,
                    &text,
                    Vec::new(),
                    Vec::new(),
                    collaboration_mode,
                )? {
                    ui.active_turn_id = Some(turn_id);
                }
                ui.set_status_message(Some("waiting for response...".to_string()));
            }
            WidgetAppEvent::LaunchExternalEditor => {
                self.launch_external_editor()?;
            }
            WidgetAppEvent::StatusLineBranchUpdated { cwd: _, branch } => {
                self.widget.ui_mut().set_status_message(Some(format!(
                    "status line branch updated: {}",
                    branch.unwrap_or_else(|| "(none)".to_string())
                )));
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
            WidgetAppEvent::FullScreenApprovalRequest(request) => {
                self.widget
                    .ui_mut()
                    .push_fullscreen_approval_request(request);
            }
            _ => {}
        }
        Ok(())
    }

    fn dispatch_slash_command(
        &mut self,
        cmd: SlashCommand,
        args: Option<String>,
        _text_elements: Vec<codex_protocol::user_input::TextElement>,
    ) -> Result<()> {
        if !cmd.available_during_task() && self.widget.ui_mut().bottom_pane_is_task_running() {
            self.widget
                .ui_mut()
                .add_history_cell(Box::new(crate::history_cell::new_error_event(format!(
                    "'/{}' is disabled while a task is in progress.",
                    cmd.command()
                ))));
            self.widget.ui_mut().drain_pending_submission_state();
            return Ok(());
        }

        let arg = args.unwrap_or_default();
        match cmd {
            SlashCommand::Model => self.open_model_picker()?,
            SlashCommand::New => self.app_event_tx.send(AppEvent::NewSession),
            SlashCommand::Resume => self.open_resume_picker()?,
            SlashCommand::Status => self.emit_status_summary(),
            SlashCommand::Statusline => self.widget.ui_mut().open_status_line_setup(None),
            SlashCommand::DebugConfig => self
                .widget
                .ui_mut()
                .push_line("[info] /debug-config is not yet ported in app-server tui"),
            SlashCommand::Fork => {
                let active_thread_id = self.widget.ui_mut().session_id.clone();
                if let Some(forked_thread_id) = fork_thread(&self.state, &active_thread_id)? {
                    self.switch_to_thread(forked_thread_id, "thread forked", true);
                } else {
                    self.widget
                        .ui_mut()
                        .set_status_message(Some("fork returned no thread id".to_string()));
                }
            }
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
                self.open_permissions_picker()?
            }
            SlashCommand::Review => {
                if arg.trim().is_empty() {
                    self.widget.ui_mut().open_review_popup();
                } else {
                    self.start_review_custom(arg.trim())?;
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
                self.widget.ui_mut().add_history_cell(Box::new(
                    crate::history_cell::new_error_event(
                        "Usage: /sandbox-add-read-dir <absolute-directory-path>".to_string(),
                    ),
                ));
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
            SlashCommand::Skills => self.widget.ui_mut().open_skills_menu(),
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
                let thread_id = self.widget.ui_mut().session_id.clone();
                self.widget
                    .ui_mut()
                    .push_line("Stopping all background terminals.");
                match clean_background_terminals(&self.state, &thread_id) {
                    Ok(()) => self
                        .widget
                        .ui_mut()
                        .push_line("Stopped all background terminals."),
                    Err(err) => self
                        .widget
                        .ui_mut()
                        .push_line(&format!("Failed to stop background terminals: {err}")),
                }
            }
            SlashCommand::Mcp => match fetch_mcp_tools_output(&self.state) {
                Ok(cell) => self.widget.ui_mut().add_history_cell(Box::new(cell)),
                Err(err) => self
                    .widget
                    .ui_mut()
                    .push_line(&format!("Failed to load MCP tools: {err}")),
            },
            SlashCommand::Rollout => {
                if let Some(path) = self.widget.ui_mut().rollout_path() {
                    self.widget
                        .ui_mut()
                        .push_line(&format!("Current rollout path: {}", path.display()));
                } else {
                    self.widget
                        .ui_mut()
                        .push_line("Rollout path is not available yet.");
                }
            }
            SlashCommand::Feedback => self.widget.ui_mut().open_feedback_selection(),
            SlashCommand::Compact => self.start_compaction()?,
            SlashCommand::Plan => {
                if !self.widget.ui_mut().collaboration_modes_enabled() {
                    self.widget
                        .ui_mut()
                        .push_line("Collaboration modes are disabled.");
                    return Ok(());
                }
                let modes = fetch_collaboration_modes(&self.state)?;
                if let Some(plan_mask) = modes
                    .iter()
                    .find(|mask| {
                        matches!(
                            mask.mode,
                            Some(codex_protocol::config_types::ModeKind::Plan)
                        )
                    })
                    .cloned()
                {
                    self.widget.ui_mut().set_collaboration_mask(plan_mask);
                    if !arg.trim().is_empty() {
                        self.app_event_tx.send(AppEvent::StartTurn {
                            text: arg.trim().to_string(),
                            text_elements: Vec::new(),
                            mention_bindings: Vec::new(),
                        });
                    }
                } else {
                    self.widget
                        .ui_mut()
                        .push_line("Plan mode unavailable right now.");
                }
            }
            SlashCommand::Collab => {
                if !self.widget.ui_mut().collaboration_modes_enabled() {
                    self.widget
                        .ui_mut()
                        .push_line("Collaboration modes are disabled.");
                    return Ok(());
                }
                let modes = fetch_collaboration_modes(&self.state)?;
                self.widget.ui_mut().open_collaboration_modes_popup(modes);
            }
            SlashCommand::Agent => self.open_agent_picker()?,
            SlashCommand::Experimental => {
                let features = fetch_experimental_features(&self.state)?;
                self.widget.ui_mut().open_experimental_popup(features);
            }
            SlashCommand::Personality => self.open_personality_picker(),
            SlashCommand::TestApproval => self
                .widget
                .ui_mut()
                .push_line("/test-approval is not available in app-server TUI."),
            SlashCommand::MemoryDrop => {
                self.handle_widget_op(codex_core::protocol::Op::DropMemories)?
            }
            SlashCommand::MemoryUpdate => {
                self.handle_widget_op(codex_core::protocol::Op::UpdateMemories)?
            }
            SlashCommand::ElevateSandbox => self
                .widget
                .ui_mut()
                .push_line("/setup-default-sandbox is not available on this runtime."),
        }
        Ok(())
    }

    fn handle_widget_op(&mut self, op: codex_core::protocol::Op) -> Result<()> {
        match op {
            codex_core::protocol::Op::Interrupt => {
                self.app_event_tx.send(AppEvent::Interrupt);
            }
            codex_core::protocol::Op::Compact => {
                self.start_compaction()?;
            }
            codex_core::protocol::Op::ExecApproval { id, decision, .. } => {
                let Some(request) = self.widget.ui_mut().take_pending_approval_for_operation(
                    &id,
                    &[
                        "item/commandExecution/requestApproval",
                        "execCommandApproval",
                    ],
                ) else {
                    self.widget
                        .ui_mut()
                        .push_line(&format!("No pending exec approval found for {id}."));
                    return Ok(());
                };
                let approve = matches!(
                    decision,
                    codex_core::protocol::ReviewDecision::Approved
                        | codex_core::protocol::ReviewDecision::ApprovedForSession
                        | codex_core::protocol::ReviewDecision::ApprovedExecpolicyAmendment { .. }
                );
                respond_to_approval(&self.state, request.request_id, &request.method, approve)?;
            }
            codex_core::protocol::Op::PatchApproval { id, decision } => {
                let Some(request) = self.widget.ui_mut().take_pending_approval_for_operation(
                    &id,
                    &["item/fileChange/requestApproval", "applyPatchApproval"],
                ) else {
                    self.widget
                        .ui_mut()
                        .push_line(&format!("No pending patch approval found for {id}."));
                    return Ok(());
                };
                let approve = matches!(
                    decision,
                    codex_core::protocol::ReviewDecision::Approved
                        | codex_core::protocol::ReviewDecision::ApprovedForSession
                        | codex_core::protocol::ReviewDecision::ApprovedExecpolicyAmendment { .. }
                );
                respond_to_approval(&self.state, request.request_id, &request.method, approve)?;
            }
            codex_core::protocol::Op::ResolveElicitation {
                server_name: _,
                request_id: _,
                decision,
            } => {
                let Some((key, request)) = self
                    .widget
                    .ui_mut()
                    .pending_approvals
                    .iter()
                    .find(|(_, request)| {
                        request.method == "item/tool/elicit"
                            || request.method == "item/mcpToolCall/requestApproval"
                    })
                    .map(|(key, request)| (key.clone(), request.clone()))
                else {
                    self.widget
                        .ui_mut()
                        .push_line("No pending MCP elicitation request found.");
                    return Ok(());
                };
                self.widget.ui_mut().pending_approvals.remove(&key);
                let decision_text = match decision {
                    codex_core::protocol::ElicitationAction::Accept => "accept",
                    codex_core::protocol::ElicitationAction::Decline => "decline",
                    codex_core::protocol::ElicitationAction::Cancel => "cancel",
                };
                app_server_rpc_respond(
                    &self.state.config.app_server_endpoint,
                    self.state.config.auth_token.as_deref(),
                    request.request_id,
                    json!({ "decision": decision_text }),
                )?;
            }
            codex_core::protocol::Op::UserInputAnswer { id, response } => {
                let Some(request) = self
                    .widget
                    .ui_mut()
                    .take_pending_request_user_input_for_turn(&id)
                else {
                    self.widget
                        .ui_mut()
                        .push_line("No pending request_user_input request found.");
                    return Ok(());
                };
                app_server_rpc_respond(
                    &self.state.config.app_server_endpoint,
                    self.state.config.auth_token.as_deref(),
                    request.request_id,
                    serde_json::to_value(response)?,
                )?;
            }
            codex_core::protocol::Op::DropMemories | codex_core::protocol::Op::UpdateMemories => {
                self.widget
                    .ui_mut()
                    .push_line("Memory debug commands are not available in app-server TUI.");
            }
            _ => {
                self.widget
                    .ui_mut()
                    .push_line("This operation is not available in app-server TUI.");
            }
        }
        Ok(())
    }

    fn open_personality_picker(&mut self) {
        use codex_protocol::config_types::Personality;

        let items = [Personality::Friendly, Personality::Pragmatic]
            .into_iter()
            .map(|personality| {
                let action: crate::bottom_pane::SelectionAction = Box::new(move |sender| {
                    sender.send(WidgetAppEvent::UpdatePersonality(personality));
                });
                crate::bottom_pane::SelectionItem {
                    name: personality_label(personality).to_string(),
                    description: Some(personality_description(personality).to_string()),
                    actions: vec![action],
                    dismiss_on_select: true,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.widget
            .ui_mut()
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Select Personality".to_string()),
                subtitle: Some("Choose a communication style for Codex.".to_string()),
                items,
                ..Default::default()
            });
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

    fn open_agent_picker(&mut self) -> Result<()> {
        let threads = fetch_resume_threads(&self.state)?;
        if threads.is_empty() {
            self.widget
                .ui_mut()
                .add_history_cell(Box::new(crate::history_cell::new_info_event(
                    "No agents available yet.".to_string(),
                    None,
                )));
            return Ok(());
        }

        let current_session_id = self.widget.ui_mut().session_id.clone();
        let mut initial_selected_idx: Option<usize> = None;
        let items = threads
            .into_iter()
            .enumerate()
            .filter_map(|(idx, thread)| {
                let thread_id_text = thread.thread_id.clone();
                let thread_id =
                    codex_protocol::ThreadId::from_string(thread_id_text.clone()).ok()?;
                if current_session_id == thread_id_text {
                    initial_selected_idx = Some(idx);
                }
                let action: crate::bottom_pane::SelectionAction = Box::new(move |sender| {
                    sender.send(WidgetAppEvent::SelectAgentThread(thread_id.clone()));
                });
                Some(crate::bottom_pane::SelectionItem {
                    name: thread_id_text.clone(),
                    is_current: current_session_id == thread_id_text,
                    actions: vec![action],
                    dismiss_on_select: true,
                    search_value: Some(thread_id_text),
                    ..Default::default()
                })
            })
            .collect::<Vec<_>>();

        if items.is_empty() {
            self.widget
                .ui_mut()
                .add_history_cell(Box::new(crate::history_cell::new_info_event(
                    "No agents available yet.".to_string(),
                    None,
                )));
            return Ok(());
        }

        self.widget
            .ui_mut()
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Agents".to_string()),
                subtitle: Some("Select a thread to focus".to_string()),
                items,
                initial_selected_idx,
                is_searchable: true,
                ..Default::default()
            });
        Ok(())
    }

    fn open_model_picker(&mut self) -> Result<()> {
        let models = fetch_model_picker_entries(&self.state)?;
        if models.is_empty() {
            self.widget
                .ui_mut()
                .set_status_message(Some("no models available".to_string()));
            return Ok(());
        }

        let current_model = fetch_current_model_from_config(&self.state)
            .or_else(|| self.status_runtime.session_model.clone());

        let items = models
            .into_iter()
            .map(|entry| {
                let slug = entry.slug.clone();
                let action: crate::bottom_pane::SelectionAction = Box::new(move |sender| {
                    sender.send(WidgetAppEvent::UpdateModel(slug.clone()));
                });
                crate::bottom_pane::SelectionItem {
                    name: entry.display_name,
                    description: Some(entry.description),
                    is_current: current_model.as_deref() == Some(entry.slug.as_str()),
                    actions: vec![action],
                    dismiss_on_select: true,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.widget
            .ui_mut()
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                view_id: Some("model-picker"),
                title: Some("Select Model".to_string()),
                subtitle: Some("Choose the model Codex should use.".to_string()),
                items,
                ..Default::default()
            });
        Ok(())
    }

    fn open_manage_skills_popup(&mut self) -> Result<()> {
        let entries = fetch_skills_toggle_entries(&self.state)?;
        let mapped = entries
            .into_iter()
            .map(|entry| crate::chatwidget::SkillsToggleEntry {
                path: entry.path,
                name: entry.name,
                description: entry.description,
                enabled: entry.enabled,
            })
            .collect::<Vec<_>>();
        self.widget.ui_mut().open_manage_skills_popup(mapped);
        Ok(())
    }

    fn apply_model_selection(&mut self, model: String) -> Result<()> {
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": "model",
                "value": model,
                "mergeStrategy": "replace",
            }),
        )?;
        self.status_runtime.session_model = Some(model.clone());
        self.widget
            .ui_mut()
            .set_status_message(Some(format!("model updated to {model}")));
        Ok(())
    }

    fn apply_reasoning_effort_selection(
        &mut self,
        effort: Option<codex_protocol::openai_models::ReasoningEffort>,
    ) -> Result<()> {
        let effort_value = effort.map(|v| v.to_string());
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": "modelReasoningEffort",
                "value": effort_value,
                "mergeStrategy": "replace",
            }),
        )?;
        self.status_runtime.session_reasoning_effort = effort;
        self.widget.ui_mut().set_status_message(Some(match effort {
            Some(level) => format!("reasoning effort updated to {level}"),
            None => "reasoning effort reset to default".to_string(),
        }));
        Ok(())
    }

    fn launch_external_editor(&mut self) -> Result<()> {
        if !self.widget.ui_mut().bottom_pane_no_modal_or_popup_active() {
            self.widget
                .ui_mut()
                .set_status_message(Some("close active popup before editing".to_string()));
            return Ok(());
        }
        let seed = self
            .widget
            .ui_mut()
            .bottom_pane_composer_text_with_pending();
        let editor_cmd = match crate::external_editor::resolve_editor_command() {
            Ok(cmd) => cmd,
            Err(crate::external_editor::EditorError::MissingEditor) => {
                self.widget
                    .ui_mut()
                    .add_history_cell(Box::new(crate::history_cell::new_error_event(
                    "Cannot open external editor: set $VISUAL or $EDITOR before starting Codex."
                        .to_string(),
                )));
                return Ok(());
            }
            Err(err) => {
                self.widget.ui_mut().add_history_cell(Box::new(
                    crate::history_cell::new_error_event(format!("Failed to open editor: {err}",)),
                ));
                return Ok(());
            }
        };

        let edit_result = thread::spawn(move || -> Result<String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime
                .block_on(crate::external_editor::run_editor(&seed, &editor_cmd))
                .map_err(|err| anyhow::anyhow!("{err}"))
        })
        .join();

        match edit_result {
            Ok(Ok(edited)) => {
                let cleaned = edited.trim_end().to_string();
                self.widget.ui_mut().apply_external_edit(cleaned);
            }
            Ok(Err(err)) => {
                self.widget.ui_mut().add_history_cell(Box::new(
                    crate::history_cell::new_error_event(format!("Failed to open editor: {err}")),
                ));
            }
            Err(_) => {
                self.widget.ui_mut().add_history_cell(Box::new(
                    crate::history_cell::new_error_event(
                        "Failed to open editor: editor panicked".to_string(),
                    ),
                ));
            }
        }
        Ok(())
    }

    fn apply_personality_selection(
        &mut self,
        personality: codex_protocol::config_types::Personality,
    ) -> Result<()> {
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": "personality",
                "value": personality_config_value(personality),
                "mergeStrategy": "replace",
            }),
        )?;
        self.widget.ui_mut().set_status_message(Some(format!(
            "personality set to {}",
            personality_label(personality)
        )));
        Ok(())
    }

    fn apply_feature_flags(
        &mut self,
        updates: Vec<(codex_core::features::Feature, bool)>,
    ) -> Result<()> {
        if updates.is_empty() {
            return Ok(());
        }

        for (feature, enabled) in updates {
            app_server_rpc_request(
                &self.state.config.app_server_endpoint,
                self.state.config.auth_token.as_deref(),
                "config/value/write",
                json!({
                    "keyPath": format!("features.{}", feature.key()),
                    "value": enabled,
                    "mergeStrategy": "replace",
                }),
            )?;
        }

        self.widget
            .ui_mut()
            .set_status_message(Some("experimental features updated".to_string()));
        Ok(())
    }

    fn apply_skill_enabled(&mut self, path: std::path::PathBuf, enabled: bool) -> Result<()> {
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "skills/config/write",
            json!({
                "path": path,
                "enabled": enabled,
            }),
        )?;
        self.refresh_skills_snapshot()?;
        Ok(())
    }

    fn apply_app_enabled(&mut self, id: String, enabled: bool) -> Result<()> {
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": format!("apps.{id}.enabled"),
                "value": enabled,
                "mergeStrategy": "replace",
            }),
        )?;
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": format!("apps.{id}.disabled_reason"),
                "value": if enabled { Value::Null } else { Value::String("user".to_string()) },
                "mergeStrategy": "replace",
            }),
        )?;
        if let Ok(snapshot) = fetch_connectors(&self.state) {
            self.widget.ui_mut().set_connectors_snapshot(Some(snapshot));
        }
        self.widget.ui_mut().set_status_message(Some(format!(
            "app {} {}",
            id,
            if enabled { "enabled" } else { "disabled" }
        )));
        Ok(())
    }

    fn refresh_skills_snapshot(&mut self) -> Result<()> {
        let skills = fetch_skills_for_cwd(&self.state)?;
        self.widget.ui_mut().set_skills(Some(skills));
        Ok(())
    }

    fn open_permissions_picker(&mut self) -> Result<()> {
        let current = fetch_current_permissions_from_config(&self.state);
        let current_approval = current
            .as_ref()
            .map(|(approval, _)| *approval)
            .unwrap_or(codex_core::protocol::AskForApproval::OnRequest);
        let current_sandbox = current
            .as_ref()
            .map(|(_, sandbox)| sandbox.clone())
            .unwrap_or_else(codex_core::protocol::SandboxPolicy::new_workspace_write_policy);

        let presets = permissions_presets();
        let items = presets
            .into_iter()
            .map(|preset| {
                let approval = preset.approval;
                let sandbox = preset.sandbox.clone();
                let sandbox_for_action = sandbox.clone();
                let action: crate::bottom_pane::SelectionAction = Box::new(move |sender| {
                    sender.send(WidgetAppEvent::UpdateAskForApprovalPolicy(approval));
                    sender.send(WidgetAppEvent::UpdateSandboxPolicy(
                        sandbox_for_action.clone(),
                    ));
                });
                crate::bottom_pane::SelectionItem {
                    name: preset.label.to_string(),
                    description: Some(preset.description.to_string()),
                    is_current: approval == current_approval && sandbox == current_sandbox,
                    actions: vec![action],
                    dismiss_on_select: true,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.widget
            .ui_mut()
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                view_id: Some("permissions-picker"),
                title: Some("Select Approval Mode".to_string()),
                subtitle: Some("Switch between Codex approval presets".to_string()),
                items,
                ..Default::default()
            });
        Ok(())
    }

    fn open_review_branch_picker(&mut self, cwd: &std::path::Path) {
        let current_branch =
            git_current_branch_name(cwd).unwrap_or_else(|| "(detached HEAD)".into());
        let branches = git_local_branches(cwd);
        if branches.is_empty() {
            self.widget
                .ui_mut()
                .set_status_message(Some("No local branches found for review.".to_string()));
            return;
        }

        self.widget
            .ui_mut()
            .show_review_branch_picker(current_branch, branches);
    }

    fn open_review_commit_picker(&mut self, cwd: &std::path::Path) {
        let commits = git_recent_commits(cwd, 100);
        if commits.is_empty() {
            self.widget
                .ui_mut()
                .set_status_message(Some("No commits found for review.".to_string()));
            return;
        }

        self.widget.ui_mut().show_review_commit_picker(
            commits
                .into_iter()
                .map(|entry| crate::chatwidget::ReviewCommitPickerEntry {
                    sha: entry.sha,
                    subject: entry.subject,
                })
                .collect(),
        );
    }

    fn start_review_uncommitted(&mut self) -> Result<()> {
        self.start_review_with_target(json!({ "type": "uncommittedChanges" }))
    }

    fn start_compaction(&mut self) -> Result<()> {
        let thread_id = self.widget.ui_mut().session_id.clone();
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "thread/compact/start",
            json!({
                "threadId": thread_id,
            }),
        )?;
        self.widget
            .ui_mut()
            .set_status_message(Some("compacting context...".to_string()));
        Ok(())
    }

    fn start_review_base_branch(&mut self, branch: &str) -> Result<()> {
        self.start_review_with_target(json!({
            "type": "baseBranch",
            "branch": branch,
        }))
    }

    fn start_review_commit(&mut self, sha: &str, title: Option<&str>) -> Result<()> {
        self.start_review_with_target(json!({
            "type": "commit",
            "sha": sha,
            "title": title,
        }))
    }

    fn start_review_custom(&mut self, instructions: &str) -> Result<()> {
        self.start_review_with_target(json!({
            "type": "custom",
            "instructions": instructions,
        }))
    }

    fn start_review_with_target(&mut self, target: Value) -> Result<()> {
        let thread_id = self.widget.ui_mut().session_id.clone();
        let response = app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "review/start",
            json!({
                "threadId": thread_id,
                "target": target,
            }),
        )?;

        if let Some(turn_id) = response
            .result
            .get("turn")
            .and_then(|turn| turn.get("id"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
        {
            self.widget.ui_mut().active_turn_id = Some(turn_id);
        }
        self.widget
            .ui_mut()
            .set_status_message(Some("running review...".to_string()));
        Ok(())
    }

    fn apply_approval_policy_selection(
        &mut self,
        approval_policy: codex_core::protocol::AskForApproval,
    ) -> Result<()> {
        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": "approval_policy",
                "value": approval_policy.to_string(),
                "mergeStrategy": "replace",
            }),
        )?;
        self.widget.ui_mut().set_status_message(Some(format!(
            "approval policy updated to {}",
            approval_policy
        )));
        Ok(())
    }

    fn apply_sandbox_policy_selection(
        &mut self,
        sandbox_policy: codex_core::protocol::SandboxPolicy,
    ) -> Result<()> {
        let sandbox_mode = match sandbox_policy {
            codex_core::protocol::SandboxPolicy::DangerFullAccess => "danger-full-access",
            codex_core::protocol::SandboxPolicy::ReadOnly { .. } => "read-only",
            codex_core::protocol::SandboxPolicy::WorkspaceWrite { .. } => "workspace-write",
            codex_core::protocol::SandboxPolicy::ExternalSandbox { .. } => "workspace-write",
        };

        app_server_rpc_request(
            &self.state.config.app_server_endpoint,
            self.state.config.auth_token.as_deref(),
            "config/value/write",
            json!({
                "keyPath": "sandbox_mode",
                "value": sandbox_mode,
                "mergeStrategy": "replace",
            }),
        )?;
        self.widget
            .ui_mut()
            .set_status_message(Some(format!("sandbox mode updated to {sandbox_mode}")));
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
            let cfg = response.result.get("config");
            if let Some(model) = cfg.and_then(|c| c.get("model")).and_then(Value::as_str) {
                config.model = Some(model.to_string());
            }
            if let Some(summary) = cfg
                .and_then(|c| c.get("modelReasoningSummary"))
                .and_then(Value::as_str)
            {
                config.model_reasoning_summary = match summary.to_ascii_lowercase().as_str() {
                    "auto" => codex_core::config::ReasoningSummary::Auto,
                    "concise" => codex_core::config::ReasoningSummary::Concise,
                    "detailed" => codex_core::config::ReasoningSummary::Detailed,
                    _ => codex_core::config::ReasoningSummary::None,
                };
            }
            if let Some(approval) = cfg
                .and_then(|c| c.get("approval_policy").or_else(|| c.get("approvalPolicy")))
                .and_then(parse_approval_policy_value)
            {
                config.permissions.approval_policy.0 = approval;
            }
            if let Some(sandbox) = cfg
                .and_then(|c| c.get("sandbox_mode").or_else(|| c.get("sandboxMode")))
                .and_then(parse_sandbox_policy_value)
            {
                config.permissions.sandbox_policy.0 = sandbox;
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

        let account = response.result.get("account").unwrap_or(&response.result);
        if !account.is_object() {
            return (crate::AuthManager::default(), None);
        }

        let account_type = account
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let email = account
            .get("email")
            .or_else(|| account.get("allegedUserEmail"))
            .or_else(|| account.get("alleged_user_email"))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let plan_type = parse_plan_type(
            account
                .get("planType")
                .or_else(|| account.get("plan_type"))
                .or_else(|| account.get("chatgptPlanType"))
                .or_else(|| account.get("chatgpt_plan_type")),
        );

        if account_type.eq_ignore_ascii_case("apikey")
            || account_type.eq_ignore_ascii_case("api_key")
            || account_type.eq_ignore_ascii_case("apiKey")
        {
            (crate::AuthManager::from_api_key(), None)
        } else if account_type.eq_ignore_ascii_case("chatgpt") || email.is_some() {
            (crate::AuthManager::from_chatgpt_email(email), plan_type)
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

fn personality_label(personality: codex_protocol::config_types::Personality) -> &'static str {
    match personality {
        codex_protocol::config_types::Personality::None => "None",
        codex_protocol::config_types::Personality::Friendly => "Friendly",
        codex_protocol::config_types::Personality::Pragmatic => "Pragmatic",
    }
}

fn personality_description(personality: codex_protocol::config_types::Personality) -> &'static str {
    match personality {
        codex_protocol::config_types::Personality::None => "No personality instructions.",
        codex_protocol::config_types::Personality::Friendly => "Warm, collaborative, and helpful.",
        codex_protocol::config_types::Personality::Pragmatic => {
            "Concise, task-focused, and direct."
        }
    }
}

fn personality_config_value(
    personality: codex_protocol::config_types::Personality,
) -> &'static str {
    match personality {
        codex_protocol::config_types::Personality::None => "none",
        codex_protocol::config_types::Personality::Friendly => "friendly",
        codex_protocol::config_types::Personality::Pragmatic => "pragmatic",
    }
}

fn collaboration_mode_from_mask(
    mask: Option<codex_protocol::config_types::CollaborationModeMask>,
    session_model: Option<String>,
    session_effort: Option<codex_protocol::openai_models::ReasoningEffort>,
) -> Option<codex_protocol::config_types::CollaborationMode> {
    let mask = mask?;
    let mode = mask.mode?;
    let model = mask.model.or(session_model)?;
    let reasoning_effort = mask.reasoning_effort.unwrap_or(session_effort);
    let developer_instructions = mask.developer_instructions.unwrap_or(None);
    Some(codex_protocol::config_types::CollaborationMode {
        mode,
        settings: codex_protocol::config_types::Settings {
            model,
            reasoning_effort,
            developer_instructions,
        },
    })
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

struct SkillToggleEntry {
    path: std::path::PathBuf,
    name: String,
    description: String,
    enabled: bool,
}

fn fetch_skills_toggle_entries(state: &CliState) -> Result<Vec<SkillToggleEntry>> {
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
            let path = skill
                .get("path")
                .and_then(Value::as_str)
                .map(std::path::PathBuf::from)
                .unwrap_or_default();
            let description = skill
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let enabled = skill
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            out.push(SkillToggleEntry {
                path,
                name: name.to_string(),
                description,
                enabled,
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

fn clean_background_terminals(state: &CliState, thread_id: &str) -> Result<()> {
    app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/backgroundTerminals/clean",
        json!({
            "threadId": thread_id,
        }),
    )?;
    Ok(())
}

#[derive(Clone)]
struct CommitPickerEntry {
    sha: String,
    subject: String,
}

fn git_command_output(cwd: &std::path::Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn git_current_branch_name(cwd: &std::path::Path) -> Option<String> {
    git_command_output(cwd, &["branch", "--show-current"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn git_local_branches(cwd: &std::path::Path) -> Vec<String> {
    let mut branches = git_command_output(cwd, &["branch", "--format=%(refname:short)"])
        .map(|out| {
            out.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    branches.sort_unstable();
    branches
}

fn git_recent_commits(cwd: &std::path::Path, limit: usize) -> Vec<CommitPickerEntry> {
    let mut args = vec!["log".to_string()];
    if limit > 0 {
        args.push("-n".to_string());
        args.push(limit.to_string());
    }
    args.push("--pretty=format:%H%x1f%ct%x1f%s".to_string());
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(out) = git_command_output(cwd, &arg_refs) else {
        return Vec::new();
    };
    out.lines()
        .filter_map(|line| {
            let mut parts = line.split('\u{001f}');
            let sha = parts.next()?.trim();
            let _timestamp = parts.next()?.trim();
            let subject = parts.next().unwrap_or_default().trim();
            if sha.is_empty() {
                return None;
            }
            Some(CommitPickerEntry {
                sha: sha.to_string(),
                subject: subject.to_string(),
            })
        })
        .collect()
}

fn fetch_mcp_tools_output(state: &CliState) -> Result<crate::history_cell::PlainHistoryCell> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "mcpServerStatus/list",
        json!({
            "limit": 200,
        }),
    )?;

    let statuses = response
        .result
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if statuses.is_empty() {
        return Ok(crate::history_cell::empty_mcp_output());
    }

    let mut tools: std::collections::HashMap<String, codex_protocol::mcp::Tool> =
        std::collections::HashMap::new();
    let mut resources: std::collections::HashMap<String, Vec<codex_protocol::mcp::Resource>> =
        std::collections::HashMap::new();
    let mut resource_templates: std::collections::HashMap<
        String,
        Vec<codex_protocol::mcp::ResourceTemplate>,
    > = std::collections::HashMap::new();
    let mut auth_statuses: std::collections::HashMap<String, codex_core::protocol::McpAuthStatus> =
        std::collections::HashMap::new();
    let mut server_configs =
        std::collections::BTreeMap::<String, codex_core::config::types::McpServerConfig>::new();

    for entry in statuses {
        let Some(name) = entry.get("name").and_then(Value::as_str) else {
            continue;
        };
        let server_name = name.to_string();

        if let Some(tool_map) = entry.get("tools")
            && let Ok(map) = serde_json::from_value::<
                std::collections::HashMap<String, codex_protocol::mcp::Tool>,
            >(tool_map.clone())
        {
            for (tool_name, tool) in map {
                tools.insert(format!("mcp__{server_name}__{tool_name}"), tool);
            }
        }

        if let Some(raw_resources) = entry.get("resources")
            && let Ok(parsed) =
                serde_json::from_value::<Vec<codex_protocol::mcp::Resource>>(raw_resources.clone())
        {
            resources.insert(server_name.clone(), parsed);
        }

        if let Some(raw_templates) = entry
            .get("resourceTemplates")
            .or_else(|| entry.get("resource_templates"))
            && let Ok(parsed) = serde_json::from_value::<Vec<codex_protocol::mcp::ResourceTemplate>>(
                raw_templates.clone(),
            )
        {
            resource_templates.insert(server_name.clone(), parsed);
        }

        if let Some(raw_auth) = entry.get("authStatus").or_else(|| entry.get("auth_status"))
            && let Ok(auth) =
                serde_json::from_value::<codex_core::protocol::McpAuthStatus>(raw_auth.clone())
        {
            auth_statuses.insert(server_name.clone(), auth);
        }

        server_configs.insert(
            server_name,
            codex_core::config::types::McpServerConfig {
                transport: codex_core::config::types::McpServerTransportConfig::default(),
                enabled: true,
                disabled_reason: None,
            },
        );
    }

    let mut config = codex_core::config::Config::default();
    config.mcp_servers = codex_core::config::McpServers(server_configs);
    Ok(crate::history_cell::new_mcp_tools_output(
        &config,
        tools,
        resources,
        resource_templates,
        &auth_statuses,
    ))
}

struct ResumeThreadEntry {
    thread_id: String,
    thread_name: Option<String>,
}

struct ModelPickerEntry {
    slug: String,
    display_name: String,
    description: String,
}

struct PermissionsPresetEntry {
    label: &'static str,
    description: &'static str,
    approval: codex_core::protocol::AskForApproval,
    sandbox: codex_core::protocol::SandboxPolicy,
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

fn fetch_collaboration_modes(
    state: &CliState,
) -> Result<Vec<codex_protocol::config_types::CollaborationModeMask>> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "collaborationMode/list",
        json!({}),
    )?;
    let data = response
        .result
        .get("data")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let mut modes: Vec<codex_protocol::config_types::CollaborationModeMask> =
        serde_json::from_value(data)?;
    modes.retain(|mask| mask.mode.is_some_and(|mode| mode.is_tui_visible()));
    Ok(modes)
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExperimentalFeatureListResponsePayload {
    data: Vec<ExperimentalFeaturePayload>,
    next_cursor: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExperimentalFeaturePayload {
    name: String,
    stage: String,
    display_name: Option<String>,
    description: Option<String>,
    enabled: bool,
}

fn fetch_experimental_features(
    state: &CliState,
) -> Result<Vec<crate::bottom_pane::ExperimentalFeatureItem>> {
    let mut cursor: Option<String> = None;
    let mut out = Vec::new();
    loop {
        let response = app_server_rpc_request(
            &state.config.app_server_endpoint,
            state.config.auth_token.as_deref(),
            "experimentalFeature/list",
            json!({
                "cursor": cursor,
            }),
        )?;
        let payload: ExperimentalFeatureListResponsePayload =
            serde_json::from_value(response.result.clone())?;

        for feature in payload.data {
            let Some(mapped_feature) = codex_core::features::Feature::from_key(&feature.name)
            else {
                continue;
            };
            let description = feature
                .description
                .unwrap_or_else(|| format!("Stage: {}", feature.stage));
            out.push(crate::bottom_pane::ExperimentalFeatureItem {
                feature: mapped_feature,
                name: feature.display_name.unwrap_or(feature.name),
                description,
                enabled: feature.enabled,
            });
        }

        cursor = payload.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(out)
}

fn fetch_model_picker_entries(state: &CliState) -> Result<Vec<ModelPickerEntry>> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "model/list",
        json!({
            "includeHidden": false,
            "limit": 100,
        }),
    )?;

    let models = response
        .result
        .get("data")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut out = Vec::new();
    for model in models {
        let slug = model
            .get("model")
            .or_else(|| model.get("id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_string();
        if slug.is_empty() {
            continue;
        }

        let display_name = model
            .get("displayName")
            .or_else(|| model.get("display_name"))
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| slug.clone());
        let description = model
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        out.push(ModelPickerEntry {
            slug,
            display_name,
            description,
        });
    }
    Ok(out)
}

fn fetch_current_model_from_config(state: &CliState) -> Option<String> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "config/read",
        json!({
            "includeLayers": false,
        }),
    )
    .ok()?;

    response
        .result
        .get("config")
        .and_then(|cfg| cfg.get("model"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn permissions_presets() -> Vec<PermissionsPresetEntry> {
    vec![
        PermissionsPresetEntry {
            label: "Default",
            description: "Read and edit files in the current directory. Ask before commands and network.",
            approval: codex_core::protocol::AskForApproval::OnRequest,
            sandbox: codex_core::protocol::SandboxPolicy::new_workspace_write_policy(),
        },
        PermissionsPresetEntry {
            label: "Auto",
            description: "Read and edit files in the current directory. Run commands and network automatically.",
            approval: codex_core::protocol::AskForApproval::Never,
            sandbox: codex_core::protocol::SandboxPolicy::new_workspace_write_policy(),
        },
        PermissionsPresetEntry {
            label: "Read Only",
            description: "Read files and ask before commands.",
            approval: codex_core::protocol::AskForApproval::OnRequest,
            sandbox: codex_core::protocol::SandboxPolicy::new_read_only_policy(),
        },
        PermissionsPresetEntry {
            label: "Full Access",
            description: "Read and edit all files. Run commands and network automatically.",
            approval: codex_core::protocol::AskForApproval::Never,
            sandbox: codex_core::protocol::SandboxPolicy::DangerFullAccess,
        },
    ]
}

fn fetch_current_permissions_from_config(
    state: &CliState,
) -> Option<(
    codex_core::protocol::AskForApproval,
    codex_core::protocol::SandboxPolicy,
)> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "config/read",
        json!({
            "includeLayers": false,
        }),
    )
    .ok()?;

    let config = response.result.get("config")?;
    let approval = config
        .get("approval_policy")
        .or_else(|| config.get("approvalPolicy"))
        .and_then(parse_approval_policy_value)?;
    let sandbox = config
        .get("sandbox_mode")
        .or_else(|| config.get("sandboxMode"))
        .and_then(parse_sandbox_policy_value)?;
    Some((approval, sandbox))
}

fn parse_approval_policy_value(value: &Value) -> Option<codex_core::protocol::AskForApproval> {
    let raw = value.as_str()?.to_ascii_lowercase();
    match raw.as_str() {
        "untrusted" => Some(codex_core::protocol::AskForApproval::UnlessTrusted),
        "on-failure" | "on_failure" => Some(codex_core::protocol::AskForApproval::OnFailure),
        "on-request" | "on_request" => Some(codex_core::protocol::AskForApproval::OnRequest),
        "never" => Some(codex_core::protocol::AskForApproval::Never),
        _ => None,
    }
}

fn parse_sandbox_policy_value(value: &Value) -> Option<codex_core::protocol::SandboxPolicy> {
    let raw = value.as_str()?.to_ascii_lowercase();
    match raw.as_str() {
        "read-only" | "read_only" => {
            Some(codex_core::protocol::SandboxPolicy::new_read_only_policy())
        }
        "workspace-write" | "workspace_write" => {
            Some(codex_core::protocol::SandboxPolicy::new_workspace_write_policy())
        }
        "danger-full-access" | "danger_full_access" => {
            Some(codex_core::protocol::SandboxPolicy::DangerFullAccess)
        }
        _ => None,
    }
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
