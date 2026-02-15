use super::*;

#[path = "chatwidget.rs"]
mod chatwidget;
#[path = "color.rs"]
pub(crate) mod color;
#[path = "key_hint.rs"]
mod key_hint;
#[path = "mention_codec.rs"]
mod mention_codec;
#[path = "bottom_pane/slash_commands.rs"]
mod slash_commands;
#[path = "style.rs"]
mod style;
#[path = "terminal_palette.rs"]
pub(crate) mod terminal_palette;
#[path = "text_formatting.rs"]
mod text_formatting;
#[path = "version.rs"]
mod version;

pub(super) use crate::core_compat::AppEvent;
pub(super) use crate::core_compat::AppEventSender;
pub(super) use crate::core_compat::AppExitInfo;
pub(super) use crate::core_compat::ExitMode;
pub(super) use crate::core_compat::ExitReason;
pub(super) use crate::core_compat::LiveTuiAction;
pub(super) use crate::core_compat::UiApprovalRequest;
pub(super) use crate::core_compat::UiEvent;
pub(super) use crate::core_compat::interrupt_turn;
pub(super) use crate::core_compat::map_daemon_stream_events;
pub(super) use crate::core_compat::map_rpc_stream_events;
pub(super) use crate::core_compat::respond_to_approval;
pub(super) use crate::core_compat::resume_thread;
pub(super) use crate::core_compat::start_thread;
pub(super) use crate::core_compat::start_turn;
pub(super) use crate::core_compat::stream_events;
use chatwidget::ChatWidget;
use chatwidget::LiveAttachTui;
use slash_commands::find_builtin_command;
use text_formatting::proper_join;
use version::CODEX_CLI_VERSION;

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
    /// Shared CLI state (daemon endpoint, sessions, auth).
    state: CliState,
    /// ID of the active app-server thread.
    thread_id: String,
}

impl App {
    /// Create a new `App` for an interactive TUI session.
    ///
    /// Mirrors upstream `App::run()` initialization: ensures the daemon is
    /// ready, starts or reuses a thread, and creates the initial `ChatWidget`.
    pub(crate) fn new(args: TuiArgs, mut state: CliState) -> Result<Self> {
        ensure_daemon_ready(&state)?;
        let thread_id = args
            .thread_id
            .or_else(|| state.last_thread_id.clone())
            .map(Ok)
            .unwrap_or_else(|| start_thread(&state))?;
        state.last_thread_id = Some(thread_id.clone());

        let mut widget = ChatWidget::new(thread_id.clone());
        widget.ui_mut().status_message = Some("connected to daemon app-server bridge".to_string());
        let _ = widget.poll_stream_updates(&state);

        Ok(Self {
            widget,
            state,
            thread_id,
        })
    }

    /// Create an `App` that attaches to an existing daemon session.
    pub(crate) fn attach(
        session_id: String,
        initial_events: Vec<DaemonStreamEnvelope>,
        mut state: CliState,
    ) -> Result<Self> {
        let mut widget = ChatWidget::new(session_id.clone());
        {
            let ui = widget.ui_mut();
            ui.latest_state = cached_session_state_label(&state, &session_id)
                .unwrap_or("unknown")
                .to_string();
            ui.apply_stream_events(&initial_events);
            ui.status_message = Some("attached to daemon app-server bridge".to_string());
        }
        state.last_thread_id = Some(session_id.clone());

        Ok(Self {
            widget,
            state,
            thread_id: session_id,
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

        enable_raw_mode().context("enable raw mode for app-server tui")?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)
            .context("enter alternate screen for app-server tui")?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).context("create app-server tui terminal")?;
        terminal.clear().context("clear app-server tui terminal")?;

        let loop_result = self.event_loop(&mut terminal);

        let _ = disable_raw_mode();
        let _ = execute!(
            terminal.backend_mut(),
            DisableBracketedPaste,
            LeaveAlternateScreen
        );
        let _ = terminal.show_cursor();

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

    fn event_loop(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        loop {
            self.widget.draw(terminal)?;
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

            // Tick: poll stream for daemon events.
            match self.handle_event(AppEvent::Tick)? {
                LiveTuiAction::Continue => {}
                LiveTuiAction::Detach => return Ok(()),
            }

            if self.widget.poll_stream_updates(&self.state)? {
                should_redraw = true;
            }

            if !should_redraw {
                thread::sleep(TUI_STREAM_POLL_INTERVAL);
            }
        }
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
            AppEvent::Paste(pasted) => {
                self.widget.ui_mut().input_insert_str(&pasted);
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Resize => Ok(LiveTuiAction::Continue),
            AppEvent::Tick => Ok(LiveTuiAction::Continue),
            AppEvent::SubmitInput(text) => self.handle_submit(&text),
            AppEvent::NewSession => {
                let thread_id = start_thread(&self.state)?;
                let ui = self.widget.ui_mut();
                ui.session_id = thread_id.clone();
                ui.active_turn_id = None;
                ui.pending_approvals.clear();
                ui.push_line(&format!("[thread switched] {thread_id}"));
                ui.status_message = Some("started new thread".to_string());
                self.state.last_thread_id = Some(thread_id.clone());
                self.thread_id = thread_id;
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Interrupt => {
                let ui = self.widget.ui_mut();
                if let Some(turn_id) = ui.active_turn_id.clone() {
                    interrupt_turn(&self.state, &ui.session_id, &turn_id)?;
                    ui.status_message = Some("interrupt requested".to_string());
                } else {
                    ui.status_message = Some("no running turn".to_string());
                }
                Ok(LiveTuiAction::Continue)
            }
            AppEvent::Exit(_mode) => Ok(LiveTuiAction::Detach),
            AppEvent::StreamUpdate(envelopes) => {
                self.widget.ui_mut().apply_rpc_stream_events(&envelopes);
                Ok(LiveTuiAction::Continue)
            }
        }
    }

    /// Handle a key press event — mirrors upstream `App::handle_key_event`.
    fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) -> Result<LiveTuiAction> {
        handle_app_server_tui_key_event(key, &mut self.state, self.widget.ui_mut())
    }

    /// Handle submitted user input (from Enter key or programmatic submit).
    fn handle_submit(&mut self, input: &str) -> Result<LiveTuiAction> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(LiveTuiAction::Continue);
        }
        let ui = self.widget.ui_mut();
        ui.hide_shortcuts_overlay();
        ui.remember_history_entry(trimmed);

        match trimmed {
            "/exit" | "/quit" => return Ok(LiveTuiAction::Detach),
            "/status" => {
                let approval_ids = ui.pending_approvals.keys().cloned().collect::<Vec<_>>();
                let approvals = if approval_ids.is_empty() {
                    "none".to_string()
                } else {
                    proper_join(&approval_ids)
                };
                ui.status_message = Some(format!(
                    "thread={} approvals={} seq={} v={}",
                    ui.session_id, approvals, ui.last_sequence, CODEX_CLI_VERSION
                ));
                return Ok(LiveTuiAction::Continue);
            }
            "/refresh" => {
                ui.status_message = Some("refreshing stream...".to_string());
                return Ok(LiveTuiAction::Continue);
            }
            "/new" => {
                // Delegate to the NewSession AppEvent path.
                return self.handle_event(AppEvent::NewSession);
            }
            "/interrupt" => {
                return self.handle_event(AppEvent::Interrupt);
            }
            "/resume" => {
                if let Some(thread_id) = resume_thread(&self.state, &ui.session_id)? {
                    ui.session_id = thread_id.clone();
                    self.state.last_thread_id = Some(thread_id);
                    ui.status_message = Some("thread resumed".to_string());
                } else {
                    ui.status_message = Some("resume returned no thread id".to_string());
                }
                return Ok(LiveTuiAction::Continue);
            }
            _ => {}
        }

        if let Some(rest) = trimmed.strip_prefix("/approve") {
            return handle_app_server_approval_decision(
                &mut self.state,
                self.widget.ui_mut(),
                rest.trim(),
                true,
            )
            .map(|_| LiveTuiAction::Continue);
        }
        if let Some(rest) = trimmed.strip_prefix("/deny") {
            return handle_app_server_approval_decision(
                &mut self.state,
                self.widget.ui_mut(),
                rest.trim(),
                false,
            )
            .map(|_| LiveTuiAction::Continue);
        }

        if let Some(command) = trimmed
            .strip_prefix('/')
            .and_then(|value| value.split_whitespace().next())
            && find_builtin_command(command, true, true, true, true).is_some()
        {
            let ui = self.widget.ui_mut();
            ui.status_message = Some(format!(
                "slash command /{command} is not implemented in crabbot app-server tui yet"
            ));
            return Ok(LiveTuiAction::Continue);
        }

        let ui = self.widget.ui_mut();
        ui.push_user_prompt(trimmed);
        if let Some(turn_id) = start_turn(&self.state, &ui.session_id, trimmed)? {
            ui.active_turn_id = Some(turn_id);
        }
        ui.status_message = Some("waiting for response...".to_string());
        Ok(LiveTuiAction::Continue)
    }
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
            "daemon_endpoint": state.config.daemon_endpoint,
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

// ---------------------------------------------------------------------------
// Key event handling
// ---------------------------------------------------------------------------

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
        KeyCode::Esc => {
            ui.hide_shortcuts_overlay();
        }
        KeyCode::Enter => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                ui.input_insert_char('\n');
                return Ok(LiveTuiAction::Continue);
            }
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
        KeyCode::Char('?') => {
            if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
                && ui.input.trim().is_empty()
            {
                ui.toggle_shortcuts_overlay();
            } else if !key.modifiers.contains(KeyModifiers::CONTROL)
                && !key.modifiers.contains(KeyModifiers::ALT)
            {
                ui.input_insert_char('?');
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

/// Legacy submit handler — keeps the inline submit flow for the key event path.
/// The `App::handle_submit` method is the canonical path going forward.
fn handle_app_server_tui_submit(state: &mut CliState, ui: &mut LiveAttachTui) -> Result<bool> {
    let input = ui.take_input();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    ui.hide_shortcuts_overlay();
    ui.remember_history_entry(trimmed);

    match trimmed {
        "/exit" | "/quit" => return Ok(true),
        "/status" => {
            let approval_ids = ui.pending_approvals.keys().cloned().collect::<Vec<_>>();
            let approvals = if approval_ids.is_empty() {
                "none".to_string()
            } else {
                proper_join(&approval_ids)
            };
            ui.status_message = Some(format!(
                "thread={} approvals={} seq={} v={}",
                ui.session_id, approvals, ui.last_sequence, CODEX_CLI_VERSION
            ));
            return Ok(false);
        }
        "/refresh" => {
            ui.status_message = Some("refreshing stream...".to_string());
            return Ok(false);
        }
        "/new" => {
            let thread_id = start_thread(state)?;
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
            interrupt_turn(state, &ui.session_id, &turn_id)?;
            ui.status_message = Some("interrupt requested".to_string());
        } else {
            ui.status_message = Some("no running turn".to_string());
        }
        return Ok(false);
    }

    if trimmed == "/resume" {
        if let Some(thread_id) = resume_thread(state, &ui.session_id)? {
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

    if let Some(command) = trimmed
        .strip_prefix('/')
        .and_then(|value| value.split_whitespace().next())
        && find_builtin_command(command, true, true, true, true).is_some()
    {
        ui.status_message = Some(format!(
            "slash command /{command} is not implemented in crabbot app-server tui yet"
        ));
        return Ok(false);
    }

    ui.push_user_prompt(trimmed);
    if let Some(turn_id) = start_turn(state, &ui.session_id, trimmed)? {
        ui.active_turn_id = Some(turn_id);
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
    respond_to_approval(state, request.request_id, approve)?;
    ui.status_message = Some(format!(
        "{} request {}",
        if approve { "approved" } else { "denied" },
        approval_key
    ));
    Ok(())
}

fn poll_app_server_tui_stream_updates(state: &CliState, ui: &mut LiveAttachTui) -> Result<bool> {
    let events = stream_events(state, ui.last_sequence)?;
    if events.is_empty() {
        return Ok(false);
    }
    ui.apply_rpc_stream_events(&events);
    Ok(true)
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
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
