use super::*;

mod live_ui;
mod slash_commands;

use live_ui::LiveAttachTui;

pub(crate) fn handle_tui(args: TuiArgs, state: &mut CliState) -> Result<CommandOutput> {
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

pub(crate) fn handle_attach_tui_interactive(
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
