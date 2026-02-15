use super::slash_commands::{TuiSlashCommand, filtered_slash_commands};
use super::*;

pub(super) struct InFlightPrompt {
    pub(super) prompt: String,
    submitted_at: Instant,
    pub(super) handle: thread::JoinHandle<Result<DaemonPromptResponse>>,
}

pub(super) struct LiveAttachTui {
    pub(super) session_id: String,
    transcript: String,
    pub(super) input: String,
    input_cursor: usize,
    command_history: Vec<String>,
    history_index: Option<usize>,
    pub(super) latest_state: String,
    previous_state: Option<String>,
    received_events: usize,
    pub(super) last_sequence: u64,
    pub(super) status_message: Option<String>,
    pub(super) active_turn_id: Option<String>,
    pending_prompt: Option<InFlightPrompt>,
    pub(super) pending_approvals: BTreeMap<String, DaemonRpcServerRequest>,
    slash_picker_index: usize,
}

impl LiveAttachTui {
    pub(super) fn new(session_id: String, latest_state: String) -> Self {
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

    pub(super) fn apply_stream_events(&mut self, stream_events: &[DaemonStreamEnvelope]) {
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

    pub(super) fn apply_rpc_stream_events(&mut self, stream_events: &[DaemonRpcStreamEnvelope]) {
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

    pub(super) fn apply_rpc_notification(&mut self, notification: &DaemonRpcNotification) {
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

    pub(super) fn push_line(&mut self, line: &str) {
        if !self.transcript.is_empty() && !self.transcript.ends_with('\n') {
            self.transcript.push('\n');
        }
        self.transcript.push_str(line);
        self.transcript.push('\n');
    }

    pub(super) fn push_user_prompt(&mut self, prompt: &str) {
        if !self.transcript.is_empty() && !self.transcript.ends_with("\n\n") {
            if !self.transcript.ends_with('\n') {
                self.transcript.push('\n');
            }
            self.transcript.push('\n');
        }
        self.transcript.push_str(&format!("\u{203a} {prompt}\n\n"));
    }

    pub(super) fn append_assistant_delta(&mut self, delta: &str) {
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

    pub(super) fn input_insert_str(&mut self, text: &str) {
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

    pub(super) fn input_insert_char(&mut self, ch: char) {
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

    pub(super) fn input_backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        let previous = previous_char_boundary(&self.input, self.input_cursor);
        self.input.drain(previous..self.input_cursor);
        self.input_cursor = previous;
        self.sync_slash_picker();
    }

    pub(super) fn input_delete(&mut self) {
        if self.input_cursor >= self.input.len() {
            return;
        }
        let next = next_char_boundary(&self.input, self.input_cursor);
        self.input.drain(self.input_cursor..next);
        self.sync_slash_picker();
    }

    pub(super) fn move_input_cursor_left(&mut self) {
        self.input_cursor = previous_char_boundary(&self.input, self.input_cursor);
    }

    pub(super) fn move_input_cursor_right(&mut self) {
        self.input_cursor = next_char_boundary(&self.input, self.input_cursor);
    }

    pub(super) fn move_input_cursor_home(&mut self) {
        self.input_cursor = 0;
    }

    pub(super) fn move_input_cursor_end(&mut self) {
        self.input_cursor = self.input.len();
    }

    pub(super) fn clear_input(&mut self) {
        self.input.clear();
        self.input_cursor = 0;
        self.sync_slash_picker();
    }

    pub(super) fn replace_input(&mut self, text: String) {
        self.input = text;
        self.input_cursor = self.input.len();
        self.sync_slash_picker();
    }

    pub(super) fn take_input(&mut self) -> String {
        self.history_index = None;
        self.input_cursor = 0;
        let taken = std::mem::take(&mut self.input);
        self.sync_slash_picker();
        taken
    }

    pub(super) fn remember_history_entry(&mut self, text: &str) {
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

    pub(super) fn history_prev(&mut self) {
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

    pub(super) fn history_next(&mut self) {
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

    pub(super) fn has_pending_prompt(&self) -> bool {
        self.pending_prompt.is_some()
    }

    pub(super) fn start_prompt_request(
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

    pub(super) fn take_finished_prompt(&mut self) -> Option<InFlightPrompt> {
        if self
            .pending_prompt
            .as_ref()
            .is_some_and(|pending| pending.handle.is_finished())
        {
            return self.pending_prompt.take();
        }
        None
    }

    pub(super) fn input_view(&self, width: usize) -> (String, usize, usize) {
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

    pub(super) fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
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

    pub(super) fn input_line(
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

    pub(super) fn footer_line_text(&self, width: usize) -> String {
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

    pub(super) fn context_left_percent(&self) -> usize {
        let consumed = (self.received_events / 12).min(99);
        100_usize.saturating_sub(consumed)
    }

    pub(super) fn composer_row_style(&self) -> Style {
        if env::var("COLORTERM")
            .map(|value| value.contains("truecolor"))
            .unwrap_or(false)
        {
            Style::default().bg(Color::Rgb(38, 42, 46))
        } else {
            Style::default().bg(Color::DarkGray)
        }
    }

    pub(super) fn special_token_style(&self, token: char) -> Option<Style> {
        let style = match token {
            '!' => Style::default().fg(Color::Yellow).bold(),
            '@' => Style::default().fg(Color::Cyan).bold(),
            '$' => Style::default().fg(Color::Magenta).bold(),
            '/' => Style::default().fg(Color::Green).bold(),
            _ => return None,
        };
        Some(style)
    }

    pub(super) fn slash_picker_query(&self) -> Option<String> {
        let trimmed = self.input.trim_start();
        if !trimmed.starts_with('/') {
            return None;
        }
        let stripped = trimmed.trim_start_matches('/');
        let token = stripped.trim_start();
        Some(token.split_whitespace().next().unwrap_or("").to_string())
    }

    pub(super) fn slash_picker_entries(&self) -> Vec<&'static TuiSlashCommand> {
        let Some(query) = self.slash_picker_query() else {
            return Vec::new();
        };
        filtered_slash_commands(&query)
    }

    pub(super) fn slash_picker_is_active(&self) -> bool {
        !self.slash_picker_entries().is_empty()
    }

    pub(super) fn sync_slash_picker(&mut self) {
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
        } else if self.slash_picker_index >= len {
            self.slash_picker_index = len - 1;
        }
    }

    pub(super) fn slash_picker_move_up(&mut self) {
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

    pub(super) fn slash_picker_move_down(&mut self) {
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
            return;
        }
        self.slash_picker_index = (self.slash_picker_index + 1) % len;
    }

    pub(super) fn selected_slash_entry(&self) -> Option<&'static TuiSlashCommand> {
        let entries = self.slash_picker_entries();
        let selected = self.slash_picker_index.min(entries.len().saturating_sub(1));
        entries.get(selected).copied()
    }

    pub(super) fn apply_selected_slash_entry(&mut self) -> bool {
        let Some(selected) = self.selected_slash_entry() else {
            return false;
        };
        self.replace_input(format!("/{}", selected.command));
        true
    }

    pub(super) fn should_apply_slash_picker_on_enter(&self) -> bool {
        if !self.slash_picker_is_active() {
            return false;
        }
        let Some(selected) = self.selected_slash_entry() else {
            return false;
        };
        self.input.trim() != format!("/{}", selected.command)
    }

    pub(super) fn slash_picker_lines(&self, width: usize) -> Vec<Line<'static>> {
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

    pub(super) fn live_input_hint(&self) -> Option<String> {
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
