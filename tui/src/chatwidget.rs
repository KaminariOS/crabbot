use crate::app::align_left_right;
use crate::core_compat::UiApprovalRequest;
use crate::core_compat::UiEvent;
use crate::core_compat::map_legacy_stream_events;
use crate::core_compat::map_rpc_stream_events;
use crate::key_hint;
use crate::mention_codec;
use crate::slash_command::SlashCommand;
use crate::slash_commands::builtins_for_input;
use crate::text_formatting;
use crate::version::CODEX_CLI_VERSION;
use crate::*;
use codex_utils_fuzzy_match::fuzzy_match;

pub(crate) struct InFlightPrompt {
    pub(crate) prompt: String,
    submitted_at: Instant,
    pub(crate) handle: thread::JoinHandle<Result<DaemonPromptResponse>>,
}

pub(crate) struct LiveAttachTui {
    pub(crate) session_id: String,
    transcript: String,
    pub(crate) input: String,
    input_cursor: usize,
    command_history: Vec<String>,
    history_index: Option<usize>,
    pub(crate) latest_state: String,
    previous_state: Option<String>,
    received_events: usize,
    pub(crate) last_sequence: u64,
    pub(crate) status_message: Option<String>,
    pub(crate) active_turn_id: Option<String>,
    pending_prompt: Option<InFlightPrompt>,
    pub(crate) pending_approvals: BTreeMap<String, UiApprovalRequest>,
    slash_picker_index: usize,
    shortcuts_overlay_visible: bool,
}

impl LiveAttachTui {
    pub(crate) fn new(session_id: String, latest_state: String) -> Self {
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
            shortcuts_overlay_visible: false,
        }
    }

    pub(crate) fn apply_stream_events(&mut self, stream_events: &[DaemonStreamEnvelope]) {
        if let Some(last) = stream_events.last() {
            self.last_sequence = last.sequence;
        }
        self.received_events += stream_events.len();
        self.apply_ui_events(map_legacy_stream_events(stream_events));
    }

    pub(crate) fn apply_rpc_stream_events(&mut self, stream_events: &[DaemonRpcStreamEnvelope]) {
        if let Some(last) = stream_events.last() {
            self.last_sequence = last.sequence;
        }
        self.received_events += stream_events.len();
        self.apply_ui_events(map_rpc_stream_events(stream_events));
    }

    fn apply_ui_events(&mut self, events: Vec<UiEvent>) {
        for event in events {
            self.apply_ui_event(event);
        }
    }

    fn apply_ui_event(&mut self, event: UiEvent) {
        match event {
            UiEvent::SessionState(state) => {
                if self.previous_state.as_deref() != Some(state.as_str()) {
                    if state == "interrupted" {
                        self.push_line(&format!(
                            "[session interrupted] resume with: crabbot codex resume --session-id {}",
                            self.session_id
                        ));
                    } else if self.previous_state.as_deref() == Some("interrupted")
                        && state == "active"
                    {
                        self.push_line("[session resumed] stream is active again");
                    }
                }
                self.latest_state = state.clone();
                self.previous_state = Some(state);
            }
            UiEvent::ThreadStarted(thread_id) => {
                let changed = self.session_id != thread_id;
                self.session_id = thread_id.clone();
                if changed {
                    self.active_turn_id = None;
                    self.pending_approvals.clear();
                    self.push_line(&format!("[thread switched] {thread_id}"));
                }
                self.status_message = Some("thread started".to_string());
            }
            UiEvent::ThreadRenamed(name) => {
                self.push_line(&format!("[thread renamed] {name}"));
            }
            UiEvent::TurnStarted(turn_id) => {
                self.active_turn_id = Some(turn_id);
                self.status_message = Some("running turn...".to_string());
            }
            UiEvent::AssistantDelta { turn_id, delta } => {
                let is_new_turn = if let Some(turn_id) = turn_id {
                    let is_new = self.active_turn_id.as_deref() != Some(turn_id.as_str());
                    if is_new {
                        self.active_turn_id = Some(turn_id);
                    }
                    is_new
                } else {
                    false
                };
                let delta = if is_new_turn {
                    delta.strip_prefix("Assistant: ").unwrap_or(&delta)
                } else {
                    &delta
                };
                self.append_assistant_delta(delta);
            }
            UiEvent::TurnCompleted { status } => {
                self.active_turn_id = None;
                if let Some(status) = status
                    && status != "completed"
                {
                    self.status_message = Some(format!(
                        "turn {}",
                        text_formatting::capitalize_first(&status)
                    ));
                } else {
                    self.status_message = None;
                }
                if !self.transcript.is_empty() && !self.transcript.ends_with('\n') {
                    self.transcript.push('\n');
                }
            }
            UiEvent::TranscriptLine(line) => {
                self.push_line(&line);
            }
            UiEvent::StatusMessage(message) => {
                self.status_message = Some(message);
            }
            UiEvent::ApprovalRequired(request) => {
                let key = request.key.clone();
                self.pending_approvals.insert(key.clone(), request.clone());
                self.push_line(&format!(
                    "[approval required] request_id={key} method={}",
                    request.method
                ));
                if let Some(reason) = &request.reason {
                    self.push_line(&format!("reason: {reason}"));
                }
            }
        }
    }

    pub(crate) fn push_line(&mut self, line: &str) {
        if !self.transcript.is_empty() && !self.transcript.ends_with('\n') {
            self.transcript.push('\n');
        }
        self.transcript.push_str(line);
        self.transcript.push('\n');
    }

    pub(crate) fn push_user_prompt(&mut self, prompt: &str) {
        let decoded = mention_codec::decode_history_mentions(prompt);
        let display_prompt = decoded.text;
        if !self.transcript.is_empty() && !self.transcript.ends_with("\n\n") {
            if !self.transcript.ends_with('\n') {
                self.transcript.push('\n');
            }
            self.transcript.push('\n');
        }
        self.transcript
            .push_str(&format!("\u{203a} {display_prompt}\n\n"));
    }

    pub(crate) fn append_assistant_delta(&mut self, delta: &str) {
        if delta.is_empty() {
            return;
        }

        self.transcript.push_str(delta);
    }

    pub(crate) fn input_insert_str(&mut self, text: &str) {
        self.shortcuts_overlay_visible = false;
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

    pub(crate) fn input_insert_char(&mut self, ch: char) {
        self.shortcuts_overlay_visible = false;
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

    pub(crate) fn input_backspace(&mut self) {
        self.shortcuts_overlay_visible = false;
        if self.input_cursor == 0 {
            return;
        }
        let previous = previous_char_boundary(&self.input, self.input_cursor);
        self.input.drain(previous..self.input_cursor);
        self.input_cursor = previous;
        self.sync_slash_picker();
    }

    pub(crate) fn input_delete(&mut self) {
        self.shortcuts_overlay_visible = false;
        if self.input_cursor >= self.input.len() {
            return;
        }
        let next = next_char_boundary(&self.input, self.input_cursor);
        self.input.drain(self.input_cursor..next);
        self.sync_slash_picker();
    }

    pub(crate) fn move_input_cursor_left(&mut self) {
        self.input_cursor = previous_char_boundary(&self.input, self.input_cursor);
    }

    pub(crate) fn move_input_cursor_right(&mut self) {
        self.input_cursor = next_char_boundary(&self.input, self.input_cursor);
    }

    pub(crate) fn move_input_cursor_home(&mut self) {
        self.input_cursor = 0;
    }

    pub(crate) fn move_input_cursor_end(&mut self) {
        self.input_cursor = self.input.len();
    }

    pub(crate) fn clear_input(&mut self) {
        self.shortcuts_overlay_visible = false;
        self.input.clear();
        self.input_cursor = 0;
        self.sync_slash_picker();
    }

    pub(crate) fn replace_input(&mut self, text: String) {
        self.shortcuts_overlay_visible = false;
        self.input = text;
        self.input_cursor = self.input.len();
        self.sync_slash_picker();
    }

    pub(crate) fn take_input(&mut self) -> String {
        self.history_index = None;
        self.shortcuts_overlay_visible = false;
        self.input_cursor = 0;
        let taken = std::mem::take(&mut self.input);
        self.sync_slash_picker();
        taken
    }

    pub(crate) fn remember_history_entry(&mut self, text: &str) {
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

    pub(crate) fn history_prev(&mut self) {
        self.shortcuts_overlay_visible = false;
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

    pub(crate) fn history_next(&mut self) {
        self.shortcuts_overlay_visible = false;
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

    pub(crate) fn has_pending_prompt(&self) -> bool {
        self.pending_prompt.is_some()
    }

    pub(crate) fn start_prompt_request(
        &mut self,
        app_server_endpoint: String,
        auth_token: Option<String>,
        prompt: String,
    ) -> Result<()> {
        if self.pending_prompt.is_some() {
            bail!("a prompt is already running");
        }

        let session_id = self.session_id.clone();
        let request_prompt = prompt.clone();
        let handle = thread::spawn(move || {
            app_server_prompt_session(
                &app_server_endpoint,
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

    pub(crate) fn take_finished_prompt(&mut self) -> Option<InFlightPrompt> {
        if self
            .pending_prompt
            .as_ref()
            .is_some_and(|pending| pending.handle.is_finished())
        {
            return self.pending_prompt.take();
        }
        None
    }

    pub(crate) fn input_view(&self, width: usize) -> (String, usize, usize) {
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

    pub(crate) fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        terminal.draw(|frame| {
            // Force a stable baseline palette similar to upstream:
            // black app background with high-contrast foreground text.
            frame.render_widget(
                Paragraph::new("").style(Style::default().bg(Color::Black).fg(Color::White)),
                frame.area(),
            );

            let shortcuts_overlay_lines = self.shortcuts_overlay_lines();
            let shortcuts_overlay_height = shortcuts_overlay_lines.len() as u16;
            let slash_picker_lines = self.slash_picker_lines(frame.area().width as usize);
            let slash_picker_height = slash_picker_lines.len() as u16;
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(1),
                    Constraint::Length(shortcuts_overlay_height),
                    Constraint::Length(slash_picker_height),
                    Constraint::Length(1),
                    Constraint::Length(1),
                ])
                .split(frame.area());

            let history = self.history_view_text();
            let history_lines = history.lines().count().max(1) as u16;
            let scroll = history_lines.saturating_sub(chunks[0].height);
            frame.render_widget(
                Paragraph::new(history)
                    .style(
                        Style::default()
                            .bg(Color::Black)
                            .fg(self.readable_fg_color())
                            .bold(),
                    )
                    .wrap(Wrap { trim: false })
                    .scroll((scroll, 0)),
                chunks[0],
            );

            if shortcuts_overlay_height > 0 {
                frame.render_widget(
                    Paragraph::new(shortcuts_overlay_lines).style(self.composer_row_style()),
                    chunks[1],
                );
            }

            if slash_picker_height > 0 {
                frame.render_widget(
                    Paragraph::new(slash_picker_lines).style(self.composer_row_style()),
                    chunks[2],
                );
            }

            let input_chunk_index = if shortcuts_overlay_height > 0 && slash_picker_height > 0 {
                3
            } else if shortcuts_overlay_height > 0 || slash_picker_height > 0 {
                2
            } else {
                1
            };
            let footer_chunk_index = input_chunk_index + 1;

            let input_width = chunks[input_chunk_index].width as usize;
            let (visible_input, cursor_col, offset) = self.input_view(input_width);
            let input_line = self.input_line(visible_input, offset, input_width);
            frame.render_widget(
                Paragraph::new(input_line).style(self.composer_row_style()),
                chunks[input_chunk_index],
            );

            frame.render_widget(
                Paragraph::new(Line::from(
                    self.footer_line_text(chunks[footer_chunk_index].width as usize),
                ))
                .style(Style::default().fg(self.readable_fg_color())),
                chunks[footer_chunk_index],
            );

            let cursor_x = chunks[input_chunk_index]
                .x
                .saturating_add(cursor_col.try_into().unwrap_or(u16::MAX));
            frame.set_cursor_position((cursor_x, chunks[input_chunk_index].y));
        })?;
        Ok(())
    }

    fn history_view_text(&self) -> String {
        let cwd = display_cwd_for_welcome();
        let mut text = format!(
            "  codex\n\n  >_ OpenAI Codex ({CODEX_CLI_VERSION})\n\n  model:     gpt-5.3-codex medium    /model to change\n\n  directory: {cwd}\n\n  Tip: New 2x rate limits until April 2nd.\n"
        );
        if !self.transcript.trim().is_empty() {
            text.push('\n');
            text.push_str(&self.transcript);
        }
        text
    }

    pub(crate) fn input_line(
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

    pub(crate) fn footer_line_text(&self, width: usize) -> String {
        let left = if self.shortcuts_overlay_visible {
            "  press ? to close shortcuts".to_string()
        } else if let Some(pending) = &self.pending_prompt {
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

    pub(crate) fn context_left_percent(&self) -> usize {
        let consumed = (self.received_events / 12).min(99);
        100_usize.saturating_sub(consumed)
    }

    pub(crate) fn composer_row_style(&self) -> Style {
        // Keep composer panel explicitly grey like upstream.
        Style::default()
            .bg(Color::DarkGray)
            .fg(self.readable_fg_color())
            .bold()
    }

    fn readable_fg_color(&self) -> Color {
        // Explicit ANSI bright white avoids terminals that map default white
        // to a dim/near-background color in alternate screen mode.
        Color::Indexed(15)
    }

    pub(crate) fn special_token_style(&self, token: char) -> Option<Style> {
        let style = match token {
            '!' => Style::default().fg(Color::Yellow).bold(),
            '@' => Style::default().fg(Color::Cyan).bold(),
            '$' => Style::default().fg(Color::Magenta).bold(),
            '/' => Style::default().fg(Color::Green).bold(),
            _ => return None,
        };
        Some(style)
    }

    pub(crate) fn slash_picker_query(&self) -> Option<String> {
        let trimmed = self.input.trim_start();
        if !trimmed.starts_with('/') {
            return None;
        }
        let stripped = trimmed.trim_start_matches('/');
        let token = stripped.trim_start();
        Some(token.split_whitespace().next().unwrap_or("").to_string())
    }

    pub(crate) fn slash_picker_entries(&self) -> Vec<(&'static str, SlashCommand)> {
        let Some(query) = self.slash_picker_query() else {
            return Vec::new();
        };
        builtins_for_input(
            true, // collaboration_modes_enabled
            true, // connectors_enabled
            true, // personality_command_enabled
            true, // allow_elevate_sandbox
        )
        .into_iter()
        .filter(|(command_name, _)| fuzzy_match(command_name, &query).is_some())
        .collect()
    }

    pub(crate) fn slash_picker_is_active(&self) -> bool {
        !self.slash_picker_entries().is_empty()
    }

    pub(crate) fn sync_slash_picker(&mut self) {
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
        } else if self.slash_picker_index >= len {
            self.slash_picker_index = len - 1;
        }
    }

    pub(crate) fn slash_picker_move_up(&mut self) {
        self.shortcuts_overlay_visible = false;
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

    pub(crate) fn slash_picker_move_down(&mut self) {
        self.shortcuts_overlay_visible = false;
        let len = self.slash_picker_entries().len();
        if len == 0 {
            self.slash_picker_index = 0;
            return;
        }
        self.slash_picker_index = (self.slash_picker_index + 1) % len;
    }

    pub(crate) fn selected_slash_entry(&self) -> Option<(&'static str, SlashCommand)> {
        let entries = self.slash_picker_entries();
        let selected = self.slash_picker_index.min(entries.len().saturating_sub(1));
        entries.get(selected).copied()
    }

    pub(crate) fn apply_selected_slash_entry(&mut self) -> bool {
        self.shortcuts_overlay_visible = false;
        let Some(selected) = self.selected_slash_entry() else {
            return false;
        };
        self.replace_input(format!("/{}", selected.0));
        true
    }

    pub(crate) fn should_apply_slash_picker_on_enter(&self) -> bool {
        if !self.slash_picker_is_active() {
            return false;
        }
        let Some(selected) = self.selected_slash_entry() else {
            return false;
        };
        self.input.trim() != format!("/{}", selected.0)
    }

    pub(crate) fn slash_picker_lines(&self, width: usize) -> Vec<Line<'static>> {
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
            .map(|entry| entry.0.len() + 1)
            .max()
            .unwrap_or(12)
            .clamp(12, 30);
        let command_budget = command_col_width.saturating_sub(1);
        let mut lines = Vec::with_capacity(end.saturating_sub(start));
        for (index, entry) in entries[start..end].iter().enumerate() {
            let absolute = start + index;
            let is_selected = absolute == selected;
            let prefix = if is_selected { "› " } else { "  " };
            let command = truncate_for_width(entry.0, command_budget);
            let command_display = format!("/{command}");
            let description = truncate_for_width(
                entry.1.description(),
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

    pub(crate) fn live_input_hint(&self) -> Option<String> {
        if self.shortcuts_overlay_visible {
            return Some("  shortcuts overlay".to_string());
        }
        if let Some(selected) = self.selected_slash_entry() {
            return Some(format!(
                "  {} \u{2022} {}",
                format!("/{}", selected.0),
                selected.1.description()
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

    pub(crate) fn toggle_shortcuts_overlay(&mut self) {
        self.shortcuts_overlay_visible = !self.shortcuts_overlay_visible;
    }

    pub(crate) fn hide_shortcuts_overlay(&mut self) {
        self.shortcuts_overlay_visible = false;
    }

    fn shortcuts_overlay_lines(&self) -> Vec<Line<'static>> {
        if !self.shortcuts_overlay_visible {
            return Vec::new();
        }

        let mut first = Line::default();
        first.push_span(Span::from(key_hint::plain(KeyCode::Char('?'))));
        first.push_span(" help  ");
        first.push_span(Span::from(key_hint::plain(KeyCode::Enter)));
        first.push_span(" send  ");
        first.push_span(Span::from(key_hint::shift(KeyCode::Enter)));
        first.push_span(" newline");

        let mut second = Line::default();
        second.push_span(Span::from(key_hint::ctrl(KeyCode::Char('c'))));
        second.push_span(" detach  ");
        second.push_span(Span::from(key_hint::plain(KeyCode::Up)));
        second.push_span("/");
        second.push_span(Span::from(key_hint::plain(KeyCode::Down)));
        second.push_span(" history  ");
        second.push_span(Span::from(key_hint::plain(KeyCode::Tab)));
        second.push_span(" apply slash command");

        vec![first, second]
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

fn display_cwd_for_welcome() -> String {
    let cwd = env::current_dir()
        .ok()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "~".to_string());
    let home = env::var("HOME").ok();
    if let Some(home) = home
        && cwd == home
    {
        return "~".to_string();
    }
    cwd
}

pub(crate) struct ChatWidget {
    ui: LiveAttachTui,
}

impl ChatWidget {
    pub(crate) fn new(thread_id: String) -> Self {
        Self {
            ui: LiveAttachTui::new(thread_id, "active".to_string()),
        }
    }

    pub(crate) fn ui_mut(&mut self) -> &mut LiveAttachTui {
        &mut self.ui
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.ui.session_id
    }

    pub(crate) fn draw(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        self.ui.draw(terminal)
    }
}

pub(crate) fn get_limits_duration(minutes: i64) -> String {
    if minutes <= 0 {
        return "unknown".to_string();
    }
    if minutes % (60 * 24 * 7) == 0 {
        let weeks = minutes / (60 * 24 * 7);
        return if weeks == 1 {
            "weekly".to_string()
        } else {
            format!("{weeks}w")
        };
    }
    if minutes % (60 * 24) == 0 {
        let days = minutes / (60 * 24);
        return if days == 1 {
            "daily".to_string()
        } else {
            format!("{days}d")
        };
    }
    if minutes % 60 == 0 {
        let hours = minutes / 60;
        return format!("{hours}h");
    }
    format!("{minutes}m")
}

#[cfg(test)]
mod tests {
    use super::LiveAttachTui;

    #[test]
    fn history_view_text_shows_welcome_card_when_empty() {
        let ui = LiveAttachTui::new("sess".to_string(), "active".to_string());
        let text = ui.history_view_text();
        assert!(text.contains("OpenAI Codex"));
        assert!(text.contains("model:"));
        assert!(text.contains("directory:"));
    }

    #[test]
    fn history_view_text_prefers_transcript_when_non_empty() {
        let mut ui = LiveAttachTui::new("sess".to_string(), "active".to_string());
        ui.push_line("hello");
        let text = ui.history_view_text();
        assert!(text.contains("hello"));
        assert!(!text.contains("OpenAI Codex"));
    }
}
