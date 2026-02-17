use crate::app::align_left_right;
use crate::app_event::AppEvent as UiAppEvent;
use crate::app_event_sender::AppEventSender as UiAppEventSender;
use crate::bottom_pane::BottomPane;
use crate::bottom_pane::BottomPaneParams;
use crate::bottom_pane::InputResult;
use crate::bottom_pane::MentionBinding;
use crate::core_compat::UiApprovalRequest;
use crate::core_compat::UiEvent;
use crate::core_compat::map_legacy_stream_events;
use crate::core_compat::map_rpc_stream_events;
use crate::exec_cell::CommandOutput;
use crate::exec_cell::ExecCell;
use crate::exec_cell::new_active_exec_command;
use crate::history_cell::HistoryCell;
use crate::history_cell::McpToolCallCell;
use crate::history_cell::PlainHistoryCell;
use crate::history_cell::SessionHeaderHistoryCell;
use crate::history_cell::new_active_mcp_tool_call;
use crate::history_cell::new_active_web_search_call;
use crate::history_cell::new_error_event;
use crate::history_cell::new_info_event;
use crate::history_cell::new_user_prompt;
use crate::history_cell::new_web_search_call;
use crate::key_hint;
use crate::mention_codec;
use crate::render::Insets;
use crate::render::line_utils::is_blank_line_spaces_only;
use crate::render::renderable::FlexRenderable;
use crate::render::renderable::Renderable;
use crate::render::renderable::RenderableExt;
use crate::render::renderable::RenderableItem;
use crate::slash_command::SlashCommand;
use crate::slash_commands::builtins_for_input;
use crate::streaming::chunking::AdaptiveChunkingPolicy;
use crate::streaming::commit_tick::CommitTickScope;
use crate::streaming::commit_tick::run_commit_tick;
use crate::streaming::controller::StreamController;
use crate::text_formatting;
use crate::version::CODEX_CLI_VERSION;
use crate::*;
use codex_file_search::FileMatch;
use codex_utils_fuzzy_match::fuzzy_match;
use crossterm::event::KeyEvent;
use crossterm::event::MouseEvent;
use crossterm::event::MouseEventKind;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

pub(crate) struct InFlightPrompt {
    pub(crate) prompt: String,
    submitted_at: Instant,
    pub(crate) handle: thread::JoinHandle<Result<DaemonPromptResponse>>,
}

struct TranscriptRenderable<'a> {
    ui: &'a LiveAttachTui,
}

impl Renderable for TranscriptRenderable<'_> {
    fn render(&self, area: Rect, buf: &mut Buffer) {
        let history_lines_vec = self
            .ui
            .history_view_lines(area.width)
            .into_iter()
            .map(|line| pad_line_to_width(line, area.width))
            .collect::<Vec<_>>();
        let history_lines = history_lines_vec.len().max(1) as u16;
        let max_scroll = history_lines.saturating_sub(area.height);
        let scroll = max_scroll.saturating_sub(self.ui.history_scroll_offset.min(max_scroll));
        Paragraph::new(history_lines_vec)
            .style(Style::default())
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0))
            .render(area, buf);
    }

    fn desired_height(&self, width: u16) -> u16 {
        self.ui.history_view_lines(width).len().max(1) as u16
    }
}

/// Mirror upstream `insert_history_lines` behavior for in-viewport transcript rendering:
/// line-level style should visually fill the whole terminal row.
fn pad_line_to_width(mut line: Line<'static>, width: u16) -> Line<'static> {
    if is_blank_line_spaces_only(&line) {
        return line;
    }
    let target = usize::from(width);
    let line_width = line.width();
    if target > line_width {
        let pad = " ".repeat(target - line_width);
        line.spans.push(Span::styled(pad, line.style));
    }
    line
}

pub(crate) struct LiveAttachTui {
    pub(crate) session_id: String,
    history_cells: Vec<Box<dyn HistoryCell>>,
    history_cells_flushed_to_scrollback: usize,
    adaptive_chunking: AdaptiveChunkingPolicy,
    assistant_stream: StreamController,
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
    bottom_pane_event_rx: tokio::sync::mpsc::UnboundedReceiver<UiAppEvent>,
    slash_picker_index: usize,
    shortcuts_overlay_visible: bool,
    kill_buffer: String,
    bottom_pane: BottomPane,
    history_scroll_offset: u16,
}

impl LiveAttachTui {
    pub(crate) fn new(session_id: String, latest_state: String) -> Self {
        let (ui_event_tx, ui_event_rx) = tokio::sync::mpsc::unbounded_channel::<UiAppEvent>();
        let bottom_pane = BottomPane::new(BottomPaneParams {
            app_event_tx: UiAppEventSender::new(ui_event_tx),
            frame_requester: crate::tui::FrameRequester::no_op(),
            has_input_focus: true,
            enhanced_keys_supported: true,
            placeholder_text: TUI_COMPOSER_PLACEHOLDER.to_string(),
            disable_paste_burst: false,
            animations_enabled: true,
            skills: None,
        });
        Self {
            session_id,
            history_cells: Vec::new(),
            history_cells_flushed_to_scrollback: 0,
            adaptive_chunking: AdaptiveChunkingPolicy::default(),
            assistant_stream: StreamController::new(None),
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
            bottom_pane_event_rx: ui_event_rx,
            slash_picker_index: 0,
            shortcuts_overlay_visible: false,
            kill_buffer: String::new(),
            bottom_pane,
            history_scroll_offset: 0,
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
                self.latest_state = "active".to_string();
                self.previous_state = Some("active".to_string());
                if changed {
                    self.active_turn_id = None;
                    self.pending_approvals.clear();
                    self.history_cells.push(Box::new(new_info_event(
                        format!("[thread switched] {thread_id}"),
                        None,
                    )));
                }
                self.status_message = Some("thread started".to_string());
            }
            UiEvent::ThreadRenamed(name) => {
                self.history_cells.push(Box::new(new_info_event(
                    format!("[thread renamed] {name}"),
                    None,
                )));
            }
            UiEvent::TurnStarted(turn_id) => {
                self.active_turn_id = Some(turn_id);
                self.adaptive_chunking.reset();
                self.assistant_stream = StreamController::new(None);
                self.bottom_pane.set_task_running(true);
                self.bottom_pane.set_interrupt_hint_visible(true);
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
                self.flush_assistant_message();
                self.active_turn_id = None;
                self.bottom_pane.set_task_running(false);
                self.bottom_pane.set_interrupt_hint_visible(false);
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
            }
            UiEvent::ExecCommandBegin {
                call_id,
                command,
                parsed,
                source,
            } => self.on_exec_command_begin(call_id, command, parsed, source),
            UiEvent::ExecCommandOutputDelta { call_id, delta } => {
                self.on_exec_command_output_delta(&call_id, &delta);
            }
            UiEvent::ExecCommandEnd {
                call_id,
                exit_code,
                aggregated_output,
                duration,
            } => self.on_exec_command_end(&call_id, exit_code, aggregated_output, duration),
            UiEvent::McpToolCallBegin {
                call_id,
                invocation,
            } => self.on_mcp_tool_call_begin(call_id, invocation),
            UiEvent::McpToolCallEnd {
                call_id,
                duration,
                result,
            } => self.on_mcp_tool_call_end(&call_id, duration, result),
            UiEvent::WebSearchBegin { call_id, query } => {
                self.on_web_search_begin(call_id, query);
            }
            UiEvent::WebSearchEnd {
                call_id,
                query,
                action,
            } => self.on_web_search_end(&call_id, query, action),
            UiEvent::TranscriptLine(line) => {
                self.push_line(&line);
            }
            UiEvent::StatusMessage(message) => {
                self.status_message = Some(message);
            }
            UiEvent::ApprovalRequired(request) => {
                let key = request.key.clone();
                self.pending_approvals.insert(key.clone(), request.clone());
                self.history_cells.push(Box::new(new_info_event(
                    format!(
                        "[approval required] request_id={key} method={}",
                        request.method
                    ),
                    None,
                )));
                if let Some(reason) = &request.reason {
                    self.history_cells.push(Box::new(new_info_event(
                        "reason".to_string(),
                        Some(reason.clone()),
                    )));
                }
            }
        }
        self.sync_bottom_pane_status();
    }

    pub(crate) fn push_line(&mut self, line: &str) {
        self.flush_assistant_message();
        let trimmed = line.trim_start();
        if trimmed.starts_with("[error") || trimmed.starts_with("error:") {
            self.history_cells
                .push(Box::new(new_error_event(line.to_string())));
        } else if trimmed.starts_with('[') && trimmed.ends_with(']') {
            self.history_cells
                .push(Box::new(new_info_event(line.to_string(), None)));
        } else {
            self.history_cells.push(Box::new(PlainHistoryCell::new(vec![
                line.to_string().into(),
            ])));
        }
    }

    pub(crate) fn push_user_prompt(
        &mut self,
        prompt: &str,
        text_elements: Vec<codex_protocol::user_input::TextElement>,
    ) {
        self.assistant_stream = StreamController::new(None);
        let decoded = mention_codec::decode_history_mentions(prompt);
        let display_prompt = decoded.text;
        self.history_cells.push(Box::new(new_user_prompt(
            display_prompt,
            text_elements,
            Vec::new(),
            Vec::new(),
        )));
    }

    pub(crate) fn append_assistant_delta(&mut self, delta: &str) {
        if delta.is_empty() {
            return;
        }
        self.assistant_stream.push(delta);
    }

    fn flush_assistant_message(&mut self) {
        if let Some(cell) = self.assistant_stream.finalize() {
            self.history_cells.push(cell);
        }
    }

    fn on_exec_command_begin(
        &mut self,
        call_id: String,
        command: Vec<String>,
        parsed: Vec<codex_protocol::parse_command::ParsedCommand>,
        source: codex_core::protocol::ExecCommandSource,
    ) {
        self.flush_assistant_message();
        if let Some(last) = self.history_cells.last_mut()
            && let Some(exec_cell) = last.as_any_mut().downcast_mut::<ExecCell>()
            && let Some(updated) = exec_cell.with_added_call(
                call_id.clone(),
                command.clone(),
                parsed.clone(),
                source,
                None,
            )
        {
            *exec_cell = updated;
            return;
        }

        self.history_cells.push(Box::new(new_active_exec_command(
            call_id, command, parsed, source, None, true,
        )));
    }

    fn on_exec_command_output_delta(&mut self, call_id: &str, delta: &str) {
        if delta.is_empty() {
            return;
        }
        for cell in self.history_cells.iter_mut().rev() {
            let Some(exec_cell) = cell.as_any_mut().downcast_mut::<ExecCell>() else {
                continue;
            };
            if exec_cell.append_output(call_id, delta) {
                return;
            }
        }

        self.push_line(delta);
    }

    fn on_exec_command_end(
        &mut self,
        call_id: &str,
        exit_code: i32,
        aggregated_output: String,
        duration: Duration,
    ) {
        for cell in self.history_cells.iter_mut().rev() {
            let Some(exec_cell) = cell.as_any_mut().downcast_mut::<ExecCell>() else {
                continue;
            };
            if !exec_cell.iter_calls().any(|call| call.call_id == call_id) {
                continue;
            }

            let mut output_text = exec_cell
                .calls
                .iter()
                .rev()
                .find(|call| call.call_id == call_id)
                .and_then(|call| call.output.as_ref())
                .map(|output| output.aggregated_output.clone())
                .unwrap_or_default();
            if !aggregated_output.is_empty() {
                output_text = aggregated_output;
            }

            exec_cell.complete_call(
                call_id,
                CommandOutput {
                    exit_code,
                    aggregated_output: output_text.clone(),
                    formatted_output: output_text,
                },
                duration,
            );
            return;
        }

        self.history_cells.push(Box::new(new_info_event(
            format!("[exec done] {call_id}"),
            None,
        )));
    }

    fn on_mcp_tool_call_begin(
        &mut self,
        call_id: String,
        invocation: codex_core::protocol::McpInvocation,
    ) {
        self.flush_assistant_message();
        self.history_cells.push(Box::new(new_active_mcp_tool_call(
            call_id, invocation, true,
        )));
    }

    fn on_mcp_tool_call_end(
        &mut self,
        call_id: &str,
        duration: Duration,
        result: Result<codex_protocol::mcp::CallToolResult, String>,
    ) {
        for cell in self.history_cells.iter_mut().rev() {
            let Some(mcp_cell) = cell.as_any_mut().downcast_mut::<McpToolCallCell>() else {
                continue;
            };
            if mcp_cell.call_id() != call_id {
                continue;
            }
            if let Some(image_cell) = mcp_cell.complete(duration, result) {
                self.history_cells.push(image_cell);
            }
            return;
        }

        self.history_cells.push(Box::new(new_info_event(
            format!("[mcp done] {call_id}"),
            None,
        )));
    }

    fn on_web_search_begin(&mut self, call_id: String, query: String) {
        self.flush_assistant_message();
        self.history_cells
            .push(Box::new(new_active_web_search_call(call_id, query, true)));
    }

    fn on_web_search_end(
        &mut self,
        call_id: &str,
        query: String,
        action: codex_protocol::models::WebSearchAction,
    ) {
        for cell in self.history_cells.iter_mut().rev() {
            let Some(web_cell) = cell
                .as_any_mut()
                .downcast_mut::<crate::history_cell::WebSearchCell>()
            else {
                continue;
            };
            if web_cell.call_id() != call_id {
                continue;
            }
            web_cell.update(action.clone(), query.clone());
            web_cell.complete();
            return;
        }
        self.history_cells.push(Box::new(new_web_search_call(
            call_id.to_string(),
            query,
            action,
        )));
    }

    pub(crate) fn commit_assistant_stream_tick(&mut self) -> bool {
        let output = run_commit_tick(
            &mut self.adaptive_chunking,
            Some(&mut self.assistant_stream),
            None,
            CommitTickScope::AnyMode,
            Instant::now(),
        );
        if output.cells.is_empty() {
            return false;
        }
        self.history_cells.extend(output.cells);
        true
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
        self.move_input_cursor_to_beginning_of_line(false);
    }

    pub(crate) fn move_input_cursor_end(&mut self) {
        self.move_input_cursor_to_end_of_line(false);
    }

    pub(crate) fn move_input_cursor_word_left(&mut self) {
        self.input_cursor = self.beginning_of_previous_word();
    }

    pub(crate) fn move_input_cursor_word_right(&mut self) {
        self.input_cursor = self.end_of_next_word();
    }

    pub(crate) fn delete_input_word_backward(&mut self) {
        self.shortcuts_overlay_visible = false;
        let start = self.beginning_of_previous_word();
        self.kill_range(start, self.input_cursor);
        self.sync_slash_picker();
    }

    pub(crate) fn delete_input_word_forward(&mut self) {
        self.shortcuts_overlay_visible = false;
        let end = self.end_of_next_word();
        self.kill_range(self.input_cursor, end);
        self.sync_slash_picker();
    }

    pub(crate) fn move_input_cursor_to_beginning_of_line(&mut self, move_up_at_bol: bool) {
        let bol = self.beginning_of_current_line();
        if move_up_at_bol && self.input_cursor == bol {
            self.input_cursor = self.beginning_of_line(bol.saturating_sub(1));
        } else {
            self.input_cursor = bol;
        }
    }

    pub(crate) fn move_input_cursor_to_end_of_line(&mut self, move_down_at_eol: bool) {
        let eol = self.end_of_current_line();
        if move_down_at_eol && self.input_cursor == eol {
            let next_pos = (self.input_cursor.saturating_add(1)).min(self.input.len());
            self.input_cursor = self.end_of_line(next_pos);
        } else {
            self.input_cursor = eol;
        }
    }

    pub(crate) fn kill_to_beginning_of_line(&mut self) {
        self.shortcuts_overlay_visible = false;
        let bol = self.beginning_of_current_line();
        if self.input_cursor == bol {
            if bol > 0 {
                self.kill_range(bol - 1, bol);
            }
        } else {
            self.kill_range(bol, self.input_cursor);
        }
        self.sync_slash_picker();
    }

    pub(crate) fn kill_to_end_of_line(&mut self) {
        self.shortcuts_overlay_visible = false;
        let eol = self.end_of_current_line();
        if self.input_cursor == eol {
            if eol < self.input.len() {
                self.kill_range(self.input_cursor, eol + 1);
            }
        } else {
            self.kill_range(self.input_cursor, eol);
        }
        self.sync_slash_picker();
    }

    pub(crate) fn yank_kill_buffer(&mut self) {
        if self.kill_buffer.is_empty() {
            return;
        }
        let pasted = self.kill_buffer.clone();
        self.input_insert_str(&pasted);
    }

    pub(crate) fn move_input_cursor_up(&mut self) {
        let line_start = self.beginning_of_current_line();
        if line_start == 0 {
            self.input_cursor = 0;
            return;
        }
        let target_col = display_width(&self.input[line_start..self.input_cursor]);
        let prev_line_end = line_start.saturating_sub(1);
        let prev_line_start = self.beginning_of_line(prev_line_end);
        self.input_cursor =
            byte_index_for_display_col(&self.input, prev_line_start, prev_line_end, target_col);
    }

    pub(crate) fn move_input_cursor_down(&mut self) {
        let line_end = self.end_of_current_line();
        if line_end >= self.input.len() {
            self.input_cursor = self.input.len();
            return;
        }
        let line_start = self.beginning_of_current_line();
        let target_col = display_width(&self.input[line_start..self.input_cursor]);
        let next_line_start = line_end + 1;
        let next_line_end = self.end_of_line(next_line_start);
        self.input_cursor =
            byte_index_for_display_col(&self.input, next_line_start, next_line_end, target_col);
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

    fn kill_range(&mut self, start: usize, end: usize) {
        let start = start.min(self.input.len());
        let end = end.min(self.input.len());
        if start >= end {
            return;
        }
        self.kill_buffer = self.input[start..end].to_string();
        self.input.drain(start..end);
        self.input_cursor = start.min(self.input.len());
    }

    fn beginning_of_line(&self, pos: usize) -> usize {
        self.input[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0)
    }

    fn end_of_line(&self, pos: usize) -> usize {
        self.input[pos..]
            .find('\n')
            .map(|i| i + pos)
            .unwrap_or(self.input.len())
    }

    fn beginning_of_current_line(&self) -> usize {
        self.beginning_of_line(self.input_cursor)
    }

    fn end_of_current_line(&self) -> usize {
        self.end_of_line(self.input_cursor)
    }

    fn beginning_of_previous_word(&self) -> usize {
        let prefix = &self.input[..self.input_cursor];
        let trimmed_end = prefix.trim_end_matches(char::is_whitespace);
        if trimmed_end.is_empty() {
            return 0;
        }
        let mut iter = trimmed_end.char_indices().rev();
        let Some((_, first_ch)) = iter.next() else {
            return 0;
        };
        let is_separator = is_word_separator(first_ch);
        for (idx, ch) in iter {
            if ch.is_whitespace() || is_word_separator(ch) != is_separator {
                return idx + ch.len_utf8();
            }
        }
        0
    }

    fn end_of_next_word(&self) -> usize {
        let suffix = &self.input[self.input_cursor..];
        let Some(first_non_ws) = suffix.find(|c: char| !c.is_whitespace()) else {
            return self.input.len();
        };
        let word_start = self.input_cursor + first_non_ws;
        let mut iter = self.input[word_start..].char_indices();
        let Some((_, first_ch)) = iter.next() else {
            return word_start;
        };
        let is_separator = is_word_separator(first_ch);
        let mut end = self.input.len();
        for (idx, ch) in iter {
            if ch.is_whitespace() || is_word_separator(ch) != is_separator {
                end = word_start + idx;
                break;
            }
        }
        end
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
        self.bottom_pane.set_task_running(true);
        self.bottom_pane.set_interrupt_hint_visible(true);
        self.sync_bottom_pane_status();
        Ok(())
    }

    pub(crate) fn take_finished_prompt(&mut self) -> Option<InFlightPrompt> {
        let done = self
            .pending_prompt
            .as_ref()
            .is_some_and(|pending| pending.handle.is_finished());
        if done {
            self.bottom_pane.set_task_running(false);
            self.bottom_pane.set_interrupt_hint_visible(false);
            self.sync_bottom_pane_status();
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

    pub(crate) fn desired_height(&self, width: u16) -> u16 {
        self.as_renderable().desired_height(width)
    }

    pub(crate) fn render(&mut self, area: Rect, buf: &mut Buffer) {
        self.as_renderable().render(area, buf);
    }

    pub(crate) fn cursor_pos(&self, area: Rect) -> Option<(u16, u16)> {
        self.as_renderable().cursor_pos(area)
    }

    pub(crate) fn scroll_history_page_up(&mut self) {
        let step = 10u16;
        self.history_scroll_offset = self.history_scroll_offset.saturating_add(step);
    }

    pub(crate) fn scroll_history_page_down(&mut self) {
        let step = 10u16;
        self.history_scroll_offset = self.history_scroll_offset.saturating_sub(step);
    }

    pub(crate) fn handle_mouse_event(&mut self, mouse_event: MouseEvent) {
        match mouse_event.kind {
            MouseEventKind::ScrollUp => {
                self.history_scroll_offset = self.history_scroll_offset.saturating_add(3);
            }
            MouseEventKind::ScrollDown => {
                self.history_scroll_offset = self.history_scroll_offset.saturating_sub(3);
            }
            _ => {}
        }
    }

    pub(crate) fn handle_bottom_pane_key_event(&mut self, key: KeyEvent) -> InputResult {
        self.bottom_pane.handle_key_event(key)
    }

    pub(crate) fn drain_bottom_pane_events(&mut self) -> Vec<UiAppEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.bottom_pane_event_rx.try_recv() {
            events.push(event);
        }
        events
    }

    pub(crate) fn handle_bottom_pane_paste(&mut self, text: String) {
        self.bottom_pane.handle_paste(text);
    }

    pub(crate) fn flush_bottom_pane_paste_burst_if_due(&mut self) -> bool {
        self.bottom_pane.flush_paste_burst_if_due()
    }

    pub(crate) fn bottom_pane_is_in_paste_burst(&self) -> bool {
        self.bottom_pane.is_in_paste_burst()
    }

    pub(crate) fn bottom_pane_is_task_running(&self) -> bool {
        self.bottom_pane.is_task_running()
    }

    pub(crate) fn bottom_pane_no_modal_or_popup_active(&self) -> bool {
        self.bottom_pane.no_modal_or_popup_active()
    }

    pub(crate) fn bottom_pane_composer_text(&self) -> String {
        self.bottom_pane.composer_text()
    }

    pub(crate) fn bottom_pane_insert_str(&mut self, text: &str) {
        self.bottom_pane.insert_str(text);
    }

    pub(crate) fn open_status_line_setup(&mut self, status_line_items: Option<&[String]>) {
        self.bottom_pane.open_status_line_setup(status_line_items);
    }

    pub(crate) fn show_selection_view(&mut self, params: crate::bottom_pane::SelectionViewParams) {
        self.bottom_pane.show_selection_view(params);
    }

    pub(crate) fn set_status_message(&mut self, message: Option<String>) {
        self.status_message = message;
        self.sync_bottom_pane_status();
    }

    pub(crate) fn take_recent_submission_mention_bindings(&mut self) -> Vec<MentionBinding> {
        self.bottom_pane.take_recent_submission_mention_bindings()
    }

    pub(crate) fn drain_pending_submission_state(&mut self) {
        self.bottom_pane.drain_pending_submission_state();
    }

    pub(crate) fn apply_file_search_result(&mut self, query: String, matches: Vec<FileMatch>) {
        self.bottom_pane.on_file_search_result(query, matches);
    }

    pub(crate) fn add_history_cell(&mut self, cell: Box<dyn HistoryCell>) {
        self.flush_assistant_message();
        self.history_cells.push(cell);
    }

    pub(crate) fn reset_for_thread_switch(&mut self, thread_id: String) {
        self.session_id = thread_id;
        self.history_cells.clear();
        self.history_cells_flushed_to_scrollback = 0;
        self.assistant_stream = StreamController::new(None);
        self.adaptive_chunking.reset();
        self.active_turn_id = None;
        self.pending_approvals.clear();
        self.pending_prompt = None;
        self.history_scroll_offset = 0;
        self.previous_state = None;
        self.latest_state = "active".to_string();
        self.received_events = 0;
        self.last_sequence = 0;
        self.clear_input();
    }

    pub(crate) fn take_new_history_lines_for_scrollback(
        &mut self,
        width: u16,
    ) -> Vec<Line<'static>> {
        if self.history_cells_flushed_to_scrollback >= self.history_cells.len() {
            return Vec::new();
        }

        let mut lines = Vec::new();
        for cell in self
            .history_cells
            .iter()
            .skip(self.history_cells_flushed_to_scrollback)
        {
            lines.extend(cell.display_lines(width));
        }
        self.history_cells_flushed_to_scrollback = self.history_cells.len();
        lines
    }

    pub(crate) fn set_skills(
        &mut self,
        skills: Option<Vec<codex_core::skills::model::SkillMetadata>>,
    ) {
        self.bottom_pane.set_skills(skills);
    }

    pub(crate) fn set_connectors_snapshot(
        &mut self,
        snapshot: Option<crate::app_event::ConnectorsSnapshot>,
    ) {
        self.bottom_pane.set_connectors_snapshot(snapshot);
    }

    fn sync_bottom_pane_status(&mut self) {
        if let Some(msg) = &self.status_message {
            self.bottom_pane
                .update_status("session".to_string(), Some(msg.clone()));
        } else {
            self.bottom_pane.hide_status_indicator();
        }
    }

    fn as_renderable(&self) -> RenderableItem<'_> {
        let transcript = RenderableItem::Owned(Box::new(TranscriptRenderable { ui: self }))
            .inset(Insets::tlbr(1, 0, 0, 0));
        let mut flex = FlexRenderable::new();
        flex.push(1, transcript);
        flex.push(
            0,
            RenderableItem::Borrowed(&self.bottom_pane).inset(Insets::tlbr(1, 0, 0, 0)),
        );
        RenderableItem::Owned(Box::new(flex))
    }

    fn history_view_lines(&self, width: u16) -> Vec<Line<'static>> {
        let header = SessionHeaderHistoryCell::new(
            "gpt-5.3-codex".to_string(),
            None,
            env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            CODEX_CLI_VERSION,
        );
        let mut lines = HistoryCell::display_lines(&header, width);
        let has_content = !self.history_cells.is_empty();
        if !has_content {
            lines.push(Line::from(""));
            lines.push(
                "  To get started, describe a task or try one of these commands:"
                    .dim()
                    .into(),
            );
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                "  ".into(),
                "/init".into(),
                " - create an AGENTS.md file with instructions for Codex".dim(),
            ]));
            lines.push(Line::from(vec![
                "  ".into(),
                "/status".into(),
                " - show current session configuration".dim(),
            ]));
            lines.push(Line::from(vec![
                "  ".into(),
                "/permissions".into(),
                " - choose what Codex is allowed to do".dim(),
            ]));
            lines.push(Line::from(vec![
                "  ".into(),
                "/model".into(),
                " - choose what model and reasoning effort to use".dim(),
            ]));
            lines.push(Line::from(vec![
                "  ".into(),
                "/review".into(),
                " - review any changes and find issues".dim(),
            ]));
        }
        for cell in self
            .history_cells
            .iter()
            .skip(self.history_cells_flushed_to_scrollback)
        {
            lines.extend(cell.display_lines(width));
        }
        if lines.is_empty() {
            lines.push(Line::from(""));
        }
        lines
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
        Style::default().bold()
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

    pub(crate) fn shortcuts_overlay_visible(&self) -> bool {
        self.shortcuts_overlay_visible
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

        let mut third = Line::default();
        third.push_span(Span::from(key_hint::ctrl(KeyCode::Char('a'))));
        third.push_span("/");
        third.push_span(Span::from(key_hint::ctrl(KeyCode::Char('e'))));
        third.push_span(" line home/end  ");
        third.push_span(Span::from(key_hint::alt(KeyCode::Char('b'))));
        third.push_span("/");
        third.push_span(Span::from(key_hint::alt(KeyCode::Char('f'))));
        third.push_span(" word move");

        vec![first, second, third]
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

fn is_word_separator(ch: char) -> bool {
    matches!(
        ch,
        '.' | ','
            | ';'
            | ':'
            | '!'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '<'
            | '>'
            | '/'
            | '\\'
            | '|'
            | '"'
            | '\''
            | '`'
            | '~'
            | '@'
            | '#'
            | '$'
            | '%'
            | '^'
            | '&'
            | '*'
            | '-'
            | '+'
            | '='
    )
}

fn display_width(text: &str) -> usize {
    text.chars().count()
}

fn byte_index_for_display_col(
    text: &str,
    line_start: usize,
    line_end: usize,
    target_col: usize,
) -> usize {
    let line = &text[line_start..line_end];
    if target_col == 0 {
        return line_start;
    }
    let mut col = 0usize;
    for (idx, _) in line.char_indices() {
        if col >= target_col {
            return line_start + idx;
        }
        col += 1;
    }
    line_end
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

    pub(crate) fn desired_height(&self, width: u16) -> u16 {
        self.ui.desired_height(width)
    }

    pub(crate) fn render(&mut self, area: Rect, buf: &mut Buffer) {
        self.ui.render(area, buf)
    }

    pub(crate) fn cursor_pos(&self, area: Rect) -> Option<(u16, u16)> {
        self.ui.cursor_pos(area)
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
    fn history_view_lines_shows_welcome_card_when_empty() {
        let ui = LiveAttachTui::new("sess".to_string(), "active".to_string());
        let lines = ui.history_view_lines(100);
        let rendered = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("OpenAI Codex"));
        assert!(rendered.contains("model:"));
        assert!(rendered.contains("directory:"));
    }

    #[test]
    fn history_view_lines_includes_transcript_when_non_empty() {
        let mut ui = LiveAttachTui::new("sess".to_string(), "active".to_string());
        ui.push_line("hello");
        let lines = ui.history_view_lines(100);
        let rendered = lines
            .into_iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("hello"));
        assert!(rendered.contains("OpenAI Codex"));
    }

    #[test]
    fn input_word_navigation_and_deletion() {
        let mut ui = LiveAttachTui::new("sess".to_string(), "active".to_string());
        ui.replace_input("alpha beta gamma".to_string());
        ui.move_input_cursor_word_left();
        ui.move_input_cursor_word_left();
        assert_eq!(&ui.input[ui.input_cursor..], "beta gamma");
        ui.delete_input_word_forward();
        assert_eq!(ui.input, "alpha  gamma");
    }

    #[test]
    fn kill_and_yank_line_segments() {
        let mut ui = LiveAttachTui::new("sess".to_string(), "active".to_string());
        ui.replace_input("hello world".to_string());
        ui.move_input_cursor_word_right();
        ui.kill_to_end_of_line();
        assert_eq!(ui.input, "hello");
        ui.yank_kill_buffer();
        assert_eq!(ui.input, "hello world");
    }
}
