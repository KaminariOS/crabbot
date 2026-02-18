use crate::app::align_left_right;
use crate::app_event::AppEvent as UiAppEvent;
use crate::app_event_sender::AppEventSender as UiAppEventSender;
use crate::bottom_pane::BottomPane;
use crate::bottom_pane::BottomPaneParams;
use crate::bottom_pane::InputResult;
use crate::bottom_pane::MentionBinding;
use crate::exec_cell::CommandOutput;
use crate::exec_cell::ExecCell;
use crate::exec_cell::new_active_exec_command;
use crate::exec_command::strip_bash_lc_and_escape;
use crate::history_cell::HistoryCell;
use crate::history_cell::McpToolCallCell;
use crate::history_cell::PlainHistoryCell;
use crate::history_cell::SessionInfoCell;
use crate::history_cell::new_active_mcp_tool_call;
use crate::history_cell::new_active_web_search_call;
use crate::history_cell::new_error_event;
use crate::history_cell::new_info_event;
use crate::history_cell::new_patch_apply_failure;
use crate::history_cell::new_patch_event;
use crate::history_cell::new_unified_exec_interaction;
use crate::history_cell::new_user_prompt;
use crate::history_cell::new_view_image_tool_call;
use crate::history_cell::new_web_search_call;
use crate::key_hint;
use crate::mention_codec;
use crate::render::Insets;
use crate::render::renderable::FlexRenderable;
use crate::render::renderable::Renderable;
use crate::render::renderable::RenderableExt;
use crate::render::renderable::RenderableItem;
use crate::slash_command::SlashCommand;
use crate::slash_commands::builtins_for_input;
use crate::status::RateLimitSnapshotDisplay;
use crate::status::RateLimitWindowDisplay;
use crate::status::format_directory_display;
use crate::status::format_tokens_compact;
use crate::status::rate_limit_snapshot_display_for_limit;
use crate::streaming::chunking::AdaptiveChunkingPolicy;
use crate::streaming::commit_tick::CommitTickScope;
use crate::streaming::commit_tick::run_commit_tick;
use crate::streaming::controller::StreamController;
use crate::text_formatting;
use crate::version::CODEX_CLI_VERSION;
use crate::*;
use codex_core::UiApprovalRequest;
use codex_core::UiEvent;
use codex_core::map_codex_protocol_event;
use codex_core::map_legacy_stream_events;
use codex_core::map_rpc_stream_events;
use codex_file_search::FileMatch;
use codex_utils_fuzzy_match::fuzzy_match;
use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use std::any::TypeId;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateLimitErrorKind {
    ServerOverloaded,
    UsageLimit,
    Generic,
}

fn rate_limit_error_kind(message: &str) -> Option<RateLimitErrorKind> {
    let msg = message.to_ascii_lowercase();
    if msg.contains("server overloaded") || msg.contains("high load") {
        return Some(RateLimitErrorKind::ServerOverloaded);
    }
    if msg.contains("rate limit") || msg.contains("usage limit") {
        return Some(RateLimitErrorKind::UsageLimit);
    }
    if msg.contains("limit") || msg.contains("overload") {
        return Some(RateLimitErrorKind::Generic);
    }
    None
}

pub(crate) struct InFlightPrompt {
    pub(crate) prompt: String,
    submitted_at: Instant,
    pub(crate) handle: thread::JoinHandle<Result<DaemonPromptResponse>>,
}

struct RunningCommand {
    process_id: Option<String>,
    command: Vec<String>,
    parsed_cmd: Vec<codex_protocol::parse_command::ParsedCommand>,
    source: codex_core::protocol::ExecCommandSource,
}

struct UnifiedExecProcessSummary {
    key: String,
    call_id: String,
    command_display: String,
    recent_chunks: Vec<String>,
}

struct UnifiedExecWaitState {
    command_display: String,
}

impl UnifiedExecWaitState {
    fn new(command_display: String) -> Self {
        Self { command_display }
    }

    fn is_duplicate(&self, command_display: &str) -> bool {
        self.command_display == command_display
    }
}

const DEFAULT_STATUS_LINE_ITEMS: [&str; 3] =
    ["model-with-reasoning", "context-remaining", "current-dir"];

#[derive(Clone, Debug)]
struct UnifiedExecWaitStreak {
    process_id: String,
    command_display: Option<String>,
}

impl UnifiedExecWaitStreak {
    fn new(process_id: String, command_display: Option<String>) -> Self {
        Self {
            process_id,
            command_display: command_display.filter(|display| !display.is_empty()),
        }
    }

    fn update_command_display(&mut self, command_display: Option<String>) {
        if self.command_display.is_some() {
            return;
        }
        self.command_display = command_display.filter(|display| !display.is_empty());
    }
}

#[derive(Debug)]
enum QueuedUiInterrupt {
    ExecApprovalRequest {
        id: String,
        command: Vec<String>,
        reason: Option<String>,
        network_approval_context: Option<codex_core::protocol::NetworkApprovalContext>,
    },
    PatchApprovalRequest {
        id: String,
        reason: Option<String>,
        cwd: std::path::PathBuf,
        changes: std::collections::HashMap<std::path::PathBuf, codex_core::protocol::FileChange>,
    },
    ElicitationRequest {
        server_name: String,
        request_id: codex_protocol::mcp::RequestId,
        message: String,
    },
    RequestUserInputRequest(codex_protocol::request_user_input::RequestUserInputEvent),
    ExecCommandBegin {
        call_id: String,
        process_id: Option<String>,
        command: Vec<String>,
        parsed: Vec<codex_protocol::parse_command::ParsedCommand>,
        source: codex_core::protocol::ExecCommandSource,
    },
    ExecCommandEnd {
        call_id: String,
        process_id: Option<String>,
        source: codex_core::protocol::ExecCommandSource,
        exit_code: i32,
        formatted_output: String,
        aggregated_output: String,
        duration: Duration,
    },
    McpToolCallBegin {
        call_id: String,
        invocation: codex_core::protocol::McpInvocation,
    },
    McpToolCallEnd {
        call_id: String,
        duration: Duration,
        result: Result<codex_protocol::mcp::CallToolResult, String>,
    },
}

pub(crate) struct LiveAttachTui {
    pub(crate) session_id: String,
    history_cells: Vec<Box<dyn HistoryCell>>,
    active_cell: Option<Box<dyn HistoryCell>>,
    active_cell_revision: u64,
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
    bottom_pane_event_tx: UiAppEventSender,
    bottom_pane_event_rx: tokio::sync::mpsc::UnboundedReceiver<UiAppEvent>,
    slash_picker_index: usize,
    shortcuts_overlay_visible: bool,
    kill_buffer: String,
    bottom_pane: BottomPane,
    active_collaboration_mask: Option<codex_protocol::config_types::CollaborationModeMask>,
    token_info: Option<codex_core::protocol::TokenUsageInfo>,
    total_token_usage: codex_core::protocol::TokenUsage,
    rate_limit_snapshots_by_limit_id: BTreeMap<String, RateLimitSnapshotDisplay>,
    running_commands: HashMap<String, RunningCommand>,
    suppressed_exec_calls: HashSet<String>,
    last_unified_wait: Option<UnifiedExecWaitState>,
    unified_exec_wait_streak: Option<UnifiedExecWaitStreak>,
    unified_exec_processes: Vec<UnifiedExecProcessSummary>,
    pending_interrupts: VecDeque<QueuedUiInterrupt>,
    local_user_message_echoes: VecDeque<String>,
    agent_turn_running: bool,
    mcp_startup_running: bool,
    retry_status_message: Option<String>,
    had_work_activity: bool,
    turn_runtime_metrics: codex_otel::RuntimeMetricsSummary,
    reasoning_buffer: String,
    full_reasoning_buffer: String,
    pending_status_indicator_restore: bool,
    is_review_mode: bool,
    pre_review_token_info: Option<Option<codex_core::protocol::TokenUsageInfo>>,
    current_rollout_path: Option<std::path::PathBuf>,
    status_line_items: Option<Vec<String>>,
    status_line_invalid_items_warned: bool,
    status_line_branch: Option<String>,
    status_line_branch_cwd: Option<PathBuf>,
    status_line_branch_pending: bool,
    status_line_branch_lookup_complete: bool,
}

pub(crate) struct ReviewCommitPickerEntry {
    pub(crate) sha: String,
    pub(crate) subject: String,
}

pub(crate) struct SkillsToggleEntry {
    pub(crate) path: std::path::PathBuf,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) enabled: bool,
}

impl LiveAttachTui {
    pub(crate) fn new(session_id: String, latest_state: String) -> Self {
        let (ui_event_tx_raw, ui_event_rx) = tokio::sync::mpsc::unbounded_channel::<UiAppEvent>();
        let ui_event_tx = UiAppEventSender::new(ui_event_tx_raw);
        let (draw_tx, _draw_rx) = tokio::sync::broadcast::channel(1);
        let bottom_pane = BottomPane::new(BottomPaneParams {
            app_event_tx: ui_event_tx.clone(),
            frame_requester: crate::tui::FrameRequester::new(draw_tx),
            has_input_focus: true,
            enhanced_keys_supported: true,
            placeholder_text: TUI_COMPOSER_PLACEHOLDER.to_string(),
            disable_paste_burst: false,
            animations_enabled: true,
            skills: None,
        });
        let mut bottom_pane = bottom_pane;
        bottom_pane.set_collaboration_modes_enabled(true);
        bottom_pane.set_status_line_enabled(!DEFAULT_STATUS_LINE_ITEMS.is_empty());
        Self {
            session_id,
            history_cells: Vec::new(),
            active_cell: None,
            active_cell_revision: 0,
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
            bottom_pane_event_tx: ui_event_tx,
            bottom_pane_event_rx: ui_event_rx,
            slash_picker_index: 0,
            shortcuts_overlay_visible: false,
            kill_buffer: String::new(),
            bottom_pane,
            active_collaboration_mask: None,
            token_info: None,
            total_token_usage: codex_core::protocol::TokenUsage::default(),
            rate_limit_snapshots_by_limit_id: BTreeMap::new(),
            running_commands: HashMap::new(),
            suppressed_exec_calls: HashSet::new(),
            last_unified_wait: None,
            unified_exec_wait_streak: None,
            unified_exec_processes: Vec::new(),
            pending_interrupts: VecDeque::new(),
            local_user_message_echoes: VecDeque::new(),
            agent_turn_running: false,
            mcp_startup_running: false,
            retry_status_message: None,
            had_work_activity: false,
            turn_runtime_metrics: codex_otel::RuntimeMetricsSummary::default(),
            reasoning_buffer: String::new(),
            full_reasoning_buffer: String::new(),
            pending_status_indicator_restore: false,
            is_review_mode: false,
            pre_review_token_info: None,
            current_rollout_path: None,
            status_line_items: None,
            status_line_invalid_items_warned: false,
            status_line_branch: None,
            status_line_branch_cwd: None,
            status_line_branch_pending: false,
            status_line_branch_lookup_complete: false,
        }
    }

    pub(crate) fn apply_stream_events(&mut self, stream_events: &[DaemonStreamEnvelope]) {
        self.apply_stream_events_with_replay(stream_events, false);
    }

    pub(crate) fn apply_stream_events_with_replay(
        &mut self,
        stream_events: &[DaemonStreamEnvelope],
        from_replay: bool,
    ) {
        if let Some(last) = stream_events.last() {
            self.last_sequence = last.sequence;
        }
        self.received_events += stream_events.len();
        self.apply_ui_events(map_legacy_stream_events(stream_events), from_replay);
    }

    pub(crate) fn apply_rpc_stream_events(&mut self, stream_events: &[DaemonRpcStreamEnvelope]) {
        self.apply_rpc_stream_events_with_replay(stream_events, false);
    }

    pub(crate) fn apply_rpc_stream_events_with_replay(
        &mut self,
        stream_events: &[DaemonRpcStreamEnvelope],
        from_replay: bool,
    ) {
        if let Some(last) = stream_events.last() {
            self.last_sequence = last.sequence;
        }
        self.received_events += stream_events.len();
        self.apply_ui_events(map_rpc_stream_events(stream_events), from_replay);
    }

    pub(crate) fn apply_codex_event(&mut self, event: codex_core::protocol::Event) {
        self.received_events += 1;
        self.apply_ui_events(map_codex_protocol_event(&event), false);
    }

    fn apply_ui_events(&mut self, events: Vec<UiEvent>, from_replay: bool) {
        for event in events {
            self.apply_ui_event(event, from_replay);
        }
    }

    pub(crate) fn apply_replay_ui_events(&mut self, events: Vec<UiEvent>) {
        self.apply_ui_events(events, true);
    }

    fn apply_ui_event(&mut self, event: UiEvent, from_replay: bool) {
        let is_stream_error = matches!(&event, UiEvent::StreamError { .. });
        if !is_stream_error {
            self.restore_retry_status_message_if_present();
        }

        match event {
            UiEvent::SessionConfigured {
                session_id,
                model: _model,
                reasoning_effort: _,
                history_log_id,
                history_entry_count,
            } => {
                if !session_id.is_empty() {
                    self.session_id = session_id;
                }
                self.bottom_pane
                    .set_history_metadata(history_log_id, history_entry_count);
            }
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
            UiEvent::ThreadStarted {
                thread_id,
                rollout_path,
            } => {
                let changed = self.session_id != thread_id;
                self.session_id = thread_id.clone();
                self.current_rollout_path = rollout_path.map(std::path::PathBuf::from);
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
                self.on_task_started(turn_id);
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
            UiEvent::AgentMessage { message } => {
                // Upstream behavior: final agent message flushes stream, and is only
                // rendered directly when no stream content was emitted.
                let streamed = self.assistant_stream.finalize();
                if let Some(cell) = streamed {
                    self.add_boxed_history(cell);
                } else if !message.is_empty() {
                    self.append_assistant_delta(&message);
                    self.flush_assistant_message();
                }
            }
            UiEvent::AgentReasoningDelta { delta } => {
                self.on_agent_reasoning_delta(delta);
            }
            UiEvent::AgentReasoningFinal => {
                self.on_agent_reasoning_final();
            }
            UiEvent::AgentReasoningSectionBreak => {
                self.on_reasoning_section_break();
            }
            UiEvent::AgentMessageItemCompleted { phase } => {
                self.on_agent_message_item_completed(phase);
            }
            UiEvent::PlanItemCompleted { text } => {
                self.on_plan_item_completed(text);
            }
            UiEvent::TurnCompleted {
                status,
                last_agent_message,
            } => {
                self.on_task_complete(status, last_agent_message, from_replay);
            }
            UiEvent::TurnAborted { reason } => {
                match reason.as_deref().map(|value| value.to_ascii_lowercase()) {
                    Some(reason) if reason == "replaced" => {
                        self.on_error("Turn aborted: replaced by a new task".to_string());
                    }
                    _ => self.on_interrupted_turn(reason, from_replay),
                }
            }
            UiEvent::Error { message } => match rate_limit_error_kind(&message) {
                Some(RateLimitErrorKind::ServerOverloaded) => {
                    self.on_server_overloaded_error(message);
                }
                Some(RateLimitErrorKind::UsageLimit | RateLimitErrorKind::Generic) | None => {
                    self.on_error(message);
                }
            },
            UiEvent::Warning { message } => {
                self.on_warning(message);
            }
            UiEvent::StreamError {
                message,
                additional_details,
            } => {
                self.on_stream_error(message, additional_details);
            }
            UiEvent::ExecCommandBegin {
                call_id,
                process_id,
                command,
                parsed,
                source,
            } => self.on_exec_command_begin_deferred(call_id, process_id, command, parsed, source),
            UiEvent::ExecCommandOutputDelta { call_id, delta } => {
                self.on_exec_command_output_delta(&call_id, &delta);
            }
            UiEvent::TerminalInteraction { process_id, stdin } => {
                self.on_terminal_interaction(process_id, stdin);
            }
            UiEvent::ExecCommandEnd {
                call_id,
                process_id,
                source,
                exit_code,
                formatted_output,
                aggregated_output,
                duration,
            } => self.on_exec_command_end_deferred(
                call_id,
                process_id,
                source,
                exit_code,
                formatted_output,
                aggregated_output,
                duration,
            ),
            UiEvent::McpToolCallBegin {
                call_id,
                invocation,
            } => self.on_mcp_tool_call_begin_deferred(call_id, invocation),
            UiEvent::McpToolCallEnd {
                call_id,
                duration,
                result,
            } => self.on_mcp_tool_call_end_deferred(call_id, duration, result),
            UiEvent::WebSearchBegin { call_id, query } => {
                self.on_web_search_begin(call_id, query);
            }
            UiEvent::WebSearchEnd {
                call_id,
                query,
                action,
            } => self.on_web_search_end(&call_id, query, action),
            UiEvent::ThreadRolledBack { num_turns } => {
                if from_replay {
                    self.bottom_pane_event_tx
                        .send(UiAppEvent::ApplyThreadRollback {
                            num_turns: u32::try_from(num_turns).unwrap_or(u32::MAX),
                        });
                }
            }
            UiEvent::TurnDiffUpdated { unified_diff: _ } => {
                self.refresh_status_line();
            }
            UiEvent::UndoStarted { message } => {
                self.on_undo_started(message);
            }
            UiEvent::UndoCompleted { message } => {
                self.on_undo_completed(message);
            }
            UiEvent::PlanUpdated(update) => {
                self.add_boxed_history(Box::new(crate::history_cell::new_plan_update(update)));
            }
            UiEvent::PatchApplyBegin { changes } => {
                self.flush_assistant_message();
                self.add_boxed_history(Box::new(new_patch_event(changes, &self.status_line_cwd())));
            }
            UiEvent::PatchApplyEnd { success, stderr } => {
                if !success {
                    self.add_boxed_history(Box::new(new_patch_apply_failure(stderr)));
                }
                self.had_work_activity = true;
            }
            UiEvent::ViewImageToolCall { path } => {
                self.add_history_cell(Box::new(new_view_image_tool_call(
                    path,
                    &self.status_line_cwd(),
                )));
            }
            UiEvent::GetHistoryEntryResponse {
                offset,
                log_id,
                entry_text,
            } => {
                self.bottom_pane
                    .on_history_entry_response(log_id, offset, entry_text);
            }
            UiEvent::DeprecationNotice { message } => {
                self.add_boxed_history(Box::new(new_info_event(
                    "[deprecation notice]".to_string(),
                    Some(message),
                )));
            }
            UiEvent::BackgroundEvent { message } => {
                self.on_background_event(message);
            }
            UiEvent::ReviewModeEntered { hint } => {
                self.on_entered_review_mode(hint, from_replay);
            }
            UiEvent::ReviewModeExited {
                review_output_overall_explanation,
                review_output_findings_count,
            } => self.on_exited_review_mode(
                review_output_overall_explanation,
                review_output_findings_count,
            ),
            UiEvent::UserMessage {
                text,
                text_elements,
            } => {
                if self.should_render_user_message_event(&text, &text_elements, from_replay) {
                    self.push_user_prompt(&text, text_elements);
                }
            }
            UiEvent::CustomPromptsListed(prompts) => {
                self.bottom_pane.set_custom_prompts(prompts);
            }
            UiEvent::SkillsListed(skills) => {
                self.set_skills(Some(skills));
            }
            UiEvent::SkillsUpdateAvailable => {
                self.bottom_pane_event_tx.send(UiAppEvent::CodexOp(
                    codex_core::protocol::Op::ListSkills {
                        cwds: Vec::new(),
                        force_reload: true,
                    },
                ));
            }
            UiEvent::ShutdownComplete => {
                self.bottom_pane_event_tx
                    .send(UiAppEvent::Exit(crate::app_event::ExitMode::Immediate));
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
            UiEvent::TokenUsageUpdated {
                token_info,
                total_usage,
            } => {
                self.total_token_usage = total_usage;
                self.set_token_info(Some(token_info));
            }
            UiEvent::RateLimitUpdated(snapshot) => {
                self.on_rate_limit_snapshot(Some(snapshot));
            }
            UiEvent::RuntimeMetricsUpdated(summary) => {
                self.apply_runtime_metrics_delta(summary);
            }
            UiEvent::McpStartupUpdate { server, status } => {
                self.mcp_startup_running = true;
                self.update_task_running_state();
                self.status_message = Some(format!("mcp {server}: {status}"));
            }
            UiEvent::McpStartupComplete { failed, cancelled } => {
                self.mcp_startup_running = false;
                self.update_task_running_state();
                if self.agent_turn_running {
                    self.status_message = Some("Working".to_string());
                } else {
                    self.status_message = None;
                }
                if !failed.is_empty() || !cancelled.is_empty() {
                    let failed_part = if failed.is_empty() {
                        String::new()
                    } else {
                        format!(" failed: {}", failed.join(","))
                    };
                    let cancelled_part = if cancelled.is_empty() {
                        String::new()
                    } else {
                        format!(" cancelled: {}", cancelled.join(","))
                    };
                    self.history_cells.push(Box::new(new_info_event(
                        format!("[mcp startup incomplete]{failed_part}{cancelled_part}"),
                        None,
                    )));
                }
            }
            UiEvent::CollabEvent(message) => {
                self.history_cells
                    .push(Box::new(new_info_event(message, None)));
            }
            UiEvent::ExecApprovalRequest {
                id,
                command,
                reason,
                network_approval_context,
            } => self.on_exec_approval_request_deferred(
                id,
                command,
                reason,
                network_approval_context,
            ),
            UiEvent::PatchApprovalRequest {
                id,
                reason,
                cwd,
                changes,
            } => self.on_patch_approval_request_deferred(id, reason, cwd, changes),
            UiEvent::ElicitationRequest {
                server_name,
                request_id,
                message,
            } => self.on_elicitation_request_deferred(server_name, request_id, message),
            UiEvent::RequestUserInputRequest(request) => {
                self.on_request_user_input_deferred(request)
            }
        }
        self.sync_bottom_pane_status();
        if !from_replay && self.agent_turn_running {
            self.refresh_runtime_metrics();
        }
    }

    fn on_exec_approval_request_deferred(
        &mut self,
        id: String,
        command: Vec<String>,
        reason: Option<String>,
        network_approval_context: Option<codex_core::protocol::NetworkApprovalContext>,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::ExecApprovalRequest {
                id: id.clone(),
                command: command.clone(),
                reason: reason.clone(),
                network_approval_context: network_approval_context.clone(),
            },
            |s| {
                s.bottom_pane.push_approval_request(
                    crate::bottom_pane::ApprovalRequest::Exec {
                        id,
                        command,
                        reason,
                        network_approval_context,
                        proposed_execpolicy_amendment: None,
                    },
                    &codex_core::features::Features::default(),
                );
            },
        );
    }

    fn on_patch_approval_request_deferred(
        &mut self,
        id: String,
        reason: Option<String>,
        cwd: std::path::PathBuf,
        changes: std::collections::HashMap<std::path::PathBuf, codex_core::protocol::FileChange>,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::PatchApprovalRequest {
                id: id.clone(),
                reason: reason.clone(),
                cwd: cwd.clone(),
                changes: changes.clone(),
            },
            |s| {
                s.bottom_pane.push_approval_request(
                    crate::bottom_pane::ApprovalRequest::ApplyPatch {
                        id,
                        reason,
                        cwd,
                        changes,
                    },
                    &codex_core::features::Features::default(),
                );
            },
        );
    }

    fn on_elicitation_request_deferred(
        &mut self,
        server_name: String,
        request_id: codex_protocol::mcp::RequestId,
        message: String,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::ElicitationRequest {
                server_name: server_name.clone(),
                request_id: request_id.clone(),
                message: message.clone(),
            },
            |s| {
                s.bottom_pane.push_approval_request(
                    crate::bottom_pane::ApprovalRequest::McpElicitation {
                        server_name,
                        request_id,
                        message,
                    },
                    &codex_core::features::Features::default(),
                );
            },
        );
    }

    fn on_request_user_input_deferred(
        &mut self,
        request: codex_protocol::request_user_input::RequestUserInputEvent,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::RequestUserInputRequest(request.clone()),
            |s| {
                s.bottom_pane.push_user_input_request(request);
            },
        );
    }

    fn defer_or_handle(&mut self, queued: QueuedUiInterrupt, handle: impl FnOnce(&mut Self)) {
        if self.assistant_stream.queued_lines() > 0 || !self.pending_interrupts.is_empty() {
            self.pending_interrupts.push_back(queued);
        } else {
            handle(self);
        }
    }

    fn flush_interrupt_queue(&mut self) {
        while let Some(interrupt) = self.pending_interrupts.pop_front() {
            match interrupt {
                QueuedUiInterrupt::ExecApprovalRequest {
                    id,
                    command,
                    reason,
                    network_approval_context,
                } => {
                    self.bottom_pane.push_approval_request(
                        crate::bottom_pane::ApprovalRequest::Exec {
                            id,
                            command,
                            reason,
                            network_approval_context,
                            proposed_execpolicy_amendment: None,
                        },
                        &codex_core::features::Features::default(),
                    );
                }
                QueuedUiInterrupt::PatchApprovalRequest {
                    id,
                    reason,
                    cwd,
                    changes,
                } => {
                    self.bottom_pane.push_approval_request(
                        crate::bottom_pane::ApprovalRequest::ApplyPatch {
                            id,
                            reason,
                            cwd,
                            changes,
                        },
                        &codex_core::features::Features::default(),
                    );
                }
                QueuedUiInterrupt::ElicitationRequest {
                    server_name,
                    request_id,
                    message,
                } => {
                    self.bottom_pane.push_approval_request(
                        crate::bottom_pane::ApprovalRequest::McpElicitation {
                            server_name,
                            request_id,
                            message,
                        },
                        &codex_core::features::Features::default(),
                    );
                }
                QueuedUiInterrupt::RequestUserInputRequest(request) => {
                    self.bottom_pane.push_user_input_request(request);
                }
                QueuedUiInterrupt::ExecCommandBegin {
                    call_id,
                    process_id,
                    command,
                    parsed,
                    source,
                } => self.on_exec_command_begin(call_id, process_id, command, parsed, source),
                QueuedUiInterrupt::ExecCommandEnd {
                    call_id,
                    process_id,
                    source,
                    exit_code,
                    formatted_output,
                    aggregated_output,
                    duration,
                } => self.on_exec_command_end(
                    &call_id,
                    process_id,
                    source,
                    exit_code,
                    formatted_output,
                    aggregated_output,
                    duration,
                ),
                QueuedUiInterrupt::McpToolCallBegin {
                    call_id,
                    invocation,
                } => self.on_mcp_tool_call_begin(call_id, invocation),
                QueuedUiInterrupt::McpToolCallEnd {
                    call_id,
                    duration,
                    result,
                } => self.on_mcp_tool_call_end(&call_id, duration, result),
            }
        }
    }

    pub(crate) fn push_line(&mut self, line: &str) {
        self.flush_assistant_message();
        self.flush_active_cell();
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
        self.flush_active_cell();
        let decoded = mention_codec::decode_history_mentions(prompt);
        let display_prompt = decoded.text;
        self.history_cells.push(Box::new(new_user_prompt(
            display_prompt,
            text_elements,
            Vec::new(),
            Vec::new(),
        )));
    }

    pub(crate) fn register_local_user_message_echo(
        &mut self,
        text: &str,
        text_elements: &[codex_protocol::user_input::TextElement],
    ) {
        const MAX_RECENT_LOCAL_ECHOES: usize = 16;
        self.local_user_message_echoes
            .push_back(user_message_fingerprint(text, text_elements));
        if self.local_user_message_echoes.len() > MAX_RECENT_LOCAL_ECHOES {
            let _ = self.local_user_message_echoes.pop_front();
        }
    }

    fn should_render_user_message_event(
        &mut self,
        text: &str,
        text_elements: &[codex_protocol::user_input::TextElement],
        from_replay: bool,
    ) -> bool {
        if from_replay {
            return true;
        }
        let fp = user_message_fingerprint(text, text_elements);
        if let Some(idx) = self
            .local_user_message_echoes
            .iter()
            .position(|item| *item == fp)
        {
            self.local_user_message_echoes.remove(idx);
            return false;
        }
        true
    }

    pub(crate) fn append_assistant_delta(&mut self, delta: &str) {
        if delta.is_empty() {
            return;
        }
        if self.assistant_stream.push(delta) {
            self.bottom_pane_event_tx
                .send(UiAppEvent::StartCommitAnimation);
            self.run_catch_up_commit_tick();
        }
    }

    fn flush_assistant_message(&mut self) {
        if let Some(cell) = self.assistant_stream.finalize() {
            self.history_cells.push(cell);
        }
    }

    fn on_exec_command_begin(
        &mut self,
        call_id: String,
        process_id: Option<String>,
        command: Vec<String>,
        parsed: Vec<codex_protocol::parse_command::ParsedCommand>,
        source: codex_core::protocol::ExecCommandSource,
    ) {
        self.flush_assistant_message();
        self.had_work_activity = true;
        self.running_commands.insert(
            call_id.clone(),
            RunningCommand {
                process_id: process_id.clone(),
                command: command.clone(),
                parsed_cmd: parsed.clone(),
                source,
            },
        );
        self.track_unified_exec_process_begin(process_id.clone(), &call_id, &command, source);
        let command_display = command.join(" ");
        let should_suppress_unified_wait = source
            == codex_core::protocol::ExecCommandSource::UnifiedExecInteraction
            && self
                .last_unified_wait
                .as_ref()
                .is_some_and(|wait| wait.is_duplicate(&command_display));
        if source == codex_core::protocol::ExecCommandSource::UnifiedExecInteraction {
            self.last_unified_wait = Some(UnifiedExecWaitState::new(command_display));
        } else {
            self.last_unified_wait = None;
        }
        if should_suppress_unified_wait {
            self.suppressed_exec_calls.insert(call_id);
            return;
        }
        if let Some(exec_cell) = self
            .active_cell
            .as_mut()
            .and_then(|cell| cell.as_any_mut().downcast_mut::<ExecCell>())
            && let Some(updated) = exec_cell.with_added_call(
                call_id.clone(),
                command.clone(),
                parsed.clone(),
                source,
                None,
            )
        {
            *exec_cell = updated;
            self.bump_active_cell_revision();
            return;
        }

        self.flush_active_cell();
        self.active_cell = Some(Box::new(new_active_exec_command(
            call_id, command, parsed, source, None, true,
        )));
        self.bump_active_cell_revision();
    }

    fn on_exec_command_output_delta(&mut self, call_id: &str, delta: &str) {
        if delta.is_empty() {
            return;
        }
        self.track_unified_exec_output_chunk(call_id, delta);
        if let Some(exec_cell) = self
            .active_cell
            .as_mut()
            .and_then(|cell| cell.as_any_mut().downcast_mut::<ExecCell>())
            && exec_cell.append_output(call_id, delta)
        {
            self.bump_active_cell_revision();
            return;
        }

        self.push_line(delta);
    }

    fn on_exec_command_end(
        &mut self,
        call_id: &str,
        process_id: Option<String>,
        source: codex_core::protocol::ExecCommandSource,
        exit_code: i32,
        formatted_output: String,
        aggregated_output: String,
        duration: Duration,
    ) {
        let running = self.running_commands.remove(call_id);
        if self.suppressed_exec_calls.remove(call_id) {
            return;
        }
        let completed_process_id = process_id
            .clone()
            .or_else(|| running.as_ref().and_then(|rc| rc.process_id.clone()));
        if let Some(pid) = completed_process_id.as_deref()
            && self
                .unified_exec_wait_streak
                .as_ref()
                .is_some_and(|wait| wait.process_id == pid)
        {
            self.flush_unified_exec_wait_streak();
        }
        self.track_unified_exec_process_end(completed_process_id.clone(), call_id, source);
        if let Some(exec_cell) = self
            .active_cell
            .as_mut()
            .and_then(|cell| cell.as_any_mut().downcast_mut::<ExecCell>())
            && exec_cell.iter_calls().any(|call| call.call_id == call_id)
        {
            let output_text = if aggregated_output.is_empty() {
                exec_cell
                    .calls
                    .iter()
                    .rev()
                    .find(|call| call.call_id == call_id)
                    .and_then(|call| call.output.as_ref())
                    .map(|output| output.aggregated_output.clone())
                    .unwrap_or_default()
            } else {
                aggregated_output
            };
            let formatted =
                if source == codex_core::protocol::ExecCommandSource::UnifiedExecInteraction {
                    String::new()
                } else if formatted_output.is_empty() {
                    output_text.clone()
                } else {
                    formatted_output
                };

            exec_cell.complete_call(
                call_id,
                CommandOutput {
                    exit_code,
                    aggregated_output: output_text.clone(),
                    formatted_output: formatted,
                },
                duration,
            );
            if exec_cell.should_flush() {
                self.flush_active_cell();
            } else {
                self.bump_active_cell_revision();
            }
            return;
        }

        let (command, parsed_cmd, source) = match running {
            Some(rc) => (rc.command, rc.parsed_cmd, rc.source),
            None => (
                Vec::new(),
                Vec::new(),
                codex_core::protocol::ExecCommandSource::Agent,
            ),
        };
        self.flush_active_cell();
        let mut cell =
            new_active_exec_command(call_id.to_string(), command, parsed_cmd, source, None, true);
        let formatted = if source == codex_core::protocol::ExecCommandSource::UnifiedExecInteraction
        {
            String::new()
        } else if formatted_output.is_empty() {
            aggregated_output.clone()
        } else {
            formatted_output
        };
        cell.complete_call(
            call_id,
            CommandOutput {
                exit_code,
                aggregated_output: aggregated_output.clone(),
                formatted_output: formatted,
            },
            duration,
        );
        self.active_cell = Some(Box::new(cell));
        self.bump_active_cell_revision();
        self.flush_active_cell();
    }

    fn on_terminal_interaction(&mut self, process_id: String, stdin: String) {
        self.flush_assistant_message();
        let command_display = self
            .unified_exec_processes
            .iter()
            .find(|process| process.key == process_id)
            .map(|process| process.command_display.clone());
        if stdin.is_empty() {
            self.bottom_pane.ensure_status_indicator();
            self.bottom_pane.set_interrupt_hint_visible(true);
            self.status_message = Some(if let Some(command) = &command_display {
                format!("Waiting for background terminal · {command}")
            } else {
                "Waiting for background terminal".to_string()
            });
            match &mut self.unified_exec_wait_streak {
                Some(wait) if wait.process_id == process_id => {
                    wait.update_command_display(command_display);
                }
                Some(_) => {
                    self.flush_unified_exec_wait_streak();
                    self.unified_exec_wait_streak =
                        Some(UnifiedExecWaitStreak::new(process_id, command_display));
                }
                None => {
                    self.unified_exec_wait_streak =
                        Some(UnifiedExecWaitStreak::new(process_id, command_display));
                }
            }
        } else {
            if self
                .unified_exec_wait_streak
                .as_ref()
                .is_some_and(|wait| wait.process_id == process_id)
            {
                self.flush_unified_exec_wait_streak();
            }
            self.flush_active_cell();
            self.add_boxed_history(Box::new(new_unified_exec_interaction(
                command_display,
                stdin,
            )));
            if self.agent_turn_running {
                self.status_message = Some("Working".to_string());
            }
        }
    }

    fn on_mcp_tool_call_begin(
        &mut self,
        call_id: String,
        invocation: codex_core::protocol::McpInvocation,
    ) {
        self.flush_assistant_message();
        self.had_work_activity = true;
        self.flush_active_cell();
        self.active_cell = Some(Box::new(new_active_mcp_tool_call(
            call_id, invocation, true,
        )));
        self.bump_active_cell_revision();
    }

    fn on_mcp_tool_call_end(
        &mut self,
        call_id: &str,
        duration: Duration,
        result: Result<codex_protocol::mcp::CallToolResult, String>,
    ) {
        if let Some(mcp_cell) = self
            .active_cell
            .as_mut()
            .and_then(|cell| cell.as_any_mut().downcast_mut::<McpToolCallCell>())
            && mcp_cell.call_id() == call_id
        {
            let image_cell = mcp_cell.complete(duration, result);
            self.bump_active_cell_revision();
            self.flush_active_cell();
            if let Some(extra) = image_cell {
                self.add_boxed_history(extra);
            }
            return;
        }

        self.flush_active_cell();
        self.history_cells.push(Box::new(new_info_event(
            format!("[mcp done] {call_id}"),
            None,
        )));
    }

    fn on_web_search_begin(&mut self, call_id: String, query: String) {
        self.flush_assistant_message();
        self.had_work_activity = true;
        self.flush_active_cell();
        self.active_cell = Some(Box::new(new_active_web_search_call(call_id, query, true)));
        self.bump_active_cell_revision();
    }

    fn on_web_search_end(
        &mut self,
        call_id: &str,
        query: String,
        action: codex_protocol::models::WebSearchAction,
    ) {
        if let Some(web_cell) = self.active_cell.as_mut().and_then(|cell| {
            cell.as_any_mut()
                .downcast_mut::<crate::history_cell::WebSearchCell>()
        }) && web_cell.call_id() == call_id
        {
            web_cell.update(action.clone(), query.clone());
            web_cell.complete();
            self.bump_active_cell_revision();
            self.flush_active_cell();
            return;
        }
        self.history_cells.push(Box::new(new_web_search_call(
            call_id.to_string(),
            query,
            action,
        )));
    }

    fn flush_unified_exec_wait_streak(&mut self) {
        let Some(wait) = self.unified_exec_wait_streak.take() else {
            return;
        };
        self.add_boxed_history(Box::new(new_unified_exec_interaction(
            wait.command_display,
            String::new(),
        )));
        if self.agent_turn_running {
            self.status_message = Some("Working".to_string());
        }
    }

    fn track_unified_exec_process_begin(
        &mut self,
        process_id: Option<String>,
        call_id: &str,
        command: &[String],
        source: codex_core::protocol::ExecCommandSource,
    ) {
        if source != codex_core::protocol::ExecCommandSource::UnifiedExecStartup {
            return;
        }
        let key = process_id.unwrap_or_else(|| call_id.to_string());
        let command_display = strip_bash_lc_and_escape(command);
        if let Some(existing) = self
            .unified_exec_processes
            .iter_mut()
            .find(|process| process.key == key)
        {
            existing.call_id = call_id.to_string();
            existing.command_display = command_display;
            existing.recent_chunks.clear();
        } else {
            self.unified_exec_processes.push(UnifiedExecProcessSummary {
                key,
                call_id: call_id.to_string(),
                command_display,
                recent_chunks: Vec::new(),
            });
        }
        self.sync_unified_exec_footer();
    }

    fn track_unified_exec_process_end(
        &mut self,
        process_id: Option<String>,
        call_id: &str,
        source: codex_core::protocol::ExecCommandSource,
    ) {
        if !matches!(
            source,
            codex_core::protocol::ExecCommandSource::UnifiedExecStartup
                | codex_core::protocol::ExecCommandSource::UnifiedExecInteraction
        ) {
            return;
        }
        let key = process_id.unwrap_or_else(|| call_id.to_string());
        let before = self.unified_exec_processes.len();
        self.unified_exec_processes
            .retain(|process| process.key != key);
        if self.unified_exec_processes.len() != before {
            self.sync_unified_exec_footer();
        }
    }

    fn sync_unified_exec_footer(&mut self) {
        let processes = self
            .unified_exec_processes
            .iter()
            .map(|process| process.command_display.clone())
            .collect();
        self.bottom_pane.set_unified_exec_processes(processes);
    }

    fn track_unified_exec_output_chunk(&mut self, call_id: &str, chunk: &str) {
        let Some(process) = self
            .unified_exec_processes
            .iter_mut()
            .find(|process| process.call_id == call_id)
        else {
            return;
        };
        for line in chunk
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty())
        {
            process.recent_chunks.push(line.to_string());
        }
        const MAX_RECENT_CHUNKS: usize = 3;
        if process.recent_chunks.len() > MAX_RECENT_CHUNKS {
            let drop_count = process.recent_chunks.len() - MAX_RECENT_CHUNKS;
            process.recent_chunks.drain(0..drop_count);
        }
    }

    fn clear_unified_exec_processes(&mut self) {
        if self.unified_exec_processes.is_empty() {
            return;
        }
        self.unified_exec_processes.clear();
        self.sync_unified_exec_footer();
    }

    fn stream_controllers_idle(&self) -> bool {
        self.assistant_stream.queued_lines() == 0
    }

    fn maybe_restore_status_indicator_after_stream_idle(&mut self) {
        if !self.pending_status_indicator_restore
            || !self.bottom_pane.is_task_running()
            || !self.stream_controllers_idle()
        {
            return;
        }
        self.bottom_pane.ensure_status_indicator();
        self.sync_bottom_pane_status();
        self.pending_status_indicator_restore = false;
    }

    fn finalize_active_cell_as_failed(&mut self) {
        if let Some(mut cell) = self.active_cell.take() {
            if let Some(exec) = cell.as_any_mut().downcast_mut::<ExecCell>() {
                exec.mark_failed();
            } else if let Some(tool) = cell.as_any_mut().downcast_mut::<McpToolCallCell>() {
                tool.mark_failed();
            }
            self.add_boxed_history(cell);
            self.bump_active_cell_revision();
        }
    }

    fn finalize_turn_as_failed(&mut self) {
        self.finalize_active_cell_as_failed();
        self.assistant_stream = StreamController::new(None);
        self.adaptive_chunking.reset();
        self.flush_unified_exec_wait_streak();
        self.clear_unified_exec_processes();
        self.active_turn_id = None;
        self.agent_turn_running = false;
        self.update_task_running_state();
        self.running_commands.clear();
        self.suppressed_exec_calls.clear();
        self.last_unified_wait = None;
        self.had_work_activity = false;
        self.turn_runtime_metrics = codex_otel::RuntimeMetricsSummary::default();
        self.reasoning_buffer.clear();
        self.full_reasoning_buffer.clear();
        self.request_status_line_branch_refresh();
    }

    fn on_task_started(&mut self, turn_id: String) {
        if !turn_id.is_empty() {
            self.active_turn_id = Some(turn_id);
        }
        self.adaptive_chunking.reset();
        self.assistant_stream = StreamController::new(None);
        self.agent_turn_running = true;
        self.had_work_activity = false;
        self.turn_runtime_metrics = codex_otel::RuntimeMetricsSummary::default();
        self.update_task_running_state();
        self.status_message = Some("Working".to_string());
        self.retry_status_message = None;
        self.pending_status_indicator_restore = false;
        self.reasoning_buffer.clear();
        self.full_reasoning_buffer.clear();
        self.sync_bottom_pane_status();
    }

    fn on_task_complete(
        &mut self,
        status: Option<String>,
        _last_agent_message: Option<String>,
        from_replay: bool,
    ) {
        let failed_like = status
            .as_deref()
            .is_some_and(|s| matches!(s, "failed" | "aborted" | "interrupted"));
        if failed_like {
            self.finalize_turn_as_failed();
            if let Some(status) = status {
                self.status_message = Some(format!(
                    "turn {}",
                    text_formatting::capitalize_first(&status)
                ));
            }
            return;
        }

        self.flush_assistant_message();
        self.flush_active_cell();
        self.flush_unified_exec_wait_streak();
        self.clear_unified_exec_processes();

        if !from_replay {
            let runtime_metrics = (!runtime_metrics_is_empty(&self.turn_runtime_metrics))
                .then_some(self.turn_runtime_metrics);
            if self.had_work_activity || runtime_metrics.is_some() {
                let elapsed_seconds = if self.had_work_activity {
                    self.bottom_pane
                        .status_widget()
                        .map(|status| status.elapsed_seconds())
                } else {
                    None
                };
                self.add_boxed_history(Box::new(crate::history_cell::FinalMessageSeparator::new(
                    elapsed_seconds,
                    runtime_metrics,
                )));
            }
        }

        self.active_turn_id = None;
        self.agent_turn_running = false;
        self.update_task_running_state();
        self.running_commands.clear();
        self.suppressed_exec_calls.clear();
        self.last_unified_wait = None;
        self.had_work_activity = false;
        self.turn_runtime_metrics = codex_otel::RuntimeMetricsSummary::default();
        self.reasoning_buffer.clear();
        self.full_reasoning_buffer.clear();
        self.request_status_line_branch_refresh();

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
        self.sync_bottom_pane_status();
    }

    fn on_server_overloaded_error(&mut self, message: String) {
        self.finalize_turn_as_failed();
        let message = if message.trim().is_empty() {
            "Codex is currently experiencing high load.".to_string()
        } else {
            message
        };
        self.add_boxed_history(Box::new(crate::history_cell::new_warning_event(message)));
    }

    fn on_error(&mut self, message: String) {
        self.finalize_turn_as_failed();
        self.add_boxed_history(Box::new(new_error_event(message)));
    }

    fn on_warning(&mut self, message: impl Into<String>) {
        self.add_boxed_history(Box::new(crate::history_cell::new_warning_event(
            message.into(),
        )));
    }

    fn on_background_event(&mut self, message: String) {
        self.bottom_pane.ensure_status_indicator();
        self.bottom_pane.set_interrupt_hint_visible(true);
        self.status_message = Some(message);
        self.sync_bottom_pane_status();
    }

    fn on_undo_started(&mut self, message: Option<String>) {
        self.bottom_pane.ensure_status_indicator();
        self.bottom_pane.set_interrupt_hint_visible(false);
        self.status_message = Some(message.unwrap_or_else(|| "Undo in progress...".to_string()));
        self.sync_bottom_pane_status();
    }

    fn on_undo_completed(&mut self, message: Option<String>) {
        self.bottom_pane.hide_status_indicator();
        let message = message.unwrap_or_else(|| "Undo completed successfully.".to_string());
        self.add_boxed_history(Box::new(new_info_event(message, None)));
        self.sync_bottom_pane_status();
    }

    fn on_entered_review_mode(&mut self, hint: Option<String>, from_replay: bool) {
        if self.pre_review_token_info.is_none() {
            self.pre_review_token_info = Some(self.token_info.clone());
        }
        if !from_replay && !self.bottom_pane.is_task_running() {
            self.bottom_pane.set_task_running(true);
        }
        self.is_review_mode = true;
        let banner = hint
            .map(|hint| format!(">> Code review started: {hint} <<"))
            .unwrap_or_else(|| ">> Code review started <<".to_string());
        self.add_boxed_history(Box::new(crate::history_cell::new_review_status_line(
            banner,
        )));
    }

    fn on_exited_review_mode(
        &mut self,
        review_output_overall_explanation: Option<String>,
        review_output_findings_count: Option<usize>,
    ) {
        self.flush_assistant_message();
        self.flush_interrupt_queue();
        self.flush_active_cell();
        if matches!(review_output_findings_count, Some(0))
            && let Some(explanation) = review_output_overall_explanation
        {
            let trimmed = explanation.trim();
            if trimmed.is_empty() {
                self.add_boxed_history(Box::new(new_error_event(
                    "Reviewer failed to output a response.".to_string(),
                )));
            } else {
                self.add_boxed_history(Box::new(PlainHistoryCell::new(vec![
                    trimmed.to_string().into(),
                ])));
            }
        }
        self.is_review_mode = false;
        self.restore_pre_review_token_info();
        self.add_boxed_history(Box::new(crate::history_cell::new_review_status_line(
            "<< Code review finished >>".to_string(),
        )));
        self.sync_bottom_pane_status();
    }

    fn restore_pre_review_token_info(&mut self) {
        if let Some(token_info) = self.pre_review_token_info.take() {
            self.set_token_info(token_info);
        }
    }

    fn on_stream_error(&mut self, message: String, additional_details: Option<String>) {
        if self.retry_status_message.is_none() {
            self.retry_status_message = self.status_message.clone();
        }
        self.status_message = Some(match additional_details {
            Some(details) if !details.trim().is_empty() => format!("{message} ({details})"),
            _ => message,
        });
        self.sync_bottom_pane_status();
    }

    fn restore_retry_status_message_if_present(&mut self) {
        if let Some(message) = self.retry_status_message.take() {
            self.status_message = Some(message);
            self.sync_bottom_pane_status();
        }
    }

    fn on_agent_message_item_completed(&mut self, phase: Option<String>) {
        self.pending_status_indicator_restore = matches!(phase.as_deref(), Some("commentary"));
        self.maybe_restore_status_indicator_after_stream_idle();
    }

    fn on_plan_item_completed(&mut self, text: String) {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return;
        }
        self.add_boxed_history(Box::new(crate::history_cell::new_proposed_plan(
            trimmed.to_string(),
        )));
    }

    fn on_interrupted_turn(&mut self, reason: Option<String>, from_replay: bool) {
        self.finalize_turn_as_failed();
        let interrupted = reason
            .as_deref()
            .map(|r| r.eq_ignore_ascii_case("interrupted"))
            .unwrap_or(true);
        if interrupted && !from_replay {
            self.add_boxed_history(Box::new(new_error_event(
                "Conversation interrupted - tell the model what to do differently. Something went wrong? Hit `/feedback` to report the issue.".to_string(),
            )));
        }
    }

    fn run_commit_tick_with_scope(&mut self, scope: CommitTickScope) -> bool {
        let output = run_commit_tick(
            &mut self.adaptive_chunking,
            Some(&mut self.assistant_stream),
            None,
            scope,
            Instant::now(),
        );
        let mut changed = false;
        for cell in output.cells {
            self.bottom_pane.hide_status_indicator();
            self.add_boxed_history(cell);
            changed = true;
        }
        if output.has_controller && output.all_idle {
            self.bottom_pane_event_tx
                .send(UiAppEvent::StopCommitAnimation);
            self.sync_bottom_pane_status();
            self.maybe_restore_status_indicator_after_stream_idle();
            self.flush_interrupt_queue();
        }
        changed
    }

    fn on_exec_command_begin_deferred(
        &mut self,
        call_id: String,
        process_id: Option<String>,
        command: Vec<String>,
        parsed: Vec<codex_protocol::parse_command::ParsedCommand>,
        source: codex_core::protocol::ExecCommandSource,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::ExecCommandBegin {
                call_id: call_id.clone(),
                process_id: process_id.clone(),
                command: command.clone(),
                parsed: parsed.clone(),
                source,
            },
            |s| {
                s.on_exec_command_begin(call_id, process_id, command, parsed, source);
            },
        );
    }

    fn on_exec_command_end_deferred(
        &mut self,
        call_id: String,
        process_id: Option<String>,
        source: codex_core::protocol::ExecCommandSource,
        exit_code: i32,
        formatted_output: String,
        aggregated_output: String,
        duration: Duration,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::ExecCommandEnd {
                call_id: call_id.clone(),
                process_id: process_id.clone(),
                source,
                exit_code,
                formatted_output: formatted_output.clone(),
                aggregated_output: aggregated_output.clone(),
                duration,
            },
            |s| {
                s.on_exec_command_end(
                    &call_id,
                    process_id,
                    source,
                    exit_code,
                    formatted_output,
                    aggregated_output,
                    duration,
                );
            },
        );
    }

    fn on_mcp_tool_call_begin_deferred(
        &mut self,
        call_id: String,
        invocation: codex_core::protocol::McpInvocation,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::McpToolCallBegin {
                call_id: call_id.clone(),
                invocation: invocation.clone(),
            },
            |s| {
                s.on_mcp_tool_call_begin(call_id, invocation);
            },
        );
    }

    fn on_mcp_tool_call_end_deferred(
        &mut self,
        call_id: String,
        duration: Duration,
        result: Result<codex_protocol::mcp::CallToolResult, String>,
    ) {
        self.defer_or_handle(
            QueuedUiInterrupt::McpToolCallEnd {
                call_id: call_id.clone(),
                duration,
                result: result.clone(),
            },
            |s| {
                s.on_mcp_tool_call_end(&call_id, duration, result);
            },
        );
    }

    pub(crate) fn commit_assistant_stream_tick(&mut self) -> bool {
        self.run_commit_tick_with_scope(CommitTickScope::AnyMode)
    }

    fn run_catch_up_commit_tick(&mut self) -> bool {
        self.run_commit_tick_with_scope(CommitTickScope::CatchUpOnly)
    }

    fn on_agent_reasoning_delta(&mut self, delta: String) {
        self.reasoning_buffer.push_str(&delta);
        if let Some(header) = extract_first_bold(&self.reasoning_buffer) {
            self.status_message = Some(header);
        }
    }

    fn on_agent_reasoning_final(&mut self) {
        self.full_reasoning_buffer.push_str(&self.reasoning_buffer);
        if !self.full_reasoning_buffer.is_empty() {
            self.history_cells
                .push(crate::history_cell::new_reasoning_summary_block(
                    self.full_reasoning_buffer.clone(),
                ));
        }
        self.reasoning_buffer.clear();
        self.full_reasoning_buffer.clear();
        if self.agent_turn_running {
            self.status_message = Some("Working".to_string());
        }
    }

    fn on_reasoning_section_break(&mut self) {
        self.full_reasoning_buffer.push_str(&self.reasoning_buffer);
        self.full_reasoning_buffer.push_str("\n\n");
        self.reasoning_buffer.clear();
    }

    pub(crate) fn on_commit_tick(&mut self) {
        self.commit_assistant_stream_tick();
    }

    fn apply_runtime_metrics_delta(&mut self, delta: codex_otel::RuntimeMetricsSummary) {
        self.turn_runtime_metrics = runtime_metrics_merge(self.turn_runtime_metrics, delta);
        let websocket_timing_only = codex_otel::RuntimeMetricsSummary {
            responses_api_overhead_ms: delta.responses_api_overhead_ms,
            responses_api_inference_time_ms: delta.responses_api_inference_time_ms,
            responses_api_engine_iapi_ttft_ms: delta.responses_api_engine_iapi_ttft_ms,
            responses_api_engine_service_ttft_ms: delta.responses_api_engine_service_ttft_ms,
            responses_api_engine_iapi_tbt_ms: delta.responses_api_engine_iapi_tbt_ms,
            responses_api_engine_service_tbt_ms: delta.responses_api_engine_service_tbt_ms,
            ..codex_otel::RuntimeMetricsSummary::default()
        };
        if let Some(label) = crate::history_cell::runtime_metrics_label(websocket_timing_only) {
            self.add_boxed_history(Box::new(PlainHistoryCell::new(vec![
                format!("• WebSocket timing: {label}").into(),
            ])));
        }
    }

    fn refresh_runtime_metrics(&mut self) {}

    pub(crate) fn apply_non_pending_thread_rollback(&mut self, num_turns: u32) -> bool {
        if num_turns == 0 {
            return false;
        }

        let session_start_type = TypeId::of::<SessionInfoCell>();
        let user_type = TypeId::of::<crate::history_cell::UserHistoryCell>();
        let start = self
            .history_cells
            .iter()
            .rposition(|cell| cell.as_any().type_id() == session_start_type)
            .map_or(0, |idx| idx + 1);
        let user_positions: Vec<usize> = self
            .history_cells
            .iter()
            .enumerate()
            .skip(start)
            .filter_map(|(idx, cell)| (cell.as_any().type_id() == user_type).then_some(idx))
            .collect();
        let Some(&first_user_idx) = user_positions.first() else {
            return false;
        };

        let turns_from_end = usize::try_from(num_turns).unwrap_or(usize::MAX);
        let cut_idx = if turns_from_end >= user_positions.len() {
            first_user_idx
        } else {
            user_positions[user_positions.len() - turns_from_end]
        };
        let original_len = self.history_cells.len();
        self.history_cells.truncate(cut_idx);
        if self.history_cells.len() == original_len {
            return false;
        }
        self.history_cells_flushed_to_scrollback = self
            .history_cells_flushed_to_scrollback
            .min(self.history_cells.len());
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
        self.agent_turn_running = true;
        self.update_task_running_state();
        self.sync_bottom_pane_status();
        Ok(())
    }

    pub(crate) fn take_finished_prompt(&mut self) -> Option<InFlightPrompt> {
        let done = self
            .pending_prompt
            .as_ref()
            .is_some_and(|pending| pending.handle.is_finished());
        if done {
            self.agent_turn_running = false;
            self.update_task_running_state();
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

    pub(crate) fn bottom_pane_composer_text_with_pending(&self) -> String {
        self.bottom_pane.composer_text_with_pending()
    }

    pub(crate) fn apply_external_edit(&mut self, text: String) {
        self.bottom_pane.apply_external_edit(text);
    }

    pub(crate) fn bottom_pane_insert_str(&mut self, text: &str) {
        self.bottom_pane.insert_str(text);
    }

    pub(crate) fn open_status_line_setup(&mut self) {
        let configured_status_line_items = self.configured_status_line_items();
        let view = crate::bottom_pane::StatusLineSetupView::new(
            Some(configured_status_line_items.as_slice()),
            self.bottom_pane_event_tx.clone(),
        );
        self.bottom_pane.show_view(Box::new(view));
    }

    pub(crate) fn show_selection_view(&mut self, params: crate::bottom_pane::SelectionViewParams) {
        self.bottom_pane.show_selection_view(params);
    }

    pub(crate) fn collaboration_modes_enabled(&self) -> bool {
        true
    }

    pub(crate) fn active_collaboration_mask(
        &self,
    ) -> Option<codex_protocol::config_types::CollaborationModeMask> {
        self.active_collaboration_mask.clone()
    }

    pub(crate) fn set_collaboration_mask(
        &mut self,
        mask: codex_protocol::config_types::CollaborationModeMask,
    ) {
        let indicator = match mask
            .mode
            .unwrap_or(codex_protocol::config_types::ModeKind::Default)
        {
            codex_protocol::config_types::ModeKind::Plan => {
                Some(crate::bottom_pane::CollaborationModeIndicator::Plan)
            }
            codex_protocol::config_types::ModeKind::PairProgramming => {
                Some(crate::bottom_pane::CollaborationModeIndicator::PairProgramming)
            }
            codex_protocol::config_types::ModeKind::Execute => {
                Some(crate::bottom_pane::CollaborationModeIndicator::Execute)
            }
            codex_protocol::config_types::ModeKind::Default => {
                Some(crate::bottom_pane::CollaborationModeIndicator::PairProgramming)
            }
        };
        self.bottom_pane.set_collaboration_mode_indicator(indicator);
        self.status_message = Some(format!("collaboration mode set to {}", mask.name));
        self.active_collaboration_mask = Some(mask);
    }

    pub(crate) fn open_collaboration_modes_popup(
        &mut self,
        presets: Vec<codex_protocol::config_types::CollaborationModeMask>,
    ) {
        if presets.is_empty() {
            self.add_history_cell(Box::new(new_info_event(
                "No collaboration modes are available right now.".to_string(),
                None,
            )));
            return;
        }

        let current_kind = self
            .active_collaboration_mask
            .as_ref()
            .and_then(|mask| mask.mode);

        let items = presets
            .into_iter()
            .map(|mask| {
                let name = mask.name.clone();
                let is_current = current_kind == mask.mode;
                let action: crate::bottom_pane::SelectionAction = Box::new(move |sender| {
                    sender.send(UiAppEvent::UpdateCollaborationMode(mask.clone()));
                });
                crate::bottom_pane::SelectionItem {
                    name,
                    is_current,
                    actions: vec![action],
                    dismiss_on_select: true,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Select Collaboration Mode".to_string()),
                subtitle: Some("Pick a collaboration preset.".to_string()),
                footer_hint: Some(crate::bottom_pane::popup_consts::standard_popup_hint_line()),
                items,
                ..Default::default()
            });
    }

    pub(crate) fn open_all_models_popup(
        &mut self,
        presets: Vec<codex_protocol::openai_models::ModelPreset>,
    ) {
        if presets.is_empty() {
            self.add_history_cell(Box::new(new_info_event(
                "No additional models are available right now.".to_string(),
                None,
            )));
            return;
        }

        let current_model = self
            .active_collaboration_mask
            .as_ref()
            .and_then(|mask| mask.model.clone());
        let items = presets
            .into_iter()
            .map(|preset| {
                let model_name = preset.model.clone();
                let preset_for_action = preset.clone();
                let actions: Vec<crate::bottom_pane::SelectionAction> =
                    vec![Box::new(move |sender| {
                        sender.send(UiAppEvent::OpenReasoningPopup {
                            model: preset_for_action.clone(),
                        });
                    })];
                crate::bottom_pane::SelectionItem {
                    name: model_name.clone(),
                    description: (!preset.description.is_empty()).then_some(preset.description),
                    is_current: current_model.as_deref() == Some(model_name.as_str()),
                    actions,
                    dismiss_on_select: false,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Select Model and Effort".to_string()),
                subtitle: Some("Select a model, then choose its reasoning effort.".to_string()),
                items,
                ..Default::default()
            });
    }

    pub(crate) fn open_reasoning_popup(
        &mut self,
        preset: codex_protocol::openai_models::ModelPreset,
    ) {
        if preset.supported_reasoning_efforts.is_empty() {
            self.bottom_pane_event_tx
                .send(UiAppEvent::UpdateModel(preset.model));
            return;
        }

        let model_name = preset.model.clone();
        let items = preset
            .supported_reasoning_efforts
            .iter()
            .map(|effort_preset| {
                let model = model_name.clone();
                let effort = effort_preset.effort;
                let actions: Vec<crate::bottom_pane::SelectionAction> =
                    vec![Box::new(move |sender| {
                        sender.send(UiAppEvent::UpdateModel(model.clone()));
                        sender.send(UiAppEvent::UpdateReasoningEffort(Some(effort)));
                    })];
                crate::bottom_pane::SelectionItem {
                    name: effort.to_string(),
                    description: (!effort_preset.label.is_empty())
                        .then_some(effort_preset.label.clone()),
                    actions,
                    dismiss_on_select: true,
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some(format!("Reasoning Level for {}", preset.model)),
                items,
                ..Default::default()
            });
    }

    pub(crate) fn open_full_access_confirmation(
        &mut self,
        preset: codex_utils_approval_presets::ApprovalPreset,
        return_to_permissions: bool,
    ) {
        let mut items = Vec::new();
        let preset_for_continue = preset.clone();
        items.push(crate::bottom_pane::SelectionItem {
            name: "Continue".to_string(),
            description: Some("Apply full access settings.".to_string()),
            actions: vec![Box::new(move |sender| {
                sender.send(UiAppEvent::UpdateAskForApprovalPolicy(
                    preset_for_continue.approval,
                ));
                sender.send(UiAppEvent::UpdateSandboxPolicy(
                    preset_for_continue.sandbox.clone(),
                ));
            })],
            dismiss_on_select: true,
            ..Default::default()
        });

        if return_to_permissions {
            items.push(crate::bottom_pane::SelectionItem {
                name: "Back".to_string(),
                description: Some("Return to permissions picker.".to_string()),
                actions: vec![Box::new(move |sender| {
                    sender.send(UiAppEvent::OpenPermissionsPopup);
                })],
                dismiss_on_select: true,
                ..Default::default()
            });
        }

        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Enable Full Access?".to_string()),
                subtitle: Some("Codex will run without sandboxing.".to_string()),
                items,
                ..Default::default()
            });
    }

    pub(crate) fn open_experimental_popup(
        &mut self,
        features: Vec<crate::bottom_pane::ExperimentalFeatureItem>,
    ) {
        let view = crate::bottom_pane::ExperimentalFeaturesView::new(
            features,
            self.bottom_pane_event_tx.clone(),
        );
        self.bottom_pane.show_view(Box::new(view));
    }

    pub(crate) fn show_review_custom_prompt(&mut self) {
        let tx = self.bottom_pane_event_tx.clone();
        let view = crate::bottom_pane::custom_prompt_view::CustomPromptView::new(
            "Custom review instructions".to_string(),
            "Type instructions and press Enter".to_string(),
            None,
            Box::new(move |prompt: String| {
                let trimmed = prompt.trim().to_string();
                if trimmed.is_empty() {
                    return;
                }
                tx.send(UiAppEvent::CodexOp(codex_core::protocol::Op::Review {
                    review_request: codex_core::protocol::ReviewRequest {
                        target: codex_core::protocol::ReviewTarget::Custom {
                            instructions: trimmed,
                        },
                        user_facing_hint: None,
                    },
                }));
            }),
        );
        self.bottom_pane.show_view(Box::new(view));
    }

    pub(crate) fn open_review_popup(&mut self) {
        let cwd = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        let items = vec![
            crate::bottom_pane::SelectionItem {
                name: "Review against a base branch".to_string(),
                description: Some("(PR Style)".to_string()),
                actions: vec![Box::new({
                    let cwd = cwd.clone();
                    move |sender| {
                        sender.send(UiAppEvent::OpenReviewBranchPicker(cwd.clone()));
                    }
                })],
                dismiss_on_select: false,
                ..Default::default()
            },
            crate::bottom_pane::SelectionItem {
                name: "Review uncommitted changes".to_string(),
                actions: vec![Box::new(move |sender| {
                    sender.send(UiAppEvent::CodexOp(codex_core::protocol::Op::Review {
                        review_request: codex_core::protocol::ReviewRequest {
                            target: codex_core::protocol::ReviewTarget::UncommittedChanges,
                            user_facing_hint: None,
                        },
                    }));
                })],
                dismiss_on_select: true,
                ..Default::default()
            },
            crate::bottom_pane::SelectionItem {
                name: "Review a commit".to_string(),
                actions: vec![Box::new({
                    let cwd = cwd.clone();
                    move |sender| {
                        sender.send(UiAppEvent::OpenReviewCommitPicker(cwd.clone()));
                    }
                })],
                dismiss_on_select: false,
                ..Default::default()
            },
            crate::bottom_pane::SelectionItem {
                name: "Custom review instructions".to_string(),
                actions: vec![Box::new(move |sender| {
                    sender.send(UiAppEvent::OpenReviewCustomPrompt);
                })],
                dismiss_on_select: false,
                ..Default::default()
            },
        ];
        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Select a review preset".to_string()),
                items,
                ..Default::default()
            });
    }

    pub(crate) fn show_review_branch_picker(
        &mut self,
        current_branch: String,
        branches: Vec<String>,
    ) {
        let items = branches
            .into_iter()
            .map(|branch| {
                let search_value = branch.clone();
                crate::bottom_pane::SelectionItem {
                    name: format!("{current_branch} -> {branch}"),
                    actions: vec![Box::new(move |sender| {
                        sender.send(UiAppEvent::CodexOp(codex_core::protocol::Op::Review {
                            review_request: codex_core::protocol::ReviewRequest {
                                target: codex_core::protocol::ReviewTarget::BaseBranch {
                                    branch: branch.clone(),
                                },
                                user_facing_hint: None,
                            },
                        }));
                    })],
                    dismiss_on_select: true,
                    search_value: Some(search_value),
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Select a base branch".to_string()),
                items,
                is_searchable: true,
                search_placeholder: Some("Type to search branches".to_string()),
                ..Default::default()
            });
    }

    pub(crate) fn show_review_commit_picker(&mut self, entries: Vec<ReviewCommitPickerEntry>) {
        let items = entries
            .into_iter()
            .map(|entry| {
                let subject = entry.subject.clone();
                let sha = entry.sha.clone();
                let search_value = format!("{subject} {sha}");
                crate::bottom_pane::SelectionItem {
                    name: subject.clone(),
                    actions: vec![Box::new(move |sender| {
                        sender.send(UiAppEvent::CodexOp(codex_core::protocol::Op::Review {
                            review_request: codex_core::protocol::ReviewRequest {
                                target: codex_core::protocol::ReviewTarget::Commit {
                                    sha: sha.clone(),
                                    title: Some(subject.clone()),
                                },
                                user_facing_hint: None,
                            },
                        }));
                    })],
                    dismiss_on_select: true,
                    search_value: Some(search_value),
                    ..Default::default()
                }
            })
            .collect::<Vec<_>>();

        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Select a commit to review".to_string()),
                items,
                is_searchable: true,
                search_placeholder: Some("Type to search commits".to_string()),
                ..Default::default()
            });
    }

    pub(crate) fn open_feedback_selection(&mut self) {
        let params =
            crate::bottom_pane::feedback_selection_params(self.bottom_pane_event_tx.clone());
        self.bottom_pane.show_selection_view(params);
    }

    pub(crate) fn open_skills_menu(&mut self) {
        let items = vec![
            crate::bottom_pane::SelectionItem {
                name: "List skills".to_string(),
                description: Some("Tip: press $ to open this list directly.".to_string()),
                actions: vec![Box::new(|sender| {
                    sender.send(UiAppEvent::OpenSkillsList);
                })],
                dismiss_on_select: true,
                ..Default::default()
            },
            crate::bottom_pane::SelectionItem {
                name: "Enable/Disable Skills".to_string(),
                description: Some("Enable or disable skills.".to_string()),
                actions: vec![Box::new(|sender| {
                    sender.send(UiAppEvent::OpenManageSkillsPopup);
                })],
                dismiss_on_select: true,
                ..Default::default()
            },
        ];
        self.bottom_pane
            .show_selection_view(crate::bottom_pane::SelectionViewParams {
                title: Some("Skills".to_string()),
                subtitle: Some("Choose an action".to_string()),
                footer_hint: Some(crate::bottom_pane::popup_consts::standard_popup_hint_line()),
                items,
                ..Default::default()
            });
    }

    pub(crate) fn open_manage_skills_popup(&mut self, entries: Vec<SkillsToggleEntry>) {
        if entries.is_empty() {
            self.add_history_cell(Box::new(new_info_event(
                "No skills available.".to_string(),
                None,
            )));
            return;
        }

        let items = entries
            .into_iter()
            .map(|entry| crate::bottom_pane::SkillsToggleItem {
                name: entry.name,
                skill_name: String::new(),
                description: entry.description,
                enabled: entry.enabled,
                path: entry.path,
            })
            .collect::<Vec<_>>();

        let view =
            crate::bottom_pane::SkillsToggleView::new(items, self.bottom_pane_event_tx.clone());
        self.bottom_pane.show_view(Box::new(view));
    }

    pub(crate) fn open_feedback_consent(
        &mut self,
        category: crate::app_event::FeedbackCategory,
        rollout_path: Option<std::path::PathBuf>,
    ) {
        let params = crate::bottom_pane::feedback_upload_consent_params(
            self.bottom_pane_event_tx.clone(),
            category,
            rollout_path,
        );
        self.bottom_pane.show_selection_view(params);
    }

    pub(crate) fn open_feedback_note(
        &mut self,
        category: crate::app_event::FeedbackCategory,
        include_logs: bool,
        rollout_path: Option<std::path::PathBuf>,
    ) {
        let snapshot = codex_feedback::CodexLogSnapshot {
            thread_id: self.session_id.clone(),
        };
        let view = crate::bottom_pane::FeedbackNoteView::new(
            category,
            snapshot,
            rollout_path,
            self.bottom_pane_event_tx.clone(),
            include_logs,
            crate::bottom_pane::FeedbackAudience::External,
        );
        self.bottom_pane.show_view(Box::new(view));
    }

    pub(crate) fn set_status_message(&mut self, message: Option<String>) {
        self.status_message = message;
        self.sync_bottom_pane_status();
    }

    pub(crate) fn rollout_path(&self) -> Option<std::path::PathBuf> {
        self.current_rollout_path.clone()
    }

    pub(crate) fn take_recent_submission_mention_bindings(&mut self) -> Vec<MentionBinding> {
        self.bottom_pane.take_recent_submission_mention_bindings()
    }

    pub(crate) fn drain_pending_submission_state(&mut self) {
        self.bottom_pane.drain_pending_submission_state();
    }

    pub(crate) fn take_pending_approval_for_operation(
        &mut self,
        operation_id: &str,
        methods: &[&str],
    ) -> Option<UiApprovalRequest> {
        let key = self.pending_approvals.iter().find_map(|(key, req)| {
            if req
                .operation_id
                .as_deref()
                .is_some_and(|op| op == operation_id)
                && methods.iter().any(|method| req.method == *method)
            {
                Some(key.clone())
            } else {
                None
            }
        })?;
        self.pending_approvals.remove(&key)
    }

    pub(crate) fn take_pending_request_user_input_for_turn(
        &mut self,
        turn_id: &str,
    ) -> Option<UiApprovalRequest> {
        let key = self.pending_approvals.iter().find_map(|(key, req)| {
            if req.method == "item/tool/requestUserInput"
                && req.turn_id.as_deref().is_some_and(|id| id == turn_id)
            {
                Some(key.clone())
            } else {
                None
            }
        })?;
        self.pending_approvals.remove(&key)
    }

    pub(crate) fn apply_file_search_result(&mut self, query: String, matches: Vec<FileMatch>) {
        self.bottom_pane.on_file_search_result(query, matches);
    }

    pub(crate) fn add_history_cell(&mut self, cell: Box<dyn HistoryCell>) {
        self.flush_assistant_message();
        self.flush_active_cell();
        self.history_cells.push(cell);
    }

    fn add_boxed_history(&mut self, cell: Box<dyn HistoryCell>) {
        self.history_cells.push(cell);
    }

    fn flush_active_cell(&mut self) {
        if let Some(cell) = self.active_cell.take() {
            self.add_boxed_history(cell);
            self.bump_active_cell_revision();
        }
    }

    fn bump_active_cell_revision(&mut self) {
        self.active_cell_revision = self.active_cell_revision.wrapping_add(1);
    }

    pub(crate) fn active_cell_transcript_key(&self) -> Option<ActiveCellTranscriptKey> {
        let cell = self.active_cell.as_ref()?;
        Some(ActiveCellTranscriptKey {
            revision: self.active_cell_revision,
            is_stream_continuation: cell.is_stream_continuation(),
            animation_tick: cell.transcript_animation_tick(),
        })
    }

    pub(crate) fn active_cell_transcript_lines(&self, width: u16) -> Option<Vec<Line<'static>>> {
        self.active_cell
            .as_ref()
            .map(|cell| cell.transcript_lines(width))
    }

    pub(crate) fn reset_for_thread_switch(&mut self, thread_id: String) {
        self.session_id = thread_id;
        self.history_cells.clear();
        self.active_cell = None;
        self.unified_exec_wait_streak = None;
        self.clear_unified_exec_processes();
        self.local_user_message_echoes.clear();
        self.history_cells_flushed_to_scrollback = 0;
        self.assistant_stream = StreamController::new(None);
        self.adaptive_chunking.reset();
        self.active_turn_id = None;
        self.pending_approvals.clear();
        self.pending_prompt = None;
        self.status_message = None;
        self.previous_state = None;
        self.latest_state = "active".to_string();
        self.received_events = 0;
        self.last_sequence = 0;
        self.token_info = None;
        self.total_token_usage = codex_core::protocol::TokenUsage::default();
        self.rate_limit_snapshots_by_limit_id.clear();
        self.running_commands.clear();
        self.agent_turn_running = false;
        self.mcp_startup_running = false;
        self.had_work_activity = false;
        self.turn_runtime_metrics = codex_otel::RuntimeMetricsSummary::default();
        self.reasoning_buffer.clear();
        self.full_reasoning_buffer.clear();
        self.current_rollout_path = None;
        self.status_line_branch = None;
        self.status_line_branch_cwd = None;
        self.status_line_branch_pending = false;
        self.status_line_branch_lookup_complete = false;
        self.bottom_pane.hide_status_indicator();
        self.bottom_pane.set_interrupt_hint_visible(false);
        self.bottom_pane.set_context_window(None, None);
        self.clear_input();
        self.refresh_status_line();
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

    pub(crate) fn has_history_cells(&self) -> bool {
        !self.history_cells.is_empty()
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

    pub(crate) fn push_fullscreen_approval_request(
        &mut self,
        request: crate::bottom_pane::ApprovalRequest,
    ) {
        self.bottom_pane
            .push_approval_request(request, &codex_core::features::Features::default());
    }

    pub(crate) fn cancel_status_line_setup(&mut self) {
        self.status_message = Some("status line setup cancelled".to_string());
    }

    pub(crate) fn setup_status_line(&mut self, items: Vec<crate::bottom_pane::StatusLineItem>) {
        let ids = items.iter().map(ToString::to_string).collect::<Vec<_>>();
        self.status_line_items = Some(ids);
        self.status_line_invalid_items_warned = false;
        self.refresh_status_line();
        self.status_message = Some("status line updated".to_string());
    }

    pub(crate) fn set_status_line_branch(&mut self, cwd: PathBuf, branch: Option<String>) {
        if self.status_line_branch_cwd.as_ref() != Some(&cwd) {
            self.status_line_branch_pending = false;
            return;
        }
        self.status_line_branch = branch;
        self.status_line_branch_pending = false;
        self.status_line_branch_lookup_complete = true;
    }

    pub(crate) fn refresh_status_line(&mut self) {
        let (items, invalid_items) = self.status_line_items_with_invalids();
        if !invalid_items.is_empty() && !self.status_line_invalid_items_warned {
            self.on_warning(format!(
                "Ignored invalid status line {}.",
                invalid_items.join(", ")
            ));
            self.status_line_invalid_items_warned = true;
        }

        let enabled = !self.configured_status_line_items().is_empty();
        self.bottom_pane.set_status_line_enabled(enabled);
        if !enabled {
            self.bottom_pane.set_status_line(None);
            self.status_line_branch = None;
            self.status_line_branch_pending = false;
            self.status_line_branch_lookup_complete = false;
            return;
        }

        let cwd = self.status_line_cwd().to_path_buf();
        self.sync_status_line_branch_state(&cwd);
        if items.contains(&crate::bottom_pane::StatusLineItem::GitBranch)
            && !self.status_line_branch_lookup_complete
        {
            self.request_status_line_branch(cwd);
        }

        let mut parts = Vec::new();
        for item in items {
            if let Some(value) = self.status_line_value_for_item(&item) {
                parts.push(value);
            }
        }

        let line = if parts.is_empty() {
            None
        } else {
            Some(Line::from(parts.join(" · ")))
        };
        self.bottom_pane.set_status_line(line);
    }

    fn request_status_line_branch_refresh(&mut self) {
        let (items, _) = self.status_line_items_with_invalids();
        if items.is_empty() || !items.contains(&crate::bottom_pane::StatusLineItem::GitBranch) {
            return;
        }
        let cwd = self.status_line_cwd();
        self.sync_status_line_branch_state(&cwd);
        self.request_status_line_branch(cwd);
    }

    fn update_task_running_state(&mut self) {
        let running = self.agent_turn_running || self.mcp_startup_running;
        self.bottom_pane.set_task_running(running);
        self.bottom_pane
            .set_interrupt_hint_visible(self.agent_turn_running);
    }

    fn set_token_info(&mut self, info: Option<codex_core::protocol::TokenUsageInfo>) {
        match info {
            Some(info) => self.apply_token_info(info),
            None => {
                self.bottom_pane.set_context_window(None, None);
                self.token_info = None;
                self.refresh_status_line();
            }
        }
    }

    fn apply_token_info(&mut self, info: codex_core::protocol::TokenUsageInfo) {
        let percent = self.context_remaining_percent(&info);
        let used_tokens = self.context_used_tokens(&info, percent.is_some());
        self.bottom_pane.set_context_window(percent, used_tokens);
        self.token_info = Some(info);
        self.refresh_status_line();
    }

    fn context_remaining_percent(
        &self,
        info: &codex_core::protocol::TokenUsageInfo,
    ) -> Option<i64> {
        info.model_context_window.map(|window| {
            info.last_token_usage
                .percent_of_context_window_remaining(window)
        })
    }

    fn context_used_tokens(
        &self,
        info: &codex_core::protocol::TokenUsageInfo,
        percent_known: bool,
    ) -> Option<i64> {
        if percent_known {
            return None;
        }
        Some(info.last_token_usage.tokens_in_context_window())
    }

    fn on_rate_limit_snapshot(
        &mut self,
        snapshot: Option<codex_core::protocol::RateLimitSnapshot>,
    ) {
        if let Some(mut snapshot) = snapshot {
            let limit_id = snapshot
                .limit_id
                .clone()
                .unwrap_or_else(|| "codex".to_string());
            let limit_label = snapshot
                .limit_name
                .clone()
                .unwrap_or_else(|| limit_id.clone());
            if snapshot.credits.is_none() {
                snapshot.credits = self
                    .rate_limit_snapshots_by_limit_id
                    .get(&limit_id)
                    .and_then(|display| display.credits.as_ref())
                    .map(|credits| codex_core::protocol::CreditsSnapshot {
                        has_credits: credits.has_credits,
                        unlimited: credits.unlimited,
                        balance: credits.balance.clone(),
                    });
            }
            let display =
                rate_limit_snapshot_display_for_limit(&snapshot, limit_label, chrono::Local::now());
            self.rate_limit_snapshots_by_limit_id
                .insert(limit_id, display);
        } else {
            self.rate_limit_snapshots_by_limit_id.clear();
        }
        self.refresh_status_line();
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
        let active_cell_renderable = match &self.active_cell {
            Some(cell) => RenderableItem::Borrowed(cell).inset(Insets::tlbr(1, 0, 0, 0)),
            None => RenderableItem::Owned(Box::new(())),
        };
        let mut flex = FlexRenderable::new();
        flex.push(1, active_cell_renderable);
        flex.push(
            0,
            RenderableItem::Borrowed(&self.bottom_pane).inset(Insets::tlbr(1, 0, 0, 0)),
        );
        RenderableItem::Owned(Box::new(flex))
    }

    pub(crate) fn history_view_lines(&self, width: u16) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        for cell in self
            .history_cells
            .iter()
            .skip(self.history_cells_flushed_to_scrollback)
        {
            lines.extend(cell.display_lines(width));
        }
        if let Some(cell) = self.active_cell.as_ref() {
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

    fn status_line_items_with_invalids(
        &self,
    ) -> (Vec<crate::bottom_pane::StatusLineItem>, Vec<String>) {
        let configured_items = self.configured_status_line_items();
        let mut items = Vec::new();
        let mut invalid = Vec::new();
        let mut invalid_seen = HashSet::new();
        for item_id in configured_items {
            match item_id.parse::<crate::bottom_pane::StatusLineItem>() {
                Ok(item) => items.push(item),
                Err(_) => {
                    if invalid_seen.insert(item_id.clone()) {
                        invalid.push(format!(r#""{item_id}""#));
                    }
                }
            }
        }
        (items, invalid)
    }

    fn configured_status_line_items(&self) -> Vec<String> {
        self.status_line_items.clone().unwrap_or_else(|| {
            DEFAULT_STATUS_LINE_ITEMS
                .iter()
                .map(ToString::to_string)
                .collect()
        })
    }

    fn status_line_cwd(&self) -> PathBuf {
        std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir())
    }

    fn status_line_project_root(&self) -> Option<PathBuf> {
        let cwd = self.status_line_cwd();
        codex_core::git_info::get_git_repo_root(&cwd)
    }

    fn status_line_project_root_name(&self) -> Option<String> {
        self.status_line_project_root().map(|root| {
            root.file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_else(|| root.display().to_string())
        })
    }

    fn sync_status_line_branch_state(&mut self, cwd: &Path) {
        if self
            .status_line_branch_cwd
            .as_ref()
            .is_some_and(|cached| cached == cwd)
        {
            return;
        }
        self.status_line_branch_cwd = Some(cwd.to_path_buf());
        self.status_line_branch = None;
        self.status_line_branch_pending = false;
        self.status_line_branch_lookup_complete = false;
    }

    fn request_status_line_branch(&mut self, cwd: PathBuf) {
        if self.status_line_branch_pending {
            return;
        }
        self.status_line_branch_pending = true;
        let sender = self.bottom_pane_event_tx.clone();
        std::thread::spawn(move || {
            let branch = std::process::Command::new("git")
                .args(["branch", "--show-current"])
                .current_dir(&cwd)
                .output()
                .ok()
                .and_then(|out| {
                    if !out.status.success() {
                        return None;
                    }
                    String::from_utf8(out.stdout).ok()
                })
                .map(|s| s.trim().to_string())
                .filter(|name| !name.is_empty());
            sender.send(UiAppEvent::StatusLineBranchUpdated { cwd, branch });
        });
    }

    fn status_line_value_for_item(
        &self,
        item: &crate::bottom_pane::StatusLineItem,
    ) -> Option<String> {
        use crate::bottom_pane::StatusLineItem;
        match item {
            StatusLineItem::ModelName => self
                .active_collaboration_mask
                .as_ref()
                .and_then(|m| m.model.clone())
                .or_else(|| Some("gpt-5.3-codex".to_string())),
            StatusLineItem::ModelWithReasoning => {
                let model = self
                    .active_collaboration_mask
                    .as_ref()
                    .and_then(|m| m.model.clone())
                    .unwrap_or_else(|| "gpt-5.3-codex".to_string());
                let effort = self
                    .active_collaboration_mask
                    .as_ref()
                    .and_then(|m| m.reasoning_effort)
                    .flatten()
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "none".to_string());
                Some(format!("{model} {effort}"))
            }
            StatusLineItem::CurrentDir => {
                Some(format_directory_display(&self.status_line_cwd(), None))
            }
            StatusLineItem::ProjectRoot => self.status_line_project_root_name(),
            StatusLineItem::GitBranch => self.status_line_branch.clone(),
            StatusLineItem::ContextRemaining => self
                .status_line_context_remaining_percent()
                .map(|v| format!("{v}% left")),
            StatusLineItem::ContextUsed => self
                .status_line_context_used_percent()
                .map(|v| format!("{v}% used")),
            StatusLineItem::FiveHourLimit => self
                .rate_limit_snapshots_by_limit_id
                .get("codex")
                .or_else(|| self.rate_limit_snapshots_by_limit_id.values().next())
                .and_then(|display| display.primary.as_ref())
                .and_then(|window| self.status_line_limit_display(window, "5h")),
            StatusLineItem::WeeklyLimit => self
                .rate_limit_snapshots_by_limit_id
                .get("codex")
                .or_else(|| self.rate_limit_snapshots_by_limit_id.values().next())
                .and_then(|display| display.secondary.as_ref())
                .and_then(|window| self.status_line_limit_display(window, "weekly")),
            StatusLineItem::CodexVersion => Some(format!("v{CODEX_CLI_VERSION}")),
            StatusLineItem::ContextWindowSize => self
                .status_line_context_window_size()
                .map(|window| format!("{} window", format_tokens_compact(window))),
            StatusLineItem::UsedTokens => Some(format!(
                "{} used",
                format_tokens_compact(self.status_line_total_usage().total_tokens)
            )),
            StatusLineItem::TotalInputTokens => Some(format!(
                "{} in",
                format_tokens_compact(self.status_line_total_usage().input_tokens)
            )),
            StatusLineItem::TotalOutputTokens => Some(format!(
                "{} out",
                format_tokens_compact(self.status_line_total_usage().output_tokens)
            )),
            StatusLineItem::SessionId => Some(self.session_id.clone()),
        }
    }

    fn status_line_context_window_size(&self) -> Option<i64> {
        self.token_info
            .as_ref()
            .and_then(|info| info.model_context_window)
    }

    fn status_line_context_remaining_percent(&self) -> Option<i64> {
        let info = self.token_info.as_ref()?;
        let context_window = info.model_context_window?;
        Some(
            info.last_token_usage
                .percent_of_context_window_remaining(context_window),
        )
    }

    fn status_line_context_used_percent(&self) -> Option<i64> {
        let remaining = self.status_line_context_remaining_percent()?;
        Some((100 - remaining).clamp(0, 100))
    }

    fn status_line_total_usage(&self) -> codex_core::protocol::TokenUsage {
        self.total_token_usage
    }

    fn status_line_limit_display(
        &self,
        window: &RateLimitWindowDisplay,
        label: &str,
    ) -> Option<String> {
        let left = (100.0 - window.used_percent).round().clamp(0.0, 100.0) as i64;
        if left <= 0 {
            return None;
        }
        Some(format!("{label} {left}%"))
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
        if let Some(info) = &self.token_info
            && let Some(window) = info.model_context_window
        {
            let remaining = info
                .last_token_usage
                .percent_of_context_window_remaining(window)
                .clamp(0, 100);
            return remaining as usize;
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ActiveCellTranscriptKey {
    pub(crate) revision: u64,
    pub(crate) is_stream_continuation: bool,
    pub(crate) animation_tick: Option<u64>,
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

    pub(crate) fn active_cell_transcript_key(&self) -> Option<ActiveCellTranscriptKey> {
        self.ui.active_cell_transcript_key()
    }

    pub(crate) fn active_cell_transcript_lines(&self, width: u16) -> Option<Vec<Line<'static>>> {
        self.ui.active_cell_transcript_lines(width)
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

fn extract_first_bold(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b'*' && bytes[i + 1] == b'*' {
            let start = i + 2;
            let mut j = start;
            while j + 1 < bytes.len() {
                if bytes[j] == b'*' && bytes[j + 1] == b'*' {
                    let inner = &s[start..j];
                    let trimmed = inner.trim();
                    if !trimmed.is_empty() {
                        return Some(trimmed.to_string());
                    } else {
                        return None;
                    }
                }
                j += 1;
            }
            return None;
        }
        i += 1;
    }
    None
}

fn runtime_metrics_is_empty(summary: &codex_otel::RuntimeMetricsSummary) -> bool {
    summary.tool_calls.count == 0
        && summary.tool_calls.duration_ms == 0
        && summary.api_calls.count == 0
        && summary.api_calls.duration_ms == 0
        && summary.websocket_calls.count == 0
        && summary.websocket_calls.duration_ms == 0
        && summary.streaming_events.count == 0
        && summary.streaming_events.duration_ms == 0
        && summary.websocket_events.count == 0
        && summary.websocket_events.duration_ms == 0
        && summary.responses_api_overhead_ms == 0
        && summary.responses_api_inference_time_ms == 0
        && summary.responses_api_engine_iapi_ttft_ms == 0
        && summary.responses_api_engine_service_ttft_ms == 0
        && summary.responses_api_engine_iapi_tbt_ms == 0
        && summary.responses_api_engine_service_tbt_ms == 0
}

fn runtime_metrics_merge(
    mut into: codex_otel::RuntimeMetricsSummary,
    delta: codex_otel::RuntimeMetricsSummary,
) -> codex_otel::RuntimeMetricsSummary {
    into.tool_calls.count = into.tool_calls.count.saturating_add(delta.tool_calls.count);
    into.tool_calls.duration_ms = into
        .tool_calls
        .duration_ms
        .saturating_add(delta.tool_calls.duration_ms);
    into.api_calls.count = into.api_calls.count.saturating_add(delta.api_calls.count);
    into.api_calls.duration_ms = into
        .api_calls
        .duration_ms
        .saturating_add(delta.api_calls.duration_ms);
    into.websocket_calls.count = into
        .websocket_calls
        .count
        .saturating_add(delta.websocket_calls.count);
    into.websocket_calls.duration_ms = into
        .websocket_calls
        .duration_ms
        .saturating_add(delta.websocket_calls.duration_ms);
    into.streaming_events.count = into
        .streaming_events
        .count
        .saturating_add(delta.streaming_events.count);
    into.streaming_events.duration_ms = into
        .streaming_events
        .duration_ms
        .saturating_add(delta.streaming_events.duration_ms);
    into.websocket_events.count = into
        .websocket_events
        .count
        .saturating_add(delta.websocket_events.count);
    into.websocket_events.duration_ms = into
        .websocket_events
        .duration_ms
        .saturating_add(delta.websocket_events.duration_ms);
    into.responses_api_overhead_ms = into
        .responses_api_overhead_ms
        .saturating_add(delta.responses_api_overhead_ms);
    into.responses_api_inference_time_ms = into
        .responses_api_inference_time_ms
        .saturating_add(delta.responses_api_inference_time_ms);
    into.responses_api_engine_iapi_ttft_ms = into
        .responses_api_engine_iapi_ttft_ms
        .saturating_add(delta.responses_api_engine_iapi_ttft_ms);
    into.responses_api_engine_service_ttft_ms = into
        .responses_api_engine_service_ttft_ms
        .saturating_add(delta.responses_api_engine_service_ttft_ms);
    into.responses_api_engine_iapi_tbt_ms = into
        .responses_api_engine_iapi_tbt_ms
        .saturating_add(delta.responses_api_engine_iapi_tbt_ms);
    into.responses_api_engine_service_tbt_ms = into
        .responses_api_engine_service_tbt_ms
        .saturating_add(delta.responses_api_engine_service_tbt_ms);
    into
}

fn user_message_fingerprint(
    text: &str,
    text_elements: &[codex_protocol::user_input::TextElement],
) -> String {
    let elements = serde_json::to_string(text_elements).unwrap_or_default();
    format!("{text}\n{elements}")
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
