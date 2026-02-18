//! App-server compatibility seam for the TUI runtime.
//!
//! This module keeps transport/event translation isolated from UI files so the
//! UI can be moved closer to upstream structure without pulling in `codex-core`.
//!
//! ## Architecture
//! Upstream codex-tui depends on `codex-core` for event types, config, auth, and
//! protocol handling. Crabbot instead talks directly to an app-server websocket server.
//! This module provides the same *structural types* the rest of the TUI expects
//! (events, exit info, config shims) without pulling in `codex-core`.
use super::*;
use crabbot_protocol::DaemonRpcServerRequest;
use std::sync::mpsc;
use std::time::Duration;

pub mod config {
    pub mod types {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub enum NotificationMethod {
            #[default]
            Auto,
            Osc9,
            Bel,
        }

        impl std::fmt::Display for NotificationMethod {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    NotificationMethod::Auto => f.write_str("auto"),
                    NotificationMethod::Osc9 => f.write_str("osc9"),
                    NotificationMethod::Bel => f.write_str("bel"),
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct UiApprovalRequest {
    pub(crate) key: String,
    pub(crate) request_id: Value,
    pub(crate) method: String,
    pub(crate) reason: Option<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) turn_id: Option<String>,
    pub(crate) server_name: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum UiEvent {
    SessionConfigured {
        session_id: String,
        model: String,
        reasoning_effort: Option<codex_protocol::openai_models::ReasoningEffort>,
        history_log_id: u64,
        history_entry_count: usize,
    },
    SessionState(String),
    ThreadStarted {
        thread_id: String,
        rollout_path: Option<String>,
    },
    ThreadRenamed(String),
    TurnStarted(String),
    AssistantDelta {
        turn_id: Option<String>,
        delta: String,
    },
    AgentMessage {
        message: String,
    },
    AgentReasoningDelta {
        delta: String,
    },
    AgentReasoningFinal,
    AgentReasoningSectionBreak,
    AgentMessageItemCompleted {
        phase: Option<String>,
    },
    PlanItemCompleted {
        text: String,
    },
    TurnCompleted {
        status: Option<String>,
        last_agent_message: Option<String>,
    },
    TurnAborted {
        reason: Option<String>,
    },
    Error {
        message: String,
    },
    Warning {
        message: String,
    },
    StreamError {
        message: String,
        additional_details: Option<String>,
    },
    ExecCommandBegin {
        call_id: String,
        process_id: Option<String>,
        command: Vec<String>,
        parsed: Vec<codex_protocol::parse_command::ParsedCommand>,
        source: codex_core::protocol::ExecCommandSource,
    },
    ExecCommandOutputDelta {
        call_id: String,
        delta: String,
    },
    TerminalInteraction {
        process_id: String,
        stdin: String,
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
    WebSearchBegin {
        call_id: String,
        query: String,
    },
    WebSearchEnd {
        call_id: String,
        query: String,
        action: codex_protocol::models::WebSearchAction,
    },
    ThreadRolledBack {
        num_turns: u64,
    },
    TurnDiffUpdated {
        unified_diff: String,
    },
    UndoStarted {
        message: Option<String>,
    },
    UndoCompleted {
        message: Option<String>,
    },
    PlanUpdated(codex_protocol::plan_tool::UpdatePlanArgs),
    PatchApplyBegin {
        changes: std::collections::HashMap<std::path::PathBuf, codex_core::protocol::FileChange>,
    },
    PatchApplyEnd {
        success: bool,
        stderr: String,
    },
    ViewImageToolCall {
        path: std::path::PathBuf,
    },
    GetHistoryEntryResponse {
        offset: usize,
        log_id: u64,
        entry_text: Option<String>,
    },
    DeprecationNotice {
        message: String,
    },
    BackgroundEvent {
        message: String,
    },
    ReviewModeEntered {
        hint: Option<String>,
    },
    ReviewModeExited {
        review_output_overall_explanation: Option<String>,
        review_output_findings_count: Option<usize>,
    },
    UserMessage {
        text: String,
        text_elements: Vec<codex_protocol::user_input::TextElement>,
    },
    CustomPromptsListed(Vec<codex_protocol::custom_prompts::CustomPrompt>),
    SkillsListed(Vec<codex_core::skills::model::SkillMetadata>),
    SkillsUpdateAvailable,
    ShutdownComplete,
    TranscriptLine(String),
    StatusMessage(String),
    ApprovalRequired(UiApprovalRequest),
    TokenUsageUpdated {
        token_info: codex_core::protocol::TokenUsageInfo,
        total_usage: codex_core::protocol::TokenUsage,
    },
    RateLimitUpdated(codex_core::protocol::RateLimitSnapshot),
    RuntimeMetricsUpdated(codex_otel::RuntimeMetricsSummary),
    McpStartupUpdate {
        server: String,
        status: String,
    },
    McpStartupComplete {
        failed: Vec<String>,
        cancelled: Vec<String>,
    },
    CollabEvent(String),
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
}

pub(crate) fn map_legacy_stream_events(stream_events: &[DaemonStreamEnvelope]) -> Vec<UiEvent> {
    let mut events = Vec::new();
    for envelope in stream_events {
        match &envelope.event {
            DaemonStreamEvent::SessionState(payload) => {
                events.push(UiEvent::SessionState(payload.state.clone()));
            }
            DaemonStreamEvent::TurnStreamDelta(payload) => {
                events.push(UiEvent::TurnStarted(payload.turn_id.clone()));
                events.push(UiEvent::AssistantDelta {
                    turn_id: Some(payload.turn_id.clone()),
                    delta: payload.delta.clone(),
                });
            }
            DaemonStreamEvent::TurnCompleted(payload) => {
                events.push(UiEvent::TurnCompleted {
                    status: Some("completed".to_string()),
                    last_agent_message: None,
                });
                if !payload.output_summary.trim().is_empty() {
                    events.push(UiEvent::TranscriptLine(format!(
                        "[turn complete] {}",
                        payload.output_summary
                    )));
                }
            }
            DaemonStreamEvent::ApprovalRequired(payload) => {
                events.push(UiEvent::TranscriptLine(format!(
                    "[approval required] id={} action={}",
                    payload.approval_id, payload.action_kind
                )));
                events.push(UiEvent::TranscriptLine(format!(
                    "prompt: {}",
                    payload.prompt
                )));
                events.push(UiEvent::TranscriptLine(
                    "after approval, resume with: /resume".to_string(),
                ));
            }
            DaemonStreamEvent::Heartbeat(_) => {}
        }
    }
    events
}

pub(crate) fn map_rpc_stream_events(stream_events: &[DaemonRpcStreamEnvelope]) -> Vec<UiEvent> {
    let mut events = Vec::new();
    for envelope in stream_events {
        match &envelope.event {
            DaemonRpcStreamEvent::Notification(notification) => {
                events.extend(map_rpc_notification(notification));
            }
            DaemonRpcStreamEvent::ServerRequest(request) => {
                let summary = summarize_server_request(request);
                if matches!(
                    request.method.as_str(),
                    "item/commandExecution/requestApproval"
                        | "item/fileChange/requestApproval"
                        | "execCommandApproval"
                        | "applyPatchApproval"
                        | "item/tool/elicit"
                        | "item/mcpToolCall/requestApproval"
                        | "item/tool/requestUserInput"
                ) {
                    let request_key = request_id_key_for_cli(&request.request_id);
                    let operation_id = request
                        .params
                        .get("id")
                        .or_else(|| request.params.get("callId"))
                        .or_else(|| request.params.get("itemId"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    let turn_id = request
                        .params
                        .get("turnId")
                        .or_else(|| request.params.get("turn_id"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    let server_name = request
                        .params
                        .get("serverName")
                        .or_else(|| request.params.get("server_name"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    events.push(UiEvent::ApprovalRequired(UiApprovalRequest {
                        key: request_key.clone(),
                        request_id: request.request_id.clone(),
                        method: request.method.clone(),
                        reason: request
                            .params
                            .get("reason")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                        operation_id,
                        turn_id,
                        server_name,
                    }));
                    if let Some(mapped) = map_rpc_server_request_to_ui_event(request, &request_key)
                    {
                        events.push(mapped);
                    }
                }
                events.push(UiEvent::TranscriptLine(summary));
            }
            DaemonRpcStreamEvent::DecodeError(error) => {
                events.push(UiEvent::TranscriptLine(format!(
                    "[app-server rpc decode error] {}",
                    error.message
                )));
            }
        }
    }
    events
}

fn map_rpc_notification(notification: &DaemonRpcNotification) -> Vec<UiEvent> {
    match notification.method.as_str() {
        "codex/event/session_configured" | "session/configured" => {
            map_session_configured_notification(&notification.params)
        }
        "thread/started" => notification
            .params
            .get("thread")
            .and_then(|thread| {
                let thread_id = thread.get("id").and_then(Value::as_str)?;
                let rollout_path = thread
                    .get("path")
                    .or_else(|| thread.get("rolloutPath"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                Some(vec![UiEvent::ThreadStarted {
                    thread_id: thread_id.to_string(),
                    rollout_path,
                }])
            })
            .unwrap_or_default(),
        "turn/started" => notification
            .params
            .get("turn")
            .and_then(|turn| turn.get("id"))
            .and_then(Value::as_str)
            .map(|turn_id| vec![UiEvent::TurnStarted(turn_id.to_string())])
            .unwrap_or_default(),
        "thread/name/updated" => notification
            .params
            .get("thread")
            .and_then(|thread| thread.get("name"))
            .and_then(Value::as_str)
            .map(|name| vec![UiEvent::ThreadRenamed(name.to_string())])
            .unwrap_or_default(),
        "item/agentMessage/delta" | "item/plan/delta" => delta_from_params(&notification.params)
            .map(|delta| {
                vec![UiEvent::AssistantDelta {
                    turn_id: None,
                    delta: delta.to_string(),
                }]
            })
            .unwrap_or_default(),
        "item/reasoning/summaryTextDelta" | "item/reasoning/textDelta" => {
            delta_from_params(&notification.params)
                .map(|delta| {
                    vec![UiEvent::AgentReasoningDelta {
                        delta: delta.to_string(),
                    }]
                })
                .unwrap_or_default()
        }
        "item/reasoning/summaryPartAdded" => vec![UiEvent::AgentReasoningSectionBreak],
        "item/commandExecution/outputDelta" | "item/fileChange/outputDelta" => {
            let Some(delta) = delta_from_params(&notification.params) else {
                return Vec::new();
            };
            let Some(call_id) = item_id_from_params(&notification.params) else {
                return vec![UiEvent::TranscriptLine(delta.to_string())];
            };
            vec![UiEvent::ExecCommandOutputDelta {
                call_id,
                delta: delta.to_string(),
            }]
        }
        "item/commandExecution/terminalInteraction" => {
            let process_id = notification
                .params
                .get("processId")
                .or_else(|| notification.params.get("process_id"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let stdin = notification
                .params
                .get("stdin")
                .or_else(|| notification.params.get("prompt"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            vec![UiEvent::TerminalInteraction { process_id, stdin }]
        }
        "item/commandExecution/begin" => {
            let command = command_vec_from_value(notification.params.get("command"));
            let command = if command.is_empty() {
                vec!["command".to_string()]
            } else {
                command
            };
            vec![UiEvent::ExecCommandBegin {
                call_id: item_id_from_params(&notification.params)
                    .unwrap_or_else(|| "exec".to_string()),
                process_id: notification
                    .params
                    .get("processId")
                    .or_else(|| notification.params.get("process_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                command,
                parsed: parsed_command_vec_from_value(
                    notification
                        .params
                        .get("parsedCommand")
                        .or_else(|| notification.params.get("commandActions")),
                ),
                source: parse_exec_source(notification.params.get("source")),
            }]
        }
        "item/commandExecution/end" => {
            let exit_code = notification
                .params
                .get("exitCode")
                .or_else(|| notification.params.get("exit_code"))
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let Some(call_id) = item_id_from_params(&notification.params) else {
                return vec![UiEvent::TranscriptLine(format!(
                    "[exec done] exit_code={exit_code}"
                ))];
            };
            vec![UiEvent::ExecCommandEnd {
                call_id,
                process_id: notification
                    .params
                    .get("processId")
                    .or_else(|| notification.params.get("process_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                source: parse_exec_source(notification.params.get("source")),
                exit_code: exit_code as i32,
                formatted_output: notification
                    .params
                    .get("formattedOutput")
                    .or_else(|| notification.params.get("formatted_output"))
                    .or_else(|| notification.params.get("output"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                aggregated_output: notification
                    .params
                    .get("aggregatedOutput")
                    .or_else(|| notification.params.get("aggregated_output"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                duration: duration_ms_to_duration(
                    notification
                        .params
                        .get("durationMs")
                        .or_else(|| notification.params.get("duration_ms"))
                        .and_then(Value::as_i64)
                        .unwrap_or_default(),
                ),
            }]
        }
        "item/fileChange/begin" => parse_file_changes(
            notification
                .params
                .get("changes")
                .or_else(|| notification.params.get("fileChanges"))
                .or_else(|| notification.params.get("diff")),
        )
        .map(|changes| vec![UiEvent::PatchApplyBegin { changes }])
        .unwrap_or_else(|| vec![UiEvent::TranscriptLine("[patch applying]".to_string())]),
        "item/fileChange/end" => {
            let success = notification
                .params
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let stderr = notification
                .params
                .get("stderr")
                .or_else(|| notification.params.get("error"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            vec![UiEvent::PatchApplyEnd { success, stderr }]
        }
        "item/mcpToolCall/begin" => {
            let call_id =
                item_id_from_params(&notification.params).unwrap_or_else(|| "mcp".to_string());
            let server = notification
                .params
                .get("serverName")
                .or_else(|| notification.params.get("server"))
                .and_then(Value::as_str)
                .unwrap_or("mcp")
                .to_string();
            let tool = notification
                .params
                .get("toolName")
                .or_else(|| notification.params.get("tool"))
                .and_then(Value::as_str)
                .unwrap_or("tool")
                .to_string();
            vec![UiEvent::McpToolCallBegin {
                call_id,
                invocation: codex_core::protocol::McpInvocation {
                    server: server.clone(),
                    tool: tool.clone(),
                    arguments: notification.params.get("arguments").cloned(),
                    server_name: server,
                    tool_name: tool,
                },
            }]
        }
        "item/mcpToolCall/end" => {
            let Some(call_id) = item_id_from_params(&notification.params) else {
                return Vec::new();
            };
            let duration_ms = notification
                .params
                .get("durationMs")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let result = if let Some(error) = notification
                .params
                .get("error")
                .and_then(|err| err.get("message"))
                .and_then(Value::as_str)
            {
                Err(error.to_string())
            } else {
                let content = notification
                    .params
                    .get("result")
                    .and_then(|result| result.get("content"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let is_error = notification
                    .params
                    .get("result")
                    .and_then(|result| result.get("isError"))
                    .and_then(Value::as_bool);
                Ok(codex_protocol::mcp::CallToolResult { content, is_error })
            };
            vec![UiEvent::McpToolCallEnd {
                call_id,
                duration: duration_ms_to_duration(duration_ms),
                result,
            }]
        }
        "item/started" => map_item_started_notification(&notification.params),
        "item/completed" => notification
            .params
            .get("item")
            .and_then(|item| item.get("type"))
            .and_then(Value::as_str)
            .filter(|item_type| *item_type == "user_message" || *item_type == "userMessage")
            .and_then(|_| {
                notification
                    .params
                    .get("item")
                    .and_then(parse_user_message_item)
            })
            .map(|(text, text_elements)| {
                vec![UiEvent::UserMessage {
                    text,
                    text_elements,
                }]
            })
            .or_else(|| {
                notification
                    .params
                    .get("item")
                    .and_then(parse_plan_item_completed)
                    .map(|text| vec![UiEvent::PlanItemCompleted { text }])
            })
            .or_else(|| {
                notification
                    .params
                    .get("item")
                    .and_then(parse_agent_message_item_completed)
                    .map(|phase| vec![UiEvent::AgentMessageItemCompleted { phase }])
            })
            .unwrap_or_else(|| map_item_completed_notification(&notification.params)),
        "item/viewImageToolCall" | "item/view_image_tool_call" | "item/viewImage/toolCall" => {
            notification
                .params
                .get("path")
                .or_else(|| notification.params.get("imagePath"))
                .and_then(Value::as_str)
                .map(|path| {
                    vec![UiEvent::ViewImageToolCall {
                        path: std::path::PathBuf::from(path),
                    }]
                })
                .unwrap_or_default()
        }
        "history/entry/response" | "history/entryResponse" | "getHistoryEntry/response" => {
            parse_history_entry_response(&notification.params)
                .map(|event| vec![event])
                .unwrap_or_default()
        }
        "turn/completed" => {
            let status = notification
                .params
                .get("turn")
                .and_then(|turn| turn.get("status"))
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let last_agent_message = notification
                .params
                .get("turn")
                .and_then(|turn| {
                    turn.get("lastAgentMessage")
                        .or_else(|| turn.get("last_agent_message"))
                })
                .and_then(Value::as_str)
                .map(ToString::to_string);
            vec![UiEvent::TurnCompleted {
                status,
                last_agent_message,
            }]
        }
        "thread/compacted" => vec![UiEvent::AssistantDelta {
            turn_id: None,
            delta: "Context compacted".to_string(),
        }],
        "thread/rolledBack" | "thread/rolled_back" => notification
            .params
            .get("rollback")
            .and_then(|rollback| {
                rollback
                    .get("numTurns")
                    .or_else(|| rollback.get("num_turns"))
            })
            .and_then(Value::as_u64)
            .map(|num_turns| vec![UiEvent::ThreadRolledBack { num_turns }])
            .unwrap_or_else(|| vec![UiEvent::ThreadRolledBack { num_turns: 0 }]),
        "turn/aborted" => vec![UiEvent::TurnAborted {
            reason: notification
                .params
                .get("turn")
                .and_then(|turn| turn.get("reason"))
                .or_else(|| notification.params.get("reason"))
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }],
        "turn/failed" => vec![UiEvent::TurnCompleted {
            status: Some("failed".to_string()),
            last_agent_message: None,
        }],
        "turn/diff/updated" => notification
            .params
            .get("unifiedDiff")
            .or_else(|| notification.params.get("unified_diff"))
            .and_then(Value::as_str)
            .map(|diff| {
                vec![UiEvent::TurnDiffUpdated {
                    unified_diff: diff.to_string(),
                }]
            })
            .unwrap_or_default(),
        "undo/started" => vec![UiEvent::UndoStarted {
            message: notification
                .params
                .get("message")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }],
        "undo/completed" => vec![UiEvent::UndoCompleted {
            message: notification
                .params
                .get("message")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }],
        "deprecation/notice" => notification
            .params
            .get("message")
            .and_then(Value::as_str)
            .map(|message| {
                vec![UiEvent::DeprecationNotice {
                    message: message.to_string(),
                }]
            })
            .unwrap_or_default(),
        "background/event" => notification
            .params
            .get("message")
            .and_then(Value::as_str)
            .map(|message| {
                vec![UiEvent::BackgroundEvent {
                    message: message.to_string(),
                }]
            })
            .unwrap_or_default(),
        "thread/tokenUsage/updated" => parse_token_usage_updated(&notification.params)
            .map(|(token_info, total_usage)| {
                vec![UiEvent::TokenUsageUpdated {
                    token_info,
                    total_usage,
                }]
            })
            .unwrap_or_default(),
        "account/rateLimits/updated" => notification
            .params
            .get("rateLimits")
            .or_else(|| notification.params.get("rate_limits"))
            .and_then(parse_rate_limit_snapshot)
            .map(|snapshot| vec![UiEvent::RateLimitUpdated(snapshot)])
            .unwrap_or_default(),
        "thread/runtimeMetrics/updated" | "thread/runtime_metrics/updated" => {
            parse_runtime_metrics_summary(
                notification
                    .params
                    .get("runtimeMetrics")
                    .or_else(|| notification.params.get("runtime_metrics"))
                    .or_else(|| notification.params.get("summary"))
                    .or_else(|| notification.params.get("delta"))
                    .unwrap_or(&notification.params),
            )
            .map(|summary| vec![UiEvent::RuntimeMetricsUpdated(summary)])
            .unwrap_or_default()
        }
        "mcp/startup/update" => {
            let server = notification
                .params
                .get("server")
                .and_then(Value::as_str)
                .unwrap_or("mcp")
                .to_string();
            let status = notification
                .params
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("starting")
                .to_string();
            vec![UiEvent::McpStartupUpdate { server, status }]
        }
        "mcp/startup/complete" => {
            let failed = notification
                .params
                .get("failed")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.get("server").and_then(Value::as_str))
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let cancelled = notification
                .params
                .get("cancelled")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            vec![UiEvent::McpStartupComplete { failed, cancelled }]
        }
        method
            if method.starts_with("collab/")
                || method.starts_with("item/collab")
                || method.contains("/collab")
                || method.contains("collab/")
                || method.contains("agentSpawn")
                || method.contains("agent_spawn") =>
        {
            vec![UiEvent::CollabEvent(format!("[collab] {method}"))]
        }
        "codex/event" => map_codex_event_notification(&notification.params),
        _ => Vec::new(),
    }
}

fn map_rpc_server_request_to_ui_event(
    request: &DaemonRpcServerRequest,
    request_key: &str,
) -> Option<UiEvent> {
    match request.method.as_str() {
        "item/commandExecution/requestApproval" | "execCommandApproval" => {
            let id = request
                .params
                .get("id")
                .or_else(|| request.params.get("callId"))
                .or_else(|| request.params.get("itemId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let command = command_vec_from_value(
                request
                    .params
                    .get("command")
                    .or_else(|| request.params.get("cmd")),
            );
            let reason = request
                .params
                .get("reason")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let network_approval_context = request
                .params
                .get("networkApprovalContext")
                .or_else(|| request.params.get("network_approval_context"))
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok());
            Some(UiEvent::ExecApprovalRequest {
                id,
                command,
                reason,
                network_approval_context,
            })
        }
        "item/fileChange/requestApproval" | "applyPatchApproval" => {
            let id = request
                .params
                .get("id")
                .or_else(|| request.params.get("callId"))
                .or_else(|| request.params.get("itemId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let reason = request
                .params
                .get("reason")
                .and_then(Value::as_str)
                .map(ToString::to_string);
            let cwd = request
                .params
                .get("cwd")
                .and_then(Value::as_str)
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir())
                });
            let changes = request
                .params
                .get("changes")
                .or_else(|| request.params.get("fileChanges"))
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<
                        std::collections::HashMap<
                            std::path::PathBuf,
                            codex_core::protocol::FileChange,
                        >,
                    >(value)
                    .ok()
                })
                .unwrap_or_default();
            Some(UiEvent::PatchApprovalRequest {
                id,
                reason,
                cwd,
                changes,
            })
        }
        "item/tool/elicit" | "item/mcpToolCall/requestApproval" => {
            let server_name = request
                .params
                .get("serverName")
                .or_else(|| request.params.get("server_name"))
                .and_then(Value::as_str)
                .unwrap_or("mcp")
                .to_string();
            let request_id = request
                .params
                .get("requestId")
                .or_else(|| request.params.get("request_id"))
                .and_then(Value::as_str)
                .map(|s| codex_protocol::mcp::RequestId::String(s.to_string()))
                .unwrap_or_else(|| codex_protocol::mcp::RequestId::String(request_key.to_string()));
            let message = request
                .params
                .get("message")
                .or_else(|| request.params.get("prompt"))
                .and_then(Value::as_str)
                .unwrap_or("MCP tool needs your approval.")
                .to_string();
            Some(UiEvent::ElicitationRequest {
                server_name,
                request_id,
                message,
            })
        }
        "item/tool/requestUserInput" => {
            let mut event = codex_protocol::request_user_input::RequestUserInputEvent {
                call_id: request
                    .params
                    .get("itemId")
                    .or_else(|| request.params.get("item_id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                turn_id: request
                    .params
                    .get("turnId")
                    .or_else(|| request.params.get("turn_id"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                request_id: request_key.to_string(),
                prompt: request
                    .params
                    .get("prompt")
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                questions: Vec::new(),
            };
            if let Some(questions) = request.params.get("questions").cloned()
                && let Ok(decoded) = serde_json::from_value::<
                    Vec<codex_protocol::request_user_input::RequestUserInputQuestion>,
                >(questions)
            {
                event.questions = decoded;
            }
            Some(UiEvent::RequestUserInputRequest(event))
        }
        _ => None,
    }
}

pub(crate) fn map_codex_protocol_event(event: &codex_core::protocol::Event) -> Vec<UiEvent> {
    let Ok(event_value) = serde_json::to_value(event) else {
        return Vec::new();
    };
    let params = json!({ "event": event_value });
    map_codex_event_notification(&params)
}

fn map_codex_event_notification(params: &Value) -> Vec<UiEvent> {
    let Some(event) = params.get("event").or_else(|| params.get("payload")) else {
        return Vec::new();
    };
    let msg = event.get("msg").unwrap_or(event);
    let msg_type = msg
        .get("type")
        .or_else(|| event.get("type"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    match msg_type {
        "session_configured" => map_session_configured_notification(msg),
        "thread_name_updated" => msg
            .get("thread_name")
            .or_else(|| msg.get("threadName"))
            .and_then(Value::as_str)
            .map(|name| vec![UiEvent::ThreadRenamed(name.to_string())])
            .unwrap_or_default(),
        "warning" => msg
            .get("message")
            .and_then(Value::as_str)
            .map(|message| {
                vec![UiEvent::Warning {
                    message: message.to_string(),
                }]
            })
            .unwrap_or_default(),
        "error" => vec![UiEvent::Error {
            message: msg
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string(),
        }],
        "stream_error" => {
            let message = msg
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("stream error")
                .to_string();
            let additional_details = msg
                .get("additional_details")
                .or_else(|| msg.get("additionalDetails"))
                .and_then(Value::as_str)
                .map(ToString::to_string);
            vec![UiEvent::StreamError {
                message,
                additional_details,
            }]
        }
        "turn_started" => msg
            .get("turn_id")
            .or_else(|| msg.get("turnId"))
            .and_then(Value::as_str)
            .map(|turn_id| vec![UiEvent::TurnStarted(turn_id.to_string())])
            .unwrap_or_default(),
        "turn_complete" | "task_complete" => vec![UiEvent::TurnCompleted {
            status: msg
                .get("status")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .or(Some("completed".to_string())),
            last_agent_message: msg
                .get("last_agent_message")
                .or_else(|| msg.get("lastAgentMessage"))
                .or_else(|| msg.get("last_agent_response"))
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }],
        "token_count" => map_codex_token_count_notification(msg),
        "runtime_metrics_updated" | "runtime_metrics_update" => parse_runtime_metrics_summary(msg)
            .map(|summary| vec![UiEvent::RuntimeMetricsUpdated(summary)])
            .unwrap_or_default(),
        "turn_aborted" => vec![UiEvent::TurnAborted {
            reason: msg
                .get("reason")
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }],
        "agent_message" => msg
            .get("message")
            .or_else(|| msg.get("text"))
            .and_then(Value::as_str)
            .map(|text| {
                vec![UiEvent::AgentMessage {
                    message: text.to_string(),
                }]
            })
            .unwrap_or_default(),
        "agent_message_delta" | "plan_delta" => msg
            .get("delta")
            .and_then(Value::as_str)
            .map(|delta| {
                vec![UiEvent::AssistantDelta {
                    turn_id: None,
                    delta: delta.to_string(),
                }]
            })
            .unwrap_or_default(),
        "agent_reasoning_delta" | "agent_reasoning_raw_content_delta" => msg
            .get("delta")
            .and_then(Value::as_str)
            .map(|delta| {
                vec![UiEvent::AgentReasoningDelta {
                    delta: delta.to_string(),
                }]
            })
            .unwrap_or_default(),
        "agent_reasoning" => vec![UiEvent::AgentReasoningFinal],
        "agent_reasoning_raw_content" => msg
            .get("text")
            .and_then(Value::as_str)
            .map(|text| {
                vec![
                    UiEvent::AgentReasoningDelta {
                        delta: text.to_string(),
                    },
                    UiEvent::AgentReasoningFinal,
                ]
            })
            .unwrap_or_else(|| vec![UiEvent::AgentReasoningFinal]),
        "agent_reasoning_section_break" => vec![UiEvent::AgentReasoningSectionBreak],
        "terminal_interaction" => {
            let process_id = msg
                .get("process_id")
                .or_else(|| msg.get("processId"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let stdin = msg
                .get("stdin")
                .or_else(|| msg.get("prompt"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            vec![UiEvent::TerminalInteraction { process_id, stdin }]
        }
        "entered_review_mode" => vec![UiEvent::ReviewModeEntered {
            hint: msg
                .get("user_facing_hint")
                .or_else(|| msg.get("userFacingHint"))
                .and_then(Value::as_str)
                .map(ToString::to_string),
        }],
        "exited_review_mode" => vec![UiEvent::ReviewModeExited {
            review_output_overall_explanation: msg
                .get("review_output")
                .and_then(|output| output.get("overall_explanation"))
                .or_else(|| {
                    msg.get("reviewOutput")
                        .and_then(|output| output.get("overallExplanation"))
                })
                .and_then(Value::as_str)
                .map(ToString::to_string),
            review_output_findings_count: msg
                .get("review_output")
                .and_then(|output| output.get("findings"))
                .or_else(|| {
                    msg.get("reviewOutput")
                        .and_then(|output| output.get("findings"))
                })
                .and_then(Value::as_array)
                .map(|findings| findings.len()),
        }],
        "undo_started" => vec![UiEvent::UndoStarted { message: None }],
        "undo_completed" => vec![UiEvent::UndoCompleted { message: None }],
        "plan_update" => parse_plan_update(msg)
            .map(UiEvent::PlanUpdated)
            .map(|event| vec![event])
            .unwrap_or_default(),
        "patch_apply_begin" => parse_file_changes(msg.get("changes"))
            .map(|changes| vec![UiEvent::PatchApplyBegin { changes }])
            .unwrap_or_default(),
        "patch_apply_end" => vec![UiEvent::PatchApplyEnd {
            success: msg.get("success").and_then(Value::as_bool).unwrap_or(true),
            stderr: msg
                .get("stderr")
                .or_else(|| msg.get("error"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        }],
        "view_image_tool_call" => msg
            .get("path")
            .and_then(Value::as_str)
            .map(|path| {
                vec![UiEvent::ViewImageToolCall {
                    path: std::path::PathBuf::from(path),
                }]
            })
            .unwrap_or_default(),
        "get_history_entry_response" => parse_history_entry_response(msg)
            .map(|event| vec![event])
            .unwrap_or_default(),
        "context_compacted" => vec![UiEvent::AssistantDelta {
            turn_id: None,
            delta: "Context compacted".to_string(),
        }],
        "list_custom_prompts_response" => parse_custom_prompts_list(msg)
            .map(UiEvent::CustomPromptsListed)
            .map(|event| vec![event])
            .unwrap_or_default(),
        "list_skills_response" => parse_skills_list(msg)
            .map(UiEvent::SkillsListed)
            .map(|event| vec![event])
            .unwrap_or_default(),
        "skills_update_available" => vec![UiEvent::SkillsUpdateAvailable],
        "shutdown_complete" => vec![UiEvent::ShutdownComplete],
        "user_message" => parse_user_message_event(msg)
            .map(|(text, text_elements)| {
                vec![UiEvent::UserMessage {
                    text,
                    text_elements,
                }]
            })
            .unwrap_or_default(),
        "deprecation_notice" => msg
            .get("message")
            .and_then(Value::as_str)
            .map(|message| {
                vec![UiEvent::DeprecationNotice {
                    message: message.to_string(),
                }]
            })
            .unwrap_or_default(),
        "background_event" => msg
            .get("message")
            .and_then(Value::as_str)
            .map(|message| {
                vec![UiEvent::BackgroundEvent {
                    message: message.to_string(),
                }]
            })
            .unwrap_or_default(),
        "mcp_startup_update" => {
            let server = msg
                .get("server")
                .and_then(Value::as_str)
                .unwrap_or("mcp")
                .to_string();
            let status = msg
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("starting")
                .to_string();
            vec![UiEvent::McpStartupUpdate { server, status }]
        }
        "mcp_startup_complete" => {
            let failed = msg
                .get("failed")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.get("server").and_then(Value::as_str))
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let cancelled = msg
                .get("cancelled")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            vec![UiEvent::McpStartupComplete { failed, cancelled }]
        }
        other if other.starts_with("collab_") || other.starts_with("collab") => {
            vec![UiEvent::CollabEvent(format!("[collab] {other}"))]
        }
        _ => Vec::new(),
    }
}

fn map_session_configured_notification(payload: &Value) -> Vec<UiEvent> {
    let model = payload
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("unknown-model")
        .to_string();
    let session_id = payload
        .get("session_id")
        .or_else(|| payload.get("sessionId"))
        .or_else(|| payload.get("thread_id"))
        .or_else(|| payload.get("threadId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let history_log_id = payload
        .get("history_log_id")
        .or_else(|| payload.get("historyLogId"))
        .and_then(value_to_u64)
        .unwrap_or_default();
    let history_entry_count = payload
        .get("history_entry_count")
        .or_else(|| payload.get("historyEntryCount"))
        .and_then(value_to_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or_default();
    let reasoning_effort = payload
        .get("reasoning_effort")
        .or_else(|| payload.get("reasoningEffort"))
        .and_then(parse_reasoning_effort_value);

    let mut events = vec![UiEvent::SessionConfigured {
        session_id,
        model,
        reasoning_effort,
        history_log_id,
        history_entry_count,
    }];

    if let Some(initial_messages) = payload
        .get("initial_messages")
        .or_else(|| payload.get("initialMessages"))
        .and_then(Value::as_array)
    {
        for message in initial_messages {
            events.extend(map_codex_event_notification(
                &json!({ "event": { "msg": message } }),
            ));
        }
    }

    events
}

fn value_to_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|v| u64::try_from(v).ok()))
        .or_else(|| value.as_str().and_then(|v| v.parse::<u64>().ok()))
}

fn parse_reasoning_effort_value(
    value: &Value,
) -> Option<codex_protocol::openai_models::ReasoningEffort> {
    let normalized = value.as_str()?.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "none" => Some(codex_protocol::openai_models::ReasoningEffort::None),
        "minimal" => Some(codex_protocol::openai_models::ReasoningEffort::Minimal),
        "low" => Some(codex_protocol::openai_models::ReasoningEffort::Low),
        "medium" => Some(codex_protocol::openai_models::ReasoningEffort::Medium),
        "high" => Some(codex_protocol::openai_models::ReasoningEffort::High),
        "xhigh" | "x-high" | "very_high" | "very-high" | "veryhigh" => {
            Some(codex_protocol::openai_models::ReasoningEffort::XHigh)
        }
        _ => None,
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

fn parse_runtime_metrics_summary(value: &Value) -> Option<codex_otel::RuntimeMetricsSummary> {
    serde_json::from_value(value.clone()).ok()
}

fn parse_custom_prompts_list(
    value: &Value,
) -> Option<Vec<codex_protocol::custom_prompts::CustomPrompt>> {
    let prompts = value
        .get("prompts")
        .or_else(|| value.get("custom_prompts"))
        .or_else(|| value.get("customPrompts"))?;
    serde_json::from_value(prompts.clone()).ok()
}

fn parse_skills_list(value: &Value) -> Option<Vec<codex_core::skills::model::SkillMetadata>> {
    let skills = value.get("skills")?;
    serde_json::from_value(skills.clone()).ok()
}

fn parse_user_message_event(
    value: &Value,
) -> Option<(String, Vec<codex_protocol::user_input::TextElement>)> {
    let text = value
        .get("text")
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)?
        .to_string();
    let text_elements = value
        .get("text_elements")
        .or_else(|| value.get("textElements"))
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    Some((text, text_elements))
}

fn parse_user_message_item(
    value: &Value,
) -> Option<(String, Vec<codex_protocol::user_input::TextElement>)> {
    let text = value
        .get("text")
        .or_else(|| value.get("message"))
        .and_then(Value::as_str)
        .or_else(|| {
            value
                .get("content")
                .and_then(Value::as_array)
                .and_then(|content| {
                    content
                        .iter()
                        .find_map(|item| item.get("text").and_then(Value::as_str))
                })
        })?
        .to_string();

    let text_elements = value
        .get("text_elements")
        .or_else(|| value.get("textElements"))
        .cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();

    Some((text, text_elements))
}

fn parse_plan_update(value: &Value) -> Option<codex_protocol::plan_tool::UpdatePlanArgs> {
    serde_json::from_value(value.clone()).ok()
}

fn parse_file_changes(
    value: Option<&Value>,
) -> Option<std::collections::HashMap<std::path::PathBuf, codex_core::protocol::FileChange>> {
    let value = value?;
    serde_json::from_value(value.clone()).ok()
}

fn parse_history_entry_response(value: &Value) -> Option<UiEvent> {
    let offset = value
        .get("offset")
        .or_else(|| value.get("entryOffset"))
        .and_then(Value::as_u64)? as usize;
    let log_id = value
        .get("logId")
        .or_else(|| value.get("log_id"))
        .and_then(Value::as_u64)?;
    let entry_text = value
        .get("entry")
        .and_then(|entry| {
            entry
                .get("text")
                .or_else(|| entry.get("message"))
                .and_then(Value::as_str)
        })
        .map(ToString::to_string);
    Some(UiEvent::GetHistoryEntryResponse {
        offset,
        log_id,
        entry_text,
    })
}

fn map_codex_token_count_notification(msg: &Value) -> Vec<UiEvent> {
    let info_value = msg.get("info").or_else(|| msg.get("token_usage_info"));
    let rate_limits_value = msg.get("rate_limits").or_else(|| msg.get("rateLimits"));
    let mut events = Vec::new();
    if let Some(info_value) = info_value
        && let Some((token_info, total_usage)) = parse_token_usage_updated_from_info(info_value)
    {
        events.push(UiEvent::TokenUsageUpdated {
            token_info,
            total_usage,
        });
    }
    if let Some(snapshot) = rate_limits_value.and_then(parse_rate_limit_snapshot) {
        events.push(UiEvent::RateLimitUpdated(snapshot));
    }
    events
}

fn parse_token_usage_updated_from_info(
    value: &Value,
) -> Option<(
    codex_core::protocol::TokenUsageInfo,
    codex_core::protocol::TokenUsage,
)> {
    if let Some((info, total)) = parse_token_usage_updated(value) {
        return Some((info, total));
    }
    let last = value
        .get("last_token_usage")
        .or_else(|| value.get("lastTokenUsage"))
        .or_else(|| value.get("last"))?;
    let total = value
        .get("total_token_usage")
        .or_else(|| value.get("totalTokenUsage"))
        .or_else(|| value.get("total"))
        .unwrap_or(last);
    let model_context_window = value
        .get("model_context_window")
        .or_else(|| value.get("modelContextWindow"))
        .and_then(Value::as_i64);
    Some((
        codex_core::protocol::TokenUsageInfo {
            last_token_usage: parse_token_usage_breakdown(last),
            model_context_window,
        },
        parse_token_usage_breakdown(total),
    ))
}

fn parse_rate_limit_snapshot(value: &Value) -> Option<codex_core::protocol::RateLimitSnapshot> {
    let primary = parse_rate_limit_window(value.get("primary"));
    let secondary = parse_rate_limit_window(value.get("secondary"));
    let credits = value
        .get("credits")
        .map(|credits| codex_core::protocol::CreditsSnapshot {
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
    let window = value?;
    Some(codex_core::protocol::RateLimitWindow {
        used_percent: window
            .get("usedPercent")
            .or_else(|| window.get("used_percent"))
            .and_then(Value::as_f64)
            .unwrap_or_default(),
        resets_at: window
            .get("resetsAt")
            .or_else(|| window.get("resets_at"))
            .and_then(Value::as_i64),
        window_minutes: window
            .get("windowMinutes")
            .or_else(|| window.get("window_minutes"))
            .and_then(Value::as_i64),
    })
}

fn delta_from_params(params: &Value) -> Option<&str> {
    params
        .get("delta")
        .or_else(|| params.get("outputDelta"))
        .and_then(Value::as_str)
}

fn item_id_from_params(params: &Value) -> Option<String> {
    params
        .get("itemId")
        .or_else(|| params.get("callId"))
        .or_else(|| params.get("id"))
        .or_else(|| params.get("item").and_then(|item| item.get("id")))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn command_vec_from_value(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect(),
        Some(Value::String(command)) => {
            shlex::split(command).unwrap_or_else(|| vec![command.clone()])
        }
        _ => Vec::new(),
    }
}

fn parse_exec_source(source: Option<&Value>) -> codex_core::protocol::ExecCommandSource {
    match source.and_then(Value::as_str).unwrap_or("agent") {
        "user" => codex_core::protocol::ExecCommandSource::User,
        "user_shell" => codex_core::protocol::ExecCommandSource::UserShell,
        "unified_exec_startup" => codex_core::protocol::ExecCommandSource::UnifiedExecStartup,
        "unified_exec_interaction" => {
            codex_core::protocol::ExecCommandSource::UnifiedExecInteraction
        }
        _ => codex_core::protocol::ExecCommandSource::Agent,
    }
}

fn parsed_command_vec_from_value(
    value: Option<&Value>,
) -> Vec<codex_protocol::parse_command::ParsedCommand> {
    value
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

fn duration_ms_to_duration(duration_ms: i64) -> Duration {
    Duration::from_millis(duration_ms.max(0) as u64)
}

fn map_item_started_notification(params: &Value) -> Vec<UiEvent> {
    let Some(item) = params.get("item") else {
        return Vec::new();
    };
    let Some(item_type) = item.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };
    match item_type {
        "reasoning" => {
            let text = item
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| {
                    item.get("summary")
                        .and_then(Value::as_array)
                        .and_then(|summary| summary.first())
                        .and_then(Value::as_str)
                })
                .unwrap_or_default()
                .to_string();

            let mut events = Vec::new();
            if !text.is_empty() {
                events.push(UiEvent::AgentReasoningDelta { delta: text });
            }
            events.push(UiEvent::AgentReasoningFinal);
            events
        }
        "command_execution" | "commandExecution" => {
            let call_id = item
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("exec")
                .to_string();
            let command = command_vec_from_value(item.get("command"));
            vec![UiEvent::ExecCommandBegin {
                call_id,
                process_id: item
                    .get("processId")
                    .or_else(|| item.get("process_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                command: if command.is_empty() {
                    vec!["command".to_string()]
                } else {
                    command
                },
                parsed: parsed_command_vec_from_value(
                    item.get("parsedCommand")
                        .or_else(|| item.get("commandActions")),
                ),
                source: parse_exec_source(item.get("source")),
            }]
        }
        "mcp_tool_call" | "mcpToolCall" => {
            let call_id = item
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("mcp")
                .to_string();
            let server = item
                .get("server")
                .or_else(|| item.get("serverName"))
                .and_then(Value::as_str)
                .unwrap_or("mcp")
                .to_string();
            let tool = item
                .get("tool")
                .or_else(|| item.get("toolName"))
                .and_then(Value::as_str)
                .unwrap_or("tool")
                .to_string();
            let invocation = codex_core::protocol::McpInvocation {
                server: server.clone(),
                tool: tool.clone(),
                arguments: item.get("arguments").cloned(),
                server_name: server,
                tool_name: tool,
            };
            vec![UiEvent::McpToolCallBegin {
                call_id,
                invocation,
            }]
        }
        "web_search" | "webSearch" => {
            let call_id = item
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("web-search")
                .to_string();
            let query = item
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if query.is_empty() {
                Vec::new()
            } else {
                vec![UiEvent::WebSearchBegin { call_id, query }]
            }
        }
        _ => Vec::new(),
    }
}

fn map_item_completed_notification(params: &Value) -> Vec<UiEvent> {
    let Some(item) = params.get("item") else {
        return Vec::new();
    };
    let Some(item_type) = item.get("type").and_then(Value::as_str) else {
        return Vec::new();
    };
    match item_type {
        "command_execution" | "commandExecution" => {
            let Some(call_id) = item.get("id").and_then(Value::as_str) else {
                return Vec::new();
            };
            let exit_code = item
                .get("exitCode")
                .or_else(|| item.get("exit_code"))
                .and_then(Value::as_i64)
                .unwrap_or_default() as i32;
            let aggregated_output = item
                .get("aggregatedOutput")
                .or_else(|| item.get("aggregated_output"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let formatted_output = item
                .get("formattedOutput")
                .or_else(|| item.get("formatted_output"))
                .or_else(|| item.get("output"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| aggregated_output.as_str())
                .to_string();
            let duration_ms = item
                .get("durationMs")
                .or_else(|| item.get("duration_ms"))
                .and_then(Value::as_i64)
                .unwrap_or_default();
            vec![UiEvent::ExecCommandEnd {
                call_id: call_id.to_string(),
                process_id: item
                    .get("processId")
                    .or_else(|| item.get("process_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string),
                source: parse_exec_source(item.get("source")),
                exit_code,
                formatted_output,
                aggregated_output,
                duration: duration_ms_to_duration(duration_ms),
            }]
        }
        "mcp_tool_call" | "mcpToolCall" => {
            let Some(call_id) = item.get("id").and_then(Value::as_str) else {
                return Vec::new();
            };
            let duration_ms = item
                .get("durationMs")
                .or_else(|| item.get("duration_ms"))
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let result = if let Some(error_msg) = item
                .get("error")
                .and_then(|err| err.get("message"))
                .and_then(Value::as_str)
            {
                Err(error_msg.to_string())
            } else if let Some(result_value) = item.get("result") {
                let call_result =
                    serde_json::from_value(result_value.clone()).unwrap_or_else(|_| {
                        codex_protocol::mcp::CallToolResult {
                            content: result_value
                                .get("content")
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default(),
                            is_error: result_value.get("isError").and_then(Value::as_bool),
                        }
                    });
                Ok(call_result)
            } else {
                Ok(codex_protocol::mcp::CallToolResult::default())
            };
            vec![UiEvent::McpToolCallEnd {
                call_id: call_id.to_string(),
                duration: duration_ms_to_duration(duration_ms),
                result,
            }]
        }
        "web_search" | "webSearch" => {
            let Some(call_id) = item.get("id").and_then(Value::as_str) else {
                return Vec::new();
            };
            let query = item
                .get("query")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let action = if item.get("action").is_some() {
                codex_protocol::models::WebSearchAction::Cached
            } else {
                codex_protocol::models::WebSearchAction::Requested
            };
            vec![UiEvent::WebSearchEnd {
                call_id: call_id.to_string(),
                query,
                action,
            }]
        }
        _ => Vec::new(),
    }
}

fn parse_agent_message_item_completed(item: &Value) -> Option<Option<String>> {
    let item_type = item.get("type").and_then(Value::as_str)?;
    if item_type != "agent_message" && item_type != "agentMessage" {
        return None;
    }
    let phase = item
        .get("phase")
        .or_else(|| item.get("messagePhase"))
        .or_else(|| item.get("message_phase"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    Some(phase)
}

fn parse_plan_item_completed(item: &Value) -> Option<String> {
    let item_type = item.get("type").and_then(Value::as_str)?;
    if item_type != "plan" {
        return None;
    }
    item.get("text")
        .or_else(|| item.get("content"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn summarize_server_request(request: &DaemonRpcServerRequest) -> String {
    let key = request_id_key_for_cli(&request.request_id);
    match request.method.as_str() {
        "item/commandExecution/requestApproval" => {
            let command = request
                .params
                .get("command")
                .and_then(Value::as_array)
                .map(|parts: &Vec<Value>| {
                    parts
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .filter(|value: &String| !value.is_empty())
                .unwrap_or_else(|| "command".to_string());
            format!("[approval required] request_id={key} command={command}")
        }
        "item/fileChange/requestApproval" => {
            let reason = request
                .params
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("file change");
            format!("[approval required] request_id={key} file_change={reason}")
        }
        "item/tool/call" => {
            let tool = request
                .params
                .get("tool")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            format!("[tool call requested] request_id={key} tool={tool}")
        }
        "item/tool/requestUserInput" => {
            format!("[tool user input requested] request_id={key}")
        }
        _ => format!(
            "[server request] request_id={key} method={}",
            request.method
        ),
    }
}

pub(crate) fn start_thread(state: &CliState) -> Result<String> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/start",
        json!({
            "approvalPolicy": "on-request"
        }),
    )?;
    extract_thread_id_from_rpc_result(&response.result)
        .ok_or_else(|| anyhow!("failed to initialize app-server thread"))
}

pub(crate) fn start_turn(state: &CliState, thread_id: &str, text: &str) -> Result<Option<String>> {
    start_turn_with_elements_and_collaboration(state, thread_id, text, Vec::new(), Vec::new(), None)
}

pub(crate) fn start_turn_with_elements(
    state: &CliState,
    thread_id: &str,
    text: &str,
    text_elements: Vec<codex_protocol::user_input::TextElement>,
    mention_bindings: Vec<crate::bottom_pane::MentionBinding>,
) -> Result<Option<String>> {
    start_turn_with_elements_and_collaboration(
        state,
        thread_id,
        text,
        text_elements,
        mention_bindings,
        None,
    )
}

pub(crate) fn start_turn_with_elements_and_collaboration(
    state: &CliState,
    thread_id: &str,
    text: &str,
    text_elements: Vec<codex_protocol::user_input::TextElement>,
    mention_bindings: Vec<crate::bottom_pane::MentionBinding>,
    collaboration_mode: Option<codex_protocol::config_types::CollaborationMode>,
) -> Result<Option<String>> {
    let mut input_items = vec![json!({
        "type": "text",
        "text": text,
        "text_elements": text_elements
    })];
    for binding in mention_bindings {
        if let Some(app_id) = binding.path.strip_prefix("app://") {
            if !app_id.is_empty() {
                input_items.push(json!({
                    "type": "mention",
                    "name": binding.mention,
                    "path": binding.path,
                }));
            }
            continue;
        }
        let skill_path = binding
            .path
            .strip_prefix("skill://")
            .unwrap_or(binding.path.as_str())
            .to_string();
        if skill_path.ends_with("SKILL.md") {
            input_items.push(json!({
                "type": "skill",
                "name": binding.mention,
                "path": skill_path,
            }));
        }
    }
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "turn/start",
        json!({
            "threadId": thread_id,
            "input": input_items,
            "collaborationMode": collaboration_mode,
        }),
    )?;
    Ok(response
        .result
        .get("turn")
        .and_then(|turn| turn.get("id"))
        .and_then(Value::as_str)
        .map(ToString::to_string))
}

pub(crate) fn interrupt_turn(state: &CliState, thread_id: &str, turn_id: &str) -> Result<()> {
    let _ = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "turn/interrupt",
        json!({
            "threadId": thread_id,
            "turnId": turn_id,
        }),
    )?;
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub(crate) struct ThreadResumeResult {
    pub(crate) thread_id: Option<String>,
    pub(crate) replay_events: Vec<UiEvent>,
}

pub(crate) fn resume_thread_detailed(
    state: &CliState,
    thread_id: &str,
) -> Result<ThreadResumeResult> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/resume",
        json!({
            "threadId": thread_id,
        }),
    )?;
    Ok(parse_thread_resume_result(&response.result))
}

pub(crate) fn resume_thread(state: &CliState, thread_id: &str) -> Result<Option<String>> {
    Ok(resume_thread_detailed(state, thread_id)?.thread_id)
}

pub(crate) fn fork_thread(state: &CliState, thread_id: &str) -> Result<Option<String>> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/fork",
        json!({
            "threadId": thread_id,
        }),
    )?;
    Ok(extract_thread_id_from_rpc_result(&response.result))
}

pub(crate) fn set_thread_name(state: &CliState, thread_id: &str, name: &str) -> Result<()> {
    let _ = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/name/set",
        json!({
            "threadId": thread_id,
            "name": name,
        }),
    )?;
    Ok(())
}

pub(crate) fn respond_to_approval(
    state: &CliState,
    request_id: Value,
    method: &str,
    approve: bool,
) -> Result<()> {
    let decision = match method {
        "execCommandApproval" | "applyPatchApproval" => {
            if approve {
                "approved"
            } else {
                "denied"
            }
        }
        _ => {
            if approve {
                "accept"
            } else {
                "decline"
            }
        }
    };

    app_server_rpc_respond(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        request_id,
        json!({
            "decision": decision
        }),
    )?;
    Ok(())
}

pub(crate) fn stream_events(
    state: &CliState,
    since_sequence: u64,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    fetch_app_server_stream(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        Some(since_sequence),
    )
}

/// Decode a single app-server wire message line into the UI stream envelope.
///
/// Accepts both:
/// - Crabbot legacy stream envelopes (`DaemonRpcStreamEnvelope`)
/// - Raw app-server JSON-RPC websocket messages (request/notification/response)
///
/// Responses for in-flight client requests are ignored (`Ok(None)`) because
/// they are handled synchronously by the caller that initiated the request.
pub(crate) fn decode_app_server_wire_line(
    line: &str,
    fallback_sequence: u64,
) -> Result<Option<DaemonRpcStreamEnvelope>> {
    #[derive(Debug, Deserialize)]
    struct JsonRpcErrorPayload {
        code: i64,
        message: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum WireMessage {
        StreamEnvelope(DaemonRpcStreamEnvelope),
        JsonRpcRequest {
            id: Value,
            method: String,
            #[serde(default)]
            params: Value,
        },
        JsonRpcNotification {
            method: String,
            #[serde(default)]
            params: Value,
        },
        JsonRpcResponse {
            id: Value,
            #[serde(default)]
            result: Value,
        },
        JsonRpcError {
            id: Value,
            error: JsonRpcErrorPayload,
        },
    }

    let message = serde_json::from_str::<WireMessage>(line)
        .with_context(|| "parse app-server wire line (app-server envelope or json-rpc)")?;

    let event = match message {
        WireMessage::StreamEnvelope(envelope) => return Ok(Some(envelope)),
        WireMessage::JsonRpcRequest { id, method, params } => {
            DaemonRpcStreamEvent::ServerRequest(DaemonRpcServerRequest {
                request_id: id,
                method,
                params,
            })
        }
        WireMessage::JsonRpcNotification { method, params } => {
            DaemonRpcStreamEvent::Notification(DaemonRpcNotification { method, params })
        }
        WireMessage::JsonRpcResponse { id, result } => {
            tracing::debug!(
                request_id = %request_id_key_for_cli(&id),
                has_result = !result.is_null(),
                "ignoring app-server json-rpc response in stream adapter"
            );
            return Ok(None);
        }
        WireMessage::JsonRpcError { id, error } => {
            tracing::warn!(
                request_id = %request_id_key_for_cli(&id),
                code = error.code,
                message = %error.message,
                "received app-server json-rpc error"
            );
            DaemonRpcStreamEvent::DecodeError(crabbot_protocol::DaemonRpcDecodeError {
                raw: line.to_string(),
                message: format!("json-rpc error {}: {}", error.code, error.message),
            })
        }
    };

    Ok(Some(DaemonRpcStreamEnvelope {
        schema_version: crabbot_protocol::DAEMON_RPC_STREAM_SCHEMA_VERSION,
        sequence: fallback_sequence,
        event,
    }))
}

fn parse_thread_resume_result(result: &Value) -> ThreadResumeResult {
    let thread_id = extract_thread_id_from_rpc_result(result);
    let model = result
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("unknown-model")
        .to_string();
    let reasoning_effort = result
        .get("reasoningEffort")
        .or_else(|| result.get("reasoning_effort"))
        .and_then(parse_reasoning_effort_value);

    let mut replay_events = vec![UiEvent::SessionConfigured {
        session_id: thread_id.clone().unwrap_or_default(),
        model,
        reasoning_effort,
        history_log_id: 0,
        history_entry_count: 0,
    }];

    if let Some(initial_messages) = result
        .get("initialMessages")
        .or_else(|| result.get("initial_messages"))
        .and_then(Value::as_array)
    {
        for message in initial_messages {
            replay_events.extend(map_codex_event_notification(&json!({
                "event": { "msg": message }
            })));
        }
    }

    ThreadResumeResult {
        thread_id,
        replay_events,
    }
}

// ---------------------------------------------------------------------------
// Application-level event types — mirrors upstream `app_event.rs`
// ---------------------------------------------------------------------------

/// Application-level events used to coordinate UI actions.
///
/// This mirrors the upstream `AppEvent` from `app_event.rs` but is adapted for
/// app-server transport. Upstream variants that depend on `codex-core` protocol
/// types are replaced with app-server equivalents.
#[derive(Debug)]
pub(crate) enum AppEvent {
    // -- Terminal input events (same as upstream) --
    Key(crossterm::event::KeyEvent),
    Mouse(crossterm::event::MouseEvent),
    Paste(String),
    Resize,
    Tick,

    // -- App-server specific events --
    /// Incoming stream events from the app-server websocket server.
    StreamUpdate(Vec<DaemonRpcStreamEnvelope>),

    /// User submitted input from the composer.
    SubmitInput {
        text: String,
        text_elements: Vec<codex_protocol::user_input::TextElement>,
        mention_bindings: Vec<crate::bottom_pane::MentionBinding>,
    },

    /// Request to start a turn for the active thread with plain text input.
    StartTurn {
        text: String,
        text_elements: Vec<codex_protocol::user_input::TextElement>,
        mention_bindings: Vec<crate::bottom_pane::MentionBinding>,
    },

    /// Request to start a new session / thread.
    NewSession,

    /// Request to interrupt the active turn.
    Interrupt,

    /// Request to show a status snapshot in the footer.
    ShowStatus,

    /// Request to refresh stream state now.
    RefreshStream,

    /// Request to resume the current thread/session.
    ResumeSession,

    /// Request to resolve a pending approval (optionally by explicit key).
    ApprovalDecision {
        arg: String,
        approve: bool,
    },

    /// Request to exit the application.
    Exit(ExitMode),
}

/// The exit strategy requested by the UI layer.
///
/// Mirrors upstream `ExitMode` from `app_event.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitMode {
    /// Shut down cleanly and exit.
    ShutdownFirst,
    /// Exit immediately without cleanup.
    Immediate,
}

/// Reason the app exited, for reporting to the calling process.
///
/// Mirrors upstream `ExitReason`.
#[derive(Debug, Clone)]
pub(crate) enum ExitReason {
    UserRequested,
    Fatal(String),
}

/// Information returned when the app exits.
///
/// Mirrors upstream `AppExitInfo`.
#[derive(Debug)]
pub(crate) struct AppExitInfo {
    pub(crate) thread_id: Option<String>,
    pub(crate) exit_reason: ExitReason,
}

/// What the TUI event loop should do after processing an event.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LiveTuiAction {
    Continue,
    Detach,
}

/// Sender half for `AppEvent`s. Cloneable so widgets can fire events without
/// direct access to the `App` struct.
///
/// Mirrors upstream `AppEventSender` from `app_event_sender.rs`.
#[derive(Clone, Debug)]
pub(crate) struct AppEventSender {
    tx: mpsc::Sender<AppEvent>,
}

impl AppEventSender {
    pub(crate) fn new(tx: mpsc::Sender<AppEvent>) -> Self {
        Self { tx }
    }

    /// Send an event. Errors are logged and swallowed so callers don't need to
    /// handle a disconnected channel (which only happens during shutdown).
    pub(crate) fn send(&self, event: AppEvent) {
        if let Err(e) = self.tx.send(event) {
            tracing::error!("failed to send AppEvent: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::decode_app_server_wire_line;
    use super::*;

    #[test]
    fn decode_wire_line_accepts_legacy_stream_envelope() {
        let line = r#"{"schema_version":1,"sequence":7,"event":{"type":"notification","payload":{"method":"turn/started","params":{"turn":{"id":"t_1"}}}}}"#;
        let envelope = decode_app_server_wire_line(line, 99)
            .expect("decode should succeed")
            .expect("envelope should be returned");

        assert_eq!(envelope.sequence, 7);
        match envelope.event {
            DaemonRpcStreamEvent::Notification(notification) => {
                assert_eq!(notification.method, "turn/started");
            }
            _ => panic!("expected notification event"),
        }
    }

    #[test]
    fn decode_wire_line_maps_jsonrpc_notification() {
        let line = r#"{"method":"item/agentMessage/delta","params":{"delta":"hello"}}"#;
        let envelope = decode_app_server_wire_line(line, 12)
            .expect("decode should succeed")
            .expect("envelope should be returned");

        assert_eq!(envelope.sequence, 12);
        match envelope.event {
            DaemonRpcStreamEvent::Notification(notification) => {
                assert_eq!(notification.method, "item/agentMessage/delta");
                assert_eq!(notification.params["delta"], "hello");
            }
            _ => panic!("expected notification event"),
        }
    }

    #[test]
    fn decode_wire_line_maps_jsonrpc_server_request() {
        let line = r#"{"id":42,"method":"item/commandExecution/requestApproval","params":{"command":["ls","-la"]}}"#;
        let envelope = decode_app_server_wire_line(line, 13)
            .expect("decode should succeed")
            .expect("envelope should be returned");

        assert_eq!(envelope.sequence, 13);
        match envelope.event {
            DaemonRpcStreamEvent::ServerRequest(request) => {
                assert_eq!(request.request_id, json!(42));
                assert_eq!(request.method, "item/commandExecution/requestApproval");
            }
            _ => panic!("expected server request event"),
        }
    }

    #[test]
    fn decode_wire_line_ignores_jsonrpc_response() {
        let line = r#"{"id":1,"result":{"ok":true}}"#;
        let envelope = decode_app_server_wire_line(line, 14).expect("decode should succeed");
        assert!(envelope.is_none());
    }
}
