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
}

#[derive(Debug, Clone)]
pub(crate) enum UiEvent {
    SessionState(String),
    ThreadStarted(String),
    ThreadRenamed(String),
    TurnStarted(String),
    AssistantDelta {
        turn_id: Option<String>,
        delta: String,
    },
    TurnCompleted {
        status: Option<String>,
    },
    ExecCommandBegin {
        call_id: String,
        command: Vec<String>,
        parsed: Vec<codex_protocol::parse_command::ParsedCommand>,
        source: codex_core::protocol::ExecCommandSource,
    },
    ExecCommandOutputDelta {
        call_id: String,
        delta: String,
    },
    ExecCommandEnd {
        call_id: String,
        exit_code: i32,
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
    TranscriptLine(String),
    StatusMessage(String),
    ApprovalRequired(UiApprovalRequest),
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
                ) {
                    events.push(UiEvent::ApprovalRequired(UiApprovalRequest {
                        key: request_id_key_for_cli(&request.request_id),
                        request_id: request.request_id.clone(),
                        method: request.method.clone(),
                        reason: request
                            .params
                            .get("reason")
                            .and_then(Value::as_str)
                            .map(ToString::to_string),
                    }));
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
        "thread/started" => notification
            .params
            .get("thread")
            .and_then(|thread| thread.get("id"))
            .and_then(Value::as_str)
            .map(|thread_id| vec![UiEvent::ThreadStarted(thread_id.to_string())])
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
        "item/reasoning/summaryTextDelta" | "item/reasoning/textDelta" => Vec::new(),
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
        "item/commandExecution/terminalInteraction" => notification
            .params
            .get("prompt")
            .or_else(|| notification.params.get("stdin"))
            .and_then(Value::as_str)
            .map(|prompt| {
                vec![UiEvent::TranscriptLine(format!(
                    "[terminal interaction] {prompt}"
                ))]
            })
            .unwrap_or_default(),
        "item/commandExecution/begin" => notification
            .params
            .get("command")
            .and_then(Value::as_array)
            .map(|parts| {
                vec![UiEvent::ExecCommandBegin {
                    call_id: item_id_from_params(&notification.params)
                        .unwrap_or_else(|| "exec".to_string()),
                    command: parts
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect(),
                    parsed: Vec::new(),
                    source: parse_exec_source(notification.params.get("source")),
                }]
            })
            .unwrap_or_else(|| vec![UiEvent::StatusMessage("running command...".to_string())]),
        "item/commandExecution/end" => {
            let exit_code = notification
                .params
                .get("exitCode")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let Some(call_id) = item_id_from_params(&notification.params) else {
                return vec![UiEvent::TranscriptLine(format!(
                    "[exec done] exit_code={exit_code}"
                ))];
            };
            vec![UiEvent::ExecCommandEnd {
                call_id,
                exit_code: exit_code as i32,
                aggregated_output: notification
                    .params
                    .get("aggregatedOutput")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                duration: duration_ms_to_duration(
                    notification
                        .params
                        .get("durationMs")
                        .and_then(Value::as_i64)
                        .unwrap_or_default(),
                ),
            }]
        }
        "item/fileChange/begin" => Vec::new(),
        "item/fileChange/end" => Vec::new(),
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
            .filter(|item_type| *item_type == "agent_message" || *item_type == "agentMessage")
            .and_then(|_| {
                notification
                    .params
                    .get("item")
                    .and_then(|item| item.get("text"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .map(|text| {
                vec![UiEvent::AssistantDelta {
                    turn_id: None,
                    delta: text,
                }]
            })
            .unwrap_or_else(|| map_item_completed_notification(&notification.params)),
        "turn/completed" => {
            let status = notification
                .params
                .get("turn")
                .and_then(|turn| turn.get("status"))
                .and_then(Value::as_str)
                .map(ToString::to_string);
            vec![UiEvent::TurnCompleted { status }]
        }
        "turn/aborted" => vec![UiEvent::TurnCompleted {
            status: Some("aborted".to_string()),
        }],
        "turn/failed" => vec![UiEvent::TurnCompleted {
            status: Some("failed".to_string()),
        }],
        "turn/diff/updated" => Vec::new(),
        "thread/tokenUsage/updated" => Vec::new(),
        _ => Vec::new(),
    }
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
        "command_execution" | "commandExecution" => {
            let call_id = item
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("exec")
                .to_string();
            let command = command_vec_from_value(item.get("command"));
            vec![UiEvent::ExecCommandBegin {
                call_id,
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
            let duration_ms = item
                .get("durationMs")
                .or_else(|| item.get("duration_ms"))
                .and_then(Value::as_i64)
                .unwrap_or_default();
            vec![UiEvent::ExecCommandEnd {
                call_id: call_id.to_string(),
                exit_code,
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
    start_turn_with_elements(state, thread_id, text, Vec::new(), Vec::new())
}

pub(crate) fn start_turn_with_elements(
    state: &CliState,
    thread_id: &str,
    text: &str,
    text_elements: Vec<codex_protocol::user_input::TextElement>,
    mention_bindings: Vec<crate::bottom_pane::MentionBinding>,
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
            "input": input_items
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

pub(crate) fn resume_thread(state: &CliState, thread_id: &str) -> Result<Option<String>> {
    let response = app_server_rpc_request(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        "thread/resume",
        json!({
            "threadId": thread_id,
        }),
    )?;
    Ok(extract_thread_id_from_rpc_result(&response.result))
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
