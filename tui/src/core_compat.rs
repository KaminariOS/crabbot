//! App-server compatibility seam for the TUI runtime.
//!
//! This module keeps transport/event translation isolated from UI files so the
//! UI can be moved closer to upstream structure without pulling in `codex-core`.
use super::*;

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
    TranscriptLine(String),
    StatusMessage(String),
    ApprovalRequired(UiApprovalRequest),
}

pub(crate) fn map_daemon_stream_events(stream_events: &[DaemonStreamEnvelope]) -> Vec<UiEvent> {
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
            DaemonStreamEvent::TurnCompleted(_) => {
                events.push(UiEvent::TurnCompleted {
                    status: Some("completed".to_string()),
                });
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
            DaemonRpcStreamEvent::DecodeError(error) => {
                events.push(UiEvent::TranscriptLine(format!(
                    "[daemon rpc decode error] {}",
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
        "item/reasoning/summaryTextDelta" | "item/reasoning/textDelta" => {
            if delta_from_params(&notification.params).is_some() {
                vec![UiEvent::StatusMessage("reasoning...".to_string())]
            } else {
                Vec::new()
            }
        }
        "item/commandExecution/outputDelta" | "item/fileChange/outputDelta" => {
            delta_from_params(&notification.params)
                .map(|delta| vec![UiEvent::TranscriptLine(delta.to_string())])
                .unwrap_or_default()
        }
        "item/commandExecution/terminalInteraction" => notification
            .params
            .get("prompt")
            .and_then(Value::as_str)
            .map(|prompt| {
                vec![UiEvent::TranscriptLine(format!(
                    "[terminal interaction] {prompt}"
                ))]
            })
            .unwrap_or_default(),
        "item/completed" => notification
            .params
            .get("item")
            .and_then(|item| item.get("type"))
            .and_then(Value::as_str)
            .filter(|item_type| *item_type == "agent_message")
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
            .unwrap_or_default(),
        "turn/completed" => {
            let status = notification
                .params
                .get("turn")
                .and_then(|turn| turn.get("status"))
                .and_then(Value::as_str)
                .map(ToString::to_string);
            vec![UiEvent::TurnCompleted { status }]
        }
        "turn/diff/updated" => vec![UiEvent::StatusMessage("diff updated".to_string())],
        "thread/tokenUsage/updated" => {
            vec![UiEvent::StatusMessage("token usage updated".to_string())]
        }
        _ => Vec::new(),
    }
}

fn delta_from_params(params: &Value) -> Option<&str> {
    params
        .get("delta")
        .or_else(|| params.get("outputDelta"))
        .and_then(Value::as_str)
}

pub(crate) fn start_thread(state: &CliState) -> Result<String> {
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
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
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "turn/start",
        json!({
            "threadId": thread_id,
            "input": [
                {
                    "type": "text",
                    "text": text,
                    "textElements": []
                }
            ]
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
    let _ = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
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
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
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
    approve: bool,
) -> Result<()> {
    daemon_app_server_rpc_respond(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        request_id,
        json!({
            "decision": if approve { "accept" } else { "decline" }
        }),
    )?;
    Ok(())
}

pub(crate) fn stream_events(
    state: &CliState,
    since_sequence: u64,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    fetch_daemon_app_server_stream(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        Some(since_sequence),
    )
}
