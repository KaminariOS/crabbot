use super::*;

pub(super) fn start_thread(state: &CliState) -> Result<String> {
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

pub(super) fn start_turn(state: &CliState, thread_id: &str, text: &str) -> Result<Option<String>> {
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

pub(super) fn interrupt_turn(state: &CliState, thread_id: &str, turn_id: &str) -> Result<()> {
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

pub(super) fn resume_thread(state: &CliState, thread_id: &str) -> Result<Option<String>> {
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

pub(super) fn respond_to_approval(
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

pub(super) fn stream_events(
    state: &CliState,
    since_sequence: u64,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    fetch_daemon_app_server_stream(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        Some(since_sequence),
    )
}
