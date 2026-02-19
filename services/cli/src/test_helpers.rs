use super::*;
use crabbot_protocol::DaemonRpcRequestResponse;
use crabbot_protocol::DaemonRpcRespondRequest;
use crabbot_protocol::DaemonRpcStreamEnvelope;

pub(super) const TUI_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const TUI_EVENT_WAIT_STEP: Duration = Duration::from_millis(50);
pub(super) const TUI_STREAM_REQUEST_TIMEOUT: Duration = Duration::from_millis(600);
pub(super) const TUI_COMPOSER_PROMPT: &str = "\u{203a} ";
pub(super) const TUI_COMPOSER_PLACEHOLDER: &str = "Ask Crabbot to do anything";
pub(super) const TUI_SLASH_PICKER_MAX_ROWS: usize = 4;

pub(super) fn run_upstream_picker_with_tui(
    state: &CliState,
    mode: crabbot_tui::StartupPicker,
    show_all: bool,
) -> Result<Option<String>> {
    let tui_state = convert_state_to_tui(state)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("initialize tokio runtime for startup picker")?;
    runtime.block_on(async { crabbot_tui::run_startup_picker(mode, show_all, &tui_state).await })
}

#[derive(Debug, Clone)]
pub(super) struct RuntimeOverrides {
    pub(super) model: Option<String>,
    pub(super) cwd: Option<String>,
    pub(super) approval_policy: Option<String>,
    pub(super) sandbox: Option<String>,
    pub(super) config: Value,
}

pub(super) fn build_runtime_overrides(args: &InteractiveArgs) -> Result<RuntimeOverrides> {
    let (sandbox_mode, approval_policy) = if args.full_auto {
        (
            Some("workspace-write".to_string()),
            Some("on-request".to_string()),
        )
    } else if args.dangerously_bypass_approvals_and_sandbox {
        (
            Some("danger-full-access".to_string()),
            Some("never".to_string()),
        )
    } else {
        (
            args.sandbox_mode.as_ref().map(sandbox_mode_to_wire),
            args.approval_policy.as_ref().map(approval_policy_to_wire),
        )
    };

    let mut config = Value::Object(serde_json::Map::new());

    for pair in &args.config {
        apply_key_value_override(&mut config, pair)?;
    }
    for feature in &args.enable {
        apply_dotted_value(
            &mut config,
            &format!("features.{feature}"),
            Value::Bool(true),
        )?;
    }
    for feature in &args.disable {
        apply_dotted_value(
            &mut config,
            &format!("features.{feature}"),
            Value::Bool(false),
        )?;
    }
    if let Some(profile) = &args.profile {
        apply_dotted_value(&mut config, "profile", Value::String(profile.clone()))?;
    }
    if args.search {
        apply_dotted_value(&mut config, "web_search", Value::String("live".to_string()))?;
    }
    if !args.add_dir.is_empty() {
        let writable_roots = args
            .add_dir
            .iter()
            .map(|path| Value::String(path.to_string_lossy().to_string()))
            .collect::<Vec<_>>();
        apply_dotted_value(
            &mut config,
            "sandbox_workspace_write.writable_roots",
            Value::Array(writable_roots),
        )?;
    }

    Ok(RuntimeOverrides {
        model: args.model.clone(),
        cwd: args
            .cwd
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        approval_policy,
        sandbox: sandbox_mode,
        config,
    })
}

pub(super) fn approval_policy_to_wire(policy: &crabbot_tui::ApprovalModeCliArg) -> String {
    match policy {
        crabbot_tui::ApprovalModeCliArg::UnlessTrusted => "untrusted",
        crabbot_tui::ApprovalModeCliArg::OnFailure => "on-failure",
        crabbot_tui::ApprovalModeCliArg::OnRequest => "on-request",
        crabbot_tui::ApprovalModeCliArg::Never => "never",
    }
    .to_string()
}

pub(super) fn sandbox_mode_to_wire(mode: &crabbot_tui::SandboxModeCliArg) -> String {
    match mode {
        crabbot_tui::SandboxModeCliArg::ReadOnly => "read-only",
        crabbot_tui::SandboxModeCliArg::WorkspaceWrite => "workspace-write",
        crabbot_tui::SandboxModeCliArg::DangerFullAccess => "danger-full-access",
    }
    .to_string()
}

pub(super) fn apply_key_value_override(config: &mut Value, pair: &str) -> Result<()> {
    let (key, raw_value) = pair
        .split_once('=')
        .ok_or_else(|| anyhow!("invalid --config override `{pair}`; expected key=value"))?;
    let parsed_value = match raw_value.parse::<toml::Value>() {
        Ok(value) => serde_json::to_value(value).context("convert parsed toml value")?,
        Err(_) => Value::String(raw_value.to_string()),
    };
    apply_dotted_value(config, key, parsed_value)
}

pub(super) fn apply_dotted_value(root: &mut Value, dotted_key: &str, value: Value) -> Result<()> {
    let mut parts = dotted_key.split('.').peekable();
    if parts.peek().is_none() {
        bail!("empty config key path");
    }
    let mut current = root;
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            match current {
                Value::Object(map) => {
                    map.insert(part.to_string(), value);
                    return Ok(());
                }
                _ => bail!("config path `{dotted_key}` collides with non-object value"),
            }
        }
        match current {
            Value::Object(map) => {
                current = map
                    .entry(part.to_string())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
            }
            _ => bail!("config path `{dotted_key}` collides with non-object value"),
        }
    }
    Ok(())
}

pub(super) fn thread_params_for_overrides(overrides: &RuntimeOverrides) -> Value {
    json!({
        "model": overrides.model,
        "cwd": overrides.cwd,
        "approvalPolicy": overrides.approval_policy,
        "sandbox": overrides.sandbox,
        "config": overrides.config,
    })
}

pub(super) fn start_thread_with_overrides(
    state: &mut CliState,
    overrides: &RuntimeOverrides,
) -> Result<String> {
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "thread/start",
        thread_params_for_overrides(overrides),
    )?;
    let thread_id = extract_thread_id_from_rpc_result(&response.result)
        .ok_or_else(|| anyhow!("thread/start response missing thread.id"))?;
    state.last_thread_id = Some(thread_id.clone());
    Ok(thread_id)
}

pub(super) fn resolve_thread_resume(
    state: &mut CliState,
    thread_id: &str,
    overrides: &RuntimeOverrides,
) -> Result<String> {
    let mut params = thread_params_for_overrides(overrides);
    params["threadId"] = Value::String(thread_id.to_string());
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "thread/resume",
        params,
    )?;
    let resolved = extract_thread_id_from_rpc_result(&response.result)
        .unwrap_or_else(|| thread_id.to_string());
    state.last_thread_id = Some(resolved.clone());
    Ok(resolved)
}

pub(super) fn resolve_thread_fork(
    state: &mut CliState,
    thread_id: &str,
    overrides: &RuntimeOverrides,
) -> Result<String> {
    let mut params = thread_params_for_overrides(overrides);
    params["threadId"] = Value::String(thread_id.to_string());
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "thread/fork",
        params,
    )?;
    let resolved = extract_thread_id_from_rpc_result(&response.result)
        .ok_or_else(|| anyhow!("thread/fork response missing thread.id"))?;
    state.last_thread_id = Some(resolved.clone());
    Ok(resolved)
}

pub(super) fn resolve_source_thread_for_resume_or_fork(
    state: &CliState,
    explicit: Option<String>,
    last: bool,
    all: bool,
) -> Result<String> {
    if let Some(value) = explicit {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("SESSION_ID cannot be empty");
        }
        return Ok(trimmed.to_string());
    }
    if last {
        return latest_thread_id_for_selection(state, all);
    }
    pick_thread_id_from_prompt(state, all)
}

pub(super) fn latest_thread_id_for_selection(state: &CliState, all: bool) -> Result<String> {
    let mut params = json!({
        "sortKey": "updated_at",
        "limit": 1,
        "archived": false,
    });
    if !all {
        let cwd = std::env::current_dir().context("resolve cwd for --last thread filter")?;
        params["cwd"] = Value::String(cwd.to_string_lossy().to_string());
    }
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "thread/list",
        params,
    )?;
    let first = response
        .result
        .get("data")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no saved sessions found"))?;
    Ok(first.to_string())
}

pub(super) fn pick_thread_id_from_prompt(state: &CliState, all: bool) -> Result<String> {
    let mut params = json!({
        "sortKey": "updated_at",
        "limit": 25,
        "archived": false,
    });
    if !all {
        let cwd = std::env::current_dir().context("resolve cwd for picker filter")?;
        params["cwd"] = Value::String(cwd.to_string_lossy().to_string());
    }
    let response = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "thread/list",
        params,
    )?;
    let rows = response
        .result
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("thread/list response missing data"))?;
    if rows.is_empty() {
        bail!("no saved sessions found");
    }

    let mut choices: Vec<(String, String)> = Vec::new();
    for row in rows {
        let Some(id) = row.get("id").and_then(Value::as_str) else {
            continue;
        };
        let title = row
            .get("threadName")
            .or_else(|| row.get("preview"))
            .and_then(Value::as_str)
            .unwrap_or(id)
            .to_string();
        choices.push((id.to_string(), title));
    }
    if choices.is_empty() {
        bail!("no saved sessions found");
    }

    eprintln!("Select a thread:");
    for (idx, (id, title)) in choices.iter().enumerate() {
        eprintln!("  {}. {} ({})", idx + 1, title, id);
    }
    eprintln!("Enter selection [1-{}]:", choices.len());
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("read picker selection")?;
    let selected_idx: usize = input
        .trim()
        .parse()
        .context("invalid picker selection, expected a number")?;
    if selected_idx == 0 || selected_idx > choices.len() {
        bail!("picker selection out of range");
    }
    Ok(choices[selected_idx - 1].0.clone())
}

pub(super) fn maybe_send_initial_prompt(
    state: &CliState,
    thread_id: &str,
    args: &InteractiveArgs,
) -> Result<()> {
    if args.images.is_empty() && args.prompt.is_none() {
        return Ok(());
    }
    let Some(prompt) = args.prompt.as_deref() else {
        bail!("--image requires an initial [PROMPT]");
    };
    if prompt.trim().is_empty() {
        bail!("[PROMPT] cannot be empty when provided");
    }

    let mut input = Vec::new();
    input.push(json!({
        "type": "text",
        "text": prompt,
        "text_elements": [],
    }));
    for image in &args.images {
        input.push(json!({
            "type": "localImage",
            "path": image.to_string_lossy().to_string(),
        }));
    }

    let _ = daemon_app_server_rpc_request(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
        "turn/start",
        json!({
            "threadId": thread_id,
            "input": input,
        }),
    )?;
    Ok(())
}

pub(super) fn daemon_app_server_rpc_request(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<DaemonRpcRequestResponse> {
    crabbot_tui::app_server_rpc_request_raw(daemon_endpoint, auth_token, method, params)
}

pub(super) fn daemon_app_server_rpc_respond(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    request_id: Value,
    result: Value,
) -> Result<()> {
    let client = http_client_with_timeout(DAEMON_PROMPT_REQUEST_TIMEOUT)?;
    let url = endpoint_url(daemon_endpoint, "/v2/app-server/respond");
    apply_auth(client.post(url), auth_token)
        .json(&DaemonRpcRespondRequest { request_id, result })
        .send()
        .context("respond daemon app-server request")?
        .error_for_status()
        .context("daemon app-server respond returned error status")?;
    Ok(())
}

pub(super) fn fetch_daemon_app_server_stream(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    let client = http_client_with_timeout(TUI_STREAM_REQUEST_TIMEOUT)?;
    let mut path = "/v2/app-server/stream".to_string();
    if let Some(since_sequence) = since_sequence {
        path.push_str(&format!("?since_sequence={since_sequence}"));
    }
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon app-server stream")?;
    let body = response
        .error_for_status()
        .context("daemon app-server stream returned error status")?
        .text()
        .context("read daemon app-server stream body")?;
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<DaemonRpcStreamEnvelope>(line)
                .context("parse daemon app-server stream line")
        })
        .collect::<Result<Vec<_>>>()
}

pub(super) fn request_id_key_for_cli(request_id: &Value) -> String {
    serde_json::to_string(request_id).unwrap_or_else(|_| request_id.to_string())
}

pub(super) fn extract_thread_id_from_rpc_result(result: &Value) -> Option<String> {
    result
        .get("thread")
        .and_then(|thread| thread.get("id"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

pub(super) fn cached_session_state_label<'a>(
    state: &'a CliState,
    session_id: &str,
) -> Option<&'a str> {
    state
        .sessions
        .get(session_id)
        .map(|runtime| match runtime.state {
            SessionStatus::Active => "active",
            SessionStatus::Interrupted => "interrupted",
        })
}
