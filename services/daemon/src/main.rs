use anyhow::Context;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use crabbot_codex_app_server::{
    CodexAppServerClient, CodexServerEvent, InitializeRequest, RuntimeEvent, SessionLifecycleState,
};
use crabbot_protocol::{
    DAEMON_STREAM_SCHEMA_VERSION, DaemonApprovalRequired, DaemonPromptRequest,
    DaemonPromptResponse, DaemonSessionState, DaemonSessionStatusResponse,
    DaemonStartSessionRequest, DaemonStreamEnvelope, DaemonStreamEvent, DaemonTurnCompleted,
    DaemonTurnStreamDelta, HealthResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    process::{ChildStdin, ChildStdout, Command, Stdio},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

const DEFAULT_DAEMON_BIND: &str = "127.0.0.1:8788";
const DEFAULT_CODEX_APP_SERVER_ENDPOINT: &str = "http://127.0.0.1:8789";
const CODEX_PROTOCOL_VERSION: &str = "2026-02-14";
const DAEMON_RUNTIME_USER_ID: &str = "daemon_local_user";
const DEFAULT_CODEX_BIN: &str = "codex";

#[derive(Clone)]
struct AppState {
    sessions: Arc<RwLock<HashMap<String, SessionRuntime>>>,
    codex_client: CodexAppServerClient,
}

#[derive(Debug, Clone)]
struct SessionRuntime {
    status: DaemonSessionStatusResponse,
    codex_session_id: String,
    codex_thread_id: String,
    active_turn_id: Option<String>,
    next_sequence: u64,
    events: Vec<DaemonStreamEnvelope>,
}

#[derive(Debug, Deserialize)]
struct StreamQuery {
    since_sequence: Option<u64>,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> anyhow::Result<()> {
    let bind = env::var("CRABBOT_DAEMON_BIND").unwrap_or_else(|_| DEFAULT_DAEMON_BIND.to_string());
    let state = AppState::from_env()?;
    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid CRABBOT_DAEMON_BIND address: {bind}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind daemon listener at {addr}"))?;
    axum::serve(listener, router_with_state(state))
        .await
        .context("serve daemon router")
}

#[cfg(test)]
fn router() -> Router {
    router_with_state(
        AppState::for_endpoint(DEFAULT_CODEX_APP_SERVER_ENDPOINT)
            .expect("default codex app server endpoint must be valid"),
    )
}

fn router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/sessions/start", post(start_session))
        .route("/v1/sessions/{session_id}/resume", post(resume_session))
        .route(
            "/v1/sessions/{session_id}/interrupt",
            post(interrupt_session),
        )
        .route("/v1/sessions/{session_id}/prompt", post(prompt_session))
        .route("/v1/sessions/{session_id}/status", get(session_status))
        .route("/v1/sessions/{session_id}/stream", get(session_stream))
        .with_state(state)
}

impl AppState {
    fn from_env() -> anyhow::Result<Self> {
        let endpoint = env::var("CRABBOT_CODEX_APP_SERVER_ENDPOINT")
            .unwrap_or_else(|_| DEFAULT_CODEX_APP_SERVER_ENDPOINT.to_string());
        Self::for_endpoint(&endpoint)
    }

    fn for_endpoint(endpoint: &str) -> anyhow::Result<Self> {
        let codex_client = CodexAppServerClient::new(endpoint)
            .with_context(|| format!("initialize codex app server client for {endpoint}"))?;
        Ok(Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            codex_client,
        })
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "crabbot_daemon".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn ensure_codex_initialized(client: &CodexAppServerClient) -> Result<(), StatusCode> {
    client
        .initialize(InitializeRequest {
            client_name: "crabbot-daemon".to_string(),
            protocol_version: CODEX_PROTOCOL_VERSION.to_string(),
        })
        .await
        .map(|_| ())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn daemon_state_from_codex(state: SessionLifecycleState) -> &'static str {
    match state {
        SessionLifecycleState::Active => "active",
        SessionLifecycleState::Interrupted => "interrupted",
        SessionLifecycleState::Closed => "interrupted",
    }
}

fn build_session_status(
    session_id: String,
    state: &str,
    last_event: &str,
) -> DaemonSessionStatusResponse {
    DaemonSessionStatusResponse {
        session_id,
        state: state.to_string(),
        last_event: last_event.to_string(),
        updated_at_unix_ms: now_unix_ms(),
    }
}

fn push_event(runtime: &mut SessionRuntime, event: DaemonStreamEvent) -> u64 {
    runtime.next_sequence += 1;
    let sequence = runtime.next_sequence;
    let envelope = DaemonStreamEnvelope {
        schema_version: DAEMON_STREAM_SCHEMA_VERSION,
        session_id: runtime.status.session_id.clone(),
        sequence,
        event: event.clone(),
    };
    runtime.events.push(envelope);

    if let DaemonStreamEvent::SessionState(payload) = event {
        runtime.status.state = payload.state;
        runtime.status.updated_at_unix_ms = now_unix_ms();
    }

    sequence
}

fn split_for_stream(text: &str, chunk_size: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let chars = text.chars().collect::<Vec<_>>();
    let mut chunks = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let end = (index + chunk_size).min(chars.len());
        chunks.push(chars[index..end].iter().collect::<String>());
        index = end;
    }
    chunks
}

fn runtime_event_to_daemon_event(event: RuntimeEvent) -> Option<DaemonStreamEvent> {
    match event {
        RuntimeEvent::TurnStarted { .. } => None,
        RuntimeEvent::TurnOutputDelta { turn_id, delta, .. } => {
            Some(DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                turn_id,
                delta,
            }))
        }
        RuntimeEvent::TurnCompleted {
            turn_id,
            output_message_id,
            ..
        } => Some(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
            turn_id,
            output_summary: format!("complete ({output_message_id})"),
        })),
        RuntimeEvent::TurnInterrupted {
            turn_id, reason, ..
        } => Some(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
            turn_id,
            output_summary: format!("interrupted: {reason}"),
        })),
        RuntimeEvent::TurnAborted {
            turn_id, reason, ..
        } => Some(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
            turn_id,
            output_summary: format!("aborted: {reason}"),
        })),
        RuntimeEvent::ActionApprovalRequired {
            turn_id,
            approval_id,
            action,
            ..
        } => Some(DaemonStreamEvent::ApprovalRequired(
            DaemonApprovalRequired {
                turn_id,
                approval_id,
                action_kind: action,
                prompt: "Approval required before continuing this action".to_string(),
            },
        )),
    }
}

#[derive(Debug)]
struct RealCodexTurnOutcome {
    thread_id: String,
    turn_id: String,
    events: Vec<DaemonStreamEvent>,
    status: String,
}

fn daemon_should_use_real_codex() -> bool {
    if cfg!(test) {
        return false;
    }
    match env::var("CRABBOT_DAEMON_REAL_CODEX") {
        Ok(raw) => {
            let value = raw.trim().to_ascii_lowercase();
            !matches!(value.as_str(), "0" | "false" | "off" | "no")
        }
        Err(_) => true,
    }
}

fn write_json_line(stdin: &mut ChildStdin, value: &Value) -> anyhow::Result<()> {
    serde_json::to_writer(&mut *stdin, value).context("serialize json-rpc message")?;
    stdin.write_all(b"\n").context("write json-rpc line")?;
    stdin.flush().context("flush json-rpc line")
}

fn read_json_line(reader: &mut BufReader<ChildStdout>) -> anyhow::Result<Value> {
    loop {
        let mut line = String::new();
        let read = reader
            .read_line(&mut line)
            .context("read codex app-server stdout")?;
        if read == 0 {
            anyhow::bail!("codex app-server closed stdout");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return serde_json::from_str(trimmed).context("parse codex app-server json line");
    }
}

fn read_response_for_request(
    reader: &mut BufReader<ChildStdout>,
    request_id: i64,
) -> anyhow::Result<Value> {
    loop {
        let message = read_json_line(reader)?;
        let Some(message_id) = message.get("id").and_then(Value::as_i64) else {
            continue;
        };
        if message_id != request_id {
            continue;
        }
        if let Some(error) = message.get("error") {
            let detail = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            anyhow::bail!("codex app-server request {request_id} failed: {detail}");
        }
        let result = message
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("missing result for request id {request_id}"))?;
        return Ok(result);
    }
}

fn try_resume_or_start_thread(
    reader: &mut BufReader<ChildStdout>,
    stdin: &mut ChildStdin,
    next_request_id: &mut i64,
    existing_thread_id: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(thread_id) = existing_thread_id {
        *next_request_id += 1;
        let resume_request_id = *next_request_id;
        write_json_line(
            stdin,
            &json!({
                "id": resume_request_id,
                "method": "thread/resume",
                "params": {
                    "threadId": thread_id,
                }
            }),
        )?;
        let resumed = read_response_for_request(reader, resume_request_id);
        if let Ok(result) = resumed {
            if let Some(resumed_id) = result
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(Value::as_str)
            {
                return Ok(resumed_id.to_string());
            }
        }
    }

    *next_request_id += 1;
    let start_request_id = *next_request_id;
    write_json_line(
        stdin,
        &json!({
            "id": start_request_id,
            "method": "thread/start",
            "params": {
                "approvalPolicy": "never"
            }
        }),
    )?;
    let started = read_response_for_request(reader, start_request_id)?;
    started
        .get("thread")
        .and_then(|thread| thread.get("id"))
        .and_then(Value::as_str)
        .map(|thread_id| thread_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("thread/start response missing thread.id"))
}

fn approval_prompt_from_request(method: &str, params: &Value) -> String {
    let reason = params
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("approval required");
    let command = params
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match method {
        "item/commandExecution/requestApproval" if !command.is_empty() => {
            format!("{reason}: {command}")
        }
        _ => reason.to_string(),
    }
}

fn run_real_codex_turn(
    existing_thread_id: Option<&str>,
    prompt: &str,
) -> anyhow::Result<RealCodexTurnOutcome> {
    let codex_bin = env::var("CRABBOT_CODEX_BIN").unwrap_or_else(|_| DEFAULT_CODEX_BIN.to_string());
    let mut child = Command::new(&codex_bin)
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn `{codex_bin} app-server`"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("codex app-server stdin unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("codex app-server stdout unavailable"))?;
    let mut reader = BufReader::new(stdout);

    let mut next_request_id = 1_i64;
    write_json_line(
        &mut stdin,
        &json!({
            "id": next_request_id,
            "method": "initialize",
            "params": {
                "clientInfo": {
                    "name": "crabbot_daemon",
                    "title": "Crabbot Daemon",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "capabilities": {
                    "experimentalApi": true
                }
            }
        }),
    )?;
    let _ = read_response_for_request(&mut reader, next_request_id)?;
    write_json_line(
        &mut stdin,
        &json!({
            "method": "initialized",
            "params": {}
        }),
    )?;

    let thread_id = try_resume_or_start_thread(
        &mut reader,
        &mut stdin,
        &mut next_request_id,
        existing_thread_id,
    )?;

    next_request_id += 1;
    let turn_start_request_id = next_request_id;
    write_json_line(
        &mut stdin,
        &json!({
            "id": turn_start_request_id,
            "method": "turn/start",
            "params": {
                "threadId": thread_id,
                "input": [
                    {
                        "type": "text",
                        "text": prompt,
                        "textElements": []
                    }
                ]
            }
        }),
    )?;

    let mut turn_id: Option<String> = None;
    let mut turn_status: Option<String> = None;
    let mut turn_start_response_seen = false;
    let mut mapped_events: Vec<DaemonStreamEvent> = Vec::new();

    while turn_status.is_none() || !turn_start_response_seen {
        let message = read_json_line(&mut reader)?;
        let method = message.get("method").and_then(Value::as_str);
        let is_request = message.get("id").is_some() && method.is_some();
        let is_response = method.is_none() && message.get("id").is_some();

        if is_response {
            if message
                .get("id")
                .and_then(Value::as_i64)
                .is_some_and(|id| id == turn_start_request_id)
            {
                turn_start_response_seen = true;
                if let Some(error) = message.get("error") {
                    let detail = error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown error");
                    anyhow::bail!("turn/start failed: {detail}");
                }
                if let Some(turn_id_value) = message
                    .get("result")
                    .and_then(|result| result.get("turn"))
                    .and_then(|turn| turn.get("id"))
                    .and_then(Value::as_str)
                {
                    turn_id = Some(turn_id_value.to_string());
                }
            }
            continue;
        }

        let Some(method_name) = method else {
            continue;
        };
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        if is_request {
            if matches!(
                method_name,
                "item/commandExecution/requestApproval" | "item/fileChange/requestApproval"
            ) {
                let approval_turn_id = params
                    .get("turnId")
                    .and_then(Value::as_str)
                    .or(turn_id.as_deref())
                    .unwrap_or("turn_unknown")
                    .to_string();
                let approval_id = params
                    .get("itemId")
                    .and_then(Value::as_str)
                    .map(|value| value.to_string())
                    .or_else(|| {
                        message
                            .get("id")
                            .and_then(Value::as_i64)
                            .map(|id| format!("approval_request_{id}"))
                    })
                    .unwrap_or_else(|| "approval_request".to_string());
                mapped_events.push(DaemonStreamEvent::ApprovalRequired(
                    DaemonApprovalRequired {
                        turn_id: approval_turn_id,
                        approval_id,
                        action_kind: if method_name == "item/fileChange/requestApproval" {
                            "file_change".to_string()
                        } else {
                            "command_execution".to_string()
                        },
                        prompt: approval_prompt_from_request(method_name, &params),
                    },
                ));

                if let Some(request_id) = message.get("id") {
                    write_json_line(
                        &mut stdin,
                        &json!({
                            "id": request_id,
                            "result": {
                                "decision": "decline"
                            }
                        }),
                    )?;
                }
            }
            continue;
        }

        match method_name {
            "item/agentMessage/delta" => {
                if let Some(delta) = params.get("delta").and_then(Value::as_str) {
                    let delta_turn_id = params
                        .get("turnId")
                        .and_then(Value::as_str)
                        .or(turn_id.as_deref())
                        .unwrap_or("turn_unknown")
                        .to_string();
                    mapped_events.push(DaemonStreamEvent::TurnStreamDelta(DaemonTurnStreamDelta {
                        turn_id: delta_turn_id,
                        delta: delta.to_string(),
                    }));
                }
            }
            "turn/completed" => {
                let completed_turn_id = params
                    .get("turn")
                    .and_then(|turn| turn.get("id"))
                    .and_then(Value::as_str)
                    .or(turn_id.as_deref())
                    .unwrap_or("turn_unknown")
                    .to_string();
                let status = params
                    .get("turn")
                    .and_then(|turn| turn.get("status"))
                    .and_then(Value::as_str)
                    .unwrap_or("completed")
                    .to_string();
                turn_status = Some(status.clone());
                turn_id = Some(completed_turn_id.clone());
                mapped_events.push(DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
                    turn_id: completed_turn_id,
                    output_summary: format!("status: {status}"),
                }));
            }
            _ => {}
        }
    }

    let _ = child.kill();
    let _ = child.wait();

    Ok(RealCodexTurnOutcome {
        thread_id,
        turn_id: turn_id.unwrap_or_else(|| "turn_unknown".to_string()),
        events: mapped_events,
        status: turn_status.unwrap_or_else(|| "completed".to_string()),
    })
}

fn synthesize_assistant_output(prompt: &str) -> String {
    let trimmed = prompt.trim();
    if trimmed.is_empty() {
        return "Please share a concrete request.".to_string();
    }
    let normalized = trimmed.to_ascii_lowercase();
    if matches!(normalized.as_str(), "hi" | "hello" | "hey") {
        return "Hi. Ready when you are.".to_string();
    }
    if normalized.ends_with('?') || normalized.starts_with("why ") || normalized.starts_with("how ")
    {
        return format!(
            "You asked: {trimmed}\nI can give a precise answer once full Codex model execution is connected."
        );
    }

    format!("You said: {trimmed}")
}

async fn start_session(
    State(state): State<AppState>,
    Json(payload): Json<DaemonStartSessionRequest>,
) -> Result<(StatusCode, Json<DaemonSessionStatusResponse>), StatusCode> {
    if payload
        .session_id
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let session_id = payload
        .session_id
        .unwrap_or_else(|| format!("sess_daemon_{}", now_unix_ms()));
    ensure_codex_initialized(&state.codex_client).await?;
    let codex_session = state
        .codex_client
        .create_session(DAEMON_RUNTIME_USER_ID)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let codex_thread = state
        .codex_client
        .create_thread(&codex_session.session_id, &format!("daemon-{session_id}"))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let status = build_session_status(session_id.clone(), "active", "started");
    let mut runtime = SessionRuntime {
        status,
        codex_session_id: codex_session.session_id,
        codex_thread_id: codex_thread.thread_id,
        active_turn_id: None,
        next_sequence: 0,
        events: Vec::new(),
    };
    push_event(
        &mut runtime,
        DaemonStreamEvent::SessionState(DaemonSessionState {
            state: "active".to_string(),
        }),
    );

    let session = runtime.status.clone();
    let mut sessions = state.sessions.write().await;
    sessions.insert(session_id, runtime);
    Ok((StatusCode::CREATED, Json(session)))
}

async fn mutate_session_state(
    state: &AppState,
    session_id: &str,
    next_state: &str,
    last_event: &str,
) -> Result<DaemonSessionStatusResponse, StatusCode> {
    ensure_codex_initialized(&state.codex_client).await?;
    let (codex_session_id, codex_thread_id, active_turn_id) = {
        let sessions = state.sessions.read().await;
        let runtime = sessions.get(session_id).ok_or(StatusCode::NOT_FOUND)?;
        (
            runtime.codex_session_id.clone(),
            runtime.codex_thread_id.clone(),
            runtime.active_turn_id.clone(),
        )
    };

    let codex_state = match next_state {
        "active" => state
            .codex_client
            .resume_session(&codex_session_id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        "interrupted" => {
            if let Some(turn_id) = active_turn_id.as_deref() {
                let _ = state
                    .codex_client
                    .interrupt_turn(
                        &codex_session_id,
                        &codex_thread_id,
                        turn_id,
                        "session_interrupt",
                    )
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            }
            state
                .codex_client
                .interrupt_session(&codex_session_id)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        }
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let mut sessions = state.sessions.write().await;
    let runtime = sessions.get_mut(session_id).ok_or(StatusCode::NOT_FOUND)?;
    runtime.status.state = daemon_state_from_codex(codex_state.state).to_string();
    runtime.status.last_event = last_event.to_string();
    runtime.status.updated_at_unix_ms = now_unix_ms();
    if next_state == "interrupted" {
        runtime.active_turn_id = None;
    }
    push_event(
        runtime,
        DaemonStreamEvent::SessionState(DaemonSessionState {
            state: runtime.status.state.clone(),
        }),
    );
    Ok(runtime.status.clone())
}

async fn resume_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<DaemonSessionStatusResponse>, StatusCode> {
    let response = mutate_session_state(&state, &session_id, "active", "resumed").await?;
    Ok(Json(response))
}

async fn interrupt_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<DaemonSessionStatusResponse>, StatusCode> {
    let response = mutate_session_state(&state, &session_id, "interrupted", "interrupted").await?;
    Ok(Json(response))
}

async fn session_status(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<DaemonSessionStatusResponse>, StatusCode> {
    let sessions = state.sessions.read().await;
    let runtime = sessions
        .get(&session_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(runtime.status))
}

async fn session_stream(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Query(query): Query<StreamQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;
    let runtime = sessions
        .get(&session_id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    let since = query.since_sequence.unwrap_or(0);
    let lines = runtime
        .events
        .iter()
        .filter(|event| event.sequence > since)
        .cloned()
        .map(|event| serde_json::to_string(&event).expect("serialize daemon stream event"))
        .collect::<Vec<_>>()
        .join("\n");
    let payload = format!("{lines}\n");
    Ok((
        [
            ("content-type", "application/x-ndjson"),
            ("cache-control", "no-store"),
            ("x-crabbot-daemon-stream", "1"),
        ],
        payload,
    ))
}

async fn prompt_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(payload): Json<DaemonPromptRequest>,
) -> Result<(StatusCode, Json<DaemonPromptResponse>), StatusCode> {
    if payload.prompt.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let (daemon_state, codex_session_id, codex_thread_id) = {
        let sessions = state.sessions.read().await;
        let runtime = sessions.get(&session_id).ok_or(StatusCode::NOT_FOUND)?;
        (
            runtime.status.state.clone(),
            runtime.codex_session_id.clone(),
            runtime.codex_thread_id.clone(),
        )
    };
    if daemon_state != "active" {
        return Err(StatusCode::CONFLICT);
    }

    if daemon_should_use_real_codex() {
        let existing_thread_id = if codex_thread_id.trim().is_empty() {
            None
        } else {
            Some(codex_thread_id.clone())
        };
        let prompt_text = payload.prompt.clone();
        let real_outcome = tokio::task::spawn_blocking(move || {
            run_real_codex_turn(existing_thread_id.as_deref(), &prompt_text)
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR);

        match real_outcome {
            Ok(Ok(real)) => {
                let mut sessions = state.sessions.write().await;
                let runtime = sessions.get_mut(&session_id).ok_or(StatusCode::NOT_FOUND)?;
                if runtime.status.state != "active" {
                    return Err(StatusCode::CONFLICT);
                }
                runtime.codex_thread_id = real.thread_id;
                runtime.active_turn_id = Some(real.turn_id.clone());
                for mapped in real.events {
                    push_event(runtime, mapped);
                }
                runtime.active_turn_id = None;
                runtime.status.last_event = format!("turn_{}", real.status);
                runtime.status.updated_at_unix_ms = now_unix_ms();

                let response = DaemonPromptResponse {
                    session_id,
                    turn_id: real.turn_id,
                    state: runtime.status.state.clone(),
                    last_event: runtime.status.last_event.clone(),
                    updated_at_unix_ms: runtime.status.updated_at_unix_ms,
                    last_sequence: runtime.next_sequence,
                };
                return Ok((StatusCode::ACCEPTED, Json(response)));
            }
            Ok(Err(error)) => {
                eprintln!("error: real codex app-server prompt failed: {error:#}");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    ensure_codex_initialized(&state.codex_client).await?;
    let turn = state
        .codex_client
        .start_turn(&codex_session_id, &codex_thread_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let turn_id = turn.turn_id.clone();

    let mut mapped_events = Vec::new();
    let started = CodexAppServerClient::map_server_event(CodexServerEvent::TurnStarted {
        session_id: codex_session_id.clone(),
        thread_id: codex_thread_id.clone(),
        turn_id: turn_id.clone(),
    });
    if let Some(event) = runtime_event_to_daemon_event(started) {
        mapped_events.push(event);
    }

    let assistant_output = synthesize_assistant_output(&payload.prompt);
    for chunk in split_for_stream(&assistant_output, 32) {
        let _ = state
            .codex_client
            .append_turn_delta(&codex_session_id, &codex_thread_id, &turn_id, &chunk)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let delta_event = CodexAppServerClient::map_server_event(CodexServerEvent::TurnDelta {
            session_id: codex_session_id.clone(),
            thread_id: codex_thread_id.clone(),
            turn_id: turn_id.clone(),
            delta: chunk,
        });
        if let Some(event) = runtime_event_to_daemon_event(delta_event) {
            mapped_events.push(event);
        }
    }

    if payload.prompt.to_ascii_lowercase().contains("approve") {
        let approval_event =
            CodexAppServerClient::map_server_event(CodexServerEvent::ApprovalRequired {
                session_id: codex_session_id.clone(),
                thread_id: codex_thread_id.clone(),
                turn_id: turn_id.clone(),
                approval_id: format!("approval_{session_id}_{turn_id}"),
                action: "shell_command".to_string(),
            });
        if let Some(event) = runtime_event_to_daemon_event(approval_event) {
            mapped_events.push(event);
        }
    }

    let output_message_id = format!("msg_{turn_id}");
    let _ = state
        .codex_client
        .complete_turn(
            &codex_session_id,
            &codex_thread_id,
            &turn_id,
            &output_message_id,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let completed = CodexAppServerClient::map_server_event(CodexServerEvent::TurnCompleted {
        session_id: codex_session_id,
        thread_id: codex_thread_id,
        turn_id: turn_id.clone(),
        output_message_id,
    });
    if let Some(event) = runtime_event_to_daemon_event(completed) {
        mapped_events.push(event);
    }

    let mut sessions = state.sessions.write().await;
    let runtime = sessions.get_mut(&session_id).ok_or(StatusCode::NOT_FOUND)?;
    if runtime.status.state != "active" {
        return Err(StatusCode::CONFLICT);
    }
    runtime.active_turn_id = Some(turn_id.clone());
    for mapped in mapped_events {
        push_event(runtime, mapped);
    }
    runtime.active_turn_id = None;
    runtime.status.last_event = "turn_completed".to_string();
    runtime.status.updated_at_unix_ms = now_unix_ms();

    let response = DaemonPromptResponse {
        session_id,
        turn_id,
        state: runtime.status.state.clone(),
        last_event: runtime.status.last_event.clone(),
        updated_at_unix_ms: runtime.status.updated_at_unix_ms,
        last_sequence: runtime.next_sequence,
    };
    Ok((StatusCode::ACCEPTED, Json(response)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use serde_json::json;
    use tower::ServiceExt;

    async fn read_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("parse json body")
    }

    #[tokio::test]
    async fn session_control_endpoints_round_trip() {
        let app = router();
        let start_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonStartSessionRequest {
                            session_id: Some("sess_daemon_test".to_string()),
                        })
                        .expect("serialize start request"),
                    ))
                    .expect("build start request"),
            )
            .await
            .expect("route start request");
        assert_eq!(start_response.status(), StatusCode::CREATED);
        let start_json = read_json(start_response).await;
        assert_eq!(start_json["session_id"], "sess_daemon_test");
        assert_eq!(start_json["state"], "active");
        assert_eq!(start_json["last_event"], "started");

        let interrupt_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/sess_daemon_test/interrupt")
                    .body(Body::empty())
                    .expect("build interrupt request"),
            )
            .await
            .expect("route interrupt request");
        assert_eq!(interrupt_response.status(), StatusCode::OK);
        let interrupt_json = read_json(interrupt_response).await;
        assert_eq!(interrupt_json["state"], "interrupted");

        let resume_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/sess_daemon_test/resume")
                    .body(Body::empty())
                    .expect("build resume request"),
            )
            .await
            .expect("route resume request");
        assert_eq!(resume_response.status(), StatusCode::OK);
        let resume_json = read_json(resume_response).await;
        assert_eq!(resume_json["state"], "active");
        assert_eq!(resume_json["last_event"], "resumed");

        let status_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_test/status")
                    .body(Body::empty())
                    .expect("build status request"),
            )
            .await
            .expect("route status request");
        assert_eq!(status_response.status(), StatusCode::OK);
        let status_json = read_json(status_response).await;
        assert_eq!(status_json["state"], "active");
        assert_eq!(status_json["last_event"], "resumed");
    }

    #[tokio::test]
    async fn stream_endpoint_returns_ndjson_envelopes() {
        let app = router();
        let _start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonStartSessionRequest {
                            session_id: Some("sess_daemon_stream".to_string()),
                        })
                        .expect("serialize start request"),
                    ))
                    .expect("build start request"),
            )
            .await
            .expect("route start request");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_stream/stream")
                    .body(Body::empty())
                    .expect("build stream request"),
            )
            .await
            .expect("route stream request");

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        let lines = body.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let first: DaemonStreamEnvelope =
            serde_json::from_str(lines[0]).expect("parse first stream line");
        assert_eq!(first.session_id, "sess_daemon_stream");
        assert_eq!(first.sequence, 1);
        assert_eq!(
            first.event,
            DaemonStreamEvent::SessionState(DaemonSessionState {
                state: "active".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn prompt_endpoint_emits_turn_events_and_stream_filtering() {
        let app = router();
        let _start = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/start")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonStartSessionRequest {
                            session_id: Some("sess_daemon_prompt".to_string()),
                        })
                        .expect("serialize start request"),
                    ))
                    .expect("build start request"),
            )
            .await
            .expect("route start request");

        let prompt_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/sessions/sess_daemon_prompt/prompt")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&DaemonPromptRequest {
                            prompt: "ship it".to_string(),
                        })
                        .expect("serialize prompt request"),
                    ))
                    .expect("build prompt request"),
            )
            .await
            .expect("route prompt request");
        assert_eq!(prompt_response.status(), StatusCode::ACCEPTED);
        let prompt_json = read_json(prompt_response).await;
        assert_eq!(prompt_json["session_id"], "sess_daemon_prompt");
        assert_eq!(prompt_json["state"], "active");
        assert_eq!(prompt_json["last_event"], "turn_completed");

        let all_events_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_prompt/stream")
                    .body(Body::empty())
                    .expect("build stream request"),
            )
            .await
            .expect("route stream request");
        assert_eq!(all_events_response.status(), StatusCode::OK);
        let all_bytes = all_events_response
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let all_body = String::from_utf8(all_bytes.to_vec()).expect("utf8 body");
        let all_lines = all_body.lines().collect::<Vec<_>>();
        assert!(all_lines.len() >= 3);

        let completion: DaemonStreamEnvelope =
            serde_json::from_str(all_lines[all_lines.len() - 1]).expect("parse completion line");
        match completion.event {
            DaemonStreamEvent::TurnCompleted(payload) => {
                assert!(payload.turn_id.starts_with("turn_"));
                assert!(payload.output_summary.starts_with("complete (msg_turn_"));
            }
            _ => panic!("expected turn completed event"),
        }

        let filtered_response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sessions/sess_daemon_prompt/stream?since_sequence=2")
                    .body(Body::empty())
                    .expect("build filtered stream request"),
            )
            .await
            .expect("route filtered stream request");
        assert_eq!(filtered_response.status(), StatusCode::OK);
        let filtered_bytes = filtered_response
            .into_body()
            .collect()
            .await
            .expect("collect filtered body")
            .to_bytes();
        let filtered_body = String::from_utf8(filtered_bytes.to_vec()).expect("utf8 body");
        let filtered_lines = filtered_body.lines().collect::<Vec<_>>();
        assert!(!filtered_lines.is_empty());
    }

    #[tokio::test]
    async fn health_endpoint_reports_daemon_service() {
        let app = router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("route request");

        assert_eq!(response.status(), StatusCode::OK);
        let value = read_json(response).await;
        assert_eq!(value["service"], json!("crabbot_daemon"));
    }
}
