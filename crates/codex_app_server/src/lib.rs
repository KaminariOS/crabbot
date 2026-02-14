use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, sync::Mutex, time::timeout};
use url::Url;

#[derive(Debug, Clone)]
pub struct CodexAppServerClient {
    endpoint: Url,
    connect_timeout: Duration,
    runtime: Arc<Mutex<RuntimeStore>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmokeConnection {
    pub endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeRequest {
    pub client_name: String,
    pub protocol_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitializeResponse {
    pub endpoint: String,
    pub protocol_version: String,
    pub initialized_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionLifecycleState {
    Active,
    Interrupted,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLifecycle {
    pub session_id: String,
    pub user_id: String,
    pub state: SessionLifecycleState,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreadLifecycleState {
    Idle,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadLifecycle {
    pub thread_id: String,
    pub session_id: String,
    pub title: String,
    pub state: ThreadLifecycleState,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TurnLifecycleState {
    Running,
    Interrupted,
    Completed,
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnLifecycle {
    pub turn_id: String,
    pub session_id: String,
    pub thread_id: String,
    pub state: TurnLifecycleState,
    pub delta_count: usize,
    pub output_message_id: Option<String>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexServerEvent {
    TurnStarted {
        session_id: String,
        thread_id: String,
        turn_id: String,
    },
    TurnDelta {
        session_id: String,
        thread_id: String,
        turn_id: String,
        delta: String,
    },
    TurnCompleted {
        session_id: String,
        thread_id: String,
        turn_id: String,
        output_message_id: String,
    },
    TurnInterrupted {
        session_id: String,
        thread_id: String,
        turn_id: String,
        reason: String,
    },
    TurnAborted {
        session_id: String,
        thread_id: String,
        turn_id: String,
        reason: String,
    },
    ApprovalRequired {
        session_id: String,
        thread_id: String,
        turn_id: String,
        approval_id: String,
        action: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    TurnStarted {
        session_id: String,
        thread_id: String,
        turn_id: String,
    },
    TurnOutputDelta {
        session_id: String,
        thread_id: String,
        turn_id: String,
        delta: String,
    },
    TurnCompleted {
        session_id: String,
        thread_id: String,
        turn_id: String,
        output_message_id: String,
    },
    TurnInterrupted {
        session_id: String,
        thread_id: String,
        turn_id: String,
        reason: String,
    },
    TurnAborted {
        session_id: String,
        thread_id: String,
        turn_id: String,
        reason: String,
    },
    ActionApprovalRequired {
        session_id: String,
        thread_id: String,
        turn_id: String,
        approval_id: String,
        action: String,
    },
}

#[derive(Debug, Default)]
struct RuntimeStore {
    initialized: Option<InitializeResponse>,
    next_session_id: u64,
    next_thread_id: u64,
    next_turn_id: u64,
    sessions: HashMap<String, SessionState>,
}

#[derive(Debug, Clone)]
struct SessionState {
    session_id: String,
    user_id: String,
    state: SessionLifecycleState,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    threads: HashMap<String, ThreadState>,
}

#[derive(Debug, Clone)]
struct ThreadState {
    thread_id: String,
    session_id: String,
    title: String,
    state: ThreadLifecycleState,
    active_turn_id: Option<String>,
    turns: HashMap<String, TurnState>,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
struct TurnState {
    turn_id: String,
    session_id: String,
    thread_id: String,
    state: TurnLifecycleState,
    deltas: Vec<String>,
    output_message_id: Option<String>,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
}

impl CodexAppServerClient {
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint = Url::parse(endpoint).context("endpoint must be a valid URL")?;
        ensure_supported_scheme(&endpoint)?;

        Ok(Self {
            endpoint,
            connect_timeout: Duration::from_secs(2),
            runtime: Arc::new(Mutex::new(RuntimeStore::default())),
        })
    }

    pub fn with_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub async fn connect_smoke(&self) -> Result<SmokeConnection> {
        let target = endpoint_socket_address(&self.endpoint)?;
        let connect_future = TcpStream::connect(&target);

        timeout(self.connect_timeout, connect_future)
            .await
            .with_context(|| format!("timed out connecting to {}", self.endpoint))?
            .with_context(|| format!("failed connecting to {}", target))?;

        Ok(SmokeConnection {
            endpoint: self.endpoint.to_string(),
        })
    }

    pub async fn initialize(&self, request: InitializeRequest) -> Result<InitializeResponse> {
        if request.client_name.trim().is_empty() || request.protocol_version.trim().is_empty() {
            bail!("initialize requires non-empty client name and protocol version");
        }

        let mut runtime = self.runtime.lock().await;
        if let Some(existing) = runtime.initialized.as_ref() {
            if existing.protocol_version != request.protocol_version {
                bail!(
                    "protocol version mismatch: initialized with {}, got {}",
                    existing.protocol_version,
                    request.protocol_version
                );
            }
            return Ok(existing.clone());
        }

        let initialized = InitializeResponse {
            endpoint: self.endpoint.to_string(),
            protocol_version: request.protocol_version,
            initialized_at_unix_ms: now_unix_ms(),
        };
        runtime.initialized = Some(initialized.clone());
        Ok(initialized)
    }

    pub async fn create_session(&self, user_id: &str) -> Result<SessionLifecycle> {
        if user_id.trim().is_empty() {
            bail!("create_session requires non-empty user_id");
        }

        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        runtime.next_session_id += 1;
        let now = now_unix_ms();
        let session = SessionState {
            session_id: format!("sess_{}", runtime.next_session_id),
            user_id: user_id.to_string(),
            state: SessionLifecycleState::Active,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            threads: HashMap::new(),
        };
        let snapshot = snapshot_session(&session);
        runtime.sessions.insert(session.session_id.clone(), session);
        Ok(snapshot)
    }

    pub async fn get_session(&self, session_id: &str) -> Result<SessionLifecycle> {
        let runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        Ok(snapshot_session(session))
    }

    pub async fn interrupt_session(&self, session_id: &str) -> Result<SessionLifecycle> {
        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;

        if session.state == SessionLifecycleState::Closed {
            bail!("cannot interrupt a closed session");
        }

        session.state = SessionLifecycleState::Interrupted;
        session.updated_at_unix_ms = now_unix_ms();
        Ok(snapshot_session(session))
    }

    pub async fn resume_session(&self, session_id: &str) -> Result<SessionLifecycle> {
        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;

        if session.state == SessionLifecycleState::Closed {
            bail!("cannot resume a closed session");
        }

        session.state = SessionLifecycleState::Active;
        session.updated_at_unix_ms = now_unix_ms();
        Ok(snapshot_session(session))
    }

    pub async fn close_session(&self, session_id: &str) -> Result<SessionLifecycle> {
        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;

        let now = now_unix_ms();
        session.state = SessionLifecycleState::Closed;
        session.updated_at_unix_ms = now;
        for thread in session.threads.values_mut() {
            thread.state = ThreadLifecycleState::Closed;
            thread.updated_at_unix_ms = now;
            for turn in thread.turns.values_mut() {
                if matches!(
                    turn.state,
                    TurnLifecycleState::Running | TurnLifecycleState::Interrupted
                ) {
                    turn.state = TurnLifecycleState::Aborted;
                }
                turn.updated_at_unix_ms = now;
            }
        }

        Ok(snapshot_session(session))
    }

    pub async fn create_thread(&self, session_id: &str, title: &str) -> Result<ThreadLifecycle> {
        if title.trim().is_empty() {
            bail!("create_thread requires non-empty title");
        }

        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let next_thread_id = {
            runtime.next_thread_id += 1;
            format!("thread_{}", runtime.next_thread_id)
        };
        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;

        if session.state != SessionLifecycleState::Active {
            bail!("cannot create thread unless session is active");
        }

        let now = now_unix_ms();
        let thread = ThreadState {
            thread_id: next_thread_id,
            session_id: session_id.to_string(),
            title: title.to_string(),
            state: ThreadLifecycleState::Idle,
            active_turn_id: None,
            turns: HashMap::new(),
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        let snapshot = snapshot_thread(&thread);
        session.threads.insert(thread.thread_id.clone(), thread);
        session.updated_at_unix_ms = now;
        Ok(snapshot)
    }

    pub async fn list_threads(&self, session_id: &str) -> Result<Vec<ThreadLifecycle>> {
        let runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        let mut threads = session
            .threads
            .values()
            .map(snapshot_thread)
            .collect::<Vec<_>>();
        threads.sort_by(|left, right| left.thread_id.cmp(&right.thread_id));
        Ok(threads)
    }

    pub async fn start_turn(&self, session_id: &str, thread_id: &str) -> Result<TurnLifecycle> {
        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        runtime.next_turn_id += 1;
        let next_turn_id = format!("turn_{}", runtime.next_turn_id);
        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        if session.state != SessionLifecycleState::Active {
            bail!("cannot start turn unless session is active");
        }

        let thread = session
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| anyhow!("thread not found: {thread_id}"))?;
        if thread.state != ThreadLifecycleState::Idle {
            bail!("cannot start turn unless thread is idle");
        }
        if thread.active_turn_id.is_some() {
            bail!("cannot start turn while another turn is active");
        }

        let now = now_unix_ms();
        let turn = TurnState {
            turn_id: next_turn_id.clone(),
            session_id: session_id.to_string(),
            thread_id: thread_id.to_string(),
            state: TurnLifecycleState::Running,
            deltas: Vec::new(),
            output_message_id: None,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        let snapshot = snapshot_turn(&turn);
        thread.turns.insert(next_turn_id.clone(), turn);
        thread.active_turn_id = Some(next_turn_id);
        thread.updated_at_unix_ms = now;
        session.updated_at_unix_ms = now;
        Ok(snapshot)
    }

    pub async fn append_turn_delta(
        &self,
        session_id: &str,
        thread_id: &str,
        turn_id: &str,
        delta: &str,
    ) -> Result<TurnLifecycle> {
        if delta.is_empty() {
            bail!("append_turn_delta requires non-empty delta");
        }

        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        let thread = session
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| anyhow!("thread not found: {thread_id}"))?;
        let turn = thread
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| anyhow!("turn not found: {turn_id}"))?;
        if turn.state != TurnLifecycleState::Running {
            bail!("cannot append delta unless turn is running");
        }

        turn.deltas.push(delta.to_string());
        let now = now_unix_ms();
        turn.updated_at_unix_ms = now;
        thread.updated_at_unix_ms = now;
        session.updated_at_unix_ms = now;
        Ok(snapshot_turn(turn))
    }

    pub async fn complete_turn(
        &self,
        session_id: &str,
        thread_id: &str,
        turn_id: &str,
        output_message_id: &str,
    ) -> Result<TurnLifecycle> {
        if output_message_id.trim().is_empty() {
            bail!("complete_turn requires non-empty output_message_id");
        }

        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        let thread = session
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| anyhow!("thread not found: {thread_id}"))?;
        let turn = thread
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| anyhow!("turn not found: {turn_id}"))?;
        if turn.state != TurnLifecycleState::Running {
            bail!("cannot complete turn unless running");
        }

        turn.state = TurnLifecycleState::Completed;
        turn.output_message_id = Some(output_message_id.to_string());
        let now = now_unix_ms();
        turn.updated_at_unix_ms = now;
        thread.active_turn_id = None;
        thread.updated_at_unix_ms = now;
        session.updated_at_unix_ms = now;
        Ok(snapshot_turn(turn))
    }

    pub async fn interrupt_turn(
        &self,
        session_id: &str,
        thread_id: &str,
        turn_id: &str,
        reason: &str,
    ) -> Result<TurnLifecycle> {
        if reason.trim().is_empty() {
            bail!("interrupt_turn requires non-empty reason");
        }

        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        let thread = session
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| anyhow!("thread not found: {thread_id}"))?;
        let turn = thread
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| anyhow!("turn not found: {turn_id}"))?;
        if turn.state != TurnLifecycleState::Running {
            bail!("cannot interrupt turn unless running");
        }

        turn.state = TurnLifecycleState::Interrupted;
        let now = now_unix_ms();
        turn.updated_at_unix_ms = now;
        thread.active_turn_id = None;
        thread.updated_at_unix_ms = now;
        session.updated_at_unix_ms = now;
        Ok(snapshot_turn(turn))
    }

    pub async fn abort_turn(
        &self,
        session_id: &str,
        thread_id: &str,
        turn_id: &str,
        reason: &str,
    ) -> Result<TurnLifecycle> {
        if reason.trim().is_empty() {
            bail!("abort_turn requires non-empty reason");
        }

        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        let thread = session
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| anyhow!("thread not found: {thread_id}"))?;
        let turn = thread
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| anyhow!("turn not found: {turn_id}"))?;
        if !matches!(
            turn.state,
            TurnLifecycleState::Running | TurnLifecycleState::Interrupted
        ) {
            bail!("cannot abort turn unless running or interrupted");
        }

        turn.state = TurnLifecycleState::Aborted;
        let now = now_unix_ms();
        turn.updated_at_unix_ms = now;
        thread.active_turn_id = None;
        thread.updated_at_unix_ms = now;
        session.updated_at_unix_ms = now;
        Ok(snapshot_turn(turn))
    }

    pub async fn resume_turn_with_replay(
        &self,
        session_id: &str,
        thread_id: &str,
        turn_id: &str,
    ) -> Result<(TurnLifecycle, Vec<RuntimeEvent>)> {
        let mut runtime = self.runtime.lock().await;
        ensure_initialized(&runtime)?;

        let session = runtime
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("session not found: {session_id}"))?;
        if session.state != SessionLifecycleState::Active {
            bail!("cannot resume turn unless session is active");
        }
        let thread = session
            .threads
            .get_mut(thread_id)
            .ok_or_else(|| anyhow!("thread not found: {thread_id}"))?;
        if thread.active_turn_id.is_some() {
            bail!("cannot resume turn while another turn is active");
        }
        let turn = thread
            .turns
            .get_mut(turn_id)
            .ok_or_else(|| anyhow!("turn not found: {turn_id}"))?;
        if turn.state != TurnLifecycleState::Interrupted {
            bail!("cannot resume turn unless interrupted");
        }

        turn.state = TurnLifecycleState::Running;
        let now = now_unix_ms();
        turn.updated_at_unix_ms = now;
        thread.active_turn_id = Some(turn_id.to_string());
        thread.updated_at_unix_ms = now;
        session.updated_at_unix_ms = now;

        let mut replay = Vec::with_capacity(turn.deltas.len() + 1);
        replay.push(RuntimeEvent::TurnStarted {
            session_id: session_id.to_string(),
            thread_id: thread_id.to_string(),
            turn_id: turn_id.to_string(),
        });
        replay.extend(
            turn.deltas
                .iter()
                .cloned()
                .map(|delta| RuntimeEvent::TurnOutputDelta {
                    session_id: session_id.to_string(),
                    thread_id: thread_id.to_string(),
                    turn_id: turn_id.to_string(),
                    delta,
                }),
        );

        Ok((snapshot_turn(turn), replay))
    }

    pub fn map_server_event(event: CodexServerEvent) -> RuntimeEvent {
        match event {
            CodexServerEvent::TurnStarted {
                session_id,
                thread_id,
                turn_id,
            } => RuntimeEvent::TurnStarted {
                session_id,
                thread_id,
                turn_id,
            },
            CodexServerEvent::TurnDelta {
                session_id,
                thread_id,
                turn_id,
                delta,
            } => RuntimeEvent::TurnOutputDelta {
                session_id,
                thread_id,
                turn_id,
                delta,
            },
            CodexServerEvent::TurnCompleted {
                session_id,
                thread_id,
                turn_id,
                output_message_id,
            } => RuntimeEvent::TurnCompleted {
                session_id,
                thread_id,
                turn_id,
                output_message_id,
            },
            CodexServerEvent::TurnInterrupted {
                session_id,
                thread_id,
                turn_id,
                reason,
            } => RuntimeEvent::TurnInterrupted {
                session_id,
                thread_id,
                turn_id,
                reason,
            },
            CodexServerEvent::TurnAborted {
                session_id,
                thread_id,
                turn_id,
                reason,
            } => RuntimeEvent::TurnAborted {
                session_id,
                thread_id,
                turn_id,
                reason,
            },
            CodexServerEvent::ApprovalRequired {
                session_id,
                thread_id,
                turn_id,
                approval_id,
                action,
            } => RuntimeEvent::ActionApprovalRequired {
                session_id,
                thread_id,
                turn_id,
                approval_id,
                action,
            },
        }
    }
}

fn ensure_supported_scheme(endpoint: &Url) -> Result<()> {
    match endpoint.scheme() {
        "http" | "https" | "ws" | "wss" => Ok(()),
        other => bail!("unsupported endpoint scheme: {other}"),
    }
}

fn endpoint_socket_address(endpoint: &Url) -> Result<String> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow!("endpoint is missing a host"))?;

    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| anyhow!("endpoint is missing a port and no default is known"))?;

    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn ensure_initialized(runtime: &RuntimeStore) -> Result<()> {
    if runtime.initialized.is_none() {
        bail!("client must be initialized before lifecycle operations");
    }
    Ok(())
}

fn snapshot_session(session: &SessionState) -> SessionLifecycle {
    SessionLifecycle {
        session_id: session.session_id.clone(),
        user_id: session.user_id.clone(),
        state: session.state.clone(),
        created_at_unix_ms: session.created_at_unix_ms,
        updated_at_unix_ms: session.updated_at_unix_ms,
    }
}

fn snapshot_thread(thread: &ThreadState) -> ThreadLifecycle {
    ThreadLifecycle {
        thread_id: thread.thread_id.clone(),
        session_id: thread.session_id.clone(),
        title: thread.title.clone(),
        state: thread.state.clone(),
        created_at_unix_ms: thread.created_at_unix_ms,
        updated_at_unix_ms: thread.updated_at_unix_ms,
    }
}

fn snapshot_turn(turn: &TurnState) -> TurnLifecycle {
    TurnLifecycle {
        turn_id: turn.turn_id.clone(),
        session_id: turn.session_id.clone(),
        thread_id: turn.thread_id.clone(),
        state: turn.state.clone(),
        delta_count: turn.deltas.len(),
        output_message_id: turn.output_message_id.clone(),
        created_at_unix_ms: turn.created_at_unix_ms,
        updated_at_unix_ms: turn.updated_at_unix_ms,
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_smoke_reaches_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        let endpoint = format!("http://{addr}");
        let client = CodexAppServerClient::new(&endpoint).unwrap();
        let result = client.connect_smoke().await;

        accept_task.await.unwrap();

        assert!(result.is_ok());
        assert_eq!(result.unwrap().endpoint, format!("{endpoint}/"));
    }

    #[test]
    fn rejects_unsupported_scheme() {
        let error = CodexAppServerClient::new("ftp://127.0.0.1:8080").unwrap_err();
        assert!(error.to_string().contains("unsupported endpoint scheme"));
    }

    #[tokio::test]
    async fn lifecycle_operations_require_initialize() {
        let client = CodexAppServerClient::new("http://127.0.0.1:3030").unwrap();
        let error = client.create_session("user_github").await.unwrap_err();
        assert!(error.to_string().contains("must be initialized"));
    }

    #[tokio::test]
    async fn initialize_is_idempotent_for_same_protocol() {
        let client = CodexAppServerClient::new("http://127.0.0.1:3030").unwrap();
        let first = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "2026-02-14".to_string(),
            })
            .await
            .unwrap();
        let second = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "2026-02-14".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn initialize_rejects_protocol_drift() {
        let client = CodexAppServerClient::new("http://127.0.0.1:3030").unwrap();
        let _ = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "v1".to_string(),
            })
            .await
            .unwrap();
        let error = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "v2".to_string(),
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("protocol version mismatch"));
    }

    #[tokio::test]
    async fn session_and_thread_lifecycle_support_interrupt_and_resume() {
        let client = CodexAppServerClient::new("http://127.0.0.1:3030").unwrap();
        let _ = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "v1".to_string(),
            })
            .await
            .unwrap();

        let session = client.create_session("user_github").await.unwrap();
        assert_eq!(session.state, SessionLifecycleState::Active);

        let thread = client
            .create_thread(&session.session_id, "main")
            .await
            .unwrap();
        assert_eq!(thread.state, ThreadLifecycleState::Idle);

        let interrupted = client.interrupt_session(&session.session_id).await.unwrap();
        assert_eq!(interrupted.state, SessionLifecycleState::Interrupted);

        let blocked_thread = client.create_thread(&session.session_id, "blocked").await;
        assert!(blocked_thread.is_err());

        let resumed = client.resume_session(&session.session_id).await.unwrap();
        assert_eq!(resumed.state, SessionLifecycleState::Active);

        let resumed_thread = client
            .create_thread(&session.session_id, "after-resume")
            .await;
        assert!(resumed_thread.is_ok());
    }

    #[tokio::test]
    async fn closing_session_closes_existing_threads() {
        let client = CodexAppServerClient::new("http://127.0.0.1:3030").unwrap();
        let _ = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "v1".to_string(),
            })
            .await
            .unwrap();

        let session = client.create_session("user_github").await.unwrap();
        let _ = client
            .create_thread(&session.session_id, "thread-1")
            .await
            .unwrap();
        let _ = client
            .create_thread(&session.session_id, "thread-2")
            .await
            .unwrap();

        let closed = client.close_session(&session.session_id).await.unwrap();
        assert_eq!(closed.state, SessionLifecycleState::Closed);

        let threads = client.list_threads(&session.session_id).await.unwrap();
        assert_eq!(threads.len(), 2);
        assert!(
            threads
                .iter()
                .all(|thread| thread.state == ThreadLifecycleState::Closed)
        );
    }

    #[tokio::test]
    async fn turn_interrupt_resume_replay_and_abort_semantics_are_deterministic() {
        let client = CodexAppServerClient::new("http://127.0.0.1:3030").unwrap();
        let _ = client
            .initialize(InitializeRequest {
                client_name: "crabbot-daemon".to_string(),
                protocol_version: "v1".to_string(),
            })
            .await
            .unwrap();

        let session = client.create_session("user_github").await.unwrap();
        let thread = client
            .create_thread(&session.session_id, "turn-thread")
            .await
            .unwrap();

        let turn = client
            .start_turn(&session.session_id, &thread.thread_id)
            .await
            .unwrap();
        assert_eq!(turn.state, TurnLifecycleState::Running);

        let duplicate_active = client
            .start_turn(&session.session_id, &thread.thread_id)
            .await;
        assert!(duplicate_active.is_err());

        let _ = client
            .append_turn_delta(
                &session.session_id,
                &thread.thread_id,
                &turn.turn_id,
                "hello ",
            )
            .await
            .unwrap();
        let _ = client
            .append_turn_delta(
                &session.session_id,
                &thread.thread_id,
                &turn.turn_id,
                "world",
            )
            .await
            .unwrap();

        let interrupted = client
            .interrupt_turn(
                &session.session_id,
                &thread.thread_id,
                &turn.turn_id,
                "user_interrupt",
            )
            .await
            .unwrap();
        assert_eq!(interrupted.state, TurnLifecycleState::Interrupted);

        let (resumed, replay) = client
            .resume_turn_with_replay(&session.session_id, &thread.thread_id, &turn.turn_id)
            .await
            .unwrap();
        assert_eq!(resumed.state, TurnLifecycleState::Running);
        assert_eq!(replay.len(), 3);
        assert!(matches!(replay[0], RuntimeEvent::TurnStarted { .. }));
        assert!(matches!(replay[1], RuntimeEvent::TurnOutputDelta { .. }));
        assert!(matches!(replay[2], RuntimeEvent::TurnOutputDelta { .. }));

        let completed = client
            .complete_turn(
                &session.session_id,
                &thread.thread_id,
                &turn.turn_id,
                "msg_output_1",
            )
            .await
            .unwrap();
        assert_eq!(completed.state, TurnLifecycleState::Completed);
        assert_eq!(completed.output_message_id.as_deref(), Some("msg_output_1"));

        let turn_2 = client
            .start_turn(&session.session_id, &thread.thread_id)
            .await
            .unwrap();
        let aborted = client
            .abort_turn(
                &session.session_id,
                &thread.thread_id,
                &turn_2.turn_id,
                "manual_abort",
            )
            .await
            .unwrap();
        assert_eq!(aborted.state, TurnLifecycleState::Aborted);
    }

    #[test]
    fn maps_server_events_to_runtime_events_deterministically() {
        let started = CodexAppServerClient::map_server_event(CodexServerEvent::TurnStarted {
            session_id: "sess_1".to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: "turn_1".to_string(),
        });
        assert_eq!(
            started,
            RuntimeEvent::TurnStarted {
                session_id: "sess_1".to_string(),
                thread_id: "thread_1".to_string(),
                turn_id: "turn_1".to_string(),
            }
        );

        let approval = CodexAppServerClient::map_server_event(CodexServerEvent::ApprovalRequired {
            session_id: "sess_1".to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: "turn_1".to_string(),
            approval_id: "approval_1".to_string(),
            action: "run_command".to_string(),
        });
        assert_eq!(
            approval,
            RuntimeEvent::ActionApprovalRequired {
                session_id: "sess_1".to_string(),
                thread_id: "thread_1".to_string(),
                turn_id: "turn_1".to_string(),
                approval_id: "approval_1".to_string(),
                action: "run_command".to_string(),
            }
        );

        let aborted = CodexAppServerClient::map_server_event(CodexServerEvent::TurnAborted {
            session_id: "sess_1".to_string(),
            thread_id: "thread_1".to_string(),
            turn_id: "turn_1".to_string(),
            reason: "manual_abort".to_string(),
        });
        assert_eq!(
            aborted,
            RuntimeEvent::TurnAborted {
                session_id: "sess_1".to_string(),
                thread_id: "thread_1".to_string(),
                turn_id: "turn_1".to_string(),
                reason: "manual_abort".to_string(),
            }
        );
    }
}
