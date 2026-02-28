use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use crabbot_protocol::DaemonPromptResponse;
use crabbot_protocol::DaemonRpcNotification;
use crabbot_protocol::DaemonRpcRequestResponse;
use crabbot_protocol::DaemonRpcServerRequest;
use crabbot_protocol::DaemonRpcStreamEnvelope;
use crabbot_protocol::DaemonRpcStreamEvent;
use crabbot_protocol::DaemonStreamEnvelope;
use crabbot_protocol::DaemonStreamEvent;
use crossterm::event::DisableBracketedPaste;
use crossterm::event::EnableBracketedPaste;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use crossterm::event::KeyEventKind;
use crossterm::event::KeyModifiers;
use crossterm::event::{self};
use crossterm::execute;
use crossterm::terminal::EnterAlternateScreen;
use crossterm::terminal::LeaveAlternateScreen;
use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Constraint;
use ratatui::layout::Direction;
use ratatui::layout::Layout;
use ratatui::style::Color;
use ratatui::style::Style;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::env;
use std::io::IsTerminal;
use std::io::{self};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::Instant;
use tungstenite::Error as WsError;
use tungstenite::Message as WsMessage;
use tungstenite::WebSocket;
use tungstenite::client::IntoClientRequest;
use tungstenite::connect;
use tungstenite::stream::MaybeTlsStream;
use url::Url;

extern crate self as codex_ansi_escape;
extern crate self as codex_app_server_protocol;
extern crate self as codex_backend_client;
extern crate self as codex_chatgpt;
extern crate self as codex_core;
extern crate self as codex_feedback;
extern crate self as codex_otel;
extern crate self as codex_utils_absolute_path;
extern crate self as codex_utils_approval_presets;
extern crate self as codex_utils_cli;
extern crate self as codex_utils_elapsed;
extern crate self as codex_utils_sandbox_summary;
extern crate self as codex_utils_sleep_inhibitor;
extern crate self as codex_utils_string;
extern crate self as rmcp;

const LEGACY_NOTIFICATIONS_TO_OPT_OUT: &[&str] = &[
    "codex/event",
    "codex/event/session_configured",
    "codex/event/task_started",
    "codex/event/task_complete",
    "codex/event/turn_started",
    "codex/event/turn_complete",
    "codex/event/raw_response_item",
    "codex/event/agent_message_content_delta",
    "codex/event/agent_message_delta",
    "codex/event/agent_reasoning_delta",
    "codex/event/reasoning_content_delta",
    "codex/event/reasoning_raw_content_delta",
    "codex/event/exec_command_output_delta",
    "codex/event/exec_approval_request",
    "codex/event/exec_command_begin",
    "codex/event/exec_command_end",
    "codex/event/exec_output",
    "codex/event/item_started",
    "codex/event/item_completed",
];

#[derive(Debug, Clone, Default)]
pub struct Client;

impl Client {
    pub fn from_auth(
        _base_url: impl Into<String>,
        _auth: &crate::CodexAuth,
    ) -> anyhow::Result<Self> {
        Ok(Self)
    }

    pub async fn get_rate_limits_many(
        &self,
    ) -> anyhow::Result<Vec<crate::protocol::RateLimitSnapshot>> {
        let backend = get_shim_backend_config();
        let response = app_server_rpc_request(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "account/rateLimits/read",
            json!({}),
        )?;
        Ok(parse_rate_limit_snapshots_from_result(&response.result))
    }
}

fn parse_rate_limit_snapshots_from_result(
    value: &serde_json::Value,
) -> Vec<crate::protocol::RateLimitSnapshot> {
    let mut snapshots = Vec::new();

    if let Some(map) = value
        .get("rateLimitsByLimitId")
        .or_else(|| value.get("rate_limits_by_limit_id"))
        .and_then(serde_json::Value::as_object)
    {
        for snapshot in map.values() {
            if let Some(parsed) = parse_rate_limit_snapshot_value(snapshot) {
                snapshots.push(parsed);
            }
        }
        return snapshots;
    }

    if let Some(array) = value
        .get("rateLimits")
        .or_else(|| value.get("rate_limits"))
        .and_then(serde_json::Value::as_array)
    {
        for snapshot in array {
            if let Some(parsed) = parse_rate_limit_snapshot_value(snapshot) {
                snapshots.push(parsed);
            }
        }
    }

    snapshots
}

fn parse_rate_limit_snapshot_value(
    value: &serde_json::Value,
) -> Option<crate::protocol::RateLimitSnapshot> {
    let primary = parse_rate_limit_window_value(
        value
            .get("primary")
            .or_else(|| value.get("primaryWindow"))
            .or_else(|| value.get("primary_window")),
    );
    let secondary = parse_rate_limit_window_value(
        value
            .get("secondary")
            .or_else(|| value.get("secondaryWindow"))
            .or_else(|| value.get("secondary_window")),
    );
    let credits = value
        .get("credits")
        .map(|credits| crate::protocol::CreditsSnapshot {
            has_credits: credits
                .get("hasCredits")
                .or_else(|| credits.get("has_credits"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            unlimited: credits
                .get("unlimited")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            balance: credits
                .get("balance")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
        });

    Some(crate::protocol::RateLimitSnapshot {
        limit_id: value
            .get("limitId")
            .or_else(|| value.get("limit_id"))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        limit_name: value
            .get("limitName")
            .or_else(|| value.get("limit_name"))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string),
        primary,
        secondary,
        credits,
        plan_type: value
            .get("planType")
            .or_else(|| value.get("plan_type"))
            .cloned()
            .and_then(|raw| serde_json::from_value(raw).ok()),
    })
}

fn parse_rate_limit_window_value(
    value: Option<&serde_json::Value>,
) -> Option<crate::protocol::RateLimitWindow> {
    let window = value?;
    let used_percent = window
        .get("usedPercent")
        .or_else(|| window.get("used_percent"))
        .and_then(serde_json::Value::as_f64)?;
    let window_minutes = window
        .get("windowMinutes")
        .or_else(|| window.get("window_minutes"))
        .or_else(|| window.get("windowDurationMins"))
        .or_else(|| window.get("window_duration_mins"))
        .and_then(serde_json::Value::as_i64)
        .or_else(|| {
            window
                .get("limitWindowSeconds")
                .or_else(|| window.get("limit_window_seconds"))
                .and_then(serde_json::Value::as_i64)
                .map(|seconds| seconds / 60)
        });

    Some(crate::protocol::RateLimitWindow {
        used_percent,
        resets_at: window
            .get("resetsAt")
            .or_else(|| window.get("resets_at"))
            .or_else(|| window.get("resetAt"))
            .or_else(|| window.get("reset_at"))
            .and_then(serde_json::Value::as_i64),
        window_minutes,
    })
}

#[cfg(test)]
mod tests {
    use super::CodexThread;
    use super::CodexThreadState;
    use super::ThreadConfigSnapshot;
    use super::parse_rate_limit_snapshots_from_result;
    use crate::ThreadId;
    use crate::protocol::AgentMessageEvent;
    use crate::protocol::AskForApproval;
    use crate::protocol::Event;
    use crate::protocol::EventMsg;
    use crate::protocol::SandboxPolicy;
    use crate::protocol::SessionSource;
    use crate::protocol::TurnCompleteEvent;
    use crate::protocol::TurnStartedEvent;
    use codex_protocol::config_types::ModeKind;
    use serde_json::json;
    use std::collections::HashMap;
    use std::collections::VecDeque;

    #[test]
    fn parse_rate_limit_snapshots_ignores_empty_secondary_window() {
        let result = json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "primary": {
                        "usedPercent": 64.0,
                        "windowMinutes": 10080,
                        "resetsAt": 1_708_000_000
                    },
                    "secondary": {}
                }
            }
        });

        let snapshots = parse_rate_limit_snapshots_from_result(&result);
        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert!(snapshot.primary.is_some());
        assert!(snapshot.secondary.is_none());
    }

    #[test]
    fn parse_rate_limit_snapshots_accepts_window_aliases() {
        let result = json!({
            "rateLimitsByLimitId": {
                "codex": {
                    "limitId": "codex",
                    "primaryWindow": {
                        "usedPercent": 64.0,
                        "windowDurationMins": 10080,
                        "resetAt": 1_708_000_000
                    },
                    "secondary_window": {
                        "usedPercent": 12.0,
                        "limitWindowSeconds": 18_000,
                        "resetsAt": 1_708_000_001
                    }
                }
            }
        });

        let snapshots = parse_rate_limit_snapshots_from_result(&result);
        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert_eq!(
            snapshot.primary.as_ref().and_then(|w| w.window_minutes),
            Some(10080)
        );
        assert_eq!(
            snapshot.secondary.as_ref().and_then(|w| w.window_minutes),
            Some(300)
        );
    }

    fn make_thread_state_for_event_queue_tests() -> CodexThreadState {
        CodexThreadState {
            thread_id: ThreadId::new(),
            app_server_endpoint: String::new(),
            auth_token: None,
            last_sequence: 0,
            next_submission_id: 1,
            current_turn_id: None,
            last_agent_message_in_turn: None,
            pending_events: VecDeque::new(),
            pending_server_requests: HashMap::new(),
            pending_request_user_input_by_turn_id: HashMap::new(),
            config_snapshot: ThreadConfigSnapshot {
                model: "test".to_string(),
                model_provider_id: "openai".to_string(),
                approval_policy: AskForApproval::OnRequest,
                sandbox_policy: SandboxPolicy::new_workspace_write_policy(),
                cwd: std::env::temp_dir(),
                reasoning_effort: None,
                session_source: SessionSource::Cli,
            },
            rollout_path: None,
        }
    }

    #[test]
    fn enqueue_pending_event_dedupes_identical_agent_message_in_turn() {
        let mut state = make_thread_state_for_event_queue_tests();
        let turn_id = "turn-1".to_string();

        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "1".to_string(),
                msg: EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: turn_id.clone(),
                    model_context_window: None,
                    collaboration_mode_kind: ModeKind::Default,
                }),
            },
        );
        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "2".to_string(),
                msg: EventMsg::AgentMessage(AgentMessageEvent {
                    message: "Same final message".to_string(),
                    phase: None,
                }),
            },
        );
        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "3".to_string(),
                msg: EventMsg::AgentMessage(AgentMessageEvent {
                    message: "Same final message".to_string(),
                    phase: None,
                }),
            },
        );
        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "4".to_string(),
                msg: EventMsg::TurnComplete(TurnCompleteEvent {
                    turn_id,
                    last_agent_message: None,
                }),
            },
        );

        let agent_messages = state
            .pending_events
            .iter()
            .filter(|event| matches!(event.msg, EventMsg::AgentMessage(_)))
            .count();
        assert_eq!(agent_messages, 1);
    }

    #[test]
    fn enqueue_pending_event_preserves_distinct_agent_messages() {
        let mut state = make_thread_state_for_event_queue_tests();

        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "1".to_string(),
                msg: EventMsg::TurnStarted(TurnStartedEvent {
                    turn_id: "turn-1".to_string(),
                    model_context_window: None,
                    collaboration_mode_kind: ModeKind::Default,
                }),
            },
        );
        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "2".to_string(),
                msg: EventMsg::AgentMessage(AgentMessageEvent {
                    message: "First message".to_string(),
                    phase: None,
                }),
            },
        );
        CodexThread::enqueue_pending_event(
            &mut state,
            Event {
                id: "3".to_string(),
                msg: EventMsg::AgentMessage(AgentMessageEvent {
                    message: "Second message".to_string(),
                    phase: None,
                }),
            },
        );

        let agent_messages = state
            .pending_events
            .iter()
            .filter(|event| matches!(event.msg, EventMsg::AgentMessage(_)))
            .count();
        assert_eq!(agent_messages, 2);
    }
}

pub mod config {
    use crate::WireApi;
    use codex_protocol::config_types::TrustLevel;
    use std::collections::BTreeMap;
    use std::io::ErrorKind;
    use std::path::Path;
    use std::path::PathBuf;

    pub mod types {
        use serde::Deserialize;
        use serde::Deserializer;
        use serde::Serialize;
        use serde::de::Error as SerdeError;
        use std::collections::BTreeMap;
        use std::collections::HashMap;
        use std::path::PathBuf;
        use std::time::Duration;

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
        #[serde(rename_all = "lowercase")]
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

        #[derive(Debug, Clone, Default)]
        pub struct ModelAvailabilityNuxConfig {
            pub shown_count: BTreeMap<String, u32>,
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(untagged, deny_unknown_fields, rename_all = "snake_case")]
        pub enum McpServerTransportConfig {
            Stdio {
                command: String,
                #[serde(default)]
                args: Vec<String>,
                #[serde(default)]
                env: Option<HashMap<String, String>>,
                #[serde(default)]
                env_vars: Vec<String>,
                #[serde(default)]
                cwd: Option<PathBuf>,
            },
            StreamableHttp {
                url: String,
                #[serde(default)]
                bearer_token_env_var: Option<String>,
                #[serde(default)]
                http_headers: Option<HashMap<String, String>>,
                #[serde(default)]
                env_http_headers: Option<HashMap<String, String>>,
            },
        }

        #[derive(Debug, Clone, Serialize)]
        pub struct McpServerConfig {
            #[serde(flatten)]
            pub transport: McpServerTransportConfig,
            #[serde(default = "enabled_default")]
            pub enabled: bool,
            #[serde(default)]
            pub required: bool,
            #[serde(default)]
            pub disabled_reason: Option<String>,
            #[serde(default, with = "option_duration_secs")]
            pub startup_timeout_sec: Option<Duration>,
            #[serde(default, with = "option_duration_secs")]
            pub tool_timeout_sec: Option<Duration>,
            #[serde(default)]
            pub enabled_tools: Option<Vec<String>>,
            #[serde(default)]
            pub disabled_tools: Option<Vec<String>>,
            #[serde(default)]
            pub scopes: Option<Vec<String>>,
        }

        #[derive(Debug, Deserialize, Clone)]
        #[serde(deny_unknown_fields)]
        struct RawMcpServerConfig {
            pub command: Option<String>,
            #[serde(default)]
            pub args: Option<Vec<String>>,
            #[serde(default)]
            pub env: Option<HashMap<String, String>>,
            #[serde(default)]
            pub env_vars: Option<Vec<String>>,
            #[serde(default)]
            pub cwd: Option<PathBuf>,
            #[serde(default)]
            pub http_headers: Option<HashMap<String, String>>,
            #[serde(default)]
            pub env_http_headers: Option<HashMap<String, String>>,
            pub url: Option<String>,
            pub bearer_token: Option<String>,
            pub bearer_token_env_var: Option<String>,
            #[serde(default)]
            pub startup_timeout_sec: Option<f64>,
            #[serde(default)]
            pub startup_timeout_ms: Option<u64>,
            #[serde(default, with = "option_duration_secs")]
            pub tool_timeout_sec: Option<Duration>,
            #[serde(default)]
            pub enabled: Option<bool>,
            #[serde(default)]
            pub required: Option<bool>,
            #[serde(default)]
            pub enabled_tools: Option<Vec<String>>,
            #[serde(default)]
            pub disabled_tools: Option<Vec<String>>,
            #[serde(default)]
            pub scopes: Option<Vec<String>>,
        }

        impl<'de> Deserialize<'de> for McpServerConfig {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let mut raw = RawMcpServerConfig::deserialize(deserializer)?;

                let startup_timeout_sec = match (raw.startup_timeout_sec, raw.startup_timeout_ms) {
                    (Some(sec), _) => {
                        let duration =
                            Duration::try_from_secs_f64(sec).map_err(SerdeError::custom)?;
                        Some(duration)
                    }
                    (None, Some(ms)) => Some(Duration::from_millis(ms)),
                    (None, None) => None,
                };

                fn throw_if_set<E, T>(
                    transport: &str,
                    field: &str,
                    value: Option<&T>,
                ) -> Result<(), E>
                where
                    E: SerdeError,
                {
                    if value.is_none() {
                        return Ok(());
                    }
                    Err(E::custom(format!(
                        "{field} is not supported for {transport}"
                    )))
                }

                let transport = if let Some(command) = raw.command.clone() {
                    throw_if_set("stdio", "url", raw.url.as_ref())?;
                    throw_if_set(
                        "stdio",
                        "bearer_token_env_var",
                        raw.bearer_token_env_var.as_ref(),
                    )?;
                    throw_if_set("stdio", "bearer_token", raw.bearer_token.as_ref())?;
                    throw_if_set("stdio", "http_headers", raw.http_headers.as_ref())?;
                    throw_if_set("stdio", "env_http_headers", raw.env_http_headers.as_ref())?;
                    McpServerTransportConfig::Stdio {
                        command,
                        args: raw.args.clone().unwrap_or_default(),
                        env: raw.env.clone(),
                        env_vars: raw.env_vars.clone().unwrap_or_default(),
                        cwd: raw.cwd.take(),
                    }
                } else if let Some(url) = raw.url.clone() {
                    throw_if_set("streamable_http", "args", raw.args.as_ref())?;
                    throw_if_set("streamable_http", "env", raw.env.as_ref())?;
                    throw_if_set("streamable_http", "env_vars", raw.env_vars.as_ref())?;
                    throw_if_set("streamable_http", "cwd", raw.cwd.as_ref())?;
                    throw_if_set("streamable_http", "bearer_token", raw.bearer_token.as_ref())?;
                    McpServerTransportConfig::StreamableHttp {
                        url,
                        bearer_token_env_var: raw.bearer_token_env_var.clone(),
                        http_headers: raw.http_headers.take(),
                        env_http_headers: raw.env_http_headers.take(),
                    }
                } else {
                    return Err(SerdeError::custom("invalid transport"));
                };

                Ok(Self {
                    transport,
                    enabled: raw.enabled.unwrap_or_else(enabled_default),
                    required: raw.required.unwrap_or_default(),
                    disabled_reason: None,
                    startup_timeout_sec,
                    tool_timeout_sec: raw.tool_timeout_sec,
                    enabled_tools: raw.enabled_tools,
                    disabled_tools: raw.disabled_tools,
                    scopes: raw.scopes,
                })
            }
        }

        fn enabled_default() -> bool {
            true
        }

        impl Default for McpServerTransportConfig {
            fn default() -> Self {
                Self::Stdio {
                    command: String::new(),
                    args: Vec::new(),
                    env: None,
                    env_vars: Vec::new(),
                    cwd: None,
                }
            }
        }

        impl Default for McpServerConfig {
            fn default() -> Self {
                Self {
                    transport: McpServerTransportConfig::default(),
                    enabled: enabled_default(),
                    required: false,
                    disabled_reason: None,
                    startup_timeout_sec: None,
                    tool_timeout_sec: None,
                    enabled_tools: None,
                    disabled_tools: None,
                    scopes: None,
                }
            }
        }

        mod option_duration_secs {
            use serde::Deserialize;
            use serde::Deserializer;
            use serde::Serializer;
            use std::time::Duration;

            pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                match value {
                    Some(duration) => serializer.serialize_some(&duration.as_secs_f64()),
                    None => serializer.serialize_none(),
                }
            }

            pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
            where
                D: Deserializer<'de>,
            {
                let secs = Option::<f64>::deserialize(deserializer)?;
                secs.map(|sec| Duration::try_from_secs_f64(sec).map_err(serde::de::Error::custom))
                    .transpose()
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum Notifications {
            Enabled(bool),
            Custom(Vec<String>),
        }

        impl Default for Notifications {
            fn default() -> Self {
                Self::Enabled(true)
            }
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum WindowsSandboxModeToml {
            Legacy,
            Elevated,
        }
    }

    pub type ReasoningSummary = codex_protocol::config_types::ReasoningSummary;

    pub type ConstraintResult<T> = std::result::Result<T, String>;

    #[derive(Debug, Clone, PartialEq)]
    pub struct ValueRef<T>(pub T);

    impl<T> ValueRef<T> {
        pub fn allow_only(value: T) -> Self {
            Self(value)
        }
        pub fn get(&self) -> &T {
            &self.0
        }
        pub fn value(&self) -> T
        where
            T: Clone,
        {
            self.0.clone()
        }
        pub fn set(&mut self, value: T) -> ConstraintResult<()> {
            self.0 = value;
            Ok(())
        }
        pub fn can_set(&self, _value: &T) -> ConstraintResult<()> {
            Ok(())
        }
    }

    pub type Constrained<T> = ValueRef<T>;

    #[derive(Debug, Clone)]
    pub struct NetworkProxySpec {
        pub socks_enabled: bool,
    }

    impl NetworkProxySpec {
        pub fn socks_enabled(&self) -> bool {
            self.socks_enabled
        }
    }

    #[derive(Debug, Clone)]
    pub struct OtelConfig {
        pub log_user_prompt: bool,
    }

    impl Default for OtelConfig {
        fn default() -> Self {
            Self {
                log_user_prompt: false,
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct Permissions {
        pub approval_policy: ValueRef<crate::protocol::AskForApproval>,
        pub sandbox_policy: ValueRef<crate::protocol::SandboxPolicy>,
        pub network: Option<NetworkProxySpec>,
        pub windows_sandbox_mode: Option<types::WindowsSandboxModeToml>,
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct McpServers(pub BTreeMap<String, types::McpServerConfig>);

    impl McpServers {
        pub fn iter(
            &self,
        ) -> std::collections::btree_map::Iter<'_, String, types::McpServerConfig> {
            self.0.iter()
        }

        pub fn get(&self) -> &BTreeMap<String, types::McpServerConfig> {
            &self.0
        }
        pub fn set(&mut self, map: BTreeMap<String, types::McpServerConfig>) {
            self.0 = map;
        }
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }

    impl Default for McpServers {
        fn default() -> Self {
            Self(BTreeMap::new())
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct Notices {
        pub hide_full_access_warning: Option<bool>,
        pub hide_world_writable_warning: Option<bool>,
        pub hide_rate_limit_model_nudge: Option<bool>,
        pub hide_gpt5_1_migration_prompt: Option<bool>,
        pub hide_gpt_5_1_codex_max_migration_prompt: Option<bool>,
        pub model_migrations: std::collections::BTreeMap<String, String>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct RealtimeAudioConfig {
        pub microphone: Option<String>,
        pub speaker: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct Config {
        pub codex_home: std::path::PathBuf,
        pub cwd: PathBuf,
        pub model: Option<String>,
        pub model_catalog: Option<serde_json::Value>,
        pub model_provider_id: String,
        pub model_provider: ConfigModelProvider,
        pub permissions: Permissions,
        pub model_reasoning_summary: Option<ReasoningSummary>,
        pub model_availability_nux: types::ModelAvailabilityNuxConfig,
        pub model_reasoning_effort: Option<crate::openai_models::ReasoningEffort>,
        pub plan_mode_reasoning_effort: Option<crate::openai_models::ReasoningEffort>,
        pub model_context_window: Option<i64>,
        pub review_model: Option<String>,
        pub model_auto_compact_token_limit: Option<i64>,
        pub startup_warnings: Vec<String>,
        pub did_user_set_custom_approval_policy_or_sandbox_mode: bool,
        pub hide_agent_reasoning: bool,
        pub show_raw_agent_reasoning: bool,
        pub user_instructions: Option<String>,
        pub base_instructions: Option<String>,
        pub developer_instructions: Option<String>,
        pub compact_prompt: Option<String>,
        pub commit_attribution: Option<String>,
        pub notify: Option<Vec<String>>,
        pub animations: bool,
        pub show_tooltips: bool,
        pub disable_paste_burst: bool,
        pub feedback_enabled: bool,
        pub mcp_servers: McpServers,
        pub model_supports_reasoning_summaries: Option<bool>,
        pub features: crate::features::Features,
        pub notices: Notices,
        pub personality: Option<crate::config_types::Personality>,
        pub tui_notifications: types::Notifications,
        pub tui_alternate_screen: codex_protocol::config_types::AltScreenMode,
        pub tui_status_line: Option<Vec<String>>,
        pub tui_theme: Option<String>,
        pub realtime_audio: RealtimeAudioConfig,
        pub config_layer_stack: crate::config_loader::ConfigLayerStack,
        pub tui_notification_method: types::NotificationMethod,
        pub cli_auth_credentials_store_mode: crate::auth::AuthCredentialsStoreMode,
        pub otel: OtelConfig,
        pub chatgpt_base_url: String,
    }

    #[derive(Debug, Clone)]
    pub struct ConfigModelProvider {
        pub name: String,
        pub env_key: Option<String>,
        pub wire_api: WireApi,
        pub base_url: Option<String>,
        pub requires_openai_auth: bool,
    }

    impl Default for ConfigModelProvider {
        fn default() -> Self {
            Self {
                name: "openai".to_string(),
                env_key: None,
                wire_api: WireApi::Responses,
                base_url: None,
                requires_openai_auth: true,
            }
        }
    }

    impl ConfigModelProvider {
        pub fn is_openai(&self) -> bool {
            self.name.eq_ignore_ascii_case("openai")
        }
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                codex_home: std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()),
                cwd: std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()),
                model: None,
                model_catalog: None,
                model_provider_id: "openai".to_string(),
                model_provider: ConfigModelProvider::default(),
                permissions: Permissions {
                    approval_policy: ValueRef(crate::protocol::AskForApproval::OnRequest),
                    sandbox_policy: ValueRef(
                        crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                    ),
                    network: None,
                    windows_sandbox_mode: None,
                },
                model_reasoning_summary: Some(ReasoningSummary::Auto),
                model_availability_nux: types::ModelAvailabilityNuxConfig::default(),
                model_reasoning_effort: None,
                plan_mode_reasoning_effort: None,
                model_context_window: None,
                review_model: None,
                model_auto_compact_token_limit: None,
                startup_warnings: Vec::new(),
                did_user_set_custom_approval_policy_or_sandbox_mode: false,
                hide_agent_reasoning: false,
                show_raw_agent_reasoning: false,
                user_instructions: None,
                base_instructions: None,
                developer_instructions: None,
                compact_prompt: None,
                commit_attribution: None,
                notify: None,
                animations: true,
                show_tooltips: true,
                disable_paste_burst: false,
                feedback_enabled: true,
                mcp_servers: McpServers::default(),
                model_supports_reasoning_summaries: None,
                features: crate::features::Features::with_defaults(),
                notices: Notices::default(),
                personality: None,
                tui_notifications: types::Notifications::default(),
                tui_alternate_screen: codex_protocol::config_types::AltScreenMode::default(),
                tui_status_line: None,
                tui_theme: None,
                realtime_audio: RealtimeAudioConfig::default(),
                config_layer_stack: crate::config_loader::ConfigLayerStack::default(),
                tui_notification_method: types::NotificationMethod::Auto,
                cli_auth_credentials_store_mode: crate::auth::AuthCredentialsStoreMode::Plaintext,
                otel: OtelConfig::default(),
                chatgpt_base_url: "https://chatgpt.com".to_string(),
            }
        }
    }

    impl Config {
        pub fn set_windows_sandbox_enabled(&mut self, enabled: bool) {
            if enabled {
                self.features
                    .enable(crate::features::Feature::WindowsSandbox);
            } else {
                self.features
                    .disable(crate::features::Feature::WindowsSandbox);
            }
        }

        pub fn set_windows_elevated_sandbox_enabled(&mut self, enabled: bool) {
            if enabled {
                self.features
                    .enable(crate::features::Feature::WindowsSandboxElevated);
            } else {
                self.features
                    .disable(crate::features::Feature::WindowsSandboxElevated);
            }
        }
    }

    /// Stub for `codex_core::config::log_dir`.
    pub fn log_dir(_config: &Config) -> Result<std::path::PathBuf, std::io::Error> {
        let mut dir = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
        dir.push("crabbot");
        dir.push("logs");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[derive(Debug, Clone, Default)]
    pub struct ConfigOverrides {
        pub model: Option<String>,
        pub review_model: Option<String>,
        pub cwd: Option<PathBuf>,
        pub approval_policy: Option<crate::protocol::AskForApproval>,
        pub sandbox_mode: Option<codex_protocol::config_types::SandboxMode>,
        pub model_provider: Option<String>,
        pub config_profile: Option<String>,
        pub oss_provider: Option<String>,
        pub personality: Option<crate::config_types::Personality>,
        pub compact_prompt: Option<String>,
        pub additional_writable_roots: Vec<PathBuf>,
    }

    #[derive(Debug, Clone)]
    pub struct ConfigBuilder {
        config: Config,
        cli_overrides: Vec<(String, toml::Value)>,
        harness_overrides: Option<ConfigOverrides>,
    }

    impl Default for ConfigBuilder {
        fn default() -> Self {
            Self {
                config: Config::default(),
                cli_overrides: Vec::new(),
                harness_overrides: None,
            }
        }
    }

    impl ConfigBuilder {
        pub fn codex_home(mut self, codex_home: PathBuf) -> Self {
            self.config.codex_home = codex_home;
            self
        }
        pub fn cli_overrides(mut self, cli_overrides: Vec<(String, toml::Value)>) -> Self {
            self.cli_overrides.extend(cli_overrides);
            self
        }
        pub fn harness_overrides(mut self, harness_overrides: ConfigOverrides) -> Self {
            self.harness_overrides = Some(harness_overrides);
            self
        }
        pub fn cloud_requirements(
            self,
            _cloud_requirements: crate::config_loader::CloudRequirementsLoader,
        ) -> Self {
            self
        }
        pub fn from_config(config: Config) -> Self {
            Self {
                config,
                cli_overrides: Vec::new(),
                harness_overrides: None,
            }
        }
        pub async fn build(mut self) -> std::io::Result<Config> {
            if self.config.codex_home
                == std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir())
            {
                if let Ok(codex_home) = find_codex_home() {
                    self.config.codex_home = codex_home;
                }
            }
            if self.config.cwd == std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()) {
                if let Ok(cwd) = std::env::current_dir() {
                    self.config.cwd = cwd;
                }
            }

            let layer_stack = load_config_layer_stack(
                self.config.codex_home.as_path(),
                self.config.cwd.as_path(),
                &self.cli_overrides,
            )?;
            let merged = layer_stack.effective_config();
            apply_toml_config(&mut self.config, &merged)?;
            if let Some(harness_overrides) = self.harness_overrides.take() {
                apply_harness_overrides(&mut self.config, harness_overrides);
            }
            self.config.config_layer_stack = layer_stack;

            Ok(self.config)
        }
    }

    fn apply_harness_overrides(config: &mut Config, harness_overrides: ConfigOverrides) {
        if let Some(model) = harness_overrides.model {
            config.model = Some(model);
        }
        if let Some(review_model) = harness_overrides.review_model {
            config.review_model = Some(review_model);
        }
        if let Some(cwd) = harness_overrides.cwd {
            config.cwd = cwd;
        }
        if let Some(approval_policy) = harness_overrides.approval_policy {
            let _ = config.permissions.approval_policy.set(approval_policy);
        }
        if let Some(sandbox_mode) = harness_overrides.sandbox_mode {
            let policy = match sandbox_mode {
                codex_protocol::config_types::SandboxMode::ReadOnly => {
                    crate::protocol::SandboxPolicy::new_read_only_policy()
                }
                codex_protocol::config_types::SandboxMode::WorkspaceWrite => {
                    crate::protocol::SandboxPolicy::new_workspace_write_policy()
                }
                codex_protocol::config_types::SandboxMode::DangerFullAccess => {
                    crate::protocol::SandboxPolicy::new_workspace_write_policy()
                }
            };
            let _ = config.permissions.sandbox_policy.set(policy);
        }
        if let Some(model_provider) = harness_overrides.model_provider {
            config.model_provider_id = model_provider;
        }
        if let Some(personality) = harness_overrides.personality {
            config.personality = Some(personality);
        }
        if let Some(compact_prompt) = harness_overrides.compact_prompt {
            config.compact_prompt = Some(compact_prompt);
        }
    }

    pub fn find_codex_home() -> anyhow::Result<std::path::PathBuf> {
        if let Some(codex_home) = std::env::var_os("CODEX_HOME") {
            let path = std::path::PathBuf::from(codex_home).canonicalize()?;
            if !path.is_dir() {
                anyhow::bail!("CODEX_HOME must point to a directory: {}", path.display());
            }
            return Ok(path);
        }

        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow::anyhow!("HOME is not set and CODEX_HOME is unset"))?;
        Ok(std::path::PathBuf::from(home).join(".codex"))
    }

    pub async fn load_config_as_toml_with_cli_overrides(
        codex_home: &std::path::Path,
        cwd: &crate::AbsolutePathBuf,
        overrides: Vec<(String, toml::Value)>,
    ) -> anyhow::Result<toml::Value> {
        let stack = load_config_layer_stack(codex_home, cwd.as_path(), &overrides)?;
        Ok(stack.effective_config())
    }

    /// Mirrors upstream precedence: explicit CLI > profile config > global config.
    pub fn resolve_oss_provider(toml: &toml::Value, cli: &ConfigOverrides) -> Option<String> {
        if let Some(provider) = cli.oss_provider.as_ref() {
            return Some(provider.clone());
        }

        let root = toml.as_table()?;
        let selected_profile = cli.config_profile.clone().or_else(|| {
            root.get("profile")
                .and_then(toml::Value::as_str)
                .map(ToString::to_string)
        });
        if let Some(selected_profile) = selected_profile {
            if let Some(profile_provider) = root
                .get("profiles")
                .and_then(toml::Value::as_table)
                .and_then(|profiles| profiles.get(selected_profile.as_str()))
                .and_then(toml::Value::as_table)
                .and_then(|profile| profile.get("oss_provider"))
                .and_then(toml::Value::as_str)
            {
                return Some(profile_provider.to_string());
            }
        }

        root.get("oss_provider")
            .and_then(toml::Value::as_str)
            .map(|s| s.to_string())
    }

    pub fn set_project_trust_level(
        codex_home: &std::path::Path,
        cwd: &std::path::Path,
        trust: codex_protocol::config_types::TrustLevel,
    ) -> anyhow::Result<()> {
        let config_path = codex_home.join("config.toml");
        let mut root = if config_path.exists() {
            std::fs::read_to_string(&config_path)?
                .parse::<toml::Value>()
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?
        } else {
            toml::Value::Table(toml::map::Map::new())
        };

        let root_table = root
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("config root must be a table"))?;
        if !root_table
            .get("projects")
            .is_some_and(toml::Value::is_table)
        {
            root_table.insert(
                "projects".to_string(),
                toml::Value::Table(toml::map::Map::new()),
            );
        }

        let projects = root_table
            .get_mut("projects")
            .and_then(toml::Value::as_table_mut)
            .ok_or_else(|| anyhow::anyhow!("projects table missing after initialization"))?;
        let project_key = cwd.to_string_lossy().to_string();

        let mut project_table = projects
            .get(&project_key)
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        project_table.insert(
            "trust_level".to_string(),
            toml::Value::String(match trust {
                TrustLevel::Trusted => "trusted".to_string(),
                TrustLevel::Untrusted => "untrusted".to_string(),
            }),
        );
        projects.insert(project_key, toml::Value::Table(project_table));

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let serialized = toml::to_string_pretty(&root)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        std::fs::write(config_path, serialized)?;
        Ok(())
    }

    pub fn set_default_oss_provider(codex_home: &Path, provider: &str) -> std::io::Result<()> {
        match provider {
            crate::LMSTUDIO_OSS_PROVIDER_ID | crate::OLLAMA_OSS_PROVIDER_ID => {}
            crate::LEGACY_OLLAMA_CHAT_PROVIDER_ID => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    crate::OLLAMA_CHAT_PROVIDER_REMOVED_ERROR,
                ));
            }
            _ => {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!(
                        "Invalid OSS provider '{provider}'. Must be one of: {}, {}",
                        crate::LMSTUDIO_OSS_PROVIDER_ID,
                        crate::OLLAMA_OSS_PROVIDER_ID
                    ),
                ));
            }
        }

        let config_path = codex_home.join("config.toml");
        let mut root = if config_path.exists() {
            std::fs::read_to_string(&config_path)?
                .parse::<toml::Value>()
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?
        } else {
            toml::Value::Table(toml::map::Map::new())
        };

        let root_table = root.as_table_mut().ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "config root must be a table")
        })?;
        root_table.insert(
            "oss_provider".to_string(),
            toml::Value::String(provider.to_string()),
        );

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let serialized = toml::to_string_pretty(&root)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))?;
        std::fs::write(config_path, serialized)?;
        Ok(())
    }

    fn apply_toml_override(config: &mut Config, key: &str, value: toml::Value) {
        match key {
            "model" => {
                if let Some(model) = value.as_str() {
                    config.model = Some(model.to_string());
                }
            }
            "review_model" => {
                if let Some(model) = value.as_str() {
                    config.review_model = Some(model.to_string());
                }
            }
            "model_provider" | "model_provider_id" => {
                if let Some(provider) = value.as_str() {
                    config.model_provider_id = provider.to_string();
                }
            }
            "chatgpt_base_url" => {
                if let Some(url) = value.as_str() {
                    config.chatgpt_base_url = url.to_string();
                }
            }
            "model_context_window" => {
                if let Some(window) = value.as_integer() {
                    config.model_context_window = Some(window);
                }
            }
            "model_auto_compact_token_limit" => {
                if let Some(limit) = value.as_integer() {
                    config.model_auto_compact_token_limit = Some(limit);
                }
            }
            "model_reasoning_summary" => {
                if let Ok(summary) = value.clone().try_into::<ReasoningSummary>() {
                    config.model_reasoning_summary = Some(summary);
                }
            }
            "model_reasoning_effort" => {
                if let Ok(effort) = value
                    .clone()
                    .try_into::<crate::openai_models::ReasoningEffort>()
                {
                    config.model_reasoning_effort = Some(effort);
                }
            }
            "plan_mode_reasoning_effort" => {
                if let Ok(effort) = value
                    .clone()
                    .try_into::<crate::openai_models::ReasoningEffort>()
                {
                    config.plan_mode_reasoning_effort = Some(effort);
                }
            }
            "approval_policy" => {
                if let Ok(policy) = value.clone().try_into::<crate::protocol::AskForApproval>() {
                    let _ = config.permissions.approval_policy.set(policy);
                }
            }
            "sandbox_mode" => {
                if let Ok(sandbox_mode) = value
                    .clone()
                    .try_into::<codex_protocol::config_types::SandboxMode>()
                {
                    let policy = match sandbox_mode {
                        codex_protocol::config_types::SandboxMode::ReadOnly => {
                            crate::protocol::SandboxPolicy::new_read_only_policy()
                        }
                        codex_protocol::config_types::SandboxMode::WorkspaceWrite => {
                            crate::protocol::SandboxPolicy::new_workspace_write_policy()
                        }
                        codex_protocol::config_types::SandboxMode::DangerFullAccess => {
                            crate::protocol::SandboxPolicy::new_workspace_write_policy()
                        }
                    };
                    let _ = config.permissions.sandbox_policy.set(policy);
                }
            }
            "user_instructions" => {
                config.user_instructions = value.as_str().map(ToString::to_string);
            }
            "base_instructions" => {
                config.base_instructions = value.as_str().map(ToString::to_string);
            }
            "developer_instructions" => {
                config.developer_instructions = value.as_str().map(ToString::to_string);
            }
            "compact_prompt" => {
                config.compact_prompt = value.as_str().map(ToString::to_string);
            }
            "commit_attribution" => {
                config.commit_attribution = value.as_str().map(ToString::to_string);
            }
            "notify" => {
                config.notify = value.as_array().map(|arr| {
                    arr.iter()
                        .filter_map(toml::Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                });
            }
            "animations" => {
                if let Some(v) = value.as_bool() {
                    config.animations = v;
                }
            }
            "show_tooltips" => {
                if let Some(v) = value.as_bool() {
                    config.show_tooltips = v;
                }
            }
            "disable_paste_burst" => {
                if let Some(v) = value.as_bool() {
                    config.disable_paste_burst = v;
                }
            }
            "feedback_enabled" => {
                if let Some(v) = value.as_bool() {
                    config.feedback_enabled = v;
                }
            }
            "hide_agent_reasoning" => {
                if let Some(v) = value.as_bool() {
                    config.hide_agent_reasoning = v;
                }
            }
            "show_raw_agent_reasoning" => {
                if let Some(v) = value.as_bool() {
                    config.show_raw_agent_reasoning = v;
                }
            }
            "personality" => {
                if let Ok(personality) =
                    value.clone().try_into::<crate::config_types::Personality>()
                {
                    config.personality = Some(personality);
                }
            }
            _ => {}
        }
    }

    fn apply_toml_config(config: &mut Config, parsed: &toml::Value) -> std::io::Result<()> {
        let Some(table) = parsed.as_table() else {
            return Ok(());
        };

        for (key, value) in table {
            apply_toml_override(config, key, value.clone());
        }

        if let Some(features) = table.get("features").and_then(toml::Value::as_table) {
            for (key, value) in features {
                let Some(feature) = crate::features::Feature::from_key(key) else {
                    continue;
                };
                if value.as_bool().unwrap_or(false) {
                    config.features.enable(feature);
                } else {
                    config.features.disable(feature);
                }
            }
        }

        if let Some(mcp_servers) = table.get("mcp_servers")
            && let Ok(servers) = mcp_servers
                .clone()
                .try_into::<std::collections::BTreeMap<String, types::McpServerConfig>>()
        {
            config.mcp_servers = McpServers(servers);
        }

        if let Some(tui) = table.get("tui").and_then(toml::Value::as_table) {
            if let Some(notifications) = tui.get("notifications")
                && let Ok(parsed) = notifications.clone().try_into::<types::Notifications>()
            {
                config.tui_notifications = parsed;
            }
            if let Some(method) = tui.get("notification_method")
                && let Ok(parsed) = method.clone().try_into::<types::NotificationMethod>()
            {
                config.tui_notification_method = parsed;
            }
            if let Some(alt_screen) = tui.get("alternate_screen")
                && let Ok(parsed) = alt_screen
                    .clone()
                    .try_into::<codex_protocol::config_types::AltScreenMode>()
            {
                config.tui_alternate_screen = parsed;
            }
            if let Some(status_line) = tui.get("status_line").and_then(toml::Value::as_array) {
                config.tui_status_line = Some(
                    status_line
                        .iter()
                        .filter_map(toml::Value::as_str)
                        .map(ToString::to_string)
                        .collect(),
                );
            }
        }

        Ok(())
    }

    fn apply_dotted_toml_value(
        root: &mut toml::Value,
        dotted_key: &str,
        value: toml::Value,
    ) -> anyhow::Result<()> {
        let mut parts = dotted_key.split('.').peekable();
        if parts.peek().is_none() {
            anyhow::bail!("empty config key path");
        }

        let mut current = root;
        while let Some(part) = parts.next() {
            let is_last = parts.peek().is_none();
            if is_last {
                let table = current.as_table_mut().ok_or_else(|| {
                    anyhow::anyhow!("config path `{dotted_key}` collides with non-table value")
                })?;
                table.insert(part.to_string(), value);
                return Ok(());
            }

            let table = current.as_table_mut().ok_or_else(|| {
                anyhow::anyhow!("config path `{dotted_key}` collides with non-table value")
            })?;
            current = table
                .entry(part.to_string())
                .or_insert_with(|| toml::Value::Table(toml::map::Map::new()));
        }
        Ok(())
    }

    fn load_toml_file(path: &Path) -> std::io::Result<toml::Value> {
        let raw = std::fs::read_to_string(path)?;
        raw.parse::<toml::Value>()
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
    }

    fn merge_toml_values(base: &mut toml::Value, overlay: &toml::Value) {
        match (base, overlay) {
            (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
                for (k, v) in overlay_table {
                    match base_table.get_mut(k) {
                        Some(base_value) => merge_toml_values(base_value, v),
                        None => {
                            base_table.insert(k.clone(), v.clone());
                        }
                    }
                }
            }
            (base_value, overlay_value) => {
                *base_value = overlay_value.clone();
            }
        }
    }

    fn load_config_layer_stack(
        codex_home: &Path,
        cwd: &Path,
        cli_overrides: &[(String, toml::Value)],
    ) -> std::io::Result<crate::config_loader::ConfigLayerStack> {
        let mut layers: Vec<crate::config_loader::ConfigLayerEntry> = Vec::new();

        let user_file = codex_home.join("config.toml");
        let user_path = crate::AbsolutePathBuf::from_absolute_path(&user_file)?;
        let user_config = if user_file.exists() {
            load_toml_file(&user_file)?
        } else {
            toml::Value::Table(toml::map::Map::new())
        };
        layers.push(crate::config_loader::ConfigLayerEntry::new(
            crate::ConfigLayerSource::User { file: user_path },
            user_config,
        ));

        let cwd_config_file = cwd.join("config.toml");
        if cwd_config_file.exists() {
            let cwd_config = load_toml_file(&cwd_config_file)?;
            let dot_codex_folder = crate::AbsolutePathBuf::from_absolute_path(cwd)?;
            layers.push(crate::config_loader::ConfigLayerEntry::new(
                crate::ConfigLayerSource::Project { dot_codex_folder },
                cwd_config,
            ));
        }

        let mut project_layers: Vec<crate::config_loader::ConfigLayerEntry> = Vec::new();
        for ancestor in cwd.ancestors().collect::<Vec<_>>().into_iter().rev() {
            let dot_codex = ancestor.join(".codex");
            let config_file = dot_codex.join("config.toml");
            if !config_file.exists() {
                continue;
            }
            let cfg = load_toml_file(&config_file)?;
            project_layers.push(crate::config_loader::ConfigLayerEntry::new(
                crate::ConfigLayerSource::Project {
                    dot_codex_folder: crate::AbsolutePathBuf::from_absolute_path(dot_codex)?,
                },
                cfg,
            ));
        }
        layers.extend(project_layers);

        if !cli_overrides.is_empty() {
            let mut cli_layer = toml::Value::Table(toml::map::Map::new());
            for (key, value) in cli_overrides {
                apply_dotted_toml_value(&mut cli_layer, key, value.clone())
                    .map_err(std::io::Error::other)?;
            }
            layers.push(crate::config_loader::ConfigLayerEntry::new(
                crate::ConfigLayerSource::SessionFlags,
                cli_layer,
            ));
        }

        crate::config_loader::ConfigLayerStack::new(
            layers,
            crate::config_loader::ConfigRequirements::default(),
            crate::config_loader::ConfigRequirementsToml::default(),
        )
    }

    pub mod edit {
        #[derive(Debug, Clone)]
        pub enum ConfigEdit {
            SetPath {
                segments: Vec<String>,
                value: serde_json::Value,
            },
            ClearPath {
                segments: Vec<String>,
            },
            SetSkillConfig {
                path: std::path::PathBuf,
                enabled: bool,
            },
        }

        #[derive(Debug, Clone, Default)]
        pub struct ConfigEditsBuilder {
            _codex_home: std::path::PathBuf,
            edits: Vec<ConfigEdit>,
        }

        impl ConfigEditsBuilder {
            pub fn new(codex_home: &std::path::Path) -> Self {
                Self {
                    _codex_home: codex_home.to_path_buf(),
                    edits: Vec::new(),
                }
            }
            pub fn with_profile(self, _profile: Option<&str>) -> Self {
                self
            }
            pub fn with_edits<I>(mut self, edits: I) -> Self
            where
                I: IntoIterator<Item = ConfigEdit>,
            {
                self.edits.extend(edits);
                self
            }
            pub fn set_windows_sandbox_mode(
                self,
                _mode: Option<super::types::WindowsSandboxModeToml>,
            ) -> Self {
                self
            }
            pub fn set_model(
                self,
                _model: Option<&str>,
                _effort: Option<crate::openai_models::ReasoningEffort>,
            ) -> Self {
                self
            }
            pub fn set_personality(
                self,
                _personality: Option<crate::config_types::Personality>,
            ) -> Self {
                self
            }
            pub fn set_feature_enabled(self, _feature_key: &str, _enabled: bool) -> Self {
                self
            }
            pub fn set_realtime_speaker(self, _speaker: Option<&str>) -> Self {
                self
            }
            pub fn set_realtime_microphone(self, _microphone: Option<&str>) -> Self {
                self
            }
            pub fn set_model_availability_nux_count(
                self,
                _shown_count: &std::collections::BTreeMap<String, u32>,
            ) -> Self {
                self
            }
            pub fn set_hide_full_access_warning(self, _value: bool) -> Self {
                self
            }
            pub fn set_hide_world_writable_warning(self, _value: bool) -> Self {
                self
            }
            pub fn set_hide_rate_limit_model_nudge(self, _value: bool) -> Self {
                self
            }
            pub fn record_model_migration_seen(self, _from: &str, _to: &str) -> Self {
                self
            }
            pub async fn apply(self) -> anyhow::Result<()> {
                Ok(())
            }
        }

        pub fn status_line_items_edit(ids: &[String]) -> ConfigEdit {
            ConfigEdit::SetPath {
                segments: vec!["tui_status_line".to_string()],
                value: serde_json::json!(ids),
            }
        }

        pub fn syntax_theme_edit(name: &str) -> ConfigEdit {
            ConfigEdit::SetPath {
                segments: vec!["tui_theme".to_string()],
                value: serde_json::json!(name),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireApi {
    ChatCompletions,
    Responses,
}

pub const DEFAULT_LMSTUDIO_PORT: u16 = 1234;
pub const DEFAULT_OLLAMA_PORT: u16 = 11434;
pub const LMSTUDIO_OSS_PROVIDER_ID: &str = "lmstudio";
pub const OLLAMA_OSS_PROVIDER_ID: &str = "ollama";
pub const LEGACY_OLLAMA_CHAT_PROVIDER_ID: &str = "ollama_chat";
pub const OLLAMA_CHAT_PROVIDER_REMOVED_ERROR: &str =
    "The legacy `ollama_chat` provider has been removed; use `ollama` instead.";

#[derive(Debug, Clone)]
pub struct CachedAuth {
    mode: auth::AuthMode,
    account_id: Option<String>,
    email: Option<String>,
    plan_type: Option<codex_protocol::account::PlanType>,
}

impl CachedAuth {
    pub fn auth_mode(&self) -> auth::AuthMode {
        self.mode
    }

    pub fn get_account_email(&self) -> Option<String> {
        self.email.clone()
    }

    pub fn get_account_id(&self) -> Option<String> {
        self.account_id.clone()
    }

    pub fn account_plan_type(&self) -> Option<codex_protocol::account::PlanType> {
        self.plan_type.clone()
    }

    pub fn is_chatgpt_auth(&self) -> bool {
        matches!(self.mode, auth::AuthMode::Chatgpt)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AuthManager {
    auth: Option<CachedAuth>,
}

impl AuthManager {
    pub fn auth_cached(&self) -> Option<CachedAuth> {
        self.auth.clone()
    }

    pub fn from_api_key() -> Self {
        Self {
            auth: Some(CachedAuth {
                mode: auth::AuthMode::ApiKey,
                account_id: None,
                email: None,
                plan_type: None,
            }),
        }
    }

    pub fn from_chatgpt_email(email: Option<String>) -> Self {
        Self {
            auth: Some(CachedAuth {
                mode: auth::AuthMode::Chatgpt,
                account_id: None,
                email,
                plan_type: None,
            }),
        }
    }

    pub fn from_chatgpt_account(
        email: Option<String>,
        plan_type: Option<codex_protocol::account::PlanType>,
    ) -> Self {
        Self {
            auth: Some(CachedAuth {
                mode: auth::AuthMode::Chatgpt,
                account_id: None,
                email,
                plan_type,
            }),
        }
    }

    pub async fn auth(&self) -> Option<CodexAuth> {
        self.auth.clone()
    }

    pub fn reload(&self) {}
}

pub mod auth {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AuthMode {
        ApiKey,
        Chatgpt,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AuthCredentialsStoreMode {
        Keyring,
        Plaintext,
    }

    pub const CLIENT_ID: &str = "crabbot";

    pub fn read_openai_api_key_from_env() -> Option<String> {
        std::env::var("OPENAI_API_KEY").ok()
    }

    pub fn login_with_api_key(
        _codex_home: &std::path::Path,
        _api_key: &str,
        _mode: AuthCredentialsStoreMode,
    ) -> std::io::Result<()> {
        Ok(())
    }

    pub fn logout(
        _codex_home: &std::path::Path,
        _mode: AuthCredentialsStoreMode,
    ) -> std::io::Result<bool> {
        Ok(true)
    }

    pub fn enforce_login_restrictions(_config: &crate::config::Config) -> std::io::Result<()> {
        Ok(())
    }
}

pub mod project_doc {
    use crate::config::Config;
    use std::path::Path;
    use std::path::PathBuf;
    pub const DEFAULT_PROJECT_DOC_FILENAME: &str = "AGENTS.md";

    pub fn discover_project_doc_paths(config: &Config) -> Result<Vec<PathBuf>, std::io::Error> {
        let mut found = Vec::new();
        let mut current = Some(config.cwd.as_path());
        while let Some(dir) = current {
            let candidate = dir.join("AGENTS.md");
            if candidate.exists() {
                found.push(candidate);
            }
            current = parent(dir);
        }
        found.reverse();
        Ok(found)
    }

    fn parent(path: &Path) -> Option<&Path> {
        path.parent()
    }
}

pub type CodexAuth = CachedAuth;

#[derive(Debug, Clone)]
pub struct CodexError {
    message: String,
}

impl CodexError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn to_error_event(&self, _turn_id: Option<String>) -> crate::protocol::ErrorEvent {
        crate::protocol::ErrorEvent {
            message: self.message.clone(),
            codex_error_info: None,
        }
    }
}

impl std::fmt::Display for CodexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodexError {}

#[derive(Debug, Clone)]
struct ShimBackendConfig {
    app_server_endpoint: String,
    auth_token: Option<String>,
}

impl Default for ShimBackendConfig {
    fn default() -> Self {
        Self {
            app_server_endpoint: "ws://127.0.0.1:8765".to_string(),
            auth_token: None,
        }
    }
}

static SHIM_BACKEND_CONFIG: LazyLock<Mutex<ShimBackendConfig>> =
    LazyLock::new(|| Mutex::new(ShimBackendConfig::default()));

fn set_shim_backend_config(app_server_endpoint: &str, auth_token: Option<&str>) {
    if let Ok(mut guard) = SHIM_BACKEND_CONFIG.lock() {
        guard.app_server_endpoint = app_server_endpoint.to_string();
        guard.auth_token = auth_token.map(ToString::to_string);
    }
}

pub(crate) fn get_shim_backend_config() -> ShimBackendConfig {
    SHIM_BACKEND_CONFIG
        .lock()
        .map(|cfg| cfg.clone())
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct CodexThread {
    state: std::sync::Arc<Mutex<CodexThreadState>>,
}

#[derive(Debug, Clone)]
struct CodexThreadState {
    thread_id: ThreadId,
    app_server_endpoint: String,
    auth_token: Option<String>,
    last_sequence: u64,
    next_submission_id: u64,
    current_turn_id: Option<String>,
    // Last finalized agent message seen within the current turn.
    // Used to suppress duplicate AgentMessage events emitted by mixed app-server notifications.
    last_agent_message_in_turn: Option<String>,
    pending_events: VecDeque<crate::protocol::Event>,
    pending_server_requests: HashMap<String, PendingServerRequest>,
    pending_request_user_input_by_turn_id: HashMap<String, VecDeque<String>>,
    config_snapshot: ThreadConfigSnapshot,
    rollout_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone)]
struct PendingServerRequest {
    request_id: Value,
    method: String,
    turn_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ThreadConfigSnapshot {
    pub model: String,
    pub model_provider_id: String,
    pub approval_policy: crate::protocol::AskForApproval,
    pub sandbox_policy: crate::protocol::SandboxPolicy,
    pub cwd: std::path::PathBuf,
    pub reasoning_effort: Option<crate::openai_models::ReasoningEffort>,
    pub session_source: crate::protocol::SessionSource,
}

impl CodexThread {
    pub async fn set_app_server_client_name(
        &self,
        _client_name: Option<String>,
    ) -> std::result::Result<(), String> {
        Ok(())
    }

    fn request_id_to_key(request_id: &crate::mcp::RequestId) -> String {
        match request_id {
            crate::mcp::RequestId::String(id) => id.clone(),
            crate::mcp::RequestId::Integer(id) => id.to_string(),
        }
    }

    fn cleanup_pending_requests_for_turn(state: &mut CodexThreadState, turn_id: &str) {
        let stale_keys: Vec<String> = state
            .pending_server_requests
            .iter()
            .filter_map(|(key, pending)| {
                (pending.turn_id.as_deref() == Some(turn_id)).then(|| key.clone())
            })
            .collect();
        for key in stale_keys {
            state.pending_server_requests.remove(&key);
        }
        state.pending_request_user_input_by_turn_id.remove(turn_id);
    }

    fn cleanup_pending_request_by_key(state: &mut CodexThreadState, request_key: &str) {
        state.pending_server_requests.remove(request_key);
        for queue in state.pending_request_user_input_by_turn_id.values_mut() {
            queue.retain(|queued_key| queued_key != request_key);
        }
        state
            .pending_request_user_input_by_turn_id
            .retain(|_, queue| !queue.is_empty());
    }

    fn new(
        thread_id: ThreadId,
        config_snapshot: ThreadConfigSnapshot,
        rollout_path: Option<std::path::PathBuf>,
    ) -> Self {
        let backend = get_shim_backend_config();
        Self {
            state: std::sync::Arc::new(Mutex::new(CodexThreadState {
                thread_id,
                app_server_endpoint: backend.app_server_endpoint,
                auth_token: backend.auth_token,
                last_sequence: 0,
                next_submission_id: 1,
                current_turn_id: None,
                last_agent_message_in_turn: None,
                pending_events: VecDeque::new(),
                pending_server_requests: HashMap::new(),
                pending_request_user_input_by_turn_id: HashMap::new(),
                config_snapshot,
                rollout_path,
            })),
        }
    }

    fn new_submission_id(state: &mut CodexThreadState) -> String {
        let id = format!("op-{}", state.next_submission_id);
        state.next_submission_id += 1;
        id
    }

    fn enqueue_pending_event(state: &mut CodexThreadState, event: crate::protocol::Event) {
        match &event.msg {
            crate::protocol::EventMsg::TurnStarted(_) => {
                state.last_agent_message_in_turn = None;
            }
            crate::protocol::EventMsg::TurnComplete(_)
            | crate::protocol::EventMsg::TurnAborted(_) => {
                state.last_agent_message_in_turn = None;
            }
            crate::protocol::EventMsg::AgentMessage(agent) => {
                if state.last_agent_message_in_turn.as_deref() == Some(agent.message.as_str()) {
                    return;
                }
                state.last_agent_message_in_turn = Some(agent.message.clone());
            }
            _ => {}
        }
        state.pending_events.push_back(event);
    }

    fn user_input_to_wire_item(input: &crate::user_input::UserInput) -> Option<Value> {
        match input {
            crate::user_input::UserInput::Text {
                text,
                text_elements,
            } => Some(json!({
                "type": "text",
                "text": text,
                "text_elements": text_elements,
            })),
            crate::user_input::UserInput::LocalImage { path } => Some(json!({
                "type": "localImage",
                "path": path.to_string_lossy().to_string(),
            })),
            crate::user_input::UserInput::Image { image_url } => Some(json!({
                "type": "image",
                "image_url": image_url,
            })),
            crate::user_input::UserInput::Skill { name, path } => Some(json!({
                "type": "skill",
                "name": name,
                "path": path.to_string_lossy().to_string(),
            })),
            crate::user_input::UserInput::Mention { name, path } => Some(json!({
                "type": "mention",
                "name": name,
                "path": path,
            })),
            _ => None,
        }
    }

    fn push_local_event(
        &self,
        event_id: String,
        msg: crate::protocol::EventMsg,
    ) -> Result<(), CodexError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
        Self::enqueue_pending_event(&mut state, crate::protocol::Event { id: event_id, msg });
        Ok(())
    }
    pub async fn submit(&self, op: crate::protocol::Op) -> Result<String, CodexError> {
        let submission_id = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
            Self::new_submission_id(&mut state)
        };

        let (endpoint, auth_token, thread_id, current_turn_id, snapshot) = {
            let state = self
                .state
                .lock()
                .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
            (
                state.app_server_endpoint.clone(),
                state.auth_token.clone(),
                state.thread_id,
                state.current_turn_id.clone(),
                state.config_snapshot.clone(),
            )
        };

        match op {
            crate::protocol::Op::UserTurn { items, .. }
            | crate::protocol::Op::UserInput {
                items,
                final_output_json_schema: _,
            } => {
                let input = items
                    .iter()
                    .filter_map(Self::user_input_to_wire_item)
                    .collect::<Vec<_>>();
                app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "turn/start",
                    json!({
                        "threadId": thread_id.to_string(),
                        "input": input,
                        "model": snapshot.model,
                    }),
                )
                .map_err(|err| CodexError::new(format!("submit turn/start failed: {err}")))
                .map(|response| {
                    if let Some(turn_id) = response
                        .result
                        .get("turn")
                        .and_then(|turn| turn.get("id"))
                        .and_then(Value::as_str)
                    {
                        if let Ok(mut state) = self.state.lock() {
                            state.current_turn_id = Some(turn_id.to_string());
                        }
                    }
                })?;
            }
            crate::protocol::Op::RunUserShellCommand { command } => {
                let call_id = format!("user-shell-{submission_id}");
                let standalone_turn_id = current_turn_id
                    .is_none()
                    .then(|| format!("user-shell-turn-{submission_id}"));
                let turn_id = current_turn_id
                    .clone()
                    .unwrap_or_else(|| standalone_turn_id.clone().unwrap_or_default());
                let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
                let shell_command = vec![shell, "-lc".to_string(), command.clone()];
                let display_command = vec![command.clone()];

                if standalone_turn_id.is_some() {
                    self.push_local_event(
                        format!("seq-local-turn-started-{submission_id}"),
                        crate::protocol::EventMsg::TurnStarted(crate::protocol::TurnStartedEvent {
                            turn_id: turn_id.clone(),
                            model_context_window: None,
                            collaboration_mode_kind: Default::default(),
                        }),
                    )?;
                }
                self.push_local_event(
                    format!("seq-local-exec-begin-{submission_id}"),
                    crate::protocol::EventMsg::ExecCommandBegin(
                        crate::protocol::ExecCommandBeginEvent {
                            call_id: call_id.clone(),
                            process_id: None,
                            turn_id: turn_id.clone(),
                            command: display_command.clone(),
                            cwd: snapshot.cwd.clone(),
                            parsed_cmd: Vec::new(),
                            source: crate::protocol::ExecCommandSource::UserShell,
                            interaction_input: None,
                        },
                    ),
                )?;
                let endpoint_for_exec = endpoint.clone();
                let auth_token_for_exec = auth_token.clone();
                let shell_command_for_exec = shell_command.clone();
                let cwd_for_exec = snapshot.cwd.clone();
                let display_command_for_exec = display_command.clone();
                let submission_id_for_exec = submission_id.clone();
                let this = self.clone();
                tokio::spawn(async move {
                    let started_at = Instant::now();
                    let endpoint_unused = endpoint_for_exec;
                    let auth_unused = auth_token_for_exec;
                    let run_result = tokio::task::spawn_blocking(move || {
                        let _ = endpoint_unused;
                        let _ = auth_unused;
                        let mut cmd = std::process::Command::new(
                            shell_command_for_exec
                                .first()
                                .map(String::as_str)
                                .unwrap_or("/bin/sh"),
                        );
                        if shell_command_for_exec.len() > 1 {
                            cmd.args(shell_command_for_exec[1..].iter().map(String::as_str));
                        }
                        cmd.current_dir(cwd_for_exec);
                        cmd.output()
                    })
                    .await;

                    let (stdout, stderr, exit_code) = match run_result {
                        Ok(Ok(output)) => (
                            String::from_utf8_lossy(&output.stdout).to_string(),
                            String::from_utf8_lossy(&output.stderr).to_string(),
                            output.status.code().unwrap_or(-1),
                        ),
                        Ok(Err(err)) => (String::new(), format!("execution error: {err}"), -1),
                        Err(err) => (
                            String::new(),
                            format!("execution task join error: {err}"),
                            -1,
                        ),
                    };

                    if !stdout.is_empty() {
                        let _ = this.push_local_event(
                            format!("seq-local-exec-stdout-{submission_id_for_exec}"),
                            crate::protocol::EventMsg::ExecCommandOutputDelta(
                                crate::protocol::ExecCommandOutputDeltaEvent {
                                    call_id: call_id.clone(),
                                    stream: crate::protocol::ExecOutputStream::Stdout,
                                    chunk: stdout.as_bytes().to_vec(),
                                },
                            ),
                        );
                    }
                    if !stderr.is_empty() {
                        let _ = this.push_local_event(
                            format!("seq-local-exec-stderr-{submission_id_for_exec}"),
                            crate::protocol::EventMsg::ExecCommandOutputDelta(
                                crate::protocol::ExecCommandOutputDeltaEvent {
                                    call_id: call_id.clone(),
                                    stream: crate::protocol::ExecOutputStream::Stderr,
                                    chunk: stderr.as_bytes().to_vec(),
                                },
                            ),
                        );
                    }

                    let duration = started_at.elapsed();
                    let status = if exit_code == 0 {
                        crate::protocol::ExecCommandStatus::Completed
                    } else {
                        crate::protocol::ExecCommandStatus::Failed
                    };
                    let aggregated_output = format!("{stdout}{stderr}");
                    let _ = this.push_local_event(
                        format!("seq-local-exec-end-{submission_id_for_exec}"),
                        crate::protocol::EventMsg::ExecCommandEnd(
                            crate::protocol::ExecCommandEndEvent {
                                call_id: call_id.clone(),
                                process_id: None,
                                turn_id: turn_id.clone(),
                                command: display_command_for_exec.clone(),
                                cwd: snapshot.cwd.clone(),
                                parsed_cmd: Vec::new(),
                                source: crate::protocol::ExecCommandSource::UserShell,
                                interaction_input: None,
                                stdout,
                                stderr,
                                aggregated_output: aggregated_output.clone(),
                                exit_code,
                                duration,
                                formatted_output: aggregated_output,
                                status,
                            },
                        ),
                    );
                    if standalone_turn_id.is_some() {
                        let _ = this.push_local_event(
                            format!("seq-local-turn-complete-{submission_id_for_exec}"),
                            crate::protocol::EventMsg::TurnComplete(
                                crate::protocol::TurnCompleteEvent {
                                    turn_id,
                                    last_agent_message: None,
                                },
                            ),
                        );
                    }
                });
            }
            crate::protocol::Op::Interrupt => {
                if let Some(turn_id) = current_turn_id {
                    app_server_rpc_request_raw(
                        &endpoint,
                        auth_token.as_deref(),
                        "turn/interrupt",
                        json!({
                            "threadId": thread_id.to_string(),
                            "turnId": turn_id,
                        }),
                    )
                    .map_err(|err| {
                        CodexError::new(format!("submit turn/interrupt failed: {err}"))
                    })?;
                }
            }
            crate::protocol::Op::CleanBackgroundTerminals => {
                app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "thread/backgroundTerminals/clean",
                    json!({
                        "threadId": thread_id.to_string(),
                    }),
                )
                .map_err(|err| {
                    CodexError::new(format!(
                        "submit thread/backgroundTerminals/clean failed: {err}"
                    ))
                })?;
            }
            crate::protocol::Op::ListSkills { cwds, force_reload } => {
                let response = app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "skills/list",
                    json!({
                        "cwds": cwds,
                        "forceReload": force_reload,
                    }),
                )
                .map_err(|err| CodexError::new(format!("submit skills/list failed: {err}")))?;
                let skills = response
                    .result
                    .get("data")
                    .cloned()
                    .and_then(|value| {
                        serde_json::from_value::<Vec<crate::protocol::SkillsListEntry>>(value).ok()
                    })
                    .unwrap_or_default();
                self.push_local_event(
                    format!("seq-local-list-skills-{submission_id}"),
                    crate::protocol::EventMsg::ListSkillsResponse(
                        crate::protocol::ListSkillsResponseEvent { skills },
                    ),
                )?;
            }
            crate::protocol::Op::ListRemoteSkills {
                hazelnut_scope,
                product_surface,
                enabled,
            } => {
                let mut params = serde_json::Map::new();
                params.insert(
                    "hazelnutScope".to_string(),
                    serde_json::to_value(hazelnut_scope).unwrap_or(Value::Null),
                );
                params.insert(
                    "productSurface".to_string(),
                    serde_json::to_value(product_surface).unwrap_or(Value::Null),
                );
                if let Some(value) = enabled {
                    params.insert("enabled".to_string(), Value::Bool(value));
                }
                let response = app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "skills/remote/list",
                    Value::Object(params),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit skills/remote/list failed: {err}"))
                })?;
                let skills = response
                    .result
                    .get("data")
                    .cloned()
                    .and_then(|value| {
                        serde_json::from_value::<Vec<crate::protocol::RemoteSkillSummary>>(value)
                            .ok()
                    })
                    .unwrap_or_default();
                self.push_local_event(
                    format!("seq-local-list-remote-skills-{submission_id}"),
                    crate::protocol::EventMsg::ListRemoteSkillsResponse(
                        crate::protocol::ListRemoteSkillsResponseEvent { skills },
                    ),
                )?;
            }
            crate::protocol::Op::DownloadRemoteSkill { hazelnut_id } => {
                let response = app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "skills/remote/export",
                    json!({
                        "hazelnutId": hazelnut_id,
                    }),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit skills/remote/export failed: {err}"))
                })?;
                let id = response
                    .result
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let name = response
                    .result
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| id.clone());
                let path = response
                    .result
                    .get("path")
                    .and_then(Value::as_str)
                    .map(std::path::PathBuf::from)
                    .unwrap_or_default();
                self.push_local_event(
                    format!("seq-local-download-remote-skill-{submission_id}"),
                    crate::protocol::EventMsg::RemoteSkillDownloaded(
                        crate::protocol::RemoteSkillDownloadedEvent { id, name, path },
                    ),
                )?;
            }
            crate::protocol::Op::ListMcpTools => {
                let response = app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "mcpServerStatus/list",
                    json!({
                        "limit": 256,
                    }),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit mcpServerStatus/list failed: {err}"))
                })?;

                let mut tools: HashMap<String, crate::mcp::Tool> = HashMap::new();
                let mut resources: HashMap<String, Vec<crate::mcp::Resource>> = HashMap::new();
                let mut resource_templates: HashMap<String, Vec<crate::mcp::ResourceTemplate>> =
                    HashMap::new();
                let mut auth_statuses: HashMap<String, crate::protocol::McpAuthStatus> =
                    HashMap::new();

                for entry in response
                    .result
                    .get("data")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                {
                    let server_name = entry
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    if server_name.is_empty() {
                        continue;
                    }

                    let server_tools = entry
                        .get("tools")
                        .cloned()
                        .and_then(|value| {
                            serde_json::from_value::<HashMap<String, crate::mcp::Tool>>(value).ok()
                        })
                        .unwrap_or_default();
                    tools.extend(server_tools);

                    let server_resources = entry
                        .get("resources")
                        .cloned()
                        .and_then(|value| {
                            serde_json::from_value::<Vec<crate::mcp::Resource>>(value).ok()
                        })
                        .unwrap_or_default();
                    resources.insert(server_name.clone(), server_resources);

                    let server_templates = entry
                        .get("resourceTemplates")
                        .or_else(|| entry.get("resource_templates"))
                        .cloned()
                        .and_then(|value| {
                            serde_json::from_value::<Vec<crate::mcp::ResourceTemplate>>(value).ok()
                        })
                        .unwrap_or_default();
                    resource_templates.insert(server_name.clone(), server_templates);

                    let auth_status = entry
                        .get("authStatus")
                        .or_else(|| entry.get("auth_status"))
                        .cloned()
                        .and_then(|value| {
                            serde_json::from_value::<crate::protocol::McpAuthStatus>(value).ok()
                        })
                        .unwrap_or(crate::protocol::McpAuthStatus::Unsupported);
                    auth_statuses.insert(server_name, auth_status);
                }

                self.push_local_event(
                    format!("seq-local-list-mcp-tools-{submission_id}"),
                    crate::protocol::EventMsg::McpListToolsResponse(
                        crate::protocol::McpListToolsResponseEvent {
                            tools,
                            resources,
                            resource_templates,
                            auth_statuses,
                        },
                    ),
                )?;
            }
            crate::protocol::Op::ListCustomPrompts => {
                self.push_local_event(
                    format!("seq-local-list-custom-prompts-{submission_id}"),
                    crate::protocol::EventMsg::ListCustomPromptsResponse(
                        crate::protocol::ListCustomPromptsResponseEvent {
                            custom_prompts: Vec::new(),
                        },
                    ),
                )?;
            }
            crate::protocol::Op::ListModels => {
                let _ = app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "model/list",
                    json!({
                        "includeHidden": true,
                        "limit": 256,
                    }),
                )
                .map_err(|err| CodexError::new(format!("submit model/list failed: {err}")))?;
            }
            crate::protocol::Op::Compact => {
                app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "thread/compact/start",
                    json!({
                        "threadId": thread_id.to_string(),
                    }),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit thread/compact/start failed: {err}"))
                })?;
            }
            crate::protocol::Op::ThreadRollback { num_turns } => {
                app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "thread/rollback",
                    json!({
                        "threadId": thread_id.to_string(),
                        "numTurns": num_turns,
                    }),
                )
                .map_err(|err| CodexError::new(format!("submit thread/rollback failed: {err}")))?;
                self.push_local_event(
                    format!("seq-local-thread-rollback-{submission_id}"),
                    crate::protocol::EventMsg::ThreadRolledBack(
                        crate::protocol::ThreadRolledBackEvent { num_turns },
                    ),
                )?;
            }
            crate::protocol::Op::Review { review_request } => {
                app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "review/start",
                    json!({
                        "threadId": thread_id.to_string(),
                        "target": review_request.target,
                    }),
                )
                .map_err(|err| CodexError::new(format!("submit review/start failed: {err}")))?;
            }
            crate::protocol::Op::GetHistoryEntryRequest { offset, log_id } => {
                self.push_local_event(
                    format!("seq-local-history-entry-{submission_id}"),
                    crate::protocol::EventMsg::GetHistoryEntryResponse(
                        crate::protocol::GetHistoryEntryResponseEvent {
                            offset,
                            log_id,
                            entry: None,
                        },
                    ),
                )?;
            }
            crate::protocol::Op::ExecApproval { id, decision, .. } => {
                let approve = !matches!(decision, crate::protocol::ReviewDecision::Abort);
                let pending = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                    state.pending_server_requests.remove(&id)
                };
                let Some(pending) = pending else {
                    return Err(CodexError::new(format!(
                        "missing pending exec approval request mapping for id: {id}"
                    )));
                };
                let decision = match pending.method.as_str() {
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
                    &endpoint,
                    auth_token.as_deref(),
                    pending.request_id,
                    json!({ "decision": decision }),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit exec approval response failed: {err}"))
                })?;
            }
            crate::protocol::Op::PatchApproval { id, decision } => {
                let approve = !matches!(decision, crate::protocol::ReviewDecision::Abort);
                let pending = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                    state.pending_server_requests.remove(&id)
                };
                let Some(pending) = pending else {
                    return Err(CodexError::new(format!(
                        "missing pending patch approval request mapping for id: {id}"
                    )));
                };
                let decision = match pending.method.as_str() {
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
                    &endpoint,
                    auth_token.as_deref(),
                    pending.request_id,
                    json!({ "decision": decision }),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit patch approval response failed: {err}"))
                })?;
            }
            crate::protocol::Op::ResolveElicitation {
                request_id,
                decision,
                ..
            } => {
                let key = Self::request_id_to_key(&request_id);
                let pending = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                    state.pending_server_requests.remove(&key)
                };
                let Some(pending) = pending else {
                    return Err(CodexError::new(format!(
                        "missing pending elicitation request mapping for id: {key}"
                    )));
                };
                let decision = match decision {
                    crate::protocol::ElicitationAction::Accept => "accept",
                    crate::protocol::ElicitationAction::Decline => "decline",
                    crate::protocol::ElicitationAction::Cancel => "cancel",
                };
                app_server_rpc_respond(
                    &endpoint,
                    auth_token.as_deref(),
                    pending.request_id,
                    json!({ "decision": decision }),
                )
                .map_err(|err| {
                    CodexError::new(format!("submit elicitation response failed: {err}"))
                })?;
            }
            crate::protocol::Op::UserInputAnswer { id, response } => {
                let pending = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                    let key = state
                        .pending_request_user_input_by_turn_id
                        .get_mut(&id)
                        .and_then(|queue| queue.pop_front());
                    if let Some(queue) = state.pending_request_user_input_by_turn_id.get(&id)
                        && queue.is_empty()
                    {
                        state.pending_request_user_input_by_turn_id.remove(&id);
                    }
                    key.and_then(|key| state.pending_server_requests.remove(&key))
                };
                let Some(pending) = pending else {
                    return Err(CodexError::new(format!(
                        "missing pending request_user_input mapping for turn id: {id}"
                    )));
                };
                let result = serde_json::to_value(response).map_err(|err| {
                    CodexError::new(format!(
                        "serialize request_user_input response failed: {err}"
                    ))
                })?;
                app_server_rpc_respond(
                    &endpoint,
                    auth_token.as_deref(),
                    pending.request_id,
                    result,
                )
                .map_err(|err| {
                    CodexError::new(format!("submit request_user_input response failed: {err}"))
                })?;
            }
            crate::protocol::Op::DynamicToolResponse { .. }
            | crate::protocol::Op::Undo
            | crate::protocol::Op::DropMemories
            | crate::protocol::Op::UpdateMemories
            | crate::protocol::Op::AddToHistory { .. }
            | crate::protocol::Op::RefreshMcpServers { .. }
            | crate::protocol::Op::ReloadUserConfig => {
                return Err(CodexError::new(format!(
                    "op not supported by app-server shim yet: {}",
                    serde_json::to_string(&op).unwrap_or_else(|_| "<serialize op>".to_string())
                )));
            }
            crate::protocol::Op::SetThreadName { name } => {
                app_server_rpc_request_raw(
                    &endpoint,
                    auth_token.as_deref(),
                    "thread/name/set",
                    json!({
                        "threadId": thread_id.to_string(),
                        "name": name,
                    }),
                )
                .map_err(|err| CodexError::new(format!("submit thread/name/set failed: {err}")))?;
            }
            crate::protocol::Op::Shutdown => {
                // The app-server shim does not expose a dedicated shutdown RPC.
                // Mirror upstream TUI shutdown semantics by emitting a local
                // ShutdownComplete event so the app exit flow can proceed.
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                state.current_turn_id = None;
                Self::enqueue_pending_event(
                    &mut state,
                    crate::protocol::Event {
                        id: format!("seq-local-shutdown-{submission_id}"),
                        msg: crate::protocol::EventMsg::ShutdownComplete,
                    },
                );
            }
            _ => {
                return Err(CodexError::new(format!(
                    "op not handled by app-server shim: {}",
                    serde_json::to_string(&op).unwrap_or_else(|_| "<serialize op>".to_string())
                )));
            }
        }

        Ok(submission_id)
    }

    fn fallback_event_from_notification(
        sequence: u64,
        notification: &crabbot_protocol::DaemonRpcNotification,
    ) -> Option<crate::protocol::Event> {
        fn parse_user_message_item(
            item: &serde_json::Value,
        ) -> Option<(String, Vec<crate::user_input::TextElement>)> {
            let item_type = item
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let role = item
                .get("role")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let is_user_item = matches!(
                item_type.as_str(),
                "usermessage" | "user_message" | "user-message"
            ) || (item_type == "message" && role == "user");
            if !is_user_item {
                return None;
            }

            let text = item
                .get("text")
                .or_else(|| item.get("message"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
                .or_else(|| {
                    item.get("content")
                        .and_then(serde_json::Value::as_array)
                        .map(|content| {
                            content
                                .iter()
                                .filter_map(|entry| {
                                    entry.get("text").and_then(serde_json::Value::as_str)
                                })
                                .collect::<Vec<_>>()
                                .join("")
                        })
                        .filter(|text| !text.is_empty())
                })?;

            let text_elements = item
                .get("text_elements")
                .or_else(|| item.get("textElements"))
                .cloned()
                .and_then(|value| {
                    serde_json::from_value::<Vec<crate::user_input::TextElement>>(value).ok()
                })
                .or_else(|| {
                    item.get("content")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|content| {
                            content.iter().find_map(|entry| {
                                entry
                                    .get("text_elements")
                                    .or_else(|| entry.get("textElements"))
                                    .cloned()
                                    .and_then(|value| {
                                        serde_json::from_value::<
                                            Vec<crate::user_input::TextElement>,
                                        >(value)
                                        .ok()
                                    })
                            })
                        })
                })
                .unwrap_or_default();

            Some((text, text_elements))
        }

        match notification.method.as_str() {
            "turn/started" => notification
                .params
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .or_else(|| notification.params.get("turnId"))
                .and_then(Value::as_str)
                .map(|turn_id| crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::TurnStarted(
                        crate::protocol::TurnStartedEvent {
                            turn_id: turn_id.to_string(),
                            model_context_window: None,
                            collaboration_mode_kind: Default::default(),
                        },
                    ),
                }),
            "turn/completed" => {
                let turn_id = notification
                    .params
                    .get("turn")
                    .and_then(|turn| turn.get("id"))
                    .or_else(|| notification.params.get("turnId"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Some(crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::TurnComplete(
                        crate::protocol::TurnCompleteEvent {
                            turn_id,
                            last_agent_message: notification
                                .params
                                .get("lastAgentMessage")
                                .or_else(|| notification.params.get("last_agent_message"))
                                .or_else(|| {
                                    notification.params.get("turn").and_then(|turn| {
                                        turn.get("lastAgentMessage")
                                            .or_else(|| turn.get("last_agent_message"))
                                    })
                                })
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                        },
                    ),
                })
            }
            "item/agentMessage/delta"
            | "item/plan/delta"
            | "item/messageDelta"
            | "item/agent_message_delta" => notification
                .params
                .get("delta")
                .and_then(Value::as_str)
                .map(|delta| crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::AgentMessageDelta(
                        crate::protocol::AgentMessageDeltaEvent {
                            delta: delta.to_string(),
                        },
                    ),
                }),
            "turn/aborted" => Some(crate::protocol::Event {
                id: format!("seq-{sequence}"),
                msg: crate::protocol::EventMsg::TurnAborted(crate::protocol::TurnAbortedEvent {
                    turn_id: notification
                        .params
                        .get("turn")
                        .and_then(|turn| turn.get("id"))
                        .or_else(|| notification.params.get("turnId"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string),
                    reason: crate::protocol::TurnAbortReason::Interrupted,
                }),
            }),
            "turn/failed" => Some(crate::protocol::Event {
                id: format!("seq-{sequence}"),
                msg: crate::protocol::EventMsg::Error(crate::protocol::ErrorEvent {
                    message: "turn failed".to_string(),
                    codex_error_info: None,
                }),
            }),
            "item/completed" => {
                let item = notification.params.get("item")?;
                let item_type = item
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if item_type == "agent_message" || item_type == "agentmessage" {
                    let message = item
                        .get("text")
                        .or_else(|| item.get("message"))
                        .and_then(Value::as_str)
                        .map(ToString::to_string)?;
                    return Some(crate::protocol::Event {
                        id: format!("seq-{sequence}"),
                        msg: crate::protocol::EventMsg::AgentMessage(
                            crate::protocol::AgentMessageEvent {
                                message,
                                phase: None,
                            },
                        ),
                    });
                }
                if let Some((message, text_elements)) = parse_user_message_item(item) {
                    return Some(crate::protocol::Event {
                        id: format!("seq-{sequence}"),
                        msg: crate::protocol::EventMsg::UserMessage(
                            crate::protocol::UserMessageEvent {
                                message,
                                images: None,
                                local_images: Vec::new(),
                                text_elements,
                            },
                        ),
                    });
                }
                None
            }
            "thread/tokenUsage/updated" => {
                let info = crate::core_compat::parse_token_usage_updated(&notification.params)
                    .map(|(token_usage_info, _total)| token_usage_info);
                Some(crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::TokenCount(crate::protocol::TokenCountEvent {
                        info,
                        rate_limits: None,
                    }),
                })
            }
            "serverRequest/resolved" => Some(crate::protocol::Event {
                id: format!("seq-{sequence}"),
                msg: crate::protocol::EventMsg::BackgroundEvent(
                    crate::protocol::BackgroundEventEvent {
                        message: "server request resolved".to_string(),
                    },
                ),
            }),
            _ => None,
        }
    }

    fn command_vec_from_value(value: Option<&Value>) -> Vec<String> {
        match value {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect(),
            Some(Value::String(command)) => vec![command.clone()],
            _ => Vec::new(),
        }
    }

    fn fallback_events_from_server_request(
        sequence: u64,
        request: &crabbot_protocol::DaemonRpcServerRequest,
        state: &mut CodexThreadState,
    ) -> Vec<crate::protocol::Event> {
        let request_key = request_id_key_for_cli(&request.request_id);
        let turn_id = request
            .params
            .get("turnId")
            .or_else(|| request.params.get("turn_id"))
            .and_then(Value::as_str)
            .map(ToString::to_string);

        match request.method.as_str() {
            "item/commandExecution/requestApproval" | "execCommandApproval" => {
                let operation_id = request
                    .params
                    .get("id")
                    .or_else(|| request.params.get("callId"))
                    .or_else(|| request.params.get("itemId"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| request_key.clone());
                state.pending_server_requests.insert(
                    operation_id.clone(),
                    PendingServerRequest {
                        request_id: request.request_id.clone(),
                        method: request.method.clone(),
                        turn_id: turn_id.clone(),
                    },
                );
                let command = Self::command_vec_from_value(
                    request
                        .params
                        .get("command")
                        .or_else(|| request.params.get("cmd")),
                );
                let cwd = request
                    .params
                    .get("cwd")
                    .and_then(Value::as_str)
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| {
                        std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir())
                    });
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
                let proposed_execpolicy_amendment = request
                    .params
                    .get("proposedExecpolicyAmendment")
                    .or_else(|| request.params.get("proposed_execpolicy_amendment"))
                    .cloned();
                vec![crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::ExecApprovalRequest(
                        crate::protocol::ExecApprovalRequestEvent {
                            call_id: operation_id,
                            approval_id: request
                                .params
                                .get("approvalId")
                                .or_else(|| request.params.get("approval_id"))
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                            turn_id: turn_id.unwrap_or_default(),
                            command,
                            cwd,
                            reason,
                            network_approval_context,
                            proposed_execpolicy_amendment: proposed_execpolicy_amendment
                                .and_then(|value| serde_json::from_value(value).ok()),
                            proposed_network_policy_amendments: None,
                            additional_permissions: None,
                            available_decisions: None,
                            parsed_cmd: Vec::new(),
                        },
                    ),
                }]
            }
            "item/fileChange/requestApproval" | "applyPatchApproval" => {
                let operation_id = request
                    .params
                    .get("id")
                    .or_else(|| request.params.get("callId"))
                    .or_else(|| request.params.get("itemId"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or_else(|| request_key.clone());
                state.pending_server_requests.insert(
                    operation_id.clone(),
                    PendingServerRequest {
                        request_id: request.request_id.clone(),
                        method: request.method.clone(),
                        turn_id: turn_id.clone(),
                    },
                );
                let reason = request
                    .params
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let changes = request
                    .params
                    .get("changes")
                    .or_else(|| request.params.get("fileChanges"))
                    .cloned()
                    .and_then(|value| {
                        serde_json::from_value::<
                            HashMap<std::path::PathBuf, crate::protocol::FileChange>,
                        >(value)
                        .ok()
                    })
                    .unwrap_or_default();
                let grant_root = request
                    .params
                    .get("grantRoot")
                    .or_else(|| request.params.get("grant_root"))
                    .and_then(Value::as_str)
                    .map(std::path::PathBuf::from);
                vec![crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::ApplyPatchApprovalRequest(
                        crate::protocol::ApplyPatchApprovalRequestEvent {
                            call_id: operation_id,
                            turn_id: turn_id.unwrap_or_default(),
                            changes,
                            reason,
                            grant_root,
                        },
                    ),
                }]
            }
            "item/tool/elicit" | "item/mcpToolCall/requestApproval" => {
                let elicitation_request_id = request
                    .params
                    .get("requestId")
                    .or_else(|| request.params.get("request_id"))
                    .and_then(Value::as_str)
                    .map(|s| crate::mcp::RequestId::String(s.to_string()))
                    .unwrap_or_else(|| crate::mcp::RequestId::String(request_key.clone()));
                let elicitation_key = Self::request_id_to_key(&elicitation_request_id);
                state.pending_server_requests.insert(
                    elicitation_key,
                    PendingServerRequest {
                        request_id: request.request_id.clone(),
                        method: request.method.clone(),
                        turn_id: turn_id.clone(),
                    },
                );
                let server_name = request
                    .params
                    .get("serverName")
                    .or_else(|| request.params.get("server_name"))
                    .and_then(Value::as_str)
                    .unwrap_or("mcp")
                    .to_string();
                let message = request
                    .params
                    .get("message")
                    .or_else(|| request.params.get("prompt"))
                    .and_then(Value::as_str)
                    .unwrap_or("MCP tool needs your approval.")
                    .to_string();
                vec![crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::ElicitationRequest(
                        crate::protocol::ElicitationRequestEvent {
                            server_name,
                            id: elicitation_request_id,
                            message,
                        },
                    ),
                }]
            }
            "item/tool/requestUserInput" => {
                state.pending_server_requests.insert(
                    request_key.clone(),
                    PendingServerRequest {
                        request_id: request.request_id.clone(),
                        method: request.method.clone(),
                        turn_id: turn_id.clone(),
                    },
                );
                let turn_id = turn_id.unwrap_or_default();
                state
                    .pending_request_user_input_by_turn_id
                    .entry(turn_id.clone())
                    .or_default()
                    .push_back(request_key.clone());
                let call_id = request
                    .params
                    .get("callId")
                    .or_else(|| request.params.get("call_id"))
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
                    .unwrap_or(request_key);
                let questions = request
                    .params
                    .get("questions")
                    .cloned()
                    .and_then(|value| serde_json::from_value(value).ok())
                    .unwrap_or_default();
                vec![crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::RequestUserInput(
                        crate::request_user_input::RequestUserInputEvent {
                            call_id,
                            turn_id,
                            questions,
                        },
                    ),
                }]
            }
            _ => Vec::new(),
        }
    }

    pub async fn next_event(&self) -> Result<crate::protocol::Event, CodexError> {
        loop {
            if let Ok(mut state) = self.state.lock()
                && let Some(event) = state.pending_events.pop_front()
            {
                return Ok(event);
            }

            let (endpoint, auth_token, since_sequence) = {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                (
                    state.app_server_endpoint.clone(),
                    state.auth_token.clone(),
                    state.last_sequence,
                )
            };

            let envelopes =
                fetch_app_server_stream(&endpoint, auth_token.as_deref(), Some(since_sequence))
                    .map_err(|err| {
                        CodexError::new(format!("fetch app-server stream failed: {err}"))
                    })?;

            if !envelopes.is_empty() {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| CodexError::new("codex thread mutex poisoned"))?;
                for envelope in envelopes {
                    // Some stream backends can replay the latest envelope for the same cursor.
                    // Skip already-processed sequence numbers so intermediate UI lines stay idempotent.
                    if envelope.sequence <= state.last_sequence {
                        continue;
                    }
                    state.last_sequence = envelope.sequence;
                    match envelope.event {
                        crabbot_protocol::DaemonRpcStreamEvent::Notification(notification) => {
                            let resolved_request_key =
                                if notification.method == "serverRequest/resolved" {
                                    notification
                                        .params
                                        .get("requestId")
                                        .or_else(|| notification.params.get("request_id"))
                                        .map(|value| match value {
                                            Value::String(id) => Some(id.clone()),
                                            Value::Number(id) => Some(id.to_string()),
                                            _ => None,
                                        })
                                        .unwrap_or(None)
                                } else {
                                    None
                                };
                            let mapped = Self::fallback_event_from_notification(
                                envelope.sequence,
                                &notification,
                            );
                            if let Some(event) = mapped {
                                if let crate::protocol::EventMsg::TurnStarted(payload) = &event.msg
                                {
                                    if let Some(previous_turn_id) = state.current_turn_id.clone() {
                                        if previous_turn_id != payload.turn_id {
                                            Self::cleanup_pending_requests_for_turn(
                                                &mut state,
                                                &previous_turn_id,
                                            );
                                        }
                                    }
                                    state.current_turn_id = Some(payload.turn_id.clone());
                                } else if matches!(
                                    &event.msg,
                                    crate::protocol::EventMsg::TurnComplete(_)
                                        | crate::protocol::EventMsg::TurnAborted(_)
                                ) {
                                    if let crate::protocol::EventMsg::TurnComplete(payload) =
                                        &event.msg
                                    {
                                        Self::cleanup_pending_requests_for_turn(
                                            &mut state,
                                            &payload.turn_id,
                                        );
                                    } else if let crate::protocol::EventMsg::TurnAborted(payload) =
                                        &event.msg
                                        && let Some(turn_id) = payload.turn_id.as_deref()
                                    {
                                        Self::cleanup_pending_requests_for_turn(
                                            &mut state, turn_id,
                                        );
                                    }
                                    state.current_turn_id = None;
                                }
                                if let Some(request_key) = resolved_request_key.as_deref() {
                                    Self::cleanup_pending_request_by_key(&mut state, request_key);
                                }
                                Self::enqueue_pending_event(&mut state, event);
                            }
                        }
                        crabbot_protocol::DaemonRpcStreamEvent::ServerRequest(request) => {
                            let mapped = Self::fallback_events_from_server_request(
                                envelope.sequence,
                                &request,
                                &mut state,
                            );
                            for event in mapped {
                                Self::enqueue_pending_event(&mut state, event);
                            }
                        }
                        crabbot_protocol::DaemonRpcStreamEvent::DecodeError(err) => {
                            Self::enqueue_pending_event(
                                &mut state,
                                crate::protocol::Event {
                                    id: format!("seq-{}", envelope.sequence),
                                    msg: crate::protocol::EventMsg::Error(
                                        crate::protocol::ErrorEvent {
                                            message: format!(
                                                "app-server stream decode error: {}",
                                                err.message
                                            ),
                                            codex_error_info: None,
                                        },
                                    ),
                                },
                            );
                        }
                    }
                }
                if let Some(event) = state.pending_events.pop_front() {
                    return Ok(event);
                }
            }

            tokio::time::sleep(Duration::from_millis(40)).await;
        }
    }

    pub async fn config_snapshot(&self) -> ThreadConfigSnapshot {
        self.state
            .lock()
            .map(|state| state.config_snapshot.clone())
            .unwrap_or_else(|_| ThreadConfigSnapshot {
                model: "unknown".to_string(),
                model_provider_id: "openai".to_string(),
                approval_policy: crate::protocol::AskForApproval::OnRequest,
                sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                cwd: std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()),
                reasoning_effort: None,
                session_source: crate::protocol::SessionSource::Cli,
            })
    }

    pub fn rollout_path(&self) -> Option<std::path::PathBuf> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.rollout_path.clone())
    }
}

#[derive(Debug, Clone)]
pub struct NewThread {
    pub thread_id: ThreadId,
    pub thread: std::sync::Arc<CodexThread>,
    pub session_configured: crate::protocol::SessionConfiguredEvent,
}

#[derive(Debug, Clone)]
pub struct ThreadManager {
    models_manager: std::sync::Arc<crate::models_manager::manager::ModelsManager>,
    thread_created_tx: tokio::sync::broadcast::Sender<ThreadId>,
    threads: std::sync::Arc<Mutex<HashMap<ThreadId, std::sync::Arc<CodexThread>>>>,
}

fn thread_rpc_params_from_config(config: &crate::config::Config) -> Value {
    let approval_policy = match config.permissions.approval_policy.get() {
        crate::protocol::AskForApproval::UnlessTrusted => "untrusted",
        crate::protocol::AskForApproval::OnFailure => "on-failure",
        crate::protocol::AskForApproval::OnRequest => "on-request",
        crate::protocol::AskForApproval::Never => "never",
        crate::protocol::AskForApproval::Reject(_) => "on-request",
    };
    let sandbox = summarize_sandbox_policy(config.permissions.sandbox_policy.get());
    json!({
        "model": config.model,
        "cwd": config.cwd,
        "approvalPolicy": approval_policy,
        "sandbox": sandbox,
    })
}

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new(
            std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()),
            std::sync::Arc::new(crate::AuthManager::default()),
            crate::protocol::SessionSource::Cli,
            None,
            crate::models_manager::collaboration_mode_presets::CollaborationModesConfig::default(),
        )
    }
}

impl ThreadManager {
    pub fn new(
        _codex_home: std::path::PathBuf,
        _auth_manager: std::sync::Arc<crate::AuthManager>,
        _session_source: crate::protocol::SessionSource,
        _model_catalog: Option<serde_json::Value>,
        _collaboration_modes: crate::models_manager::collaboration_mode_presets::CollaborationModesConfig,
    ) -> Self {
        let (thread_created_tx, _) = tokio::sync::broadcast::channel(64);
        Self {
            models_manager: std::sync::Arc::new(crate::models_manager::manager::ModelsManager),
            thread_created_tx,
            threads: std::sync::Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn get_models_manager(
        &self,
    ) -> std::sync::Arc<crate::models_manager::manager::ModelsManager> {
        self.models_manager.clone()
    }

    pub fn subscribe_thread_created(&self) -> tokio::sync::broadcast::Receiver<ThreadId> {
        self.thread_created_tx.subscribe()
    }

    pub async fn get_thread(
        &self,
        thread_id: ThreadId,
    ) -> Result<std::sync::Arc<CodexThread>, CodexError> {
        let threads = self
            .threads
            .lock()
            .map_err(|_| CodexError::new("thread map mutex poisoned"))?;
        threads
            .get(&thread_id)
            .cloned()
            .ok_or_else(|| CodexError::new(format!("thread not found: {thread_id}")))
    }

    pub async fn remove_thread(&self, thread_id: &ThreadId) {
        if let Ok(mut threads) = self.threads.lock() {
            threads.remove(thread_id);
        }
    }

    pub async fn remove_and_close_all_threads(&self) -> Result<(), CodexError> {
        if let Ok(mut threads) = self.threads.lock() {
            threads.clear();
        }
        Ok(())
    }

    pub async fn start_thread(
        &self,
        config: crate::config::Config,
    ) -> Result<NewThread, CodexError> {
        let backend = get_shim_backend_config();
        let start_params = thread_rpc_params_from_config(&config);
        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/start",
            start_params,
        )
        .map_err(|err| CodexError::new(format!("thread/start failed: {err}")))?;

        let thread_id = extract_thread_id_from_rpc_result(&response.result)
            .and_then(|raw| ThreadId::from_string(&raw).ok())
            .unwrap_or_default();
        let model = response
            .result
            .get("thread")
            .and_then(|thread| thread.get("model"))
            .or_else(|| response.result.get("model"))
            .and_then(Value::as_str)
            .or(config.model.as_deref())
            .unwrap_or("unknown")
            .to_string();

        let config_snapshot = ThreadConfigSnapshot {
            model: model.clone(),
            model_provider_id: config.model_provider_id.clone(),
            approval_policy: config.permissions.approval_policy.value(),
            sandbox_policy: config.permissions.sandbox_policy.value(),
            cwd: config.cwd.clone(),
            reasoning_effort: config.model_reasoning_effort,
            session_source: crate::protocol::SessionSource::Cli,
        };
        let thread = std::sync::Arc::new(CodexThread::new(thread_id, config_snapshot, None));
        if let Ok(mut threads) = self.threads.lock() {
            threads.insert(thread_id, thread.clone());
        }
        let _ = self.thread_created_tx.send(thread_id);

        Ok(NewThread {
            thread_id,
            thread,
            session_configured: crate::protocol::SessionConfiguredEvent {
                session_id: thread_id,
                forked_from_id: None,
                thread_name: None,
                model,
                model_provider_id: config.model_provider_id,
                approval_policy: config.permissions.approval_policy.value(),
                sandbox_policy: config.permissions.sandbox_policy.value(),
                cwd: config.cwd,
                reasoning_effort: config.model_reasoning_effort,
                history_log_id: 0,
                history_entry_count: 0,
                initial_messages: None,
                network_proxy: None,
                rollout_path: None,
            },
        })
    }

    pub async fn resume_thread_from_rollout(
        &self,
        config: crate::config::Config,
        path: std::path::PathBuf,
        auth_manager: std::sync::Arc<crate::AuthManager>,
    ) -> Result<NewThread, CodexError> {
        let Some(thread_id) = extract_thread_id_from_picker_path(&path) else {
            return self.start_thread(config).await;
        };
        self.resume_thread(config, thread_id, auth_manager).await
    }

    pub async fn resume_thread(
        &self,
        config: crate::config::Config,
        thread_id: String,
        auth_manager: std::sync::Arc<crate::AuthManager>,
    ) -> Result<NewThread, CodexError> {
        let Some(thread_id) = ThreadId::from_string(&thread_id).ok() else {
            return self.start_thread(config).await;
        };
        let _ = auth_manager;
        let backend = get_shim_backend_config();
        let mut resume_params = thread_rpc_params_from_config(&config);
        resume_params["threadId"] = Value::String(thread_id.to_string());
        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/resume",
            resume_params,
        )
        .map_err(|err| CodexError::new(format!("thread/resume failed: {err}")))?;
        let model = response
            .result
            .get("thread")
            .and_then(|thread| thread.get("model"))
            .or_else(|| response.result.get("model"))
            .and_then(Value::as_str)
            .or(config.model.as_deref())
            .unwrap_or("unknown")
            .to_string();
        let initial_messages = parse_initial_messages_from_thread_rpc_result(&response.result);
        let config_snapshot = ThreadConfigSnapshot {
            model: model.clone(),
            model_provider_id: config.model_provider_id.clone(),
            approval_policy: config.permissions.approval_policy.value(),
            sandbox_policy: config.permissions.sandbox_policy.value(),
            cwd: config.cwd.clone(),
            reasoning_effort: config.model_reasoning_effort,
            session_source: crate::protocol::SessionSource::Cli,
        };
        let thread = std::sync::Arc::new(CodexThread::new(thread_id, config_snapshot, None));
        if let Ok(mut threads) = self.threads.lock() {
            threads.insert(thread_id, thread.clone());
        }
        let _ = self.thread_created_tx.send(thread_id);

        Ok(NewThread {
            thread_id,
            thread,
            session_configured: crate::protocol::SessionConfiguredEvent {
                session_id: thread_id,
                forked_from_id: None,
                thread_name: None,
                model,
                model_provider_id: config.model_provider_id,
                approval_policy: config.permissions.approval_policy.value(),
                sandbox_policy: config.permissions.sandbox_policy.value(),
                cwd: config.cwd,
                reasoning_effort: config.model_reasoning_effort,
                history_log_id: 0,
                history_entry_count: 0,
                initial_messages,
                network_proxy: None,
                rollout_path: None,
            },
        })
    }

    pub async fn fork_thread_from_id(
        &self,
        config: crate::config::Config,
        source_thread_id: String,
    ) -> Result<NewThread, CodexError> {
        let Some(source_thread_id) = ThreadId::from_string(&source_thread_id).ok() else {
            return self.start_thread(config).await;
        };
        self.fork_thread_inner(config, source_thread_id.to_string())
            .await
    }

    pub async fn fork_thread(
        &self,
        _history_len: usize,
        config: crate::config::Config,
        path: std::path::PathBuf,
        _skip_compaction: bool,
    ) -> Result<NewThread, CodexError> {
        let Some(source_thread_id) = extract_thread_id_from_picker_path(&path) else {
            return self.start_thread(config).await;
        };
        self.fork_thread_inner(config, source_thread_id).await
    }

    async fn fork_thread_inner(
        &self,
        config: crate::config::Config,
        source_thread_id: String,
    ) -> Result<NewThread, CodexError> {
        let backend = get_shim_backend_config();
        let mut fork_params = thread_rpc_params_from_config(&config);
        fork_params["threadId"] = Value::String(source_thread_id);
        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/fork",
            fork_params,
        )
        .map_err(|err| CodexError::new(format!("thread/fork failed: {err}")))?;

        let thread_id = extract_thread_id_from_rpc_result(&response.result)
            .and_then(|raw| ThreadId::from_string(&raw).ok())
            .unwrap_or_default();
        let model = response
            .result
            .get("thread")
            .and_then(|thread| thread.get("model"))
            .or_else(|| response.result.get("model"))
            .and_then(Value::as_str)
            .or(config.model.as_deref())
            .unwrap_or("unknown")
            .to_string();
        let initial_messages = parse_initial_messages_from_thread_rpc_result(&response.result);
        let config_snapshot = ThreadConfigSnapshot {
            model: model.clone(),
            model_provider_id: config.model_provider_id.clone(),
            approval_policy: config.permissions.approval_policy.value(),
            sandbox_policy: config.permissions.sandbox_policy.value(),
            cwd: config.cwd.clone(),
            reasoning_effort: config.model_reasoning_effort,
            session_source: crate::protocol::SessionSource::Cli,
        };
        let thread = std::sync::Arc::new(CodexThread::new(thread_id, config_snapshot, None));
        if let Ok(mut threads) = self.threads.lock() {
            threads.insert(thread_id, thread.clone());
        }
        let _ = self.thread_created_tx.send(thread_id);

        Ok(NewThread {
            thread_id,
            thread,
            session_configured: crate::protocol::SessionConfiguredEvent {
                session_id: thread_id,
                forked_from_id: None,
                thread_name: None,
                model,
                model_provider_id: config.model_provider_id,
                approval_policy: config.permissions.approval_policy.value(),
                sandbox_policy: config.permissions.sandbox_policy.value(),
                cwd: config.cwd,
                reasoning_effort: config.model_reasoning_effort,
                history_log_id: 0,
                history_entry_count: 0,
                initial_messages,
                network_proxy: None,
                rollout_path: None,
            },
        })
    }
}

pub type Cursor = String;
pub const INTERACTIVE_SESSION_SOURCES: &[crate::protocol::SessionSource] =
    &[crate::protocol::SessionSource::Cli];

#[derive(Debug, Clone, Default)]
pub struct ThreadItem {
    pub path: std::path::PathBuf,
    pub thread_id: Option<ThreadId>,
    pub first_user_message: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub cwd: Option<std::path::PathBuf>,
    pub git_branch: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ThreadsPage {
    pub items: Vec<ThreadItem>,
    pub next_cursor: Option<Cursor>,
    pub num_scanned_files: usize,
    pub reached_scan_cap: bool,
}

pub struct RolloutRecorder;

impl RolloutRecorder {
    #[allow(clippy::too_many_arguments)]
    pub async fn list_threads(
        _config: &crate::config::Config,
        limit: usize,
        cursor: Option<&Cursor>,
        sort_key: crate::ThreadSortKey,
        _sources: &[crate::protocol::SessionSource],
        _provider_filter: Option<&[String]>,
        _default_provider: &str,
        _include_archived: Option<bool>,
    ) -> std::io::Result<ThreadsPage> {
        let backend = get_shim_backend_config();
        let sort_key = match sort_key {
            crate::ThreadSortKey::CreatedAt => "created_at",
            crate::ThreadSortKey::UpdatedAt => "updated_at",
        };
        let mut params = json!({
            "sortKey": sort_key,
            "limit": limit,
            "archived": false,
        });
        if let Some(cursor) = cursor {
            params["cursor"] = Value::String(cursor.clone());
        }

        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/list",
            params,
        )
        .map_err(|err| std::io::Error::other(err.to_string()))?;

        let rows = response
            .result
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        fn normalize_timestamp(value: Option<&Value>) -> Option<String> {
            match value {
                Some(Value::String(text)) => Some(text.to_string()),
                Some(Value::Number(number)) => {
                    let raw = number.as_i64()?;
                    // Accept both seconds and milliseconds.
                    let millis = if raw.abs() >= 1_000_000_000_000 {
                        raw
                    } else {
                        raw.saturating_mul(1000)
                    };
                    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(millis)
                        .map(|dt| dt.to_rfc3339())
                }
                _ => None,
            }
        }

        let items = rows
            .into_iter()
            .filter_map(|row| {
                let id = row
                    .get("id")
                    .and_then(Value::as_str)
                    .map(std::borrow::ToOwned::to_owned)?;
                let preview = row
                    .get("threadName")
                    .or_else(|| row.get("preview"))
                    .or_else(|| row.get("firstUserMessage"))
                    .and_then(Value::as_str)
                    .map(std::borrow::ToOwned::to_owned);
                let path = row
                    .get("rolloutPath")
                    .or_else(|| row.get("path"))
                    .and_then(Value::as_str)
                    .map(PathBuf::from)
                    .filter(|candidate| extract_thread_id_from_picker_path(candidate).is_some())
                    .unwrap_or_else(|| PathBuf::from(id.clone()));
                let thread_id = ThreadId::from_string(&id).ok();
                let created_at = normalize_timestamp(
                    row.get("createdAt")
                        .or_else(|| row.get("created_at"))
                        .or_else(|| row.get("created")),
                );
                let updated_at = normalize_timestamp(
                    row.get("updatedAt")
                        .or_else(|| row.get("updated_at"))
                        .or_else(|| row.get("updated")),
                );
                let cwd = row.get("cwd").and_then(Value::as_str).map(PathBuf::from);
                let git_branch = row
                    .get("gitBranch")
                    .or_else(|| row.get("git_branch"))
                    .or_else(|| row.get("gitInfo").and_then(|info| info.get("branch")))
                    .or_else(|| row.get("git_info").and_then(|info| info.get("branch")))
                    .and_then(Value::as_str)
                    .map(std::borrow::ToOwned::to_owned);
                Some(ThreadItem {
                    path,
                    thread_id,
                    first_user_message: preview,
                    created_at,
                    updated_at,
                    cwd,
                    git_branch,
                })
            })
            .collect::<Vec<_>>();

        let next_cursor = response
            .result
            .get("nextCursor")
            .or_else(|| response.result.get("next_cursor"))
            .and_then(Value::as_str)
            .map(std::borrow::ToOwned::to_owned);
        let num_scanned_files = response
            .result
            .get("numScannedFiles")
            .or_else(|| response.result.get("num_scanned_files"))
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or(items.len());
        let reached_scan_cap = response
            .result
            .get("reachedScanCap")
            .or_else(|| response.result.get("reached_scan_cap"))
            .and_then(Value::as_bool)
            .unwrap_or(false);

        Ok(ThreadsPage {
            items,
            next_cursor,
            num_scanned_files,
            reached_scan_cap,
        })
    }
}

pub async fn find_thread_name_by_id(
    _codex_home: &std::path::Path,
    _thread_id: &ThreadId,
) -> std::io::Result<Option<String>> {
    Ok(None)
}

pub async fn find_thread_names_by_ids(
    _codex_home: &std::path::Path,
    _thread_ids: &std::collections::HashSet<ThreadId>,
) -> std::io::Result<std::collections::HashMap<ThreadId, String>> {
    Ok(std::collections::HashMap::new())
}

pub mod bash {
    pub fn extract_bash_command(command: &[String]) -> Option<(&str, &str)> {
        crate::parse_command::extract_shell_command(command)
    }
}

pub mod web_search {
    pub fn web_search_detail(
        action: Option<&crate::models::WebSearchAction>,
        query: &str,
    ) -> String {
        let _ = action;
        query.to_string()
    }
}

pub mod util {
    pub fn resume_command(
        thread_name: Option<&str>,
        thread_id: Option<crate::ThreadId>,
    ) -> Option<String> {
        match (thread_name, thread_id) {
            (Some(name), _) => Some(format!("crab resume {name}")),
            (None, Some(id)) => Some(format!("crab resume {id}")),
            _ => None,
        }
    }

    pub fn normalize_thread_name(name: &str) -> Option<String> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

pub mod review_prompts {
    pub fn user_facing_hint(_target: &crate::protocol::ReviewTarget) -> String {
        "Review requested".to_string()
    }
}

pub mod default_client {
    #[derive(Debug, Clone)]
    pub struct Originator {
        pub value: String,
    }

    pub fn originator() -> Originator {
        Originator {
            value: "crabbot".to_string(),
        }
    }
}

pub mod git_info {
    use std::path::Path;
    use std::path::PathBuf;

    #[derive(Debug, Clone)]
    pub struct CommitLogEntry {
        pub sha: String,
        pub subject: String,
    }

    pub fn get_git_repo_root(base_dir: &Path) -> Option<PathBuf> {
        let mut dir = base_dir.to_path_buf();
        loop {
            if dir.join(".git").exists() {
                return Some(dir);
            }
            if !dir.pop() {
                break;
            }
        }
        None
    }

    pub fn resolve_root_git_project_for_trust(base_dir: &Path) -> Option<PathBuf> {
        get_git_repo_root(base_dir)
    }

    pub async fn current_branch_name(_cwd: &Path) -> Option<String> {
        None
    }

    pub async fn local_git_branches(_cwd: &Path) -> Vec<String> {
        Vec::new()
    }

    pub async fn recent_commits(_cwd: &Path, _limit: usize) -> Vec<CommitLogEntry> {
        Vec::new()
    }
}

pub mod path_utils {
    use std::path::Path;
    use std::path::PathBuf;

    pub fn normalize_for_path_comparison(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
        path.as_ref().canonicalize()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadSortKey {
    CreatedAt,
    UpdatedAt,
}

pub mod parse_command {
    pub use codex_protocol::parse_command::*;
    pub fn extract_shell_command(command: &[String]) -> Option<(&str, &str)> {
        if command.len() >= 3 {
            let shell = command[0].as_str();
            let basename = shell.rsplit('/').next().unwrap_or(shell);
            let flag = command[1].as_str();
            if matches!(basename, "bash" | "zsh" | "sh" | "fish" | "dash")
                && matches!(flag, "-c" | "-lc" | "-ic")
            {
                return Some((basename, command[2].as_str()));
            }
        }
        None
    }
}

pub mod features {
    use std::collections::HashSet;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum Feature {
        CollaborationModes,
        Personality,
        Apps,
        RealtimeConversation,
        VoiceTranscription,
        PreventIdleSleep,
        RuntimeMetrics,
        GhostCommit,
        ShellTool,
        JsRepl,
        UnifiedExec,
        ApplyPatchFreeform,
        WebSearchRequest,
        WebSearchCached,
        SearchTool,
        UseLinuxSandboxBwrap,
        RequestRule,
        DefaultModeRequestUserInput,
        WindowsSandbox,
        WindowsSandboxElevated,
        Steer,
    }

    impl Feature {
        fn info(self) -> &'static FeatureSpec {
            FEATURES
                .iter()
                .find(|spec| spec.id == self)
                .unwrap_or_else(|| unreachable!("missing FeatureSpec for {:?}", self))
        }

        pub fn key(self) -> &'static str {
            self.info().key
        }
        pub fn from_key(key: &str) -> Option<Self> {
            FEATURES
                .iter()
                .find(|spec| spec.key == key)
                .map(|spec| spec.id)
        }

        pub fn default_enabled(self) -> bool {
            self.info().default_enabled
        }
    }

    pub struct FeatureSpec {
        pub id: Feature,
        pub key: &'static str,
        pub default_enabled: bool,
        pub stage: FeatureStage,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum FeatureStage {
        Stable,
        Experimental(&'static str, &'static str),
    }

    impl FeatureStage {
        pub fn experimental_announcement(&self) -> Option<&'static str> {
            match self {
                FeatureStage::Experimental(msg, _) => Some(msg),
                _ => None,
            }
        }
        pub fn experimental_menu_name(&self) -> Option<&'static str> {
            match self {
                FeatureStage::Experimental(_, name) => Some(name),
                _ => None,
            }
        }
        pub fn experimental_menu_description(&self) -> Option<&'static str> {
            self.experimental_announcement()
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct Features {
        enabled: HashSet<Feature>,
    }

    impl Features {
        pub fn with_defaults() -> Self {
            let mut enabled = HashSet::new();
            for spec in FEATURES {
                if spec.default_enabled {
                    enabled.insert(spec.id);
                }
            }
            Self { enabled }
        }
        pub fn enabled(&self, feature: Feature) -> bool {
            self.enabled.contains(&feature)
        }
        pub fn is_enabled(&self, feature: Feature) -> bool {
            self.enabled(feature)
        }
        pub fn enable(&mut self, feature: Feature) {
            self.enabled.insert(feature);
        }
        pub fn disable(&mut self, feature: Feature) {
            self.enabled.remove(&feature);
        }
    }

    pub static FEATURES: &[FeatureSpec] = &[
        FeatureSpec {
            id: Feature::CollaborationModes,
            key: "collaboration_modes",
            default_enabled: true,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::Personality,
            key: "personality",
            default_enabled: true,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::Apps,
            key: "apps",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::RealtimeConversation,
            key: "realtime_conversation",
            default_enabled: false,
            stage: FeatureStage::Experimental(
                "Realtime conversation is still experimental.",
                "Realtime conversation",
            ),
        },
        FeatureSpec {
            id: Feature::VoiceTranscription,
            key: "voice_transcription",
            default_enabled: false,
            stage: FeatureStage::Experimental(
                "Voice transcription is still experimental.",
                "Voice transcription",
            ),
        },
        FeatureSpec {
            id: Feature::PreventIdleSleep,
            key: "prevent_idle_sleep",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::RuntimeMetrics,
            key: "runtime_metrics",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::GhostCommit,
            key: "ghost_commit",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::ShellTool,
            key: "shell_tool",
            default_enabled: true,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::JsRepl,
            key: "js_repl",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::UnifiedExec,
            key: "unified_exec",
            default_enabled: !cfg!(windows),
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::ApplyPatchFreeform,
            key: "apply_patch_freeform",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::WebSearchRequest,
            key: "web_search_request",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::WebSearchCached,
            key: "web_search_cached",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::SearchTool,
            key: "search_tool",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::UseLinuxSandboxBwrap,
            key: "use_linux_sandbox_bwrap",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::RequestRule,
            key: "request_rule",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::DefaultModeRequestUserInput,
            key: "default_mode_request_user_input",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::WindowsSandbox,
            key: "windows_sandbox",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::WindowsSandboxElevated,
            key: "windows_sandbox_elevated",
            default_enabled: false,
            stage: FeatureStage::Stable,
        },
        FeatureSpec {
            id: Feature::Steer,
            key: "steer",
            default_enabled: true,
            stage: FeatureStage::Stable,
        },
    ];
}

pub mod skills {
    pub mod model {
        pub use codex_protocol::protocol::SkillDependencies;
        pub use codex_protocol::protocol::SkillInterface;
        pub use codex_protocol::protocol::SkillToolDependency;

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
        pub struct SkillMetadata {
            pub name: String,
            pub description: String,
            pub short_description: Option<String>,
            pub interface: Option<SkillInterface>,
            pub dependencies: Option<SkillDependencies>,
            pub policy: Option<serde_json::Value>,
            pub permission_profile: Option<serde_json::Value>,
            pub permissions: Option<serde_json::Value>,
            pub path_to_skills_md: std::path::PathBuf,
            pub scope: codex_protocol::protocol::SkillScope,
        }
    }
}

pub mod protocol {
    pub use codex_protocol::approvals::ApplyPatchApprovalRequestEvent;
    pub use codex_protocol::approvals::ElicitationAction;
    pub use codex_protocol::approvals::ElicitationRequestEvent;
    pub use codex_protocol::approvals::ExecApprovalRequestEvent;
    pub use codex_protocol::approvals::NetworkApprovalContext;
    pub use codex_protocol::mcp::RequestId;
    pub use codex_protocol::protocol::*;
}

pub mod models {
    pub use codex_protocol::models::*;
    pub type PermissionProfile = serde_json::Value;
}

pub mod user_input {
    pub use codex_protocol::user_input::*;
    pub const MAX_USER_INPUT_TEXT_CHARS: usize = 32000;
}

pub mod request_user_input {
    pub use codex_protocol::request_user_input::*;
}

pub mod openai_models {
    pub use codex_protocol::openai_models::*;
}

pub mod config_types {
    pub use codex_protocol::config_types::*;
}

pub mod mcp {
    pub use codex_protocol::mcp::*;
}

pub mod plan_tool {
    pub use codex_protocol::plan_tool::*;
}

pub mod custom_prompts {
    pub use codex_protocol::custom_prompts::*;
}

pub mod account {
    pub use codex_protocol::account::*;
}

pub mod items {
    pub use codex_protocol::items::*;
}

pub mod test_support {
    use std::sync::LazyLock;

    pub static ALL_MODEL_PRESETS: LazyLock<Vec<codex_protocol::openai_models::ModelPreset>> =
        LazyLock::new(Vec::new);

    pub fn all_model_presets() -> &'static Vec<codex_protocol::openai_models::ModelPreset> {
        &ALL_MODEL_PRESETS
    }
}

pub mod connectors {
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, PartialEq, Eq)]
    pub struct AppInfo {
        pub id: String,
        pub name: String,
        pub description: Option<String>,
        pub logo_url: Option<String>,
        pub logo_url_dark: Option<String>,
        pub distribution_channel: Option<String>,
        pub branding: Option<serde_json::Value>,
        pub app_metadata: Option<serde_json::Value>,
        pub labels: Option<serde_json::Value>,
        pub install_url: Option<String>,
        pub is_accessible: bool,
        pub is_enabled: bool,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct AccessibleConnectorsStatus {
        pub connectors: Vec<AppInfo>,
        pub codex_apps_ready: bool,
    }

    pub fn connector_display_label(connector: &AppInfo) -> String {
        connector.name.clone()
    }

    pub fn connector_mention_slug(connector: &AppInfo) -> String {
        let mut normalized = String::with_capacity(connector.name.len());
        for character in connector.name.chars() {
            if character.is_ascii_alphanumeric() {
                normalized.push(character.to_ascii_lowercase());
            } else {
                normalized.push('-');
            }
        }
        let normalized = normalized.trim_matches('-');
        if normalized.is_empty() {
            "app".to_string()
        } else {
            normalized.to_string()
        }
    }

    pub async fn list_accessible_connectors_from_mcp_tools_with_options(
        _config: &crate::config::Config,
        _force_refetch: bool,
    ) -> anyhow::Result<Vec<AppInfo>> {
        let backend = crate::get_shim_backend_config();
        let mut state = crate::CliState::default();
        state.config.app_server_endpoint = backend.app_server_endpoint;
        state.config.auth_token = backend.auth_token;
        let connectors = crate::core_compat::list_connectors(&state)?;
        Ok(connectors
            .into_iter()
            .filter(|connector| connector.is_accessible)
            .collect())
    }

    pub async fn list_accessible_connectors_from_mcp_tools_with_options_and_status(
        config: &crate::config::Config,
        force_refetch: bool,
    ) -> anyhow::Result<AccessibleConnectorsStatus> {
        let connectors =
            list_accessible_connectors_from_mcp_tools_with_options(config, force_refetch).await?;
        Ok(AccessibleConnectorsStatus {
            connectors,
            codex_apps_ready: true,
        })
    }

    pub async fn list_all_connectors(
        _config: &crate::config::Config,
    ) -> anyhow::Result<Vec<AppInfo>> {
        let backend = crate::get_shim_backend_config();
        let mut state = crate::CliState::default();
        state.config.app_server_endpoint = backend.app_server_endpoint;
        state.config.auth_token = backend.auth_token;
        crate::core_compat::list_connectors(&state)
    }

    pub async fn list_all_connectors_with_options(
        config: &crate::config::Config,
        _force_refetch: bool,
    ) -> anyhow::Result<Vec<AppInfo>> {
        list_all_connectors(config).await
    }

    pub fn merge_connectors_with_accessible(
        mut all_connectors: Vec<AppInfo>,
        accessible_connectors: Vec<AppInfo>,
        allow_inaccessible: bool,
    ) -> Vec<AppInfo> {
        let mut by_id = std::collections::HashMap::new();
        for connector in all_connectors.drain(..) {
            by_id.insert(connector.id.clone(), connector);
        }
        for accessible in accessible_connectors {
            by_id.insert(accessible.id.clone(), accessible);
        }
        let mut connectors: Vec<AppInfo> = by_id.into_values().collect();
        if !allow_inaccessible {
            connectors.retain(|connector| connector.is_accessible);
        }
        connectors.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        connectors
    }

    pub fn with_app_enabled_state(
        connectors: Vec<AppInfo>,
        _config: &crate::config::Config,
    ) -> Vec<AppInfo> {
        connectors
    }
}

pub fn ansi_escape_line(input: &str) -> ratatui::text::Line<'static> {
    ratatui::text::Line::from(input.to_string())
}

#[derive(Debug, Clone, Default)]
pub struct CodexFeedback;

impl CodexFeedback {
    pub fn new() -> Self {
        Self
    }

    pub fn snapshot(&self, _session_id: Option<ThreadId>) -> CodexLogSnapshot {
        CodexLogSnapshot {
            thread_id: ThreadId::new().to_string(),
        }
    }
}

pub fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    let rem = secs % 60;
    if rem == 0 {
        format!("{mins}m")
    } else {
        format!("{mins}m {rem}s")
    }
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeMetricCounter {
    pub count: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct RuntimeMetricsSummary {
    pub tool_calls: RuntimeMetricCounter,
    pub api_calls: RuntimeMetricCounter,
    pub websocket_calls: RuntimeMetricCounter,
    pub streaming_events: RuntimeMetricCounter,
    pub websocket_events: RuntimeMetricCounter,
    pub responses_api_overhead_ms: u64,
    pub responses_api_inference_time_ms: u64,
    pub responses_api_engine_iapi_ttft_ms: u64,
    pub responses_api_engine_service_ttft_ms: u64,
    pub responses_api_engine_iapi_tbt_ms: u64,
    pub responses_api_engine_service_tbt_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum TelemetryAuthMode {
    ApiKey,
    Chatgpt,
    None,
}

impl From<auth::AuthMode> for TelemetryAuthMode {
    fn from(value: auth::AuthMode) -> Self {
        match value {
            auth::AuthMode::ApiKey => Self::ApiKey,
            auth::AuthMode::Chatgpt => Self::Chatgpt,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OtelManager;

impl OtelManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        _conversation_id: ThreadId,
        _model: &str,
        _slug: &str,
        _account_id: Option<String>,
        _account_email: Option<String>,
        _auth_mode: Option<TelemetryAuthMode>,
        _originator: String,
        _log_user_prompts: bool,
        _terminal_type: String,
        _session_source: crate::protocol::SessionSource,
    ) -> Self {
        Self
    }

    pub fn set_auth_mode(_mode: TelemetryAuthMode) {}
    pub fn counter(&self, _name: &str, _inc: i64, _tags: &[(&str, &str)]) {}
    pub fn record_duration(
        &self,
        _name: &str,
        _duration: std::time::Duration,
        _tags: &[(&str, &str)],
    ) {
    }
    pub fn reset_runtime_metrics(&self) {}
    pub fn runtime_metrics_summary(&self) -> Option<RuntimeMetricsSummary> {
        None
    }
}

impl RuntimeMetricsSummary {
    pub fn is_empty(self) -> bool {
        self.tool_calls.count == 0
            && self.tool_calls.duration_ms == 0
            && self.api_calls.count == 0
            && self.api_calls.duration_ms == 0
            && self.websocket_calls.count == 0
            && self.websocket_calls.duration_ms == 0
            && self.streaming_events.count == 0
            && self.streaming_events.duration_ms == 0
            && self.websocket_events.count == 0
            && self.websocket_events.duration_ms == 0
            && self.responses_api_overhead_ms == 0
            && self.responses_api_inference_time_ms == 0
            && self.responses_api_engine_iapi_ttft_ms == 0
            && self.responses_api_engine_service_ttft_ms == 0
            && self.responses_api_engine_iapi_tbt_ms == 0
            && self.responses_api_engine_service_tbt_ms == 0
    }

    pub fn merge(&mut self, other: Self) {
        self.tool_calls.count = self.tool_calls.count.saturating_add(other.tool_calls.count);
        self.tool_calls.duration_ms = self
            .tool_calls
            .duration_ms
            .saturating_add(other.tool_calls.duration_ms);
        self.api_calls.count = self.api_calls.count.saturating_add(other.api_calls.count);
        self.api_calls.duration_ms = self
            .api_calls
            .duration_ms
            .saturating_add(other.api_calls.duration_ms);
        self.websocket_calls.count = self
            .websocket_calls
            .count
            .saturating_add(other.websocket_calls.count);
        self.websocket_calls.duration_ms = self
            .websocket_calls
            .duration_ms
            .saturating_add(other.websocket_calls.duration_ms);
        self.streaming_events.count = self
            .streaming_events
            .count
            .saturating_add(other.streaming_events.count);
        self.streaming_events.duration_ms = self
            .streaming_events
            .duration_ms
            .saturating_add(other.streaming_events.duration_ms);
        self.websocket_events.count = self
            .websocket_events
            .count
            .saturating_add(other.websocket_events.count);
        self.websocket_events.duration_ms = self
            .websocket_events
            .duration_ms
            .saturating_add(other.websocket_events.duration_ms);
        self.responses_api_overhead_ms = other.responses_api_overhead_ms;
        self.responses_api_inference_time_ms = other.responses_api_inference_time_ms;
        self.responses_api_engine_iapi_ttft_ms = other.responses_api_engine_iapi_ttft_ms;
        self.responses_api_engine_service_ttft_ms = other.responses_api_engine_service_ttft_ms;
        self.responses_api_engine_iapi_tbt_ms = other.responses_api_engine_iapi_tbt_ms;
        self.responses_api_engine_service_tbt_ms = other.responses_api_engine_service_tbt_ms;
    }

    pub fn responses_api_summary(&self) -> Self {
        Self {
            responses_api_overhead_ms: self.responses_api_overhead_ms,
            responses_api_inference_time_ms: self.responses_api_inference_time_ms,
            responses_api_engine_iapi_ttft_ms: self.responses_api_engine_iapi_ttft_ms,
            responses_api_engine_service_ttft_ms: self.responses_api_engine_service_ttft_ms,
            responses_api_engine_iapi_tbt_ms: self.responses_api_engine_iapi_tbt_ms,
            responses_api_engine_service_tbt_ms: self.responses_api_engine_service_tbt_ms,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct AbsolutePathBuf(pub std::path::PathBuf);

impl AbsolutePathBuf {
    pub fn current_dir() -> std::io::Result<Self> {
        Ok(Self(std::env::current_dir()?))
    }
    pub fn from_absolute_path(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        Ok(Self(path.as_ref().to_path_buf()))
    }
    pub fn as_path(&self) -> &std::path::Path {
        &self.0
    }
    pub fn into_path_buf(self) -> std::path::PathBuf {
        self.0
    }
    pub fn resolve_path_against_base(
        relative: impl AsRef<std::path::Path>,
        base: impl AsRef<std::path::Path>,
    ) -> std::io::Result<Self> {
        let path = if relative.as_ref().is_absolute() {
            relative.as_ref().to_path_buf()
        } else {
            base.as_ref().join(relative)
        };
        Ok(Self(path))
    }
}

impl std::ops::Deref for AbsolutePathBuf {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        self.0.as_path()
    }
}

pub mod config_loader {
    use std::collections::BTreeMap;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RequirementSource {
        Unknown,
        CloudRequirements,
        LegacyManagedConfigTomlFromMdm,
        LegacyManagedConfigTomlFromFile { file: crate::AbsolutePathBuf },
        SystemRequirementsToml { file: crate::AbsolutePathBuf },
        MdmManagedPreferences { domain: String, key: String },
    }

    impl std::fmt::Display for RequirementSource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RequirementSource::Unknown => f.write_str("<unspecified>"),
                RequirementSource::CloudRequirements => f.write_str("cloud requirements"),
                RequirementSource::LegacyManagedConfigTomlFromMdm => {
                    f.write_str("MDM managed_config.toml (legacy)")
                }
                RequirementSource::LegacyManagedConfigTomlFromFile { file } => {
                    write!(f, "{}", file.as_path().display())
                }
                RequirementSource::SystemRequirementsToml { file } => {
                    write!(f, "{}", file.as_path().display())
                }
                RequirementSource::MdmManagedPreferences { domain, key } => {
                    write!(f, "MDM {domain}:{key}")
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ResidencyRequirement {
        Us,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SandboxModeRequirement {
        ReadOnly,
        WorkspaceWrite,
        DangerFullAccess,
        ExternalSandbox,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WebSearchModeRequirement {
        Disabled,
        Cached,
        Live,
    }

    impl std::fmt::Display for WebSearchModeRequirement {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Disabled => f.write_str("disabled"),
                Self::Cached => f.write_str("cached"),
                Self::Live => f.write_str("live"),
            }
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct NetworkConstraints {
        pub enabled: Option<bool>,
        pub http_port: Option<u16>,
        pub socks_port: Option<u16>,
        pub allow_upstream_proxy: Option<bool>,
        pub dangerously_allow_non_loopback_proxy: Option<bool>,
        pub dangerously_allow_non_loopback_admin: Option<bool>,
        pub dangerously_allow_all_unix_sockets: Option<bool>,
        pub allowed_domains: Option<Vec<String>>,
        pub denied_domains: Option<Vec<String>>,
        pub allow_unix_sockets: Option<Vec<String>>,
        pub allow_local_binding: Option<bool>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct Sourced<T> {
        pub value: T,
        pub source: RequirementSource,
    }

    impl<T> Sourced<T> {
        pub fn new(value: T, source: RequirementSource) -> Self {
            Self { value, source }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ConstrainedWithSource<T> {
        pub value: crate::config::ValueRef<T>,
        pub source: Option<RequirementSource>,
    }

    impl<T> ConstrainedWithSource<T> {
        pub fn new(value: crate::config::ValueRef<T>, source: Option<RequirementSource>) -> Self {
            Self { value, source }
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ConfigRequirements {
        pub approval_policy: ConstrainedWithSource<crate::protocol::AskForApproval>,
        pub sandbox_policy: ConstrainedWithSource<crate::protocol::SandboxPolicy>,
        pub web_search_mode: ConstrainedWithSource<codex_protocol::config_types::WebSearchMode>,
        pub mcp_servers: Option<Sourced<BTreeMap<String, McpServerRequirement>>>,
        pub enforce_residency: ConstrainedWithSource<Option<ResidencyRequirement>>,
        pub network: Option<Sourced<NetworkConstraints>>,
    }

    impl Default for ConfigRequirements {
        fn default() -> Self {
            Self {
                approval_policy: ConstrainedWithSource {
                    value: crate::config::ValueRef(crate::protocol::AskForApproval::OnRequest),
                    source: None,
                },
                sandbox_policy: ConstrainedWithSource {
                    value: crate::config::ValueRef(
                        crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                    ),
                    source: None,
                },
                web_search_mode: ConstrainedWithSource {
                    value: crate::config::ValueRef(
                        codex_protocol::config_types::WebSearchMode::Cached,
                    ),
                    source: None,
                },
                mcp_servers: None,
                enforce_residency: ConstrainedWithSource {
                    value: crate::config::ValueRef(None),
                    source: None,
                },
                network: None,
            }
        }
    }

    impl ConfigRequirements {
        pub fn exec_policy_source(&self) -> Option<&RequirementSource> {
            None
        }
    }

    #[derive(Debug, Clone, Default, PartialEq)]
    pub struct ConfigRequirementsToml {
        pub allowed_approval_policies: Option<Vec<crate::protocol::AskForApproval>>,
        pub allowed_sandbox_modes: Option<Vec<SandboxModeRequirement>>,
        pub allowed_web_search_modes: Option<Vec<WebSearchModeRequirement>>,
        pub mcp_servers: Option<BTreeMap<String, McpServerRequirement>>,
        pub rules: Option<serde_json::Value>,
        pub enforce_residency: Option<ResidencyRequirement>,
        pub network: Option<NetworkConstraints>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum McpServerIdentity {
        Command { command: String },
        Url { url: String },
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct McpServerRequirement {
        pub identity: McpServerIdentity,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ConfigLayerEntry {
        pub name: crate::ConfigLayerSource,
        pub config: toml::Value,
        pub raw_toml: Option<String>,
        pub disabled_reason: Option<String>,
    }

    impl ConfigLayerEntry {
        pub fn new(name: crate::ConfigLayerSource, config: toml::Value) -> Self {
            Self {
                name,
                config,
                raw_toml: None,
                disabled_reason: None,
            }
        }
        pub fn new_with_raw_toml(
            name: crate::ConfigLayerSource,
            config: toml::Value,
            raw_toml: String,
        ) -> Self {
            Self {
                name,
                config,
                raw_toml: Some(raw_toml),
                disabled_reason: None,
            }
        }
        pub fn new_disabled(
            name: crate::ConfigLayerSource,
            config: toml::Value,
            disabled_reason: impl Into<String>,
        ) -> Self {
            Self {
                name,
                config,
                raw_toml: None,
                disabled_reason: Some(disabled_reason.into()),
            }
        }
        pub fn is_disabled(&self) -> bool {
            self.disabled_reason.is_some()
        }
        pub fn raw_toml(&self) -> Option<&str> {
            self.raw_toml.as_deref()
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub enum ConfigLayerStackOrdering {
        LowestPrecedenceFirst,
        HighestPrecedenceFirst,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct ConfigLayerStack {
        layers: Vec<ConfigLayerEntry>,
        requirements: ConfigRequirements,
        requirements_toml: ConfigRequirementsToml,
    }

    impl Default for ConfigLayerStack {
        fn default() -> Self {
            Self {
                layers: Vec::new(),
                requirements: ConfigRequirements::default(),
                requirements_toml: ConfigRequirementsToml::default(),
            }
        }
    }

    impl ConfigLayerStack {
        pub fn new(
            mut layers: Vec<ConfigLayerEntry>,
            requirements: ConfigRequirements,
            requirements_toml: ConfigRequirementsToml,
        ) -> std::io::Result<Self> {
            layers.sort_by_key(|layer| layer.name.precedence());
            Ok(Self {
                layers,
                requirements,
                requirements_toml,
            })
        }

        pub fn get_layers(
            &self,
            ordering: ConfigLayerStackOrdering,
            _include_disabled: bool,
        ) -> Vec<&ConfigLayerEntry> {
            let mut layers = self.layers.iter().collect::<Vec<_>>();
            if matches!(ordering, ConfigLayerStackOrdering::HighestPrecedenceFirst) {
                layers.reverse();
            }
            layers
        }

        pub fn requirements(&self) -> &ConfigRequirements {
            &self.requirements
        }

        pub fn requirements_toml(&self) -> &ConfigRequirementsToml {
            &self.requirements_toml
        }

        pub fn effective_config(&self) -> toml::Value {
            let mut merged = toml::Value::Table(toml::map::Map::new());
            for layer in &self.layers {
                if layer.is_disabled() {
                    continue;
                }
                merge_toml_values(&mut merged, &layer.config);
            }
            merged
        }
    }

    fn merge_toml_values(base: &mut toml::Value, overlay: &toml::Value) {
        match (base, overlay) {
            (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
                for (key, value) in overlay_table {
                    match base_table.get_mut(key) {
                        Some(base_value) => merge_toml_values(base_value, value),
                        None => {
                            base_table.insert(key.clone(), value.clone());
                        }
                    }
                }
            }
            (base_value, overlay_value) => {
                *base_value = overlay_value.clone();
            }
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct CloudRequirementsLoader;

    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    pub struct ConfigLoadError(pub String);

    impl ConfigLoadError {
        pub fn config_error(&self) -> &str {
            &self.0
        }
    }

    pub fn format_config_error_with_source(error: &str) -> String {
        error.to_string()
    }
}

pub mod models_manager {
    pub mod collaboration_mode_presets {
        #[derive(Debug, Clone, Default)]
        pub struct CollaborationModesConfig {
            pub default_mode_request_user_input: bool,
        }
    }

    pub mod model_presets {
        pub const HIDE_GPT_5_1_CODEX_MAX_MIGRATION_PROMPT_CONFIG: &str =
            "hide_gpt_5_1_codex_max_migration_prompt";
        pub const HIDE_GPT5_1_MIGRATION_PROMPT_CONFIG: &str = "hide_gpt5_1_migration_prompt";
    }

    pub mod manager {
        use crate::config::Config;
        use codex_protocol::config_types::CollaborationModeMask;
        use codex_protocol::openai_models::ModelPreset;

        #[derive(Debug, Clone, Copy)]
        pub enum RefreshStrategy {
            Offline,
            Online,
        }

        #[derive(Debug, Clone, Default)]
        pub struct ModelsManager;

        impl ModelsManager {
            pub fn from_config(_config: &Config) -> Self {
                Self
            }
            pub async fn list_models(&self, _strategy: RefreshStrategy) -> Vec<ModelPreset> {
                Vec::new()
            }
            pub fn try_list_models(&self) -> anyhow::Result<Vec<ModelPreset>> {
                Ok(Vec::new())
            }
            pub async fn get_default_model(
                &self,
                model: &Option<String>,
                _strategy: RefreshStrategy,
            ) -> String {
                model.clone().unwrap_or_default()
            }
            pub fn list_collaboration_modes(&self) -> Vec<CollaborationModeMask> {
                Vec::new()
            }
        }
    }
}

pub mod app_server_protocol {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub enum ConfigLayerSource {
        Mdm {
            domain: String,
            key: String,
        },
        System {
            file: crate::AbsolutePathBuf,
        },
        User {
            file: crate::AbsolutePathBuf,
        },
        Project {
            dot_codex_folder: crate::AbsolutePathBuf,
        },
        SessionFlags,
        LegacyManagedConfigTomlFromFile {
            file: crate::AbsolutePathBuf,
        },
        LegacyManagedConfigTomlFromMdm,
    }

    impl ConfigLayerSource {
        pub fn precedence(&self) -> u8 {
            match self {
                Self::Mdm { .. } => 0,
                Self::System { .. } => 1,
                Self::User { .. } => 2,
                Self::Project { .. } => 3,
                Self::SessionFlags => 4,
                Self::LegacyManagedConfigTomlFromFile { .. } => 5,
                Self::LegacyManagedConfigTomlFromMdm => 6,
            }
        }
    }
}
pub use app_server_protocol::ConfigLayerSource;

pub mod terminal {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TerminalName {
        AppleTerminal,
        Ghostty,
        Iterm2,
        WarpTerminal,
        VsCode,
        WezTerm,
        Kitty,
        Alacritty,
        Konsole,
        GnomeTerminal,
        Vte,
        WindowsTerminal,
        Dumb,
        Unknown,
    }

    impl Default for TerminalName {
        fn default() -> Self {
            Self::Unknown
        }
    }

    #[derive(Debug, Clone)]
    pub enum Multiplexer {
        Zellij { pane_id: Option<String> },
    }

    #[derive(Debug, Clone, Default)]
    pub struct TerminalInfo {
        pub name: TerminalName,
        pub multiplexer: Option<Multiplexer>,
    }

    pub fn terminal_info() -> TerminalInfo {
        let in_zellij = std::env::var("ZELLIJ")
            .map(|value| !value.trim().is_empty() && value != "0")
            .unwrap_or(false);
        let multiplexer = if in_zellij {
            Some(Multiplexer::Zellij {
                pane_id: std::env::var("ZELLIJ_PANE_ID").ok(),
            })
        } else {
            None
        };
        TerminalInfo {
            name: TerminalName::Unknown,
            multiplexer,
        }
    }

    pub fn user_agent() -> String {
        "crabbot-tui".to_string()
    }
}

pub mod windows_sandbox {
    pub const ELEVATED_SANDBOX_NUX_ENABLED: bool = false;
    pub trait WindowsSandboxLevelExt {}
    impl WindowsSandboxLevelExt for codex_protocol::config_types::WindowsSandboxLevel {}
}

#[derive(Debug, Clone, Default)]
pub struct SleepInhibitor;

impl SleepInhibitor {
    pub fn create() -> anyhow::Result<Self> {
        Ok(Self)
    }
    pub fn new(_enabled: bool) -> Self {
        Self
    }
    pub fn set_turn_running(&mut self, _running: bool) {}
}

pub mod model {
    use serde::Deserialize;
    use serde::Serialize;

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct Content {
        #[serde(default)]
        pub raw: RawContent,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum RawContent {
        Text(TextContent),
        Image(ImageContent),
        Audio(AudioContent),
        Resource(ResourceContent),
        ResourceLink(ResourceLink),
    }

    impl Default for RawContent {
        fn default() -> Self {
            Self::Text(TextContent::default())
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct TextContent {
        #[serde(default)]
        pub text: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct ImageContent {
        #[serde(default)]
        pub data: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct AudioContent {
        #[serde(default)]
        pub data: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ResourceContent {
        pub resource: ResourceContents,
    }

    impl Default for ResourceContent {
        fn default() -> Self {
            Self {
                resource: ResourceContents::TextResourceContents { uri: String::new() },
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ResourceContents {
        TextResourceContents { uri: String },
        BlobResourceContents { uri: String },
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct ResourceLink {
        #[serde(default)]
        pub uri: String,
    }
}

pub use codex_protocol::ThreadId;

#[derive(Debug, Clone, Default)]
pub struct CodexLogSnapshot {
    pub thread_id: String,
}

impl CodexLogSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn upload_feedback(
        &self,
        _classification: &str,
        _reason: Option<&str>,
        _include_logs: bool,
        _log_file_paths: &[std::path::PathBuf],
        _source: Option<crate::protocol::SessionSource>,
    ) -> Result<(), String> {
        Ok(())
    }
}

pub fn summarize_sandbox_policy(policy: &protocol::SandboxPolicy) -> String {
    policy.to_string()
}

/// Convert markdown `#L...` hash suffixes to terminal-friendly `:line[:col]` form.
pub fn normalize_markdown_hash_location_suffix(suffix: &str) -> Option<String> {
    let fragment = suffix.strip_prefix('#')?;
    let (start, end) = match fragment.split_once('-') {
        Some((start, end)) => (start, Some(end)),
        None => (fragment, None),
    };
    let (start_line, start_column) = parse_markdown_hash_location_point(start)?;
    let mut normalized = String::from(":");
    normalized.push_str(start_line);
    if let Some(column) = start_column {
        normalized.push(':');
        normalized.push_str(column);
    }
    if let Some(end) = end {
        let (end_line, end_column) = parse_markdown_hash_location_point(end)?;
        normalized.push('-');
        normalized.push_str(end_line);
        if let Some(column) = end_column {
            normalized.push(':');
            normalized.push_str(column);
        }
    }
    Some(normalized)
}

fn parse_markdown_hash_location_point(point: &str) -> Option<(&str, Option<&str>)> {
    let point = point.strip_prefix('L')?;
    match point.split_once('C') {
        Some((line, column)) => Some((line, Some(column))),
        None => Some((point, None)),
    }
}

/// Upstream-compatible backing for `codex_utils_approval_presets`.
mod codex_utils_approval_presets_compat {
    use crate::protocol::AskForApproval;
    use crate::protocol::SandboxPolicy;

    /// Approval preset pairing approval + sandbox policies.
    #[derive(Debug, Clone)]
    pub struct ApprovalPreset {
        pub id: &'static str,
        pub label: &'static str,
        pub description: &'static str,
        pub approval: AskForApproval,
        pub sandbox: SandboxPolicy,
    }

    pub fn builtin_approval_presets() -> Vec<ApprovalPreset> {
        vec![
            ApprovalPreset {
                id: "read-only",
                label: "Read Only",
                description: "Codex can read files in the current workspace. Approval is required to edit files or access the internet.",
                approval: AskForApproval::OnRequest,
                sandbox: SandboxPolicy::new_read_only_policy(),
            },
            ApprovalPreset {
                id: "auto",
                label: "Default",
                description: "Codex can read and edit files in the current workspace, and run commands. Approval is required to access the internet or edit other files. (Identical to Agent mode)",
                approval: AskForApproval::OnRequest,
                sandbox: SandboxPolicy::new_workspace_write_policy(),
            },
            ApprovalPreset {
                id: "full-access",
                label: "Full Access",
                description: "Codex can edit files outside this workspace and access the internet without asking for approval. Exercise caution when using.",
                approval: AskForApproval::Never,
                sandbox: SandboxPolicy::DangerFullAccess,
            },
        ]
    }
}
pub use codex_utils_approval_presets_compat::ApprovalPreset;
pub use codex_utils_approval_presets_compat::builtin_approval_presets;

/// Upstream-compatible backing for `codex_utils_cli`.
mod codex_utils_cli_compat {
    use clap::ArgAction;
    use clap::ValueEnum;
    use serde::Deserialize;
    use serde::Serialize;
    use serde::de::Error as SerdeError;
    use toml::Value;

    #[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize)]
    #[value(rename_all = "kebab-case")]
    pub enum ApprovalModeCliArg {
        OnFailure,
        /// Only run trusted commands without asking the user.
        ///
        /// Serialized as `untrusted` for wire-compat with existing callers.
        #[value(alias = "untrusted")]
        UnlessTrusted,
        OnRequest,
        Never,
    }

    impl From<ApprovalModeCliArg> for crate::protocol::AskForApproval {
        fn from(value: ApprovalModeCliArg) -> Self {
            match value {
                ApprovalModeCliArg::UnlessTrusted => Self::UnlessTrusted,
                ApprovalModeCliArg::OnFailure => Self::OnFailure,
                ApprovalModeCliArg::OnRequest => Self::OnRequest,
                ApprovalModeCliArg::Never => Self::Never,
            }
        }
    }

    #[derive(Clone, Copy, Debug, ValueEnum, Serialize, Deserialize)]
    #[value(rename_all = "kebab-case")]
    pub enum SandboxModeCliArg {
        DangerFullAccess,
        ReadOnly,
        WorkspaceWrite,
    }

    impl From<SandboxModeCliArg> for crate::config_types::SandboxMode {
        fn from(value: SandboxModeCliArg) -> Self {
            match value {
                SandboxModeCliArg::ReadOnly => Self::ReadOnly,
                SandboxModeCliArg::WorkspaceWrite => Self::WorkspaceWrite,
                SandboxModeCliArg::DangerFullAccess => Self::DangerFullAccess,
            }
        }
    }

    #[derive(clap::Parser, Debug, Default, Clone)]
    pub struct CliConfigOverrides {
        #[arg(
            short = 'c',
            long = "config",
            value_name = "key=value",
            action = ArgAction::Append,
            global = true,
        )]
        pub raw_overrides: Vec<String>,
    }

    impl CliConfigOverrides {
        pub fn parse_overrides(&self) -> Result<Vec<(String, Value)>, String> {
            self.raw_overrides
                .iter()
                .map(|s| {
                    let mut parts = s.splitn(2, '=');
                    let key = match parts.next() {
                        Some(k) => k.trim(),
                        None => return Err("Override missing key".to_string()),
                    };
                    let value_str = parts
                        .next()
                        .ok_or_else(|| format!("Invalid override (missing '='): {s}"))?
                        .trim();

                    if key.is_empty() {
                        return Err(format!("Empty key in override: {s}"));
                    }

                    let value: Value = match parse_toml_value(value_str) {
                        Ok(v) => v,
                        Err(_) => {
                            let trimmed = value_str.trim().trim_matches(|c| c == '"' || c == '\'');
                            Value::String(trimmed.to_string())
                        }
                    };

                    Ok((canonicalize_override_key(key), value))
                })
                .collect()
        }

        pub fn apply_on_value(&self, target: &mut Value) -> Result<(), String> {
            let overrides = self.parse_overrides()?;
            for (path, value) in overrides {
                apply_single_override(target, &path, value);
            }
            Ok(())
        }
    }

    fn canonicalize_override_key(key: &str) -> String {
        if key == "use_linux_sandbox_bwrap" {
            "features.use_linux_sandbox_bwrap".to_string()
        } else {
            key.to_string()
        }
    }

    fn apply_single_override(root: &mut Value, path: &str, value: Value) {
        use toml::value::Table;

        let parts: Vec<&str> = path.split('.').collect();
        let mut current = root;

        for (i, part) in parts.iter().enumerate() {
            let is_last = i == parts.len() - 1;

            if is_last {
                match current {
                    Value::Table(tbl) => {
                        tbl.insert((*part).to_string(), value);
                    }
                    _ => {
                        let mut tbl = Table::new();
                        tbl.insert((*part).to_string(), value);
                        *current = Value::Table(tbl);
                    }
                }
                return;
            }

            match current {
                Value::Table(tbl) => {
                    current = tbl
                        .entry((*part).to_string())
                        .or_insert_with(|| Value::Table(Table::new()));
                }
                _ => {
                    *current = Value::Table(Table::new());
                    if let Value::Table(tbl) = current {
                        current = tbl
                            .entry((*part).to_string())
                            .or_insert_with(|| Value::Table(Table::new()));
                    }
                }
            }
        }
    }

    fn parse_toml_value(raw: &str) -> Result<Value, toml::de::Error> {
        let wrapped = format!("_x_ = {raw}");
        let table: toml::Table = toml::from_str(&wrapped)?;
        table
            .get("_x_")
            .cloned()
            .ok_or_else(|| SerdeError::custom("missing sentinel key"))
    }

    pub mod format_env_display {
        use std::collections::HashMap;

        pub fn format_env_display(
            env: Option<&HashMap<String, String>>,
            env_vars: &[String],
        ) -> String {
            let mut entries: Vec<String> = Vec::new();
            if let Some(env) = env {
                let mut pairs: Vec<_> = env.iter().collect();
                pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
                entries.extend(pairs.into_iter().map(|(k, _)| format!("{k}=*****")));
            }
            entries.extend(env_vars.iter().map(|k| format!("{k}=*****")));
            if entries.is_empty() {
                "-".to_string()
            } else {
                entries.join(", ")
            }
        }
    }
}
pub use codex_utils_cli_compat::ApprovalModeCliArg;
pub use codex_utils_cli_compat::CliConfigOverrides;
pub use codex_utils_cli_compat::SandboxModeCliArg;
pub use codex_utils_cli_compat::format_env_display;

const TUI_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TUI_EVENT_WAIT_STEP: Duration = Duration::from_millis(50);
const APP_SERVER_RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const TUI_COMPOSER_PROMPT: &str = "\u{203a} ";
const TUI_COMPOSER_PLACEHOLDER: &str = "Ask Crabbot to do anything";
const TUI_SLASH_PICKER_MAX_ROWS: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Interrupted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRuntimeState {
    pub state: SessionStatus,
    pub updated_at_unix_ms: u64,
    pub last_event: String,
    #[serde(default)]
    pub last_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub api_endpoint: String,
    #[serde(alias = "daemon_endpoint")]
    pub app_server_endpoint: String,
    pub auth_token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:8787".to_string(),
            app_server_endpoint: "ws://127.0.0.1:8765".to_string(),
            auth_token: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CliState {
    pub sessions: BTreeMap<String, SessionRuntimeState>,
    pub config: CliConfig,
    #[serde(default)]
    pub last_thread_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TuiArgs {
    pub thread_id: Option<String>,
    pub no_alt_screen: bool,
    pub startup_picker: Option<StartupPicker>,
    pub startup_picker_show_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StartupPicker {
    Resume,
    Fork,
}

pub enum CommandOutput {
    Json(Value),
    Text(String),
}

#[derive(Debug, Clone)]
pub enum ResolveCwdOutcome {
    Continue(Option<std::path::PathBuf>),
    Exit,
}

pub async fn resolve_cwd_for_resume_or_fork(
    _tui: &mut crate::tui::Tui,
    _config: &crate::config::Config,
    current: &std::path::Path,
    _thread_id: ThreadId,
    _path: &std::path::Path,
    _action: crate::cwd_prompt::CwdPromptAction,
    _allow_current: bool,
) -> std::io::Result<ResolveCwdOutcome> {
    Ok(ResolveCwdOutcome::Continue(Some(current.to_path_buf())))
}

pub fn cwds_differ(a: &std::path::Path, b: &std::path::Path) -> bool {
    a != b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginStatus {
    LoggedIn,
    LoggedOut,
}

#[derive(Debug, Default, Clone)]
struct ConfigSetArgs {
    api_endpoint: Option<String>,
    app_server_endpoint: Option<String>,
    auth_token: Option<String>,
    clear_auth_token: bool,
}

mod additional_dirs;
mod app;
mod app_backtrack;
mod app_event;
mod app_event_sender;
mod ascii_animation;
mod bottom_pane;
mod chatwidget;
mod cli;
pub use cli::Cli;
mod clipboard_paste;
mod clipboard_text;
mod collaboration_modes;
mod color;
mod core_compat;
mod debug_config;
pub(crate) use crate::core_compat::AppEvent;
pub(crate) use crate::core_compat::AppEventSender;
pub(crate) use crate::core_compat::AppExitInfo;
pub(crate) use crate::core_compat::ExitMode;
pub(crate) use crate::core_compat::ExitReason;
pub(crate) use crate::core_compat::LiveTuiAction;
pub(crate) use crate::core_compat::PickerGitInfo;
pub(crate) use crate::core_compat::PickerThreadEntry;
pub(crate) use crate::core_compat::PickerThreadPage;
pub(crate) use crate::core_compat::UiApprovalRequest;
pub(crate) use crate::core_compat::UiEvent;
pub(crate) use crate::core_compat::clean_background_terminals;
pub(crate) use crate::core_compat::decode_app_server_wire_line;
pub(crate) use crate::core_compat::fork_thread;
pub(crate) use crate::core_compat::interrupt_turn;
pub(crate) use crate::core_compat::list_collaboration_modes;
pub(crate) use crate::core_compat::list_connectors;
pub(crate) use crate::core_compat::list_experimental_features_page;
pub(crate) use crate::core_compat::list_mcp_server_statuses;
pub(crate) use crate::core_compat::list_models;
pub(crate) use crate::core_compat::list_skills_for_cwd;
pub(crate) use crate::core_compat::list_threads_page;
pub(crate) use crate::core_compat::list_threads_page_for_picker;
pub(crate) use crate::core_compat::map_codex_protocol_event;
pub(crate) use crate::core_compat::map_legacy_stream_events;
pub(crate) use crate::core_compat::map_rpc_stream_events;
pub(crate) use crate::core_compat::read_account;
pub(crate) use crate::core_compat::read_config_snapshot;
pub(crate) use crate::core_compat::read_config_snapshot_for_cwd;
pub(crate) use crate::core_compat::read_rate_limits;
pub(crate) use crate::core_compat::respond_to_approval;
pub(crate) use crate::core_compat::respond_to_request_json;
pub(crate) use crate::core_compat::resume_thread_detailed;
pub(crate) use crate::core_compat::set_thread_name;
pub(crate) use crate::core_compat::start_compaction;
pub(crate) use crate::core_compat::start_review;
pub(crate) use crate::core_compat::start_thread;
pub(crate) use crate::core_compat::start_turn_with_elements_and_collaboration;
pub(crate) use crate::core_compat::stream_events;
pub(crate) use crate::core_compat::write_config_value;
pub(crate) use crate::core_compat::write_skill_enabled;
mod custom_terminal;
mod cwd_prompt;
mod diff_render;
mod exec_cell;
mod exec_command;
mod external_editor;
mod file_search;
mod frames;
mod get_git_diff;
mod history_cell;
mod insert_history;
mod key_hint;
mod line_truncation;
pub mod live_wrap;
mod markdown;
mod markdown_render;
mod markdown_stream;
mod mention_codec;
mod model_migration;
mod multi_agents;
mod notifications;
mod pager_overlay;
pub mod public_widgets;
mod render;
mod resume_picker;
mod selection_list;
mod session_log;
mod shimmer;
mod skills_helpers;
mod slash_command;
mod status;
mod status_indicator_widget;
mod streaming;
mod style;
mod terminal_palette;
mod text_formatting;
mod theme_picker;
mod tooltips;
pub mod tui;
mod ui_consts;
mod update_action;
mod version;
mod wrapping;

pub async fn run_startup_picker(
    mode: StartupPicker,
    show_all: bool,
    _state: &CliState,
) -> Result<Option<String>> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(None);
    }

    let terminal = crate::tui::init().context("initialize tui terminal for startup picker")?;
    let mut tui = crate::tui::Tui::new(terminal);
    let config = crate::config::ConfigBuilder::default()
        .build()
        .await
        .unwrap_or_else(|_| crate::config::Config::default());
    let selection = match mode {
        StartupPicker::Resume => resume_picker::run_resume_picker(&mut tui, &config, show_all)
            .await
            .map_err(|err| anyhow!("{err}"))?,
        StartupPicker::Fork => resume_picker::run_fork_picker(&mut tui, &config, show_all)
            .await
            .map_err(|err| anyhow!("{err}"))?,
    };
    let _ = crate::tui::restore();

    match selection {
        resume_picker::SessionSelection::Resume(target)
        | resume_picker::SessionSelection::Fork(target) => Ok(Some(target.thread_id.to_string())),
        resume_picker::SessionSelection::StartFresh | resume_picker::SessionSelection::Exit => {
            Ok(None)
        }
    }
}

pub fn set_app_server_connection_raw(app_server_endpoint: &str, auth_token: Option<&str>) {
    set_shim_backend_config(app_server_endpoint, auth_token);
}

pub fn set_daemon_connection_raw(daemon_endpoint: &str, auth_token: Option<&str>) {
    set_app_server_connection_raw(daemon_endpoint, auth_token);
}

pub async fn run_main(
    cli: Cli,
    _codex_linux_sandbox_exe: Option<PathBuf>,
) -> std::io::Result<app::AppExitInfo> {
    let mut state = CliState::default();
    let backend = get_shim_backend_config();
    state.config.app_server_endpoint = backend.app_server_endpoint;
    state.config.auth_token = backend.auth_token;

    let startup_picker = if cli.resume_picker {
        Some(StartupPicker::Resume)
    } else if cli.fork_picker {
        Some(StartupPicker::Fork)
    } else {
        None
    };
    let startup_picker_show_all = cli.resume_show_all || cli.fork_show_all;
    let mut config = crate::config::ConfigBuilder::default()
        .build()
        .await
        .unwrap_or_else(|_| crate::config::Config::default());
    if let Ok(cwd) = std::env::current_dir() {
        config.cwd = cwd;
    }
    let thread_id = if let Some(id_or_name) = cli.fork_session_id.as_deref() {
        match resolve_named_or_id_thread_id_for_cli(&config, id_or_name)
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))?
        {
            Some(thread_id) => Some(thread_id),
            None => {
                return Err(std::io::Error::other(format!(
                    "No saved session found with ID {id_or_name}. Run `crabbot fork` without an ID to choose from existing sessions."
                )));
            }
        }
    } else if let Some(id_or_name) = cli.resume_session_id.as_deref() {
        match resolve_named_or_id_thread_id_for_cli(&config, id_or_name)
            .await
            .map_err(|err| std::io::Error::other(err.to_string()))?
        {
            Some(thread_id) => Some(thread_id),
            None => {
                return Err(std::io::Error::other(format!(
                    "No saved session found with ID {id_or_name}. Run `crabbot resume` without an ID to choose from existing sessions."
                )));
            }
        }
    } else if cli.fork_last {
        resolve_last_thread_id_for_cli(&config, LastThreadLookup::Fork)
            .await
            .ok()
            .flatten()
    } else if cli.resume_last {
        resolve_last_thread_id_for_cli(
            &config,
            LastThreadLookup::Resume {
                show_all: cli.resume_show_all,
            },
        )
        .await
        .ok()
        .flatten()
    } else {
        None
    };

    let exit_info = handle_tui(
        TuiArgs {
            thread_id,
            no_alt_screen: cli.no_alt_screen,
            startup_picker,
            startup_picker_show_all,
        },
        &mut state,
    )
    .await
    .map_err(|err| std::io::Error::other(err.to_string()))?;

    Ok(exit_info)
}

#[derive(Debug, Clone, Copy)]
enum LastThreadLookup {
    Resume { show_all: bool },
    Fork,
}

async fn resolve_last_thread_id_for_cli(
    config: &crate::config::Config,
    mode: LastThreadLookup,
) -> Result<Option<String>> {
    let default_provider = config.model_provider_id.to_string();
    let provider_filter = vec![default_provider.clone()];
    let page = RolloutRecorder::list_threads(
        config,
        50,
        None,
        crate::ThreadSortKey::UpdatedAt,
        INTERACTIVE_SESSION_SOURCES,
        Some(provider_filter.as_slice()),
        default_provider.as_str(),
        None,
    )
    .await
    .map_err(|err| anyhow!(err.to_string()))?;

    let cwd = match mode {
        LastThreadLookup::Fork => None,
        LastThreadLookup::Resume { show_all: true } => None,
        LastThreadLookup::Resume { show_all: false } => std::env::current_dir().ok(),
    };

    let pick = page.items.iter().find(|item| {
        if let Some(filter) = cwd.as_ref() {
            return item.cwd.as_ref() == Some(filter);
        }
        true
    });

    Ok(pick.and_then(thread_item_to_thread_id_string))
}

async fn resolve_named_or_id_thread_id_for_cli(
    config: &crate::config::Config,
    id_or_name: &str,
) -> Result<Option<String>> {
    let trimmed = id_or_name.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let is_thread_id = ThreadId::from_string(trimmed).is_ok();
    let default_provider = config.model_provider_id.to_string();
    let provider_filter = vec![default_provider.clone()];
    let mut cursor: Option<Cursor> = None;

    loop {
        let page = RolloutRecorder::list_threads(
            config,
            200,
            cursor.as_ref(),
            crate::ThreadSortKey::UpdatedAt,
            INTERACTIVE_SESSION_SOURCES,
            Some(provider_filter.as_slice()),
            default_provider.as_str(),
            None,
        )
        .await
        .map_err(|err| anyhow!(err.to_string()))?;

        if let Some(item) = page.items.iter().find(|item| {
            let item_thread_id = thread_item_to_thread_id_string(item);
            if is_thread_id {
                return item_thread_id.as_deref() == Some(trimmed);
            }
            let file_stem = item.path.file_stem().and_then(|name| name.to_str());
            let file_name = item.path.file_name().and_then(|name| name.to_str());
            let title = item.first_user_message.as_deref();
            file_stem == Some(trimmed) || file_name == Some(trimmed) || title == Some(trimmed)
        }) {
            return Ok(thread_item_to_thread_id_string(item));
        }

        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(None);
        }
    }
}

fn thread_item_to_thread_id_string(item: &ThreadItem) -> Option<String> {
    item.thread_id
        .map(|id| id.to_string())
        .or_else(|| extract_thread_id_from_picker_path(&item.path))
        .or_else(|| {
            item.path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
}

async fn resolve_session_selection_from_args(
    args: &TuiArgs,
    _state: &CliState,
) -> Result<resume_picker::SessionSelection> {
    if let Some(thread_id) = args.thread_id.as_deref() {
        let trimmed = thread_id.trim();
        if trimmed.is_empty() {
            bail!("thread id cannot be empty");
        }
        return Ok(match args.startup_picker {
            Some(StartupPicker::Fork) => {
                resume_picker::SessionSelection::Fork(resume_picker::SessionTarget {
                    path: std::path::PathBuf::from(trimmed),
                    thread_id: ThreadId::from_string(trimmed)
                        .map_err(|_| anyhow!("invalid thread id: {trimmed}"))?,
                })
            }
            _ => resume_picker::SessionSelection::Resume(resume_picker::SessionTarget {
                path: std::path::PathBuf::from(trimmed),
                thread_id: ThreadId::from_string(trimmed)
                    .map_err(|_| anyhow!("invalid thread id: {trimmed}"))?,
            }),
        });
    }

    let Some(mode) = args.startup_picker.as_ref() else {
        return Ok(resume_picker::SessionSelection::StartFresh);
    };

    let terminal = crate::tui::init().context("initialize tui terminal for startup picker")?;
    let mut tui = crate::tui::Tui::new(terminal);
    let config = crate::config::ConfigBuilder::default()
        .build()
        .await
        .unwrap_or_else(|_| crate::config::Config::default());
    let selection = match mode {
        StartupPicker::Resume => {
            resume_picker::run_resume_picker(&mut tui, &config, args.startup_picker_show_all)
                .await
                .map_err(|err| anyhow!("{err}"))?
        }
        StartupPicker::Fork => {
            resume_picker::run_fork_picker(&mut tui, &config, args.startup_picker_show_all)
                .await
                .map_err(|err| anyhow!("{err}"))?
        }
    };
    let _ = crate::tui::restore();
    Ok(selection)
}

pub async fn handle_tui(args: TuiArgs, state: &mut CliState) -> Result<app::AppExitInfo> {
    tooltips::announcement::prewarm();

    set_shim_backend_config(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
    );
    let session_selection = resolve_session_selection_from_args(&args, state).await?;

    let mut terminal = crate::tui::init().context("initialize tui terminal")?;
    terminal.clear()?;
    let mut tui = crate::tui::Tui::new(terminal);
    let mut config = crate::config::ConfigBuilder::default()
        .build()
        .await
        .unwrap_or_else(|_| crate::config::Config::default());
    if let Ok(cwd) = std::env::current_dir() {
        config.cwd = cwd;
    }
    if let Ok(Some(config_snapshot)) = crate::read_config_snapshot(state) {
        apply_tui_config_snapshot(&mut config, &config_snapshot);
    }
    let use_alt_screen = determine_alt_screen_mode(args.no_alt_screen, config.tui_alternate_screen);
    tui.set_alt_screen_enabled(use_alt_screen);
    let auth_manager = resolve_auth_manager_for_tui(state);

    let run_result = app::App::run(
        &mut tui,
        auth_manager,
        config,
        Vec::new(),
        crate::config::ConfigOverrides::default(),
        None,
        None,
        Vec::new(),
        session_selection,
        CodexFeedback::new(),
        false,
        false,
    )
    .await
    .map_err(|err| anyhow!("{err}"));
    let _ = crate::tui::restore();

    let exit_info = run_result?;
    if let Some(thread_id) = exit_info.thread_id {
        state.last_thread_id = Some(thread_id.to_string());
    }

    Ok(exit_info)
}

fn apply_tui_config_snapshot(config: &mut crate::config::Config, snapshot: &serde_json::Value) {
    let snapshot_model = snapshot
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    if snapshot_model.is_some() {
        config.model = snapshot_model;
    }

    if let Some(model_provider_id) = snapshot
        .get("model_provider")
        .or_else(|| snapshot.get("modelProvider"))
        .and_then(serde_json::Value::as_str)
    {
        config.model_provider_id = model_provider_id.to_string();
    }

    if let Some(chatgpt_base_url) = snapshot
        .get("chatgpt_base_url")
        .or_else(|| snapshot.get("chatgptBaseUrl"))
        .and_then(serde_json::Value::as_str)
    {
        config.chatgpt_base_url = chatgpt_base_url.to_string();
    }

    if let Some(model_context_window) = snapshot
        .get("model_context_window")
        .or_else(|| snapshot.get("modelContextWindow"))
        .and_then(serde_json::Value::as_i64)
    {
        config.model_context_window = Some(model_context_window);
    }

    if let Some(reasoning_summary) = snapshot
        .get("model_reasoning_summary")
        .or_else(|| snapshot.get("modelReasoningSummary"))
        .cloned()
        .and_then(|value| serde_json::from_value::<crate::config::ReasoningSummary>(value).ok())
    {
        config.model_reasoning_summary = Some(reasoning_summary);
    }

    if let Some(reasoning_effort) = snapshot
        .get("model_reasoning_effort")
        .or_else(|| snapshot.get("modelReasoningEffort"))
        .cloned()
        .and_then(|value| {
            serde_json::from_value::<crate::openai_models::ReasoningEffort>(value).ok()
        })
    {
        config.model_reasoning_effort = Some(reasoning_effort);
    }

    if let Some(approval_policy) = snapshot
        .get("approval_policy")
        .or_else(|| snapshot.get("approvalPolicy"))
        .cloned()
        .and_then(|value| serde_json::from_value::<crate::protocol::AskForApproval>(value).ok())
    {
        let _ = config.permissions.approval_policy.set(approval_policy);
    }

    if let Some(sandbox_policy) = snapshot
        .get("sandbox")
        .or_else(|| snapshot.get("sandbox_policy"))
        .or_else(|| snapshot.get("sandboxPolicy"))
        .cloned()
        .and_then(|value| serde_json::from_value::<crate::protocol::SandboxPolicy>(value).ok())
    {
        let _ = config.permissions.sandbox_policy.set(sandbox_policy);
    }

    if let Some(plan_mode_reasoning_effort) = snapshot
        .get("plan_mode_reasoning_effort")
        .or_else(|| snapshot.get("planModeReasoningEffort"))
        .cloned()
        .and_then(|value| {
            serde_json::from_value::<crate::openai_models::ReasoningEffort>(value).ok()
        })
    {
        config.plan_mode_reasoning_effort = Some(plan_mode_reasoning_effort);
    }

    if let Some(features) = snapshot
        .get("features")
        .and_then(serde_json::Value::as_object)
    {
        for (key, enabled) in features {
            let Some(feature) = crate::features::Feature::from_key(key) else {
                continue;
            };
            if enabled.as_bool().unwrap_or(false) {
                config.features.enable(feature);
            } else {
                config.features.disable(feature);
            }
        }
    }
}

fn resolve_auth_manager_for_tui(state: &CliState) -> std::sync::Arc<AuthManager> {
    match crate::read_account(state, true) {
        Ok(Some(account)) => {
            let account_type = account
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            if account_type == "chatgpt" {
                let email = account
                    .get("email")
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string);
                let plan_type = account
                    .get("planType")
                    .or_else(|| account.get("plan_type"))
                    .cloned()
                    .and_then(|value| {
                        serde_json::from_value::<codex_protocol::account::PlanType>(value).ok()
                    });
                std::sync::Arc::new(AuthManager::from_chatgpt_account(email, plan_type))
            } else if account_type == "apikey" || account_type == "api_key" {
                std::sync::Arc::new(AuthManager::from_api_key())
            } else {
                std::sync::Arc::new(AuthManager::default())
            }
        }
        Ok(None) => std::sync::Arc::new(AuthManager::default()),
        Err(err) => {
            tracing::debug!("failed to read account info for tui startup: {err:#}");
            std::sync::Arc::new(AuthManager::default())
        }
    }
}

fn determine_alt_screen_mode(
    no_alt_screen: bool,
    tui_alternate_screen: codex_protocol::config_types::AltScreenMode,
) -> bool {
    if no_alt_screen {
        false
    } else {
        match tui_alternate_screen {
            codex_protocol::config_types::AltScreenMode::Always => true,
            codex_protocol::config_types::AltScreenMode::Never => false,
            codex_protocol::config_types::AltScreenMode::Auto => {
                let terminal_info = crate::terminal::terminal_info();
                !matches!(
                    terminal_info.multiplexer,
                    Some(crate::terminal::Multiplexer::Zellij { .. })
                )
            }
        }
    }
}

pub async fn handle_attach_tui_interactive(
    session_id: String,
    _initial_events: Vec<DaemonStreamEnvelope>,
    state: &mut CliState,
) -> Result<CommandOutput> {
    let _ = handle_tui(
        TuiArgs {
            thread_id: Some(session_id),
            no_alt_screen: false,
            startup_picker: None,
            startup_picker_show_all: false,
        },
        state,
    )
    .await?;
    Ok(CommandOutput::Text(String::new()))
}

fn extract_thread_id_from_picker_path(path: &std::path::Path) -> Option<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        candidates.push(stem.to_string());
    }
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        candidates.push(name.to_string());
    }
    for component in path.components() {
        if let std::path::Component::Normal(value) = component
            && let Some(text) = value.to_str()
        {
            candidates.push(text.to_string());
        }
    }

    let matched = candidates
        .into_iter()
        .find(|value| ThreadId::from_string(value).is_ok());
    matched
}

pub async fn resolve_session_thread_id(
    path: &std::path::Path,
    _codex_home: Option<&std::path::Path>,
) -> Option<ThreadId> {
    extract_thread_id_from_picker_path(path).and_then(|value| ThreadId::from_string(&value).ok())
}

fn parse_initial_messages_from_thread_rpc_result(
    result: &serde_json::Value,
) -> Option<Vec<crate::protocol::EventMsg>> {
    let raw_messages = result
        .get("initialMessages")
        .or_else(|| result.get("initial_messages"))
        .or_else(|| {
            result
                .get("thread")
                .and_then(|thread| thread.get("initialMessages"))
        })
        .or_else(|| {
            result
                .get("thread")
                .and_then(|thread| thread.get("initial_messages"))
        });

    if let Some(raw_messages) = raw_messages.and_then(serde_json::Value::as_array) {
        let parsed = raw_messages
            .iter()
            .filter_map(|message| {
                serde_json::from_value::<crate::protocol::EventMsg>(message.clone()).ok()
            })
            .collect::<Vec<_>>();
        return if parsed.is_empty() {
            None
        } else {
            Some(parsed)
        };
    }

    let parsed = parse_initial_messages_from_thread_turns(
        result.get("thread").and_then(|thread| thread.get("turns")),
    );
    parsed
}

fn parse_initial_messages_from_thread_turns(
    turns: Option<&serde_json::Value>,
) -> Option<Vec<crate::protocol::EventMsg>> {
    let turns = turns.and_then(serde_json::Value::as_array)?;
    let mut events = Vec::new();

    for turn in turns {
        let turn_id = turn
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        events.push(crate::protocol::EventMsg::TurnStarted(
            crate::protocol::TurnStartedEvent {
                turn_id: turn_id.clone(),
                model_context_window: None,
                collaboration_mode_kind: crate::config_types::ModeKind::default(),
            },
        ));

        let mut last_agent_message: Option<String> = None;
        if let Some(items) = turn.get("items").and_then(serde_json::Value::as_array) {
            for item in items {
                if let Some((message, text_elements)) = parse_user_message_item_from_turn(item) {
                    events.push(crate::protocol::EventMsg::UserMessage(
                        crate::protocol::UserMessageEvent {
                            message,
                            images: None,
                            local_images: Vec::new(),
                            text_elements,
                        },
                    ));
                } else if let Some(message) = parse_agent_message_text_from_turn(item) {
                    last_agent_message = Some(message.clone());
                    events.push(crate::protocol::EventMsg::AgentMessage(
                        crate::protocol::AgentMessageEvent {
                            message,
                            phase: None,
                        },
                    ));
                }
            }
        }

        events.push(crate::protocol::EventMsg::TurnComplete(
            crate::protocol::TurnCompleteEvent {
                turn_id,
                last_agent_message,
            },
        ));
    }

    if events.is_empty() {
        None
    } else {
        Some(events)
    }
}

fn parse_user_message_item_from_turn(
    value: &serde_json::Value,
) -> Option<(String, Vec<crate::user_input::TextElement>)> {
    let item_type = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let role = value
        .get("role")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_user_item = matches!(
        item_type.as_str(),
        "usermessage" | "user_message" | "user-message"
    ) || (item_type == "message" && role == "user");
    if !is_user_item {
        return None;
    }

    let message = value
        .get("text")
        .or_else(|| value.get("message"))
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .get("content")
                .and_then(serde_json::Value::as_array)
                .and_then(|content| {
                    content
                        .iter()
                        .find_map(|entry| entry.get("text").and_then(serde_json::Value::as_str))
                })
        })?
        .to_string();

    let text_elements = value
        .get("text_elements")
        .or_else(|| value.get("textElements"))
        .cloned()
        .and_then(|raw| serde_json::from_value(raw).ok())
        .unwrap_or_default();

    Some((message, text_elements))
}

fn parse_agent_message_text_from_turn(value: &serde_json::Value) -> Option<String> {
    let item_type = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let role = value
        .get("role")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_agent_item = matches!(
        item_type.as_str(),
        "agentmessage" | "agent_message" | "agent-message"
    ) || (item_type == "message" && role == "assistant");
    if !is_agent_item {
        return None;
    }

    let message = value
        .get("text")
        .or_else(|| value.get("message"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            value
                .get("content")
                .and_then(serde_json::Value::as_array)
                .map(|content| {
                    content
                        .iter()
                        .filter_map(|entry| entry.get("text").and_then(serde_json::Value::as_str))
                        .collect::<Vec<_>>()
                        .join("")
                })
        })?;

    if message.is_empty() {
        None
    } else {
        Some(message)
    }
}
fn truncate_for_width(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if text.chars().count() <= width {
        return text.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    let mut truncated = text.chars().take(width - 3).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn persist_latest_session_state_from_stream(
    state: &mut CliState,
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
) -> Result<()> {
    let Some(last_sequence) = stream_events.last().map(|event| event.sequence) else {
        return Ok(());
    };
    let latest_state = stream_events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            DaemonStreamEvent::SessionState(payload) => Some(payload.state.clone()),
            _ => None,
        });

    if let Some(runtime) = state.sessions.get_mut(session_id) {
        if let Some(next_state) = latest_state {
            runtime.state = parse_session_status(&next_state)?;
            runtime.last_event = "attached".to_string();
        }
        runtime.updated_at_unix_ms = now_unix_ms();
        runtime.last_sequence = runtime.last_sequence.max(last_sequence);
        return Ok(());
    }

    if let Some(next_state) = latest_state {
        state.sessions.insert(
            session_id.to_string(),
            SessionRuntimeState {
                state: parse_session_status(&next_state)?,
                updated_at_unix_ms: now_unix_ms(),
                last_event: "attached".to_string(),
                last_sequence,
            },
        );
    }
    Ok(())
}

fn handle_config_show(state: &CliState) -> Value {
    json!({
        "ok": true,
        "config": state.config,
    })
}

fn handle_config_set(args: ConfigSetArgs, state: &mut CliState) -> Result<Value> {
    let mut changed = false;

    if let Some(api_endpoint) = args.api_endpoint {
        if api_endpoint.trim().is_empty() {
            bail!("api_endpoint cannot be empty");
        }
        state.config.api_endpoint = api_endpoint;
        changed = true;
    }

    if let Some(app_server_endpoint) = args.app_server_endpoint {
        if app_server_endpoint.trim().is_empty() {
            bail!("app_server_endpoint cannot be empty");
        }
        state.config.app_server_endpoint = app_server_endpoint;
        changed = true;
    }

    if let Some(auth_token) = args.auth_token {
        if auth_token.trim().is_empty() {
            bail!("auth_token cannot be empty");
        }
        state.config.auth_token = Some(auth_token);
        changed = true;
    }

    if args.clear_auth_token {
        state.config.auth_token = None;
        changed = true;
    }

    if !changed {
        bail!("no config fields were provided");
    }

    Ok(json!({
        "ok": true,
        "action": "config_set",
        "config": state.config,
    }))
}

fn parse_session_status(state: &str) -> Result<SessionStatus> {
    match state {
        "active" => Ok(SessionStatus::Active),
        "interrupted" => Ok(SessionStatus::Interrupted),
        other => bail!("unsupported app-server session state: {other}"),
    }
}

fn ensure_app_server_ready(state: &CliState) -> Result<()> {
    with_app_server_ws_client(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
        |_| Ok(()),
    )
    .with_context(|| {
        format!(
            "failed to connect to app-server websocket at {}",
            state.config.app_server_endpoint
        )
    })
}

fn app_server_prompt_session(
    app_server_endpoint: &str,
    session_id: &str,
    text: &str,
    auth_token: Option<&str>,
) -> Result<DaemonPromptResponse> {
    let response = app_server_rpc_request(
        app_server_endpoint,
        auth_token,
        "turn/start",
        json!({
            "threadId": session_id,
            "input": [
                {
                    "type": "text",
                    "text": text,
                    "text_elements": []
                }
            ]
        }),
    )
    .with_context(|| {
        format!(
            "request app-server turn/start (session={session_id}, endpoint={app_server_endpoint})"
        )
    })?;

    let turn_id = response
        .result
        .get("turn")
        .and_then(|turn| turn.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("app-server turn/start response missing turn.id"))?
        .to_string();

    Ok(DaemonPromptResponse {
        session_id: session_id.to_string(),
        turn_id,
        state: "active".to_string(),
        last_event: "turn_started".to_string(),
        updated_at_unix_ms: now_unix_ms(),
        last_sequence: 0,
    })
}

static APP_SERVER_WS_CLIENT: LazyLock<Mutex<Option<AppServerWsClient>>> =
    LazyLock::new(|| Mutex::new(None));

struct AppServerWsClient {
    ws_url: String,
    auth_token: Option<String>,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_request_id: i64,
    next_sequence: u64,
    buffered_events: VecDeque<DaemonRpcStreamEnvelope>,
}

impl AppServerWsClient {
    fn connect(ws_url: String, auth_token: Option<String>) -> Result<Self> {
        let mut request = ws_url
            .clone()
            .into_client_request()
            .context("build websocket request")?;
        if let Some(token) = auth_token.as_deref() {
            let header_value = format!("Bearer {token}")
                .parse()
                .context("parse auth header for websocket request")?;
            request.headers_mut().insert("Authorization", header_value);
        }

        let (socket, _response) = connect(request).context("connect websocket app-server")?;
        let mut client = Self {
            ws_url,
            auth_token,
            socket,
            next_request_id: 1,
            next_sequence: 1,
            buffered_events: VecDeque::new(),
        };
        client.initialize()?;
        Ok(client)
    }

    fn matches(&self, ws_url: &str, auth_token: Option<&str>) -> bool {
        self.ws_url == ws_url && self.auth_token.as_deref() == auth_token
    }

    fn initialize(&mut self) -> Result<()> {
        let _ = self.request(
            "initialize",
            json!({
                "clientInfo": {
                    "name": "crabbot_tui",
                    "title": "Crabbot TUI",
                    "version": "0.1.0",
                },
                "capabilities": {
                    "experimentalApi": true,
                    "optOutNotificationMethods": LEGACY_NOTIFICATIONS_TO_OPT_OUT,
                },
            }),
        )?;
        self.send_json(&json!({ "method": "initialized" }))
    }

    fn send_json(&mut self, payload: &Value) -> Result<()> {
        self.socket
            .send(WsMessage::Text(payload.to_string().into()))
            .context("send websocket app-server json payload")
    }

    fn read_text_with_timeout(&mut self, timeout: Duration) -> Result<Option<String>> {
        // Keep polling non-blocking across plain and TLS transports. Without this,
        // a stalled TLS read can block forever and starve local events like Ctrl-C shutdown.
        set_ws_stream_read_timeout(self.socket.get_mut(), timeout);

        loop {
            match self.socket.read() {
                Ok(WsMessage::Text(text)) => return Ok(Some(text.to_string())),
                Ok(WsMessage::Binary(_)) => continue,
                Ok(WsMessage::Ping(payload)) => {
                    self.socket
                        .send(WsMessage::Pong(payload))
                        .context("reply websocket ping")?;
                }
                Ok(WsMessage::Pong(_)) => {}
                Ok(WsMessage::Frame(_)) => {}
                Ok(WsMessage::Close(frame)) => {
                    let reason = frame
                        .as_ref()
                        .map(|f| f.reason.to_string())
                        .unwrap_or_else(|| "no reason".to_string());
                    bail!("websocket app-server closed connection: {reason}");
                }
                Err(WsError::Io(err))
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(WsError::ConnectionClosed | WsError::AlreadyClosed) => {
                    bail!("websocket app-server connection closed")
                }
                Err(err) => bail!("read websocket app-server message: {err}"),
            }
        }
    }

    fn ingest_wire_line(&mut self, raw_line: &str) -> Result<()> {
        if let Some(envelope) = crate::decode_app_server_wire_line(raw_line, self.next_sequence)? {
            if let DaemonRpcStreamEvent::ServerRequest(request) = &envelope.event {
                self.respond_to_server_request(request)?;
            }
            self.next_sequence = self.next_sequence.max(envelope.sequence.saturating_add(1));
            self.buffered_events.push_back(envelope);
        }
        Ok(())
    }

    fn send_rpc_error(&mut self, request_id: &Value, code: i64, message: &str) -> Result<()> {
        self.send_json(&json!({
            "id": request_id,
            "error": {
                "code": code,
                "message": message,
            }
        }))
    }

    fn respond_to_server_request(&mut self, request: &DaemonRpcServerRequest) -> Result<()> {
        match request.method.as_str() {
            // Approvals are handled by the TUI and explicitly responded later.
            "item/commandExecution/requestApproval"
            | "item/fileChange/requestApproval"
            | "item/mcpToolCall/requestApproval"
            | "item/tool/elicit"
            | "item/tool/requestUserInput"
            | "execCommandApproval"
            | "applyPatchApproval" => Ok(()),
            // We don't support dynamic tool execution yet; decline gracefully.
            "item/tool/call" => self.send_json(&json!({
                "id": request.request_id,
                "result": {
                    "success": false,
                    "contentItems": [
                        {
                            "type": "inputText",
                            "text": "Dynamic tool calls are not supported by this client."
                        }
                    ]
                }
            })),
            // Unknown server-initiated request: reply with standard JSON-RPC method-not-found.
            _ => self.send_rpc_error(
                &request.request_id,
                -32601,
                &format!("Unhandled server request method: {}", request.method),
            ),
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Result<DaemonRpcRequestResponse> {
        let request_id = json!(self.next_request_id);
        self.next_request_id += 1;
        self.send_json(&json!({
            "id": request_id,
            "method": method,
            "params": params,
        }))?;

        let deadline = Instant::now() + APP_SERVER_RPC_REQUEST_TIMEOUT;
        while Instant::now() < deadline {
            let Some(raw_line) = self.read_text_with_timeout(Duration::from_millis(200))? else {
                continue;
            };
            let value: Value = serde_json::from_str(&raw_line)
                .with_context(|| "parse websocket app-server message while waiting response")?;
            let is_matching_id = value.get("id") == Some(&request_id);
            if is_matching_id && value.get("result").is_some() {
                return Ok(DaemonRpcRequestResponse {
                    request_id,
                    result: value.get("result").cloned().unwrap_or(Value::Null),
                });
            }
            if is_matching_id && value.get("error").is_some() {
                bail!("websocket app-server rpc error: {}", value["error"]);
            }
            self.ingest_wire_line(&raw_line)?;
        }

        bail!("timed out waiting for websocket app-server rpc response")
    }

    fn respond(&mut self, request_id: Value, result: Value) -> Result<()> {
        self.send_json(&json!({
            "id": request_id,
            "result": result,
        }))
    }

    fn drain_stream_events(&mut self, since_sequence: u64) -> Result<Vec<DaemonRpcStreamEnvelope>> {
        // Pull currently available messages without blocking the UI loop for long.
        for _ in 0..64 {
            let Some(raw_line) = self.read_text_with_timeout(Duration::from_millis(10))? else {
                break;
            };
            self.ingest_wire_line(&raw_line)?;
        }

        let mut out = Vec::new();
        while let Some(envelope) = self.buffered_events.pop_front() {
            if envelope.sequence > since_sequence {
                out.push(envelope);
            }
        }
        Ok(out)
    }
}

fn set_ws_stream_read_timeout(stream: &mut MaybeTlsStream<TcpStream>, timeout: Duration) {
    match stream {
        MaybeTlsStream::Plain(socket) => {
            let _ = socket.set_read_timeout(Some(timeout));
        }
        #[cfg(feature = "native-tls")]
        MaybeTlsStream::NativeTls(socket) => {
            let _ = socket.get_mut().set_read_timeout(Some(timeout));
        }
        #[cfg(feature = "__rustls-tls")]
        MaybeTlsStream::Rustls(socket) => {
            let _ = socket.sock.set_read_timeout(Some(timeout));
        }
        _ => {}
    }
}

fn app_server_ws_url(app_server_endpoint: &str) -> Result<String> {
    if let Ok(value) = env::var("CODEX_APP_SERVER_WS_URL")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    if app_server_endpoint.starts_with("ws://") || app_server_endpoint.starts_with("wss://") {
        return Ok(app_server_endpoint.to_string());
    }
    let mut url =
        Url::parse(app_server_endpoint).context("parse app-server endpoint for websocket")?;
    match url.scheme() {
        "http" => {
            let _ = url.set_scheme("ws");
        }
        "https" => {
            let _ = url.set_scheme("wss");
        }
        other => bail!("unsupported app-server endpoint scheme for websocket: {other}"),
    }
    Ok(url.to_string())
}

fn with_app_server_ws_client<T, F>(
    app_server_endpoint: &str,
    auth_token: Option<&str>,
    f: F,
) -> Result<T>
where
    F: FnOnce(&mut AppServerWsClient) -> Result<T>,
{
    let ws_url = app_server_ws_url(app_server_endpoint)?;
    let mut guard = APP_SERVER_WS_CLIENT
        .lock()
        .map_err(|_| anyhow!("app-server websocket client mutex poisoned"))?;
    if guard
        .as_ref()
        .is_none_or(|client| !client.matches(&ws_url, auth_token))
    {
        *guard = Some(AppServerWsClient::connect(
            ws_url,
            auth_token.map(ToString::to_string),
        )?);
    }
    let result = f(guard
        .as_mut()
        .ok_or_else(|| anyhow!("websocket client missing after connect"))?);
    if result.is_err() {
        *guard = None;
    }
    result
}

fn app_server_rpc_request(
    app_server_endpoint: &str,
    auth_token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<DaemonRpcRequestResponse> {
    with_app_server_ws_client(app_server_endpoint, auth_token, |client| {
        client.request(method, params)
    })
}

pub fn app_server_rpc_request_raw(
    app_server_endpoint: &str,
    auth_token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<DaemonRpcRequestResponse> {
    app_server_rpc_request(app_server_endpoint, auth_token, method, params)
}

pub fn ensure_app_server_ready_raw(
    app_server_endpoint: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    with_app_server_ws_client(app_server_endpoint, auth_token, |_client| Ok(()))
}

pub fn ensure_daemon_ready_raw(daemon_endpoint: &str, auth_token: Option<&str>) -> Result<()> {
    ensure_app_server_ready_raw(daemon_endpoint, auth_token)
}

fn app_server_rpc_respond(
    app_server_endpoint: &str,
    auth_token: Option<&str>,
    request_id: Value,
    result: Value,
) -> Result<()> {
    with_app_server_ws_client(app_server_endpoint, auth_token, |client| {
        client.respond(request_id, result)
    })
}

fn fetch_app_server_stream(
    app_server_endpoint: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    with_app_server_ws_client(app_server_endpoint, auth_token, |client| {
        client.drain_stream_events(since_sequence.unwrap_or_default())
    })
}

fn request_id_key_for_cli(request_id: &Value) -> String {
    serde_json::to_string(request_id).unwrap_or_else(|_| request_id.to_string())
}

fn extract_thread_id_from_rpc_result(result: &Value) -> Option<String> {
    result
        .get("thread")
        .and_then(|thread| thread.get("id"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn latest_cached_session_id(state: &CliState) -> Option<String> {
    state
        .sessions
        .iter()
        .max_by_key(|(_, value)| value.updated_at_unix_ms)
        .map(|(key, _)| key.clone())
}

fn cached_last_sequence(state: &CliState, session_id: &str) -> Option<u64> {
    state
        .sessions
        .get(session_id)
        .map(|runtime| runtime.last_sequence)
}

fn render_attach_tui(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    app_server_endpoint: &str,
) -> String {
    render_attach_tui_with_columns_and_fallback(
        session_id,
        stream_events,
        app_server_endpoint,
        terminal_columns(),
        None,
    )
}

#[cfg(test)]
fn render_attach_tui_with_columns(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    app_server_endpoint: &str,
    columns: usize,
) -> String {
    render_attach_tui_with_columns_and_fallback(
        session_id,
        stream_events,
        app_server_endpoint,
        columns,
        None,
    )
}

fn render_attach_tui_with_columns_and_fallback(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    app_server_endpoint: &str,
    columns: usize,
    fallback_state: Option<&str>,
) -> String {
    let mut output = String::new();
    let mut latest_state = fallback_state.unwrap_or("unknown").to_string();
    let mut previous_state: Option<String> = None;

    for envelope in stream_events {
        match &envelope.event {
            DaemonStreamEvent::SessionState(payload) => {
                if previous_state.as_deref() != Some(payload.state.as_str()) {
                    if payload.state == "interrupted" {
                        if !output.is_empty() && !output.ends_with('\n') {
                            output.push('\n');
                        }
                        output.push_str(&format!(
                            "[session interrupted] resume with: crabbot codex resume --session-id {session_id}\n"
                        ));
                    }

                    if previous_state.as_deref() == Some("interrupted")
                        && payload.state.as_str() == "active"
                    {
                        output.push_str("[session resumed] stream is active again\n");
                    }
                }
                latest_state = payload.state.clone();
                previous_state = Some(payload.state.clone());
            }
            DaemonStreamEvent::TurnStreamDelta(payload) => output.push_str(&payload.delta),
            DaemonStreamEvent::TurnCompleted(payload) => {
                if !output.is_empty() && !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str(&format!(
                    "[turn {} complete] {}\n",
                    payload.turn_id, payload.output_summary
                ));
            }
            DaemonStreamEvent::ApprovalRequired(payload) => {
                if !output.is_empty() && !output.ends_with('\n') {
                    output.push('\n');
                }
                output.push_str(&format!(
                    "[approval required] id={} action={}\n",
                    payload.approval_id, payload.action_kind
                ));
                output.push_str(&format!("prompt: {}\n", payload.prompt));
                output.push_str(&format!(
                    "after approval, resume with: crabbot codex resume --session-id {session_id}\n"
                ));
            }
            DaemonStreamEvent::Heartbeat(_) => {}
        }
    }

    if !output.is_empty() && !output.ends_with('\n') {
        output.push('\n');
    }

    let last_sequence = stream_events
        .last()
        .map(|event| event.sequence)
        .unwrap_or(0);
    let footer = build_attach_footer(
        session_id,
        &latest_state,
        stream_events.len(),
        last_sequence,
        app_server_endpoint,
        columns,
    );

    let separator_width = columns.clamp(24, 80);
    output.push_str(&"-".repeat(separator_width));
    output.push('\n');
    output.push_str(&footer);
    output
}

fn cached_session_state_label<'a>(state: &'a CliState, session_id: &str) -> Option<&'a str> {
    state
        .sessions
        .get(session_id)
        .map(|runtime| match runtime.state {
            SessionStatus::Active => "active",
            SessionStatus::Interrupted => "interrupted",
        })
}

fn terminal_columns() -> usize {
    env::var("COLUMNS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .filter(|columns| *columns > 0)
        .unwrap_or(100)
}

fn build_attach_footer(
    session_id: &str,
    state: &str,
    received_events: usize,
    last_sequence: u64,
    app_server_endpoint: &str,
    columns: usize,
) -> String {
    let full = format!(
        "session={session_id} state={state} events={received_events} seq={last_sequence} daemon={app_server_endpoint}"
    );
    if full.len() <= columns {
        return full;
    }

    format!("session={session_id} state={state} events={received_events} seq={last_sequence}")
}

fn resolve_state_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("CRABBOT_CLI_STATE_PATH") {
        let candidate = PathBuf::from(path);
        if !candidate.as_os_str().is_empty() {
            return Ok(candidate);
        }
    }

    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".crabbot").join("cli-state.json"))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
