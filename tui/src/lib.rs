use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use crabbot_protocol::DaemonPromptRequest;
use crabbot_protocol::DaemonPromptResponse;
use crabbot_protocol::DaemonRpcNotification;
use crabbot_protocol::DaemonRpcRequestResponse;
use crabbot_protocol::DaemonRpcStreamEnvelope;
use crabbot_protocol::DaemonRpcStreamEvent;
use crabbot_protocol::DaemonSessionStatusResponse;
use crabbot_protocol::DaemonStartSessionRequest;
use crabbot_protocol::DaemonStreamEnvelope;
use crabbot_protocol::DaemonStreamEvent;
use crabbot_protocol::HealthResponse;
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
use reqwest::StatusCode;
use reqwest::blocking::Client;
use reqwest::blocking::Response;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::env;
use std::io::IsTerminal;
use std::io::{self};
use std::net::TcpStream;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
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

extern crate self as codex_chatgpt;
extern crate self as codex_core;
extern crate self as codex_file_search;
extern crate self as codex_protocol;
extern crate self as codex_utils_approval_presets;
extern crate self as codex_utils_cli;

pub mod config {
    pub mod types {
        pub use crate::core_compat::config::types::NotificationMethod;

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum McpServerTransportConfig {
            Stdio,
            Sse,
        }
    }

    /// Stub for `codex_core::config::Config` – only the fields that TUI modules
    /// actually access are included.
    #[derive(Debug, Clone)]
    pub struct Config {
        pub cwd: std::path::PathBuf,
        pub model: String,
        pub model_provider_id: String,
        pub model_provider: ConfigModelProvider,
    }

    #[derive(Debug, Clone)]
    pub struct ConfigModelProvider {
        pub name: String,
    }

    /// Stub for `codex_core::config::log_dir`.
    pub fn log_dir(_config: &Config) -> Result<std::path::PathBuf, std::io::Error> {
        let mut dir = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
        dir.push("crabbot");
        dir.push("logs");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

pub mod protocol {
    use serde::Deserialize;
    use serde::Serialize;
    use std::path::PathBuf;

    /// File change description for diff rendering.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum FileChange {
        Add {
            content: String,
        },
        Delete {
            content: String,
        },
        Update {
            unified_diff: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            move_path: Option<PathBuf>,
        },
    }

    /// Sandbox execution policy.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "kebab-case")]
    pub enum SandboxPolicy {
        #[serde(rename = "danger-full-access")]
        DangerFullAccess,
        #[serde(rename = "read-only")]
        ReadOnly {
            #[serde(default)]
            access: ReadOnlyAccess,
        },
        #[serde(rename = "external-sandbox")]
        ExternalSandbox {
            #[serde(default)]
            network_access: NetworkAccess,
        },
        #[serde(rename = "workspace-write")]
        WorkspaceWrite {
            #[serde(default)]
            writable_roots: Vec<PathBuf>,
            #[serde(default)]
            read_only_access: ReadOnlyAccess,
            #[serde(default)]
            network_access: bool,
            #[serde(default)]
            exclude_tmpdir_env_var: bool,
            #[serde(default)]
            exclude_slash_tmp: bool,
        },
    }

    impl SandboxPolicy {
        pub fn new_read_only_policy() -> Self {
            SandboxPolicy::ReadOnly {
                access: ReadOnlyAccess::FullAccess,
            }
        }

        pub fn new_workspace_write_policy() -> Self {
            SandboxPolicy::WorkspaceWrite {
                writable_roots: vec![],
                read_only_access: ReadOnlyAccess::FullAccess,
                network_access: false,
                exclude_tmpdir_env_var: false,
                exclude_slash_tmp: false,
            }
        }
    }

    impl std::fmt::Display for SandboxPolicy {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                SandboxPolicy::DangerFullAccess => write!(f, "danger-full-access"),
                SandboxPolicy::ReadOnly { .. } => write!(f, "read-only"),
                SandboxPolicy::ExternalSandbox { .. } => write!(f, "external-sandbox"),
                SandboxPolicy::WorkspaceWrite { .. } => write!(f, "workspace-write"),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum ReadOnlyAccess {
        Restricted,
        #[default]
        FullAccess,
    }

    impl ReadOnlyAccess {
        pub fn has_full_disk_read_access(&self) -> bool {
            matches!(self, ReadOnlyAccess::FullAccess)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum NetworkAccess {
        #[default]
        Restricted,
        Enabled,
    }

    impl NetworkAccess {
        pub fn is_enabled(self) -> bool {
            matches!(self, NetworkAccess::Enabled)
        }
    }

    impl std::fmt::Display for NetworkAccess {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                NetworkAccess::Restricted => write!(f, "restricted"),
                NetworkAccess::Enabled => write!(f, "enabled"),
            }
        }
    }

    /// Review decision for command/patch approvals.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ReviewDecision {
        Approve,
        Deny,
        Explain,
    }

    /// Source of an exec command.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ExecCommandSource {
        Agent,
        User,
    }

    /// Stub for `codex_core::protocol::Op` – submission operation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    pub enum Op {
        Interrupt,
        UserInput { items: Vec<serde_json::Value> },
        GetHistoryEntryRequest { offset: i32, log_id: Option<String> },
        ListSkills { query: Option<String> },
        Shutdown,
    }

    /// Approval policy.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum AskForApproval {
        UnlessTrusted,
        OnFailure,
        #[default]
        OnRequest,
        Never,
    }

    impl std::fmt::Display for AskForApproval {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AskForApproval::UnlessTrusted => write!(f, "untrusted"),
                AskForApproval::OnFailure => write!(f, "on-failure"),
                AskForApproval::OnRequest => write!(f, "on-request"),
                AskForApproval::Never => write!(f, "never"),
            }
        }
    }

    /// Event from the agent.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Event {
        pub id: String,
        pub msg: EventMsg,
    }

    /// Response event payload.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    pub enum EventMsg {
        Error { message: String },
        AgentMessage { text: String },
        TaskComplete,
        Other(serde_json::Value),
    }

    /// Rate limit snapshot.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RateLimitSnapshot {
        pub limit_id: Option<String>,
        pub limit_name: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SessionSource {
        Local,
        Remote,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ElicitationAction {
        Accept,
        Decline,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum McpAuthStatus {
        Unknown,
        Authorized,
        Unauthorized,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct McpInvocation {
        pub server_name: String,
        pub tool_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionConfiguredEvent {
        pub session_id: String,
        #[serde(default)]
        pub model: Option<String>,
    }

    /// MCP request identifier.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum RequestId {
        String(String),
    }

    impl std::fmt::Display for RequestId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                RequestId::String(s) => f.write_str(s),
            }
        }
    }

    /// Network approval protocol.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum NetworkApprovalProtocol {
        Http,
        Https,
    }

    /// Network approval context.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct NetworkApprovalContext {
        pub host: String,
        pub protocol: NetworkApprovalProtocol,
    }

    /// Exec policy amendment.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecPolicyAmendment {
        pub command: Vec<String>,
    }

    impl ExecPolicyAmendment {
        pub fn new(command: Vec<String>) -> Self {
            Self { command }
        }

        pub fn command(&self) -> &[String] {
            &self.command
        }
    }
}

pub mod git_info {
    use std::path::Path;
    use std::path::PathBuf;

    /// Walk up directory hierarchy looking for `.git` — matches upstream behavior.
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
}

pub mod parse_command {
    /// Extract shell name and script from a command like `["bash", "-lc", "echo hello"]`.
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
    /// Feature flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[allow(dead_code)]
    pub enum Feature {
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
        WindowsSandbox,
        WindowsSandboxElevated,
    }

    /// Feature spec for tooltip announcements.
    pub struct FeatureSpec {
        pub feature: Feature,
        pub stage: FeatureStage,
    }

    #[derive(Debug, Clone, Copy)]
    pub enum FeatureStage {
        Stable,
        Experimental(&'static str),
    }

    impl FeatureStage {
        pub fn experimental_announcement(&self) -> Option<&'static str> {
            match self {
                FeatureStage::Experimental(msg) => Some(msg),
                _ => None,
            }
        }
    }

    #[derive(Debug, Clone, Default)]
    pub struct Features;

    impl Features {
        pub fn with_defaults() -> Self {
            Self
        }

        pub fn is_enabled(&self, _feature: Feature) -> bool {
            false
        }
    }

    /// Static feature list (empty in stub — features are server-side in crabbot).
    pub static FEATURES: &[FeatureSpec] = &[];
}

pub mod skills {
    pub mod model {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct SkillMetadata {
            pub name: String,
            #[serde(default)]
            pub description: Option<String>,
        }
    }
}

// ---------------------------------------------------------------------------
// External crate stub modules
// ---------------------------------------------------------------------------

/// Stub backing `codex_chatgpt::connectors`.
mod codex_chatgpt_stub {
    pub mod connectors {
        /// App connector info.
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct AppInfo {
            pub id: String,
            pub name: String,
            pub description: Option<String>,
            pub logo_url: Option<String>,
            pub logo_url_dark: Option<String>,
            pub distribution_channel: Option<String>,
            pub install_url: Option<String>,
            #[serde(default)]
            pub is_accessible: bool,
        }
    }
}
pub use codex_chatgpt_stub::connectors;

/// Stub backing `codex_file_search`.
mod codex_file_search_stub {
    use serde::Deserialize;
    use serde::Serialize;
    use std::path::PathBuf;

    /// File match result.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FileMatch {
        pub score: u32,
        pub path: PathBuf,
        pub root: PathBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub indices: Option<Vec<u32>>,
    }

    impl FileMatch {
        pub fn full_path(&self) -> PathBuf {
            self.root.join(&self.path)
        }
    }

    /// Options for creating a file search session.
    #[derive(Debug, Clone, Default)]
    pub struct FileSearchOptions {
        pub compute_indices: bool,
    }

    /// File search snapshot.
    #[derive(Debug, Clone)]
    pub struct FileSearchSnapshot {
        pub query: String,
        pub matches: Vec<FileMatch>,
    }

    /// Trait for receiving search updates.
    pub trait SessionReporter: Send + Sync + 'static {
        fn on_update(&self, snapshot: &FileSearchSnapshot);
        fn on_complete(&self);
    }

    /// Active file search session handle.
    pub struct FileSearchSession {
        _private: (),
    }

    impl FileSearchSession {
        pub fn update_query(&self, _query: &str) {}
    }

    /// Create a file search session.
    pub fn create_session(
        _roots: Vec<PathBuf>,
        _options: FileSearchOptions,
        _reporter: std::sync::Arc<dyn SessionReporter>,
        _cancel: Option<()>,
    ) -> Result<FileSearchSession, String> {
        Err("file search not implemented in crabbot stub".into())
    }
}
pub use codex_file_search_stub::FileMatch;
pub use codex_file_search_stub::FileSearchOptions;
pub use codex_file_search_stub::FileSearchSession;
pub use codex_file_search_stub::FileSearchSnapshot;
pub use codex_file_search_stub::SessionReporter;
pub use codex_file_search_stub::create_session;

/// Stub backing `codex_protocol`.
mod codex_protocol_stub {
    use serde::Deserialize;
    use serde::Serialize;

    /// Thread identifier.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct ThreadId {
        uuid: String,
    }

    impl ThreadId {
        pub fn new() -> Self {
            Self {
                uuid: uuid::Uuid::new_v4().to_string(),
            }
        }
    }

    impl Default for ThreadId {
        fn default() -> Self {
            Self::new()
        }
    }

    impl std::fmt::Display for ThreadId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.uuid)
        }
    }

    pub mod openai_models {
        use serde::Deserialize;
        use serde::Serialize;

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum ReasoningEffort {
            None,
            Minimal,
            Low,
            #[default]
            Medium,
            High,
            XHigh,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ModelPreset {
            pub id: String,
            pub model: String,
            pub display_name: String,
            pub description: String,
            pub default_reasoning_effort: ReasoningEffort,
            #[serde(default)]
            pub supported_reasoning_efforts: Vec<ReasoningEffortPreset>,
            #[serde(default)]
            pub supports_personality: bool,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ReasoningEffortPreset {
            pub effort: ReasoningEffort,
            pub label: String,
        }
    }

    pub mod config_types {
        use serde::Deserialize;
        use serde::Serialize;

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum Personality {
            #[default]
            None,
            Friendly,
            Pragmatic,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct CollaborationModeMask {
            pub name: String,
            pub mode: Option<ModeKind>,
            pub model: Option<String>,
            pub reasoning_effort: Option<Option<super::openai_models::ReasoningEffort>>,
            pub developer_instructions: Option<Option<String>>,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum ModeKind {
            Code,
            Chat,
            Ask,
        }
    }

    pub mod account {
        use serde::Deserialize;
        use serde::Serialize;

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "lowercase")]
        pub enum PlanType {
            Free,
            Go,
            Plus,
            Pro,
            Team,
            Business,
            Enterprise,
        }
    }

    pub mod mcp {
        use serde::Deserialize;
        use serde::Serialize;

        pub use crate::protocol::RequestId;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Resource {
            pub uri: String,
            #[serde(default)]
            pub name: Option<String>,
            #[serde(default)]
            pub description: Option<String>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ResourceTemplate {
            pub uri_template: String,
            #[serde(default)]
            pub name: Option<String>,
            #[serde(default)]
            pub description: Option<String>,
        }
    }

    pub mod custom_prompts {
        use serde::Deserialize;
        use serde::Serialize;

        pub const PROMPTS_CMD_PREFIX: &str = "prompts";

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct CustomPrompt {
            pub name: String,
            pub content: String,
        }
    }

    pub mod user_input {
        use serde::Deserialize;
        use serde::Serialize;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ByteRange {
            pub start: usize,
            pub end: usize,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct TextElement {
            pub kind: String,
            pub range: ByteRange,
        }
    }

    pub mod request_user_input {
        use serde::Deserialize;
        use serde::Serialize;
        use std::collections::BTreeMap;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputAnswer {
            pub value: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputEvent {
            pub request_id: String,
            #[serde(default)]
            pub prompt: Option<String>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputResponse {
            #[serde(default)]
            pub answers: BTreeMap<String, RequestUserInputAnswer>,
        }
    }

    pub mod models {
        pub fn local_image_label_text() -> &'static str {
            "local image"
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum WebSearchAction {
            Requested,
            Cached,
        }
    }
}
pub use codex_protocol_stub::*;

/// Stub backing `codex_utils_approval_presets`.
mod codex_utils_approval_presets_stub {
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
}
pub use codex_utils_approval_presets_stub::ApprovalPreset;

/// Stub backing `codex_utils_cli`.
mod codex_utils_cli_stub {
    use serde::Deserialize;
    use serde::Serialize;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    pub enum ApprovalModeCliArg {
        OnFailure,
        UnlessTrusted,
        OnRequest,
        Never,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    pub enum SandboxModeCliArg {
        DangerFullAccess,
        ReadOnly,
        WorkspaceWrite,
    }

    #[derive(Debug, Clone, Default)]
    pub struct CliConfigOverrides {
        pub model_provider: Option<String>,
    }
}
pub use codex_utils_cli_stub::ApprovalModeCliArg;
pub use codex_utils_cli_stub::CliConfigOverrides;
pub use codex_utils_cli_stub::SandboxModeCliArg;

const TUI_STREAM_POLL_INTERVAL: Duration = Duration::from_millis(250);
const TUI_EVENT_WAIT_STEP: Duration = Duration::from_millis(50);
const DAEMON_PROMPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
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
    pub daemon_endpoint: String,
    pub auth_token: Option<String>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            api_endpoint: "http://127.0.0.1:8787".to_string(),
            daemon_endpoint: "http://127.0.0.1:8788".to_string(),
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
}

pub enum CommandOutput {
    Json(Value),
    Text(String),
}

#[derive(Debug, Default, Clone)]
struct ConfigSetArgs {
    api_endpoint: Option<String>,
    daemon_endpoint: Option<String>,
    auth_token: Option<String>,
    clear_auth_token: bool,
}

mod additional_dirs;
mod app;
mod app_event;
mod app_event_sender;
mod ascii_animation;
#[path = "bottom_pane_stub.rs"]
mod bottom_pane;
mod chatwidget;
mod cli;
mod color;
mod core_compat;
mod custom_terminal;
mod cwd_prompt;
mod diff_render;
mod exec_command;
mod external_editor;
mod file_search;
mod frames;
mod get_git_diff;
#[path = "history_cell_stub.rs"]
mod history_cell;
mod insert_history;
mod key_hint;
pub mod live_wrap;
mod markdown;
mod markdown_render;
mod markdown_stream;
mod mention_codec;
mod model_migration;
mod notifications;
mod render;
mod selection_list;
mod session_log;
mod shimmer;
mod slash_command;
#[path = "bottom_pane/slash_commands.rs"]
mod slash_commands;
mod style;
mod terminal_palette;
mod text_formatting;
pub mod tui;
mod ui_consts;
mod version;
mod wrapping;

pub use app::handle_attach_tui_interactive;
pub use app::handle_tui;
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

    if let Some(daemon_endpoint) = args.daemon_endpoint {
        if daemon_endpoint.trim().is_empty() {
            bail!("daemon_endpoint cannot be empty");
        }
        state.config.daemon_endpoint = daemon_endpoint;
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
        other => bail!("unsupported daemon session state: {other}"),
    }
}

fn persist_daemon_session(
    state: &mut CliState,
    daemon_session: &DaemonSessionStatusResponse,
) -> Result<()> {
    let state_value = parse_session_status(&daemon_session.state)?;
    let last_sequence = state
        .sessions
        .get(&daemon_session.session_id)
        .map(|runtime| runtime.last_sequence)
        .unwrap_or(0);
    state.sessions.insert(
        daemon_session.session_id.clone(),
        SessionRuntimeState {
            state: state_value,
            updated_at_unix_ms: daemon_session.updated_at_unix_ms,
            last_event: daemon_session.last_event.clone(),
            last_sequence,
        },
    );
    Ok(())
}

fn http_client_with_timeout(timeout: Duration) -> Result<Client> {
    Client::builder()
        .timeout(timeout)
        .build()
        .context("build http client")
}

fn http_client() -> Result<Client> {
    http_client_with_timeout(Duration::from_secs(5))
}

fn endpoint_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn apply_auth(
    request: reqwest::blocking::RequestBuilder,
    auth_token: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    if let Some(token) = auth_token {
        if !token.trim().is_empty() {
            return request.bearer_auth(token);
        }
    }
    request
}

fn fetch_api_health(api_endpoint: &str, auth_token: Option<&str>) -> Result<HealthResponse> {
    let client = http_client()?;
    let url = endpoint_url(api_endpoint, "/health");
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request api health")?
        .error_for_status()
        .context("api health returned error status")?;
    response
        .json::<HealthResponse>()
        .context("parse api health response")
}

fn health_http_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .context("build health-check http client")
}

fn daemon_is_healthy(daemon_endpoint: &str, auth_token: Option<&str>) -> bool {
    let client = match health_http_client() {
        Ok(client) => client,
        Err(_) => return false,
    };
    let url = endpoint_url(daemon_endpoint, "/health");
    let response = match apply_auth(client.get(url), auth_token).send() {
        Ok(response) => response,
        Err(_) => return false,
    };
    if !response.status().is_success() {
        return false;
    }

    response
        .json::<HealthResponse>()
        .map(|health| health.status == "ok")
        .unwrap_or(false)
}

fn ensure_daemon_ready(state: &CliState) -> Result<()> {
    if app_server_ws_url(&state.config.daemon_endpoint).is_ok() {
        with_app_server_ws_client(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
            |_| Ok(()),
        )
        .context("ensure websocket app-server is reachable")?;
        return Ok(());
    }

    if daemon_is_healthy(
        &state.config.daemon_endpoint,
        state.config.auth_token.as_deref(),
    ) {
        return Ok(());
    }

    auto_start_daemon_process()?;

    for _ in 0..20 {
        if daemon_is_healthy(
            &state.config.daemon_endpoint,
            state.config.auth_token.as_deref(),
        ) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(150));
    }

    bail!(
        "daemon is not healthy at {}; run `cargo run -p crabbot_daemon` or set CRABBOT_DAEMON_BIN",
        state.config.daemon_endpoint
    )
}

fn auto_start_daemon_process() -> Result<()> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(explicit) = env::var_os("CRABBOT_DAEMON_BIN") {
        if !PathBuf::from(&explicit).as_os_str().is_empty() {
            candidates.push(PathBuf::from(explicit));
        }
    }

    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join("crabbot_daemon"));
        }
    }
    candidates.push(PathBuf::from("crabbot_daemon"));

    let mut last_error: Option<anyhow::Error> = None;
    for candidate in candidates {
        match spawn_daemon_process(&candidate) {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }

    if spawn_daemon_via_cargo().is_ok() {
        return Ok(());
    }

    match last_error {
        Some(error) => Err(error),
        None => bail!("unable to auto-start daemon"),
    }
}

fn spawn_daemon_process(binary: &Path) -> Result<()> {
    let mut command = Command::new(binary);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(bind) = env::var_os("CRABBOT_DAEMON_BIND") {
        command.env("CRABBOT_DAEMON_BIND", bind);
    }

    command
        .spawn()
        .with_context(|| format!("auto-start daemon via {}", binary.display()))?;
    Ok(())
}

fn spawn_daemon_via_cargo() -> Result<()> {
    if !Path::new("Cargo.toml").exists() {
        bail!("Cargo.toml not found in current working directory");
    }

    Command::new("cargo")
        .args(["run", "-p", "crabbot_daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("auto-start daemon via cargo run -p crabbot_daemon")?;
    Ok(())
}

fn daemon_start_session(
    daemon_endpoint: &str,
    session_id: Option<String>,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let url = endpoint_url(daemon_endpoint, "/v1/sessions/start");
    let response = apply_auth(client.post(url), auth_token)
        .json(&DaemonStartSessionRequest { session_id })
        .send()
        .context("request daemon session start")?
        .error_for_status()
        .context("daemon session start returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon start response")
}

fn daemon_resume_session(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/resume");
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.post(url), auth_token)
        .send()
        .context("request daemon session resume")?
        .error_for_status()
        .context("daemon session resume returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon resume response")
}

fn daemon_interrupt_session(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/interrupt");
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.post(url), auth_token)
        .send()
        .context("request daemon session interrupt")?
        .error_for_status()
        .context("daemon session interrupt returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon interrupt response")
}

fn daemon_prompt_session(
    daemon_endpoint: &str,
    session_id: &str,
    text: &str,
    auth_token: Option<&str>,
) -> Result<DaemonPromptResponse> {
    let path = format!("/v1/sessions/{session_id}/prompt");
    let url = endpoint_url(daemon_endpoint, &path);
    let request = DaemonPromptRequest {
        prompt: text.to_string(),
    };

    let response = send_daemon_prompt_request(&url, &request, auth_token).with_context(|| {
        format!("request daemon prompt (session={session_id}, endpoint={daemon_endpoint})")
    })?;
    if response.status() == StatusCode::NOT_FOUND {
        daemon_start_session(daemon_endpoint, Some(session_id.to_string()), auth_token)
            .with_context(|| format!("recover missing daemon session {session_id}"))?;
        let retry = send_daemon_prompt_request(&url, &request, auth_token).with_context(|| {
            format!("retry daemon prompt after session recovery (session={session_id})")
        })?;
        return parse_daemon_prompt_response(retry);
    }

    parse_daemon_prompt_response(response)
}

fn send_daemon_prompt_request(
    url: &str,
    request: &DaemonPromptRequest,
    auth_token: Option<&str>,
) -> Result<Response> {
    let client = http_client_with_timeout(DAEMON_PROMPT_REQUEST_TIMEOUT)?;
    apply_auth(client.post(url.to_string()), auth_token)
        .json(request)
        .send()
        .context("send daemon prompt request")
}

fn parse_daemon_prompt_response(response: Response) -> Result<DaemonPromptResponse> {
    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .ok()
            .map(|text| text.trim().to_string())
            .unwrap_or_default();
        if body.is_empty() {
            bail!("daemon prompt returned HTTP {status}");
        }
        bail!(
            "daemon prompt returned HTTP {status}: {}",
            truncate_for_width(&body, 200)
        );
    }

    response
        .json::<DaemonPromptResponse>()
        .context("parse daemon prompt response")
}

fn daemon_get_session_status(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
) -> Result<DaemonSessionStatusResponse> {
    let client = http_client()?;
    let path = format!("/v1/sessions/{session_id}/status");
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon session status")?
        .error_for_status()
        .context("daemon session status returned error status")?;
    response
        .json::<DaemonSessionStatusResponse>()
        .context("parse daemon status response")
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
                }
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
        // Non-plain transports (e.g. TLS) may ignore this fast-poll timeout.
        if let MaybeTlsStream::Plain(stream) = self.socket.get_mut() {
            let _ = stream.set_read_timeout(Some(timeout));
        }

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
        if let Some(envelope) =
            crate::core_compat::decode_app_server_wire_line(raw_line, self.next_sequence)?
        {
            self.next_sequence = self.next_sequence.max(envelope.sequence.saturating_add(1));
            self.buffered_events.push_back(envelope);
        }
        Ok(())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<DaemonRpcRequestResponse> {
        let request_id = json!(self.next_request_id);
        self.next_request_id += 1;
        self.send_json(&json!({
            "id": request_id,
            "method": method,
            "params": params,
        }))?;

        let deadline = Instant::now() + DAEMON_PROMPT_REQUEST_TIMEOUT;
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

fn app_server_ws_url(daemon_endpoint: &str) -> Result<String> {
    if let Ok(value) = env::var("CODEX_APP_SERVER_WS_URL")
        && !value.trim().is_empty()
    {
        return Ok(value);
    }
    if daemon_endpoint.starts_with("ws://") || daemon_endpoint.starts_with("wss://") {
        return Ok(daemon_endpoint.to_string());
    }
    let mut url = Url::parse(daemon_endpoint).context("parse daemon endpoint for websocket")?;
    match url.scheme() {
        "http" => {
            let _ = url.set_scheme("ws");
        }
        "https" => {
            let _ = url.set_scheme("wss");
        }
        other => bail!("unsupported daemon endpoint scheme for websocket: {other}"),
    }
    Ok(url.to_string())
}

fn with_app_server_ws_client<T, F>(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    f: F,
) -> Result<T>
where
    F: FnOnce(&mut AppServerWsClient) -> Result<T>,
{
    let ws_url = app_server_ws_url(daemon_endpoint)?;
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

fn daemon_app_server_rpc_request(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    method: &str,
    params: Value,
) -> Result<DaemonRpcRequestResponse> {
    with_app_server_ws_client(daemon_endpoint, auth_token, |client| {
        client.request(method, params)
    })
}

fn daemon_app_server_rpc_respond(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    request_id: Value,
    result: Value,
) -> Result<()> {
    with_app_server_ws_client(daemon_endpoint, auth_token, |client| {
        client.respond(request_id, result)
    })
}

fn fetch_daemon_app_server_stream(
    daemon_endpoint: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
) -> Result<Vec<DaemonRpcStreamEnvelope>> {
    with_app_server_ws_client(daemon_endpoint, auth_token, |client| {
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

#[derive(Debug)]
enum DaemonStreamFetchResult {
    Stream(Vec<DaemonStreamEnvelope>),
    NotFound,
}

fn fetch_daemon_stream(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
) -> Result<DaemonStreamFetchResult> {
    fetch_daemon_stream_with_timeout(
        daemon_endpoint,
        session_id,
        auth_token,
        since_sequence,
        Duration::from_secs(5),
    )
}

fn fetch_daemon_stream_with_timeout(
    daemon_endpoint: &str,
    session_id: &str,
    auth_token: Option<&str>,
    since_sequence: Option<u64>,
    timeout: Duration,
) -> Result<DaemonStreamFetchResult> {
    let client = http_client_with_timeout(timeout)?;
    let mut path = format!("/v1/sessions/{session_id}/stream");
    if let Some(since_sequence) = since_sequence {
        path.push_str(&format!("?since_sequence={since_sequence}"));
    }
    let url = endpoint_url(daemon_endpoint, &path);
    let response = apply_auth(client.get(url), auth_token)
        .send()
        .context("request daemon stream")?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(DaemonStreamFetchResult::NotFound);
    }
    let body = response
        .error_for_status()
        .context("daemon stream returned error status")?
        .text()
        .context("read daemon stream body")?;

    let stream_events = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<DaemonStreamEnvelope>(line).context("parse daemon stream line")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DaemonStreamFetchResult::Stream(stream_events))
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
    daemon_endpoint: &str,
) -> String {
    render_attach_tui_with_columns_and_fallback(
        session_id,
        stream_events,
        daemon_endpoint,
        terminal_columns(),
        None,
    )
}

#[cfg(test)]
fn render_attach_tui_with_columns(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    daemon_endpoint: &str,
    columns: usize,
) -> String {
    render_attach_tui_with_columns_and_fallback(
        session_id,
        stream_events,
        daemon_endpoint,
        columns,
        None,
    )
}

fn render_attach_tui_with_columns_and_fallback(
    session_id: &str,
    stream_events: &[DaemonStreamEnvelope],
    daemon_endpoint: &str,
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
        daemon_endpoint,
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
    daemon_endpoint: &str,
    columns: usize,
) -> String {
    let full = format!(
        "session={session_id} state={state} events={received_events} seq={last_sequence} daemon={daemon_endpoint}"
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
