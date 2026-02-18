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
extern crate self as codex_chatgpt;
extern crate self as codex_core;
extern crate self as codex_feedback;
extern crate self as codex_file_search;
extern crate self as codex_otel;
extern crate self as codex_protocol;
extern crate self as codex_utils_approval_presets;
extern crate self as codex_utils_cli;
extern crate self as codex_utils_elapsed;
extern crate self as codex_utils_sandbox_summary;
extern crate self as rmcp;

pub mod config {
    use crate::WireApi;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    pub mod types {
        pub use crate::core_compat::config::types::NotificationMethod;
        use serde::Deserialize;
        use serde::Serialize;
        use std::collections::HashMap;
        use std::path::PathBuf;

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        pub enum McpServerTransportConfig {
            Stdio {
                command: String,
                #[serde(default)]
                args: Vec<String>,
                #[serde(default)]
                env: Option<HashMap<String, String>>,
                #[serde(default)]
                env_vars: Option<HashMap<String, String>>,
                #[serde(default)]
                cwd: Option<PathBuf>,
            },
            StreamableHttp {
                url: String,
                #[serde(default)]
                http_headers: Option<HashMap<String, String>>,
                #[serde(default)]
                env_http_headers: Option<HashMap<String, String>>,
            },
        }

        #[derive(Debug, Clone, Default, Serialize, Deserialize)]
        pub struct McpServerConfig {
            pub transport: McpServerTransportConfig,
            #[serde(default = "enabled_default")]
            pub enabled: bool,
            #[serde(default)]
            pub disabled_reason: Option<String>,
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
                    env_vars: None,
                    cwd: None,
                }
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub enum ReasoningSummary {
        None,
        Auto,
        Concise,
        Detailed,
    }

    impl std::fmt::Display for ReasoningSummary {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                ReasoningSummary::None => f.write_str("none"),
                ReasoningSummary::Auto => f.write_str("auto"),
                ReasoningSummary::Concise => f.write_str("concise"),
                ReasoningSummary::Detailed => f.write_str("detailed"),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ValueRef<T>(pub T);

    impl<T> ValueRef<T> {
        pub fn get(&self) -> &T {
            &self.0
        }
        pub fn value(&self) -> T
        where
            T: Clone,
        {
            self.0.clone()
        }
    }

    #[derive(Debug, Clone)]
    pub struct Permissions {
        pub approval_policy: ValueRef<crate::protocol::AskForApproval>,
        pub sandbox_policy: ValueRef<crate::protocol::SandboxPolicy>,
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
    }

    impl Default for McpServers {
        fn default() -> Self {
            Self(BTreeMap::new())
        }
    }

    #[derive(Debug, Clone)]
    pub struct Config {
        pub cwd: PathBuf,
        pub model: Option<String>,
        pub model_provider_id: String,
        pub model_provider: ConfigModelProvider,
        pub permissions: Permissions,
        pub model_reasoning_summary: ReasoningSummary,
        pub model_context_window: Option<i64>,
        pub show_tooltips: bool,
        pub mcp_servers: McpServers,
        pub model_supports_reasoning_summaries: Option<bool>,
    }

    #[derive(Debug, Clone)]
    pub struct ConfigModelProvider {
        pub name: String,
        pub env_key: Option<String>,
        pub wire_api: WireApi,
        pub base_url: Option<String>,
    }

    impl Default for ConfigModelProvider {
        fn default() -> Self {
            Self {
                name: "openai".to_string(),
                env_key: None,
                wire_api: WireApi::Responses,
                base_url: None,
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
                cwd: std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()),
                model: None,
                model_provider_id: "openai".to_string(),
                model_provider: ConfigModelProvider::default(),
                permissions: Permissions {
                    approval_policy: ValueRef(crate::protocol::AskForApproval::OnRequest),
                    sandbox_policy: ValueRef(
                        crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                    ),
                },
                model_reasoning_summary: ReasoningSummary::None,
                model_context_window: None,
                show_tooltips: true,
                mcp_servers: McpServers::default(),
                model_supports_reasoning_summaries: None,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireApi {
    ChatCompletions,
    Responses,
}

pub mod auth {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AuthMode {
        ApiKey,
        Chatgpt,
    }
}

#[derive(Debug, Clone)]
pub struct CachedAuth {
    mode: auth::AuthMode,
    email: Option<String>,
}

impl CachedAuth {
    pub fn auth_mode(&self) -> auth::AuthMode {
        self.mode
    }

    pub fn get_account_email(&self) -> Option<String> {
        self.email.clone()
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
                email: None,
            }),
        }
    }

    pub fn from_chatgpt_email(email: Option<String>) -> Self {
        Self {
            auth: Some(CachedAuth {
                mode: auth::AuthMode::Chatgpt,
                email,
            }),
        }
    }
}

pub mod project_doc {
    use crate::config::Config;
    use std::path::Path;
    use std::path::PathBuf;

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
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ReviewDecision {
        Approved,
        ApprovedExecpolicyAmendment {
            proposed_execpolicy_amendment: ExecPolicyAmendment,
        },
        ApprovedForSession,
        Denied,
        Abort,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "camelCase")]
    pub enum ReviewTarget {
        UncommittedChanges,
        BaseBranch {
            branch: String,
        },
        Commit {
            sha: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            title: Option<String>,
        },
        Custom {
            instructions: String,
        },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ReviewRequest {
        pub target: ReviewTarget,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub user_facing_hint: Option<String>,
    }

    /// Source of an exec command.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ExecCommandSource {
        Agent,
        User,
        UserShell,
        UnifiedExecStartup,
        UnifiedExecInteraction,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SkillScope {
        #[default]
        User,
        Repo,
        System,
        Admin,
    }

    /// Stub for `codex_core::protocol::Op` – submission operation.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    #[allow(dead_code)]
    pub enum Op {
        Interrupt,
        Compact,
        DropMemories,
        UpdateMemories,
        UserInput {
            items: Vec<serde_json::Value>,
        },
        Review {
            review_request: ReviewRequest,
        },
        ExecApproval {
            id: String,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            turn_id: Option<String>,
            decision: ReviewDecision,
        },
        PatchApproval {
            id: String,
            decision: ReviewDecision,
        },
        ResolveElicitation {
            server_name: String,
            request_id: RequestId,
            decision: ElicitationAction,
        },
        UserInputAnswer {
            id: String,
            response: crate::request_user_input::RequestUserInputResponse,
        },
        GetHistoryEntryRequest {
            offset: usize,
            log_id: u64,
        },
        ListSkills {
            #[serde(default, skip_serializing_if = "Vec::is_empty")]
            cwds: Vec<std::path::PathBuf>,
            #[serde(default, skip_serializing_if = "std::ops::Not::not")]
            force_reload: bool,
        },
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
        #[serde(default)]
        pub primary: Option<RateLimitWindow>,
        #[serde(default)]
        pub secondary: Option<RateLimitWindow>,
        #[serde(default)]
        pub credits: Option<CreditsSnapshot>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RateLimitWindow {
        #[serde(default)]
        pub used_percent: f64,
        #[serde(default)]
        pub resets_at: Option<i64>,
        #[serde(default)]
        pub window_minutes: Option<i64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CreditsSnapshot {
        #[serde(default)]
        pub has_credits: bool,
        #[serde(default)]
        pub unlimited: bool,
        #[serde(default)]
        pub balance: Option<String>,
    }

    #[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub struct TokenUsage {
        #[serde(default)]
        pub input_tokens: i64,
        #[serde(default)]
        pub cached_input_tokens: i64,
        #[serde(default)]
        pub output_tokens: i64,
        #[serde(default)]
        pub reasoning_output_tokens: i64,
        #[serde(default)]
        pub total_tokens: i64,
    }

    impl TokenUsage {
        pub fn tokens_in_context_window(&self) -> i64 {
            self.input_tokens + self.cached_input_tokens + self.output_tokens
        }

        pub fn blended_total(&self) -> i64 {
            self.total_tokens
        }

        pub fn non_cached_input(&self) -> i64 {
            self.input_tokens
        }

        pub fn percent_of_context_window_remaining(&self, window: i64) -> i64 {
            if window <= 0 {
                return 0;
            }
            let used = self.tokens_in_context_window().max(0);
            ((window - used).max(0) * 100) / window
        }
    }

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct TokenUsageInfo {
        #[serde(default)]
        pub last_token_usage: TokenUsage,
        #[serde(default)]
        pub model_context_window: Option<i64>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum SessionSource {
        Local,
        Remote,
        Cli,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ElicitationAction {
        Accept,
        Decline,
        Cancel,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum McpAuthStatus {
        Unknown,
        Authorized,
        Unauthorized,
        Unsupported,
    }

    impl std::fmt::Display for McpAuthStatus {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                McpAuthStatus::Unknown => f.write_str("unknown"),
                McpAuthStatus::Authorized => f.write_str("authorized"),
                McpAuthStatus::Unauthorized => f.write_str("unauthorized"),
                McpAuthStatus::Unsupported => f.write_str("unsupported"),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct McpInvocation {
        pub server: String,
        pub tool: String,
        #[serde(default)]
        pub arguments: Option<serde_json::Value>,
        pub server_name: String,
        pub tool_name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SessionConfiguredEvent {
        pub session_id: String,
        pub model: String,
        #[serde(default)]
        pub reasoning_effort: Option<crate::openai_models::ReasoningEffort>,
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
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub mod path_utils {
    use std::path::Path;
    use std::path::PathBuf;

    /// Compatibility shim for upstream `codex_core::path_utils::normalize_for_path_comparison`.
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
    use serde::Deserialize;
    use serde::Serialize;
    use std::path::PathBuf;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    pub enum ParsedCommand {
        Read {
            cmd: String,
            name: String,
            path: PathBuf,
        },
        ListFiles {
            cmd: String,
            path: Option<String>,
        },
        Search {
            cmd: String,
            query: Option<String>,
            path: Option<String>,
        },
        Unknown {
            cmd: String,
        },
    }

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
        CollaborationModes,
        Personality,
        Apps,
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

    impl Feature {
        pub const fn key(self) -> &'static str {
            match self {
                Feature::CollaborationModes => "collaboration_modes",
                Feature::Personality => "personality",
                Feature::Apps => "apps",
                Feature::PreventIdleSleep => "prevent_idle_sleep",
                Feature::RuntimeMetrics => "runtime_metrics",
                Feature::GhostCommit => "ghost_commit",
                Feature::ShellTool => "shell_tool",
                Feature::JsRepl => "js_repl",
                Feature::UnifiedExec => "unified_exec",
                Feature::ApplyPatchFreeform => "apply_patch_freeform",
                Feature::WebSearchRequest => "web_search_request",
                Feature::WebSearchCached => "web_search_cached",
                Feature::SearchTool => "search_tool",
                Feature::UseLinuxSandboxBwrap => "use_linux_sandbox_bwrap",
                Feature::RequestRule => "request_rule",
                Feature::WindowsSandbox => "windows_sandbox",
                Feature::WindowsSandboxElevated => "windows_sandbox_elevated",
            }
        }

        pub fn from_key(key: &str) -> Option<Self> {
            match key {
                "collaboration_modes" => Some(Feature::CollaborationModes),
                "personality" => Some(Feature::Personality),
                "apps" => Some(Feature::Apps),
                "prevent_idle_sleep" => Some(Feature::PreventIdleSleep),
                "runtime_metrics" => Some(Feature::RuntimeMetrics),
                "ghost_commit" => Some(Feature::GhostCommit),
                "shell_tool" => Some(Feature::ShellTool),
                "js_repl" => Some(Feature::JsRepl),
                "unified_exec" => Some(Feature::UnifiedExec),
                "apply_patch_freeform" => Some(Feature::ApplyPatchFreeform),
                "web_search_request" => Some(Feature::WebSearchRequest),
                "web_search_cached" => Some(Feature::WebSearchCached),
                "search_tool" => Some(Feature::SearchTool),
                "use_linux_sandbox_bwrap" => Some(Feature::UseLinuxSandboxBwrap),
                "request_rule" => Some(Feature::RequestRule),
                "windows_sandbox" => Some(Feature::WindowsSandbox),
                "windows_sandbox_elevated" => Some(Feature::WindowsSandboxElevated),
                _ => None,
            }
        }
    }

    /// Static feature list (empty in stub — features are server-side in crabbot).
    pub static FEATURES: &[FeatureSpec] = &[];
}

pub mod skills {
    pub mod model {
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct SkillInterface {
            #[serde(default)]
            pub display_name: Option<String>,
            #[serde(default)]
            pub short_description: Option<String>,
        }

        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        pub struct SkillMetadata {
            pub name: String,
            pub description: String,
            #[serde(default)]
            pub short_description: Option<String>,
            #[serde(default)]
            pub interface: Option<SkillInterface>,
            #[serde(default)]
            pub path: std::path::PathBuf,
            #[serde(default)]
            pub scope: crate::protocol::SkillScope,
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
            #[serde(default)]
            pub branding: Option<serde_json::Value>,
            #[serde(default)]
            pub app_metadata: Option<serde_json::Value>,
            #[serde(default)]
            pub labels: Option<std::collections::HashMap<String, String>>,
            pub install_url: Option<String>,
            #[serde(default)]
            pub is_accessible: bool,
            #[serde(default)]
            pub is_enabled: bool,
        }

        pub fn connector_display_label(connector: &AppInfo) -> String {
            connector.name.clone()
        }

        pub fn connector_mention_slug(connector: &AppInfo) -> String {
            connector_name_slug(&connector.name)
        }

        fn connector_name_slug(name: &str) -> String {
            let mut normalized = String::with_capacity(name.len());
            for character in name.chars() {
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
    }
}
pub use codex_chatgpt_stub::connectors;

/// Stub backing `codex_file_search`.
mod codex_file_search_stub {
    use serde::Deserialize;
    use serde::Serialize;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::thread;

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
        query_tx: mpsc::Sender<String>,
    }

    impl FileSearchSession {
        pub fn update_query(&self, query: &str) {
            let _ = self.query_tx.send(query.to_string());
        }
    }

    /// Create a file search session.
    pub fn create_session(
        roots: Vec<PathBuf>,
        _options: FileSearchOptions,
        reporter: std::sync::Arc<dyn SessionReporter>,
        _cancel: Option<()>,
    ) -> Result<FileSearchSession, String> {
        if roots.is_empty() {
            return Err("no search roots configured".to_string());
        }
        let (query_tx, query_rx) = mpsc::channel::<String>();
        thread::spawn(move || {
            while let Ok(mut query) = query_rx.recv() {
                while let Ok(next) = query_rx.try_recv() {
                    query = next;
                }

                let query = query.trim().to_ascii_lowercase();
                if query.is_empty() {
                    reporter.on_update(&FileSearchSnapshot {
                        query: String::new(),
                        matches: Vec::new(),
                    });
                    continue;
                }

                let mut matches = Vec::new();
                for root in &roots {
                    collect_matches(root, root, &query, &mut matches);
                    if matches.len() >= 200 {
                        break;
                    }
                }
                matches.sort_by_key(|m| m.path.clone());
                reporter.on_update(&FileSearchSnapshot { query, matches });
            }
            reporter.on_complete();
        });
        Ok(FileSearchSession { query_tx })
    }

    fn collect_matches(root: &PathBuf, dir: &PathBuf, query: &str, out: &mut Vec<FileMatch>) {
        if out.len() >= 200 {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if out.len() >= 200 {
                break;
            }
            let path = entry.path();
            let file_name = entry.file_name();
            let file_name = file_name.to_string_lossy();
            if file_name.starts_with(".git") || file_name == "target" {
                continue;
            }

            if path.is_dir() {
                collect_matches(root, &path, query, out);
                continue;
            }
            if !path.is_file() {
                continue;
            }

            let Ok(rel) = path.strip_prefix(root) else {
                continue;
            };
            let rel_str = rel.to_string_lossy().to_ascii_lowercase();
            if rel_str.contains(query) {
                let score = if rel_str.ends_with(query) {
                    100
                } else if rel_str.contains(&format!("/{query}")) {
                    80
                } else {
                    60
                };
                out.push(FileMatch {
                    score,
                    path: rel.to_path_buf(),
                    root: root.clone(),
                    indices: None,
                });
            }
        }
    }
}
pub use codex_file_search_stub::FileMatch;
pub use codex_file_search_stub::FileSearchOptions;
pub use codex_file_search_stub::FileSearchSession;
pub use codex_file_search_stub::FileSearchSnapshot;
pub use codex_file_search_stub::SessionReporter;
pub use codex_file_search_stub::create_session;

pub fn ansi_escape_line(input: &str) -> ratatui::text::Line<'static> {
    ratatui::text::Line::from(input.to_string())
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

        pub fn from_string(value: impl Into<String>) -> Result<Self, uuid::Error> {
            let uuid = value.into();
            let parsed = uuid::Uuid::parse_str(&uuid)?;
            Ok(Self {
                uuid: parsed.to_string(),
            })
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

        impl std::fmt::Display for ReasoningEffort {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    ReasoningEffort::None => f.write_str("none"),
                    ReasoningEffort::Minimal => f.write_str("minimal"),
                    ReasoningEffort::Low => f.write_str("low"),
                    ReasoningEffort::Medium => f.write_str("medium"),
                    ReasoningEffort::High => f.write_str("high"),
                    ReasoningEffort::XHigh => f.write_str("xhigh"),
                }
            }
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

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
        #[serde(rename_all = "snake_case")]
        pub enum ModeKind {
            Plan,
            #[default]
            #[serde(
                alias = "code",
                alias = "pair_programming",
                alias = "execute",
                alias = "custom"
            )]
            Default,
            #[doc(hidden)]
            #[serde(skip_serializing, skip_deserializing)]
            PairProgramming,
            #[doc(hidden)]
            #[serde(skip_serializing, skip_deserializing)]
            Execute,
        }

        impl ModeKind {
            pub const fn is_tui_visible(self) -> bool {
                matches!(self, Self::Plan | Self::Default)
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Settings {
            pub model: String,
            pub reasoning_effort: Option<super::openai_models::ReasoningEffort>,
            pub developer_instructions: Option<String>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct CollaborationMode {
            pub mode: ModeKind,
            pub settings: Settings,
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
        use serde_json::Value;

        pub use crate::protocol::RequestId;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct Resource {
            pub uri: String,
            pub name: String,
            #[serde(default)]
            pub title: Option<String>,
            #[serde(default)]
            pub description: Option<String>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct ResourceTemplate {
            pub uri_template: String,
            pub name: String,
            #[serde(default)]
            pub title: Option<String>,
            #[serde(default)]
            pub description: Option<String>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        pub struct Tool {
            #[serde(default)]
            pub name: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        pub struct CallToolResult {
            #[serde(default)]
            pub content: Vec<Value>,
            #[serde(default)]
            pub is_error: Option<bool>,
        }
    }

    pub mod plan_tool {
        use serde::Deserialize;
        use serde::Serialize;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct PlanItemArg {
            pub step: String,
            pub status: StepStatus,
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum StepStatus {
            Pending,
            InProgress,
            Completed,
        }

        impl std::fmt::Display for StepStatus {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    StepStatus::Pending => f.write_str("pending"),
                    StepStatus::InProgress => f.write_str("in_progress"),
                    StepStatus::Completed => f.write_str("completed"),
                }
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize, Default)]
        pub struct UpdatePlanArgs {
            #[serde(default)]
            pub explanation: Option<String>,
            #[serde(default)]
            pub plan: Vec<PlanItemArg>,
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
            #[serde(default)]
            pub description: Option<String>,
        }
    }

    pub mod user_input {
        use serde::Deserialize;
        use serde::Serialize;

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct ByteRange {
            pub start: usize,
            pub end: usize,
        }

        impl From<std::ops::Range<usize>> for ByteRange {
            fn from(range: std::ops::Range<usize>) -> Self {
                Self {
                    start: range.start,
                    end: range.end,
                }
            }
        }

        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct TextElement {
            pub byte_range: ByteRange,
            #[serde(default)]
            placeholder: Option<String>,
        }

        impl TextElement {
            pub fn new(byte_range: ByteRange, placeholder: Option<String>) -> Self {
                Self {
                    byte_range,
                    placeholder,
                }
            }

            pub fn map_range<F>(&self, map: F) -> Self
            where
                F: FnOnce(ByteRange) -> ByteRange,
            {
                Self {
                    byte_range: map(self.byte_range.clone()),
                    placeholder: self.placeholder.clone(),
                }
            }

            pub fn set_placeholder(&mut self, placeholder: Option<String>) {
                self.placeholder = placeholder;
            }

            pub fn placeholder<'a>(&'a self, text: &'a str) -> Option<&'a str> {
                self.placeholder
                    .as_deref()
                    .or_else(|| text.get(self.byte_range.start..self.byte_range.end))
            }
        }
    }

    pub mod request_user_input {
        use serde::Deserialize;
        use serde::Serialize;
        use std::collections::HashMap;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputQuestionOption {
            pub label: String,
            pub description: String,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputQuestion {
            pub id: String,
            pub header: String,
            pub question: String,
            #[serde(default, rename = "isOther")]
            pub is_other: bool,
            #[serde(default, rename = "isSecret")]
            pub is_secret: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub options: Option<Vec<RequestUserInputQuestionOption>>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputAnswer {
            #[serde(default)]
            pub answers: Vec<String>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputEvent {
            #[serde(default)]
            pub call_id: String,
            #[serde(default)]
            pub turn_id: String,
            #[serde(default)]
            pub request_id: String,
            #[serde(default)]
            pub prompt: Option<String>,
            #[serde(default)]
            pub questions: Vec<RequestUserInputQuestion>,
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct RequestUserInputResponse {
            #[serde(default)]
            pub answers: HashMap<String, RequestUserInputAnswer>,
        }
    }

    pub mod models {
        pub fn local_image_label_text(index: usize) -> String {
            format!("[Image #{index}]")
        }

        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum WebSearchAction {
            Requested,
            Cached,
        }
    }
}
pub use codex_protocol_stub::*;

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
        _rollout_path: Option<&std::path::Path>,
        _source: Option<crate::protocol::SessionSource>,
    ) -> Result<(), String> {
        Ok(())
    }
}

pub fn summarize_sandbox_policy(policy: &protocol::SandboxPolicy) -> String {
    policy.to_string()
}

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

    pub mod format_env_display {
        use std::collections::HashMap;

        pub fn format_env_display(
            env: Option<&HashMap<String, String>>,
            env_vars: &Option<HashMap<String, String>>,
        ) -> String {
            let mut entries: Vec<String> = Vec::new();
            if let Some(env) = env {
                for (k, _v) in env {
                    entries.push(format!("{k}=*****"));
                }
            }
            if let Some(env_vars) = env_vars {
                for (k, v) in env_vars {
                    entries.push(format!("{k}={v}"));
                }
            }
            entries.sort();
            if entries.is_empty() {
                "-".to_string()
            } else {
                entries.join(", ")
            }
        }
    }
}
pub use codex_utils_cli_stub::ApprovalModeCliArg;
pub use codex_utils_cli_stub::CliConfigOverrides;
pub use codex_utils_cli_stub::SandboxModeCliArg;
pub use codex_utils_cli_stub::format_env_display;

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

#[derive(Debug, Default, Clone)]
struct ConfigSetArgs {
    api_endpoint: Option<String>,
    app_server_endpoint: Option<String>,
    auth_token: Option<String>,
    clear_auth_token: bool,
}

mod additional_dirs;
mod app;
mod app_event;
mod app_event_sender;
mod ascii_animation;
mod bottom_pane;
mod chatwidget;
mod cli;
mod clipboard_paste;
mod color;
mod core_compat;
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
pub mod live_wrap;
mod markdown;
mod markdown_render;
mod markdown_stream;
mod mention_codec;
mod model_migration;
mod notifications;
mod pager_overlay;
mod render;
mod resume_picker;
mod selection_list;
mod session_log;
mod shimmer;
mod skills_helpers;
mod slash_command;
#[path = "bottom_pane/slash_commands.rs"]
mod slash_commands;
mod status;
mod status_indicator_widget;
mod streaming;
mod style;
mod terminal_palette;
mod text_formatting;
mod tooltips;
pub mod tui;
mod ui_consts;
mod update_action;
mod version;
mod wrapping;

pub use app::handle_attach_tui_interactive;
pub use app::handle_tui;

pub async fn run_startup_picker(
    mode: StartupPicker,
    show_all: bool,
    state: &CliState,
) -> Result<Option<String>> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(None);
    }

    let terminal = crate::tui::init().context("initialize tui terminal for startup picker")?;
    let mut tui = crate::tui::Tui::new(terminal);
    let selection = match mode {
        StartupPicker::Resume => resume_picker::run_resume_picker(&mut tui, state, show_all)
            .await
            .map_err(|err| anyhow!("{err}"))?,
        StartupPicker::Fork => resume_picker::run_fork_picker(&mut tui, state, show_all)
            .await
            .map_err(|err| anyhow!("{err}"))?,
    };
    let _ = crate::tui::restore();

    match selection {
        resume_picker::SessionSelection::Resume(thread_id)
        | resume_picker::SessionSelection::Fork(thread_id) => Ok(Some(thread_id)),
        resume_picker::SessionSelection::StartFresh | resume_picker::SessionSelection::Exit => {
            Ok(None)
        }
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
            // Keep protocol unblocked with a schema-compliant empty answer map.
            "item/tool/requestUserInput" => self.send_json(&json!({
                "id": request.request_id,
                "result": { "answers": {} }
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
        "session={session_id} state={state} events={received_events} seq={last_sequence} app_server={app_server_endpoint}"
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
