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
extern crate self as codex_core;
extern crate self as codex_feedback;
extern crate self as codex_file_search;
extern crate self as codex_otel;
extern crate self as codex_utils_absolute_path;
extern crate self as codex_utils_approval_presets;
extern crate self as codex_utils_cli;
extern crate self as codex_utils_elapsed;
extern crate self as codex_utils_sandbox_summary;
extern crate self as codex_utils_sleep_inhibitor;
extern crate self as rmcp;

pub mod config {
    use crate::WireApi;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    pub mod types {
        use serde::Deserialize;
        use serde::Serialize;
        use std::collections::HashMap;
        use std::path::PathBuf;

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

    #[derive(Debug, Clone)]
    pub struct Config {
        pub codex_home: std::path::PathBuf,
        pub cwd: PathBuf,
        pub model: Option<String>,
        pub model_provider_id: String,
        pub model_provider: ConfigModelProvider,
        pub permissions: Permissions,
        pub model_reasoning_summary: ReasoningSummary,
        pub model_reasoning_effort: Option<crate::openai_models::ReasoningEffort>,
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
                model_reasoning_summary: ReasoningSummary::None,
                model_reasoning_effort: None,
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
        pub personality: Option<crate::config_types::Personality>,
        pub compact_prompt: Option<String>,
        pub additional_writable_roots: Vec<PathBuf>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct ConfigBuilder {
        config: Config,
    }

    impl ConfigBuilder {
        pub fn codex_home(mut self, codex_home: PathBuf) -> Self {
            self.config.codex_home = codex_home;
            self
        }
        pub fn cli_overrides(self, _cli_overrides: Vec<(String, toml::Value)>) -> Self {
            self
        }
        pub fn harness_overrides(mut self, harness_overrides: ConfigOverrides) -> Self {
            if let Some(cwd) = harness_overrides.cwd {
                self.config.cwd = cwd;
            }
            self
        }
        pub fn cloud_requirements(
            self,
            _cloud_requirements: crate::config_loader::CloudRequirementsLoader,
        ) -> Self {
            self
        }
        pub fn from_config(config: Config) -> Self {
            Self { config }
        }
        pub async fn build(self) -> std::io::Result<Config> {
            Ok(self.config)
        }
    }

    pub fn find_codex_home() -> anyhow::Result<std::path::PathBuf> {
        Ok(std::env::current_dir()?)
    }

    pub async fn load_config_as_toml_with_cli_overrides(
        _codex_home: &std::path::Path,
        _cwd: &crate::AbsolutePathBuf,
        _overrides: Vec<(String, toml::Value)>,
    ) -> anyhow::Result<toml::Value> {
        Ok(toml::Value::Table(toml::map::Map::new()))
    }

    pub fn resolve_oss_provider(_toml: &toml::Value, _cli: &ConfigOverrides) -> Option<String> {
        None
    }

    pub fn set_project_trust_level(
        _codex_home: &std::path::Path,
        _cwd: &std::path::Path,
        _trust: codex_protocol::config_types::TrustLevel,
    ) -> anyhow::Result<()> {
        Ok(())
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
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireApi {
    ChatCompletions,
    Responses,
}

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

fn get_shim_backend_config() -> ShimBackendConfig {
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
    pending_events: VecDeque<crate::protocol::Event>,
    config_snapshot: ThreadConfigSnapshot,
    rollout_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ThreadConfigSnapshot {
    pub model: String,
    pub model_provider_id: String,
    pub approval_policy: crate::protocol::AskForApproval,
    pub sandbox_policy: crate::protocol::SandboxPolicy,
    pub cwd: std::path::PathBuf,
    pub reasoning_effort: Option<crate::openai_models::ReasoningEffort>,
}

impl CodexThread {
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
                pending_events: VecDeque::new(),
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
                state.pending_events.push_back(crate::protocol::Event {
                    id: format!("seq-local-shutdown-{submission_id}"),
                    msg: crate::protocol::EventMsg::ShutdownComplete,
                });
            }
            _ => {}
        }

        Ok(submission_id)
    }

    fn event_from_codex_notification(
        sequence: u64,
        params: &Value,
    ) -> Option<crate::protocol::Event> {
        let event_value = params
            .get("event")
            .cloned()
            .unwrap_or_else(|| params.clone());
        if let Ok(event) = serde_json::from_value::<crate::protocol::Event>(event_value.clone()) {
            return Some(event);
        }
        if let Ok(msg) = serde_json::from_value::<crate::protocol::EventMsg>(event_value.clone()) {
            return Some(crate::protocol::Event {
                id: format!("seq-{sequence}"),
                msg,
            });
        }
        event_value
            .get("msg")
            .cloned()
            .and_then(|msg| serde_json::from_value::<crate::protocol::EventMsg>(msg).ok())
            .map(|msg| crate::protocol::Event {
                id: format!("seq-{sequence}"),
                msg,
            })
    }

    fn fallback_event_from_notification(
        sequence: u64,
        notification: &crabbot_protocol::DaemonRpcNotification,
    ) -> Option<crate::protocol::Event> {
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
                                .get("turn")
                                .and_then(|turn| {
                                    turn.get("lastAgentMessage")
                                        .or_else(|| turn.get("last_agent_message"))
                                })
                                .and_then(Value::as_str)
                                .map(ToString::to_string),
                        },
                    ),
                })
            }
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
                if item_type != "agent_message" && item_type != "agentmessage" {
                    return None;
                }
                let text = item
                    .get("text")
                    .or_else(|| item.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                Some(crate::protocol::Event {
                    id: format!("seq-{sequence}"),
                    msg: crate::protocol::EventMsg::AgentMessage(
                        crate::protocol::AgentMessageEvent { message: text },
                    ),
                })
            }
            _ => None,
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
                    state.last_sequence = state.last_sequence.max(envelope.sequence);
                    match envelope.event {
                        crabbot_protocol::DaemonRpcStreamEvent::Notification(notification) => {
                            let mapped = if notification.method == "codex/event" {
                                Self::event_from_codex_notification(
                                    envelope.sequence,
                                    &notification.params,
                                )
                            } else {
                                Self::fallback_event_from_notification(
                                    envelope.sequence,
                                    &notification,
                                )
                            };
                            if let Some(event) = mapped {
                                if let crate::protocol::EventMsg::TurnStarted(payload) = &event.msg
                                {
                                    state.current_turn_id = Some(payload.turn_id.clone());
                                } else if matches!(
                                    &event.msg,
                                    crate::protocol::EventMsg::TurnComplete(_)
                                        | crate::protocol::EventMsg::TurnAborted(_)
                                ) {
                                    state.current_turn_id = None;
                                }
                                state.pending_events.push_back(event);
                            }
                        }
                        crabbot_protocol::DaemonRpcStreamEvent::ServerRequest(_)
                        | crabbot_protocol::DaemonRpcStreamEvent::DecodeError(_) => {}
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

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new(
            std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir()),
            std::sync::Arc::new(crate::AuthManager::default()),
            crate::protocol::SessionSource::Cli,
        )
    }
}

impl ThreadManager {
    pub fn new(
        _codex_home: std::path::PathBuf,
        _auth_manager: std::sync::Arc<crate::AuthManager>,
        _session_source: crate::protocol::SessionSource,
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
        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/start",
            json!({
                "approvalPolicy": "on-request",
            }),
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
            approval_policy: crate::protocol::AskForApproval::OnRequest,
            sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
            cwd: config.cwd.clone(),
            reasoning_effort: None,
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
                approval_policy: crate::protocol::AskForApproval::OnRequest,
                sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                cwd: config.cwd,
                reasoning_effort: None,
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
        let Some(thread_id) = extract_thread_id_from_picker_path(&path)
            .and_then(|raw| ThreadId::from_string(&raw).ok())
        else {
            return self.start_thread(config).await;
        };
        let _ = auth_manager;

        let backend = get_shim_backend_config();
        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/resume",
            json!({
                "threadId": thread_id.to_string(),
            }),
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
        let config_snapshot = ThreadConfigSnapshot {
            model: model.clone(),
            model_provider_id: config.model_provider_id.clone(),
            approval_policy: crate::protocol::AskForApproval::OnRequest,
            sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
            cwd: config.cwd.clone(),
            reasoning_effort: None,
        };
        let thread = std::sync::Arc::new(CodexThread::new(
            thread_id,
            config_snapshot,
            Some(path.clone()),
        ));
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
                approval_policy: crate::protocol::AskForApproval::OnRequest,
                sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                cwd: config.cwd,
                reasoning_effort: None,
                history_log_id: 0,
                history_entry_count: 0,
                initial_messages: None,
                network_proxy: None,
                rollout_path: Some(path),
            },
        })
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
        let backend = get_shim_backend_config();
        let response = app_server_rpc_request_raw(
            &backend.app_server_endpoint,
            backend.auth_token.as_deref(),
            "thread/fork",
            json!({
                "threadId": source_thread_id,
            }),
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
        let config_snapshot = ThreadConfigSnapshot {
            model: model.clone(),
            model_provider_id: config.model_provider_id.clone(),
            approval_policy: crate::protocol::AskForApproval::OnRequest,
            sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
            cwd: config.cwd.clone(),
            reasoning_effort: None,
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
                approval_policy: crate::protocol::AskForApproval::OnRequest,
                sandbox_policy: crate::protocol::SandboxPolicy::new_workspace_write_policy(),
                cwd: config.cwd,
                reasoning_effort: None,
                history_log_id: 0,
                history_entry_count: 0,
                initial_messages: None,
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
        _limit: usize,
        _cursor: Option<&Cursor>,
        _sort_key: crate::ThreadSortKey,
        _sources: &[crate::protocol::SessionSource],
        _provider_filter: Option<&[String]>,
        _default_provider: &str,
    ) -> std::io::Result<ThreadsPage> {
        Ok(ThreadsPage::default())
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
            (Some(name), _) => Some(format!("crabbot resume {name}")),
            (None, Some(id)) => Some(format!("crabbot resume {id}")),
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
        Steer,
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
                Feature::Steer => "steer",
            }
        }
        pub fn from_key(key: &str) -> Option<Self> {
            match key {
                "collaboration_modes" => Some(Self::CollaborationModes),
                "personality" => Some(Self::Personality),
                "apps" => Some(Self::Apps),
                "prevent_idle_sleep" => Some(Self::PreventIdleSleep),
                "runtime_metrics" => Some(Self::RuntimeMetrics),
                "ghost_commit" => Some(Self::GhostCommit),
                "shell_tool" => Some(Self::ShellTool),
                "js_repl" => Some(Self::JsRepl),
                "unified_exec" => Some(Self::UnifiedExec),
                "apply_patch_freeform" => Some(Self::ApplyPatchFreeform),
                "web_search_request" => Some(Self::WebSearchRequest),
                "web_search_cached" => Some(Self::WebSearchCached),
                "search_tool" => Some(Self::SearchTool),
                "use_linux_sandbox_bwrap" => Some(Self::UseLinuxSandboxBwrap),
                "request_rule" => Some(Self::RequestRule),
                "windows_sandbox" => Some(Self::WindowsSandbox),
                "windows_sandbox_elevated" => Some(Self::WindowsSandboxElevated),
                "steer" => Some(Self::Steer),
                _ => None,
            }
        }

        pub const fn default_enabled(self) -> bool {
            let _ = self;
            false
        }
    }

    pub struct FeatureSpec {
        pub id: Feature,
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
            Self::default()
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

    pub static FEATURES: &[FeatureSpec] = &[];
}

pub mod skills {
    pub mod model {
        pub use codex_protocol::protocol::SkillDependencies;
        pub use codex_protocol::protocol::SkillInterface;
        pub use codex_protocol::protocol::SkillMetadata;
        pub use codex_protocol::protocol::SkillToolDependency;
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
}

pub mod user_input {
    pub use codex_protocol::user_input::*;
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

        pub async fn list_accessible_connectors_from_mcp_tools_with_options(
            _config: &crate::config::Config,
            _force_refetch: bool,
        ) -> anyhow::Result<Vec<AppInfo>> {
            Ok(Vec::new())
        }

        pub async fn list_all_connectors(
            _config: &crate::config::Config,
        ) -> anyhow::Result<Vec<AppInfo>> {
            Ok(Vec::new())
        }

        pub fn merge_connectors_with_accessible(
            mut all_connectors: Vec<AppInfo>,
            accessible_connectors: Vec<AppInfo>,
            allow_inaccessible: bool,
        ) -> Vec<AppInfo> {
            let mut by_id = std::collections::HashMap::new();
            for mut connector in all_connectors.drain(..) {
                by_id.insert(connector.id.clone(), connector.clone());
                if let Some(existing) = by_id.get_mut(&connector.id) {
                    *existing = connector;
                }
            }
            for accessible in accessible_connectors {
                by_id.insert(accessible.id.clone(), accessible);
            }
            let mut connectors: Vec<AppInfo> = by_id.into_values().collect();
            if !allow_inaccessible {
                connectors.retain(|c| c.is_accessible);
            }
            connectors.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            connectors
        }

        pub fn with_app_enabled_state(
            connectors: Vec<AppInfo>,
            _config: &crate::config::Config,
        ) -> Vec<AppInfo> {
            connectors
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

    #[derive(Debug, Clone, PartialEq)]
    pub struct ConstrainedWithSource<T> {
        pub value: crate::config::ValueRef<T>,
        pub source: Option<RequirementSource>,
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
            layers: Vec<ConfigLayerEntry>,
            requirements: ConfigRequirements,
            requirements_toml: ConfigRequirementsToml,
        ) -> std::io::Result<Self> {
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
            toml::Value::Table(toml::map::Map::new())
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
    #[derive(Debug, Clone)]
    pub enum Multiplexer {
        Zellij { pane_id: Option<String> },
    }

    #[derive(Debug, Clone, Default)]
    pub struct TerminalInfo {
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
        TerminalInfo { multiplexer }
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

    pub fn builtin_approval_presets() -> Vec<ApprovalPreset> {
        vec![ApprovalPreset {
            id: "default",
            label: "Default",
            description: "Default approvals",
            approval: AskForApproval::OnRequest,
            sandbox: SandboxPolicy::new_workspace_write_policy(),
        }]
    }
}
pub use codex_utils_approval_presets_stub::ApprovalPreset;
pub use codex_utils_approval_presets_stub::builtin_approval_presets;

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

#[derive(Debug, Clone)]
pub enum ResolveCwdOutcome {
    Continue(Option<std::path::PathBuf>),
    Exit,
}

pub async fn resolve_cwd_for_resume_or_fork(
    _tui: &mut crate::tui::Tui,
    current: &std::path::Path,
    _thread_path: &std::path::Path,
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
    let config = crate::config::Config::default();
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
        resume_picker::SessionSelection::Resume(thread_path)
        | resume_picker::SessionSelection::Fork(thread_path) => {
            Ok(extract_thread_id_from_picker_path(&thread_path)
                .or_else(|| Some(thread_path.to_string_lossy().to_string())))
        }
        resume_picker::SessionSelection::StartFresh | resume_picker::SessionSelection::Exit => {
            Ok(None)
        }
    }
}

pub fn set_app_server_connection_raw(app_server_endpoint: &str, auth_token: Option<&str>) {
    set_shim_backend_config(app_server_endpoint, auth_token);
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
    let thread_id = cli.resume_session_id.or(cli.fork_session_id);
    let startup_picker_show_all = cli.resume_show_all || cli.fork_show_all;

    handle_tui(
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

    Ok(app::AppExitInfo {
        token_usage: crate::protocol::TokenUsage::default(),
        thread_id: state
            .last_thread_id
            .as_deref()
            .and_then(|value| ThreadId::from_string(value).ok()),
        thread_name: None,
        update_action: None,
        exit_reason: app::ExitReason::UserRequested,
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
        return Ok(resume_picker::SessionSelection::Resume(PathBuf::from(
            trimmed,
        )));
    }

    let Some(mode) = args.startup_picker.as_ref() else {
        return Ok(resume_picker::SessionSelection::StartFresh);
    };

    let terminal = crate::tui::init().context("initialize tui terminal for startup picker")?;
    let mut tui = crate::tui::Tui::new(terminal);
    let config = crate::config::Config::default();
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

pub async fn handle_tui(args: TuiArgs, state: &mut CliState) -> Result<CommandOutput> {
    set_shim_backend_config(
        &state.config.app_server_endpoint,
        state.config.auth_token.as_deref(),
    );
    let session_selection = resolve_session_selection_from_args(&args, state).await?;

    let terminal = crate::tui::init().context("initialize tui terminal")?;
    let mut tui = crate::tui::Tui::new(terminal);
    let mut config = crate::config::Config::default();
    if let Ok(cwd) = std::env::current_dir() {
        config.cwd = cwd.clone();
        config.codex_home = cwd;
    }
    let use_alt_screen = determine_alt_screen_mode(args.no_alt_screen, config.tui_alternate_screen);
    tui.set_alt_screen_enabled(use_alt_screen);

    let run_result = app::App::run(
        &mut tui,
        std::sync::Arc::new(AuthManager::default()),
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

    Ok(CommandOutput::Text(String::new()))
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
    handle_tui(
        TuiArgs {
            thread_id: Some(session_id),
            no_alt_screen: false,
            startup_picker: None,
            startup_picker_show_all: false,
        },
        state,
    )
    .await
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

    candidates
        .into_iter()
        .find(|value| ThreadId::from_string(value).is_ok())
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
