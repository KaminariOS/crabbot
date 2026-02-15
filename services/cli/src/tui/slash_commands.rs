pub(super) struct TuiSlashCommand {
    pub(super) command: &'static str,
    pub(super) description: &'static str,
    hide_in_empty_picker: bool,
    requires_collaboration_modes: bool,
    requires_connectors: bool,
    requires_personality: bool,
    requires_windows_degraded_sandbox: bool,
    windows_only: bool,
    debug_only: bool,
}

const TUI_SLASH_COMMANDS: &[TuiSlashCommand] = &[
    TuiSlashCommand {
        command: "model",
        description: "choose what model and reasoning effort to use",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "approvals",
        description: "choose what Codex is allowed to do",
        hide_in_empty_picker: true,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "permissions",
        description: "choose what Codex is allowed to do",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "setup-default-sandbox",
        description: "set up elevated agent sandbox",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: true,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "sandbox-add-read-dir",
        description: "let sandbox read a directory: /sandbox-add-read-dir <absolute_path>",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: true,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "experimental",
        description: "toggle experimental features",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "skills",
        description: "use skills to improve how Codex performs specific tasks",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "review",
        description: "review my current changes and find issues",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "rename",
        description: "rename the current thread",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "new",
        description: "start a new chat during a conversation",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "resume",
        description: "resume a saved chat",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "fork",
        description: "fork the current chat",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "init",
        description: "create an AGENTS.md file with instructions for Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "compact",
        description: "summarize conversation to prevent hitting the context limit",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "plan",
        description: "switch to Plan mode",
        hide_in_empty_picker: false,
        requires_collaboration_modes: true,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "collab",
        description: "change collaboration mode (experimental)",
        hide_in_empty_picker: false,
        requires_collaboration_modes: true,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "agent",
        description: "switch the active agent thread",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "diff",
        description: "show git diff (including untracked files)",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "mention",
        description: "mention a file",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "status",
        description: "show current session configuration and token usage",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "debug-config",
        description: "show config layers and requirement sources for debugging",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "statusline",
        description: "configure which items appear in the status line",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "mcp",
        description: "list configured MCP tools",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "apps",
        description: "manage apps",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: true,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "logout",
        description: "log out of Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "quit",
        description: "exit Codex",
        hide_in_empty_picker: true,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "exit",
        description: "exit Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "feedback",
        description: "send logs to maintainers",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "rollout",
        description: "print the rollout file path",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: true,
    },
    TuiSlashCommand {
        command: "ps",
        description: "list background terminals",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "clean",
        description: "stop all background terminals",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "personality",
        description: "choose a communication style for Codex",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: true,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "test-approval",
        description: "test approval request",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: true,
    },
    TuiSlashCommand {
        command: "debug-m-drop",
        description: "DO NOT USE",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
    TuiSlashCommand {
        command: "debug-m-update",
        description: "DO NOT USE",
        hide_in_empty_picker: false,
        requires_collaboration_modes: false,
        requires_connectors: false,
        requires_personality: false,
        requires_windows_degraded_sandbox: false,
        windows_only: false,
        debug_only: false,
    },
];

const TUI_COLLABORATION_MODES_ENABLED: bool = false;
const TUI_CONNECTORS_ENABLED: bool = false;
const TUI_PERSONALITY_COMMAND_ENABLED: bool = false;
const TUI_WINDOWS_DEGRADED_SANDBOX_ACTIVE: bool = false;

fn slash_command_visible_in_picker(command: &TuiSlashCommand) -> bool {
    if command.windows_only && !cfg!(target_os = "windows") {
        return false;
    }
    if command.debug_only && !cfg!(debug_assertions) {
        return false;
    }
    if command.requires_collaboration_modes && !TUI_COLLABORATION_MODES_ENABLED {
        return false;
    }
    if command.requires_connectors && !TUI_CONNECTORS_ENABLED {
        return false;
    }
    if command.requires_personality && !TUI_PERSONALITY_COMMAND_ENABLED {
        return false;
    }
    if command.requires_windows_degraded_sandbox && !TUI_WINDOWS_DEGRADED_SANDBOX_ACTIVE {
        return false;
    }
    true
}

pub(super) fn filtered_slash_commands(query: &str) -> Vec<&'static TuiSlashCommand> {
    let builtins: Vec<&'static TuiSlashCommand> = TUI_SLASH_COMMANDS
        .iter()
        .filter(|command| slash_command_visible_in_picker(command))
        .collect();
    let filter = query.trim();
    if filter.is_empty() {
        return builtins
            .into_iter()
            .filter(|command| !command.hide_in_empty_picker)
            .collect();
    }

    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    let filter_lower = filter.to_ascii_lowercase();
    for command in builtins {
        let command_lower = command.command.to_ascii_lowercase();
        if command_lower == filter_lower {
            exact.push(command);
        } else if command_lower.starts_with(&filter_lower) {
            prefix.push(command);
        }
    }
    exact.extend(prefix);
    exact
}
