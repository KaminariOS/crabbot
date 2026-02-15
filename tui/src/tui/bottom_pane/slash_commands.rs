fn fuzzy_match(haystack: &str, needle: &str) -> Option<(Vec<usize>, i32)> {
    if needle.is_empty() {
        return Some((Vec::new(), i32::MAX));
    }

    let mut lowered_chars: Vec<char> = Vec::new();
    let mut lowered_to_orig_char_idx: Vec<usize> = Vec::new();
    for (orig_idx, ch) in haystack.chars().enumerate() {
        for lc in ch.to_lowercase() {
            lowered_chars.push(lc);
            lowered_to_orig_char_idx.push(orig_idx);
        }
    }

    let lowered_needle: Vec<char> = needle.to_lowercase().chars().collect();
    let mut result_orig_indices: Vec<usize> = Vec::with_capacity(lowered_needle.len());
    let mut last_lower_pos: Option<usize> = None;
    let mut cur = 0usize;
    for &nc in &lowered_needle {
        let mut found_at: Option<usize> = None;
        while cur < lowered_chars.len() {
            if lowered_chars[cur] == nc {
                found_at = Some(cur);
                cur += 1;
                break;
            }
            cur += 1;
        }
        let pos = found_at?;
        result_orig_indices.push(lowered_to_orig_char_idx[pos]);
        last_lower_pos = Some(pos);
    }

    let first_lower_pos = if result_orig_indices.is_empty() {
        0usize
    } else {
        let target_orig = result_orig_indices[0];
        lowered_to_orig_char_idx
            .iter()
            .position(|&oi| oi == target_orig)
            .unwrap_or(0)
    };
    let last_lower_pos = last_lower_pos.unwrap_or(first_lower_pos);
    let window =
        (last_lower_pos as i32 - first_lower_pos as i32 + 1) - (lowered_needle.len() as i32);
    let mut score = window.max(0);
    if first_lower_pos == 0 {
        score -= 100;
    }

    result_orig_indices.sort_unstable();
    result_orig_indices.dedup();
    Some((result_orig_indices, score))
}

pub(crate) struct TuiSlashCommand {
    pub(crate) command: &'static str,
    pub(crate) description: &'static str,
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

pub(crate) fn filtered_slash_commands(query: &str) -> Vec<&'static TuiSlashCommand> {
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

    let filter_lower = filter.to_ascii_lowercase();
    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    let mut fuzzy = Vec::new();

    for (index, command) in builtins.into_iter().enumerate() {
        let command_lower = command.command.to_ascii_lowercase();
        if command_lower == filter_lower {
            exact.push(command);
            continue;
        }
        if command_lower.starts_with(&filter_lower) {
            prefix.push(command);
            continue;
        }
        fuzzy.push((command, index));
    }

    if !exact.is_empty() || !prefix.is_empty() {
        let mut ordered = Vec::with_capacity(exact.len() + prefix.len());
        ordered.extend(exact);
        ordered.extend(prefix);
        return ordered;
    }

    let mut fuzzy_ranked = Vec::new();
    for (command, index) in fuzzy {
        if let Some((_, score)) = fuzzy_match(command.command, filter) {
            fuzzy_ranked.push((command, score, index));
        }
    }

    fuzzy_ranked.sort_by(|lhs, rhs| lhs.1.cmp(&rhs.1).then(lhs.2.cmp(&rhs.2)));

    fuzzy_ranked
        .into_iter()
        .map(|(command, _, _)| command)
        .collect()
}

pub(crate) fn find_visible_slash_command(name: &str) -> Option<&'static TuiSlashCommand> {
    let normalized = name.trim().trim_start_matches('/');
    if normalized.is_empty() {
        return None;
    }
    TUI_SLASH_COMMANDS.iter().find(|command| {
        slash_command_visible_in_picker(command) && command.command.eq_ignore_ascii_case(normalized)
    })
}

#[cfg(test)]
mod tests {
    use super::{filtered_slash_commands, find_visible_slash_command};

    #[test]
    fn fuzzy_fallback_works_when_no_prefix_matches() {
        let matches = filtered_slash_commands("mdl")
            .into_iter()
            .map(|entry| entry.command)
            .collect::<Vec<_>>();
        assert_eq!(matches.first().copied(), Some("model"));
    }

    #[test]
    fn exact_visible_command_lookup_is_case_insensitive() {
        assert!(find_visible_slash_command("/ReSuMe").is_some());
        assert!(find_visible_slash_command("   ").is_none());
    }
}
