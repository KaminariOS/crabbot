//! Stub module providing types from `bottom_pane` that `app_event` needs.
//!
//! The real `bottom_pane/` module has too many transitive deps to wire yet.
//! This stub provides the two types `app_event.rs` imports:
//!   - `ApprovalRequest`
//!   - `StatusLineItem`

use std::collections::HashMap;
use std::path::PathBuf;

use crate::protocol::ExecPolicyAmendment;
use crate::protocol::FileChange;
use crate::protocol::NetworkApprovalContext;
use crate::protocol::RequestId;

/// Approval request from the agent.
#[derive(Debug)]
pub(crate) enum ApprovalRequest {
    Exec {
        id: String,
        command: Vec<String>,
        reason: Option<String>,
        network_approval_context: Option<NetworkApprovalContext>,
        proposed_execpolicy_amendment: Option<ExecPolicyAmendment>,
    },
    ApplyPatch {
        id: String,
        reason: Option<String>,
        cwd: PathBuf,
        changes: HashMap<PathBuf, FileChange>,
    },
    McpElicitation {
        server_name: String,
        request_id: RequestId,
        message: String,
    },
}

/// Status line item selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusLineItem {
    ModelName,
    ModelWithReasoning,
    CurrentDir,
    ProjectRoot,
    GitBranch,
    ContextRemaining,
    ContextUsed,
    FiveHourLimit,
    WeeklyLimit,
    CodexVersion,
}
