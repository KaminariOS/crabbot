# M4 Codex Runtime

## Objective
Implement the Codex App Server adapter and map runtime events into Crabbot protocol events.

## Acceptance Criteria
- [x] `crates/codex_app_server` supports initialize/session/thread lifecycle primitives.
- [x] Turn start/stream/complete flows are mapped to internal protocol updates.
- [x] Interrupt/abort/resume semantics are implemented and replay-tested.
- [x] Approval-required actions are surfaced with deterministic state transitions.
