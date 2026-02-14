# M4 Codex Runtime

## Objective
Implement the Codex App Server adapter and map runtime events into Crabbot protocol events.

## Acceptance Criteria
- [ ] `crates/codex_app_server` supports initialize/session/thread lifecycle primitives.
- [ ] Turn start/stream/complete flows are mapped to internal protocol updates.
- [ ] Interrupt/abort/resume semantics are implemented and replay-tested.
- [ ] Approval-required actions are surfaced with deterministic state transitions.
