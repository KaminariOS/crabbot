# M6 TUI Parity Pass

## Objective
Reach native Codex-like terminal UX parity in the Rust CLI experience.

## Acceptance Criteria
- [ ] Streaming token output and status footer behavior match target UX requirements.
- [ ] Approval prompts, interrupts, and resume UI states are clear and recoverable.
- [ ] Terminal layout adapts to narrow and wide Linux terminal sizes.
- [ ] UX regression tests and screenshot/golden checks are in place.

## Progress
- [x] `crabbot codex attach --session-id ... --tui` renders streamed turn deltas inline with turn completion lines.
- [x] `attach --tui` now includes a compact status footer with session/state/event/sequence metadata.
- [x] Footer output adapts to terminal width by removing endpoint details in narrow terminals.
- [x] `attach --tui` surfaces approval-required prompts and explicit resume recovery hints for interrupted sessions.
- [x] Added golden regression fixture coverage for `attach --tui` output formatting stability.
