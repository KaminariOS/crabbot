# TUI Upstream Port Checklist

Goal: make `crabbot` TUI match upstream `codex-rs/tui` behavior and structure, with exactly one architectural difference: backend transport uses app-server (`core_compat.rs`) instead of `codex-core`.

## Finish Plan (From Current State)

Current baseline:
- Real upstream modules are wired for:
  - `history_cell`
  - `exec_cell`
  - `status`
  - `status_indicator_widget`
  - `skills_helpers`
- Temporary compatibility stubs have been removed from module wiring and deleted.
- Build gates currently pass:
  - `cargo check -p crabbot_tui`
  - `cargo run -p crabbot_cli -- codex --help`
- One temporary non-transport diff remains in `history_cell.rs`:
  - `UpdateAvailableHistoryCell::display_lines` uses manual `Line` construction instead of `ratatui_macros::{line,text}` due local workspace `ratatui` git patch type mismatch against crates.io `ratatui-macros`.
  - This is a compatibility workaround, not intended long-term drift.

Execution order to finish full port:

1. **History/Cell parity first**
- Replace `history_cell_stub` with real upstream `history_cell`.
- Keep only transport-facing protocol differences in `core_compat`/`lib` compatibility types.
- Exit criteria:
  - [x] `mod history_cell` points to real module.
  - [x] No `history_cell_stub` references in build graph.
  - [x] `cargo check -p crabbot_tui` passes.

2. **Exec + status surface parity**
- Replace `exec_cell_stub`, `status_stub`, and `status_indicator_widget_stub` with real upstream modules.
- Port missing type/API shims in `lib.rs` so upstream modules compile unchanged.
- Exit criteria:
  - [x] Real `exec_cell`, `status`, `status_indicator_widget` are active.
  - [x] Footer/status rendering paths come from upstream modules.
  - [x] `cargo check -p crabbot_tui` passes.

3. **Skill/helpers parity**
- Replace `skills_helpers_stub` with real upstream `skills_helpers`.
- Align `SkillMetadata` compatibility shape to upstream expectations used by picker/rendering.
- Exit criteria:
  - [x] Real `skills_helpers` active.
  - [ ] Skill list/filter UI behavior matches upstream (manual verification pending).

4. **ChatWidget full upstream structure**
- Port `chatwidget.rs` structure to upstream flow (state shape, render orchestration, bottom pane coordination).
- Remove custom preamble/render patches not present upstream.
- Keep only event translation boundary at app-server seam.
- Exit criteria:
  - Visual behavior for composer/footer/status/overlay matches upstream.
  - No custom rendering hacks outside upstream code paths.

5. **App loop full upstream structure**
- Port `app.rs` event routing/order/mode transitions to upstream layout.
- Route backend operations strictly through `core_compat.rs`.
- Exit criteria:
  - Key handling, overlays, and run loop scheduling match upstream behavior.
  - Attach/new/resume/interrupt flow works with app-server transport.

6. **Compatibility shim reduction**
- Remove obsolete stubbed types/functions from `lib.rs` once real upstream modules compile.
- Keep only required compatibility shims for app-server seam and crates intentionally not imported.
- Exit criteria:
  - `lib.rs` shim surface minimized and documented.

7. **Strict diff cleanup + validation**
- Re-run diff audit and reduce drift.
- Required validation set:
  - `cargo check -p crabbot_tui`
  - `cargo run -p crabbot_cli -- codex --help`
  - Manual `cargo run -p crabbot_cli -- codex` visual parity checks
  - `attach/resume/new/interrupt` lifecycle checks
- Exit criteria:
  - Final diff list is intentional and transport-seam-scoped.
  - UI is visually/functionally parity-aligned with upstream.

## Phase 0: Baseline and Guardrails

- [x] Pull latest upstream reference (`~/repos/codex`).
- [x] Confirm current source diff scope against upstream (`tui/src`).
- [x] Freeze current seam rule: all backend-specific logic stays in `tui/src/core_compat.rs`.
- [x] Add a repeatable diff check command set to validate only allowed diffs.
- [x] Add a compile gate command set (`cargo check -p crabbot_tui`, `cargo run -p crabbot_cli -- codex --help`).

## Phase 1: Runtime Path Parity (No UI Feature Changes Yet)

- [ ] Replace simplified runtime entry flow with upstream runtime flow shape (in progress):
- [x] `tui/src/lib.rs` uses upstream module graph structure for real UI modules (stub module paths removed).
- [x] `tui/src/tui.rs` now matches upstream file content.
- [x] Keep crate compiling while introducing runtime modules incrementally.
- [x] Keep command entry points stable for CLI integration (`crabbot_cli -> crabbot_tui`).
- [x] Verify TUI still launches after each runtime-step merge.

## Phase 2: App Layer Port (`app.rs`)

- [ ] Port upstream `app.rs` structure in place (same file name/path). (in progress)
- [x] Added upstream-style internal `AppEvent` dispatch queue in `App` (`AppEventSender` + receiver drain in main loop).
- [x] Centralized Enter submit path through `AppEvent::SubmitInput` -> `App::handle_submit` for app-runner flow.
- [x] Removed duplicate legacy key/submit path from `app.rs`; app runtime now has a single active submit/action route.
- [x] Routed stream polling through `AppEvent::Tick` -> `AppEvent::StreamUpdate` queue handling (removed direct widget polling path).
- [x] `/new` and `/interrupt` submit commands now enqueue app events instead of recursively calling handlers.
- [x] `/resume`, `/approve`, `/deny`, and `/refresh` now dispatch through explicit app events (`ResumeSession`, `ApprovalDecision`, `Tick`) instead of inline side effects.
- [x] Event-loop queue draining deduplicated into a single helper to keep loop scheduling flow centralized.
- [x] Ctrl-C and `/exit`/`/quit` now route through `AppEvent::Exit` dispatch; tick stream poll failures now set status and continue instead of aborting the TUI loop.
- [x] `/status` and `/refresh` now dispatch through dedicated app events (`ShowStatus`, `RefreshStream`) so submit handling remains dispatch-oriented.
- [x] Centralized thread-switch state updates in `app.rs` (`switch_to_thread`) and reused for `NewSession`/`ResumeSession`.
- [x] `chatwidget` now clears per-thread transient state on `thread/started` stream events (active turn + pending approvals) and emits a switch line when thread id changes.
- [ ] Remove `codex-core` calls from `app.rs`; route backend operations through `core_compat.rs`.
- [ ] Preserve upstream app event handling order and redraw scheduling.
- [ ] Preserve upstream overlays/pickers mode transitions.
- [ ] Keep app-server transport mapping isolated from UI logic.

## Phase 3: Chat Layer Port (`chatwidget.rs`)

- [ ] Port upstream `chatwidget.rs` flow in place (same file name/path).
- [ ] Keep upstream transcript/history rendering behavior.
- [ ] Keep upstream bottom pane interactions (composer, slash, overlays, status rows).
- [ ] Replace core event ingestion with translated app-server events from `core_compat.rs`.
- [ ] Keep approvals UX matching upstream behavior where protocol allows.

## Phase 4: Module Wiring Completion

- [x] Ensure all copied upstream modules are actually wired into compile/runtime graph.
- [x] Remove/avoid dead parallel runtime paths.
- [x] Keep no `*_app_server.rs` duplicate UI files; modify upstream-path files in place.
- [x] Keep path/name parity with upstream for all TUI source files (transport seam files excepted).

## Phase 5: Diff Cleanup (Strict)

- [x] Run `diff -qr ~/repos/codex/codex-rs/tui/src ~/repos/crabbot/tui/src`.
- [ ] Reduce diffs to only:
- [x] `tui/src/lib.rs`
- [x] `tui/src/app.rs`
- [x] `tui/src/chatwidget.rs`
- [x] `tui/src/core_compat.rs` (local seam file)
- [ ] `tui/src/history_cell.rs` temporary compatibility workaround remains (remove after ratatui macro compatibility fix).
- [x] Confirm no other unnecessary drift/stub files.

## Phase 6: Behavior Validation

- [ ] Manual run: `cargo run -p crabbot_cli -- codex`.
- [ ] Validate visual parity for:
- [ ] composer/footer rows
- [ ] slash picker behavior
- [ ] transcript cell rendering
- [ ] status/working indicators
- [ ] approval prompts and flow
- [ ] attach/resume/new/interrupt behaviors
- [ ] Validate no regressions for app-server turn lifecycle.

## Phase 7: Finalization

- [ ] Final diff audit with `delta` for each differing file.
- [ ] Document exact seam points inside `core_compat.rs`.
- [ ] Keep commits scoped by phase.
- [ ] Provide final report: what changed, remaining known gaps (if any), exact diff list.

## Allowed End-State Diff Policy

- Allowed conceptual difference: transport/backend wiring to app-server.
- Not allowed: alternate UI architecture, duplicate runtime loops, renamed parallel files, or UI behavior drift outside transport constraints.

## Transitional Notes (Current)

- `tui/src/app.rs` now hosts the active app-server runtime loop (previous temporary shim removed).
- `tui/src/app.rs` now uses an internal event queue similar to upstream app-event dispatch and drains queued events each loop iteration.
- App submit handling in the app runtime is now single-path (`Enter` queues `SubmitInput`, handled by `App::handle_submit`) to reduce duplicated behavior drift.
- Removed now-unused alternate `ChatWidget::on_event` bridge that relied on deleted legacy key/submit helpers.
- Stream ingestion now follows the same app-event pipeline (`Tick` polls stream, emits `StreamUpdate`, applies in `handle_event`), matching upstream central dispatch style.
- `tui/src/tui.rs` and `tui/src/notifications/mod.rs` now match upstream exactly.
- `tui/src/insert_history.rs` now matches upstream exactly.
- `lib.rs` now provides an expanded compatibility surface so upstream `history_cell` / `exec_cell` / `status` compile while transport remains app-server driven.
- `history_cell.rs` has one temporary compatibility diff in `UpdateAvailableHistoryCell::display_lines` due `ratatui` patch + `ratatui-macros` type mismatch in this workspace.

## Current Diff Inventory

- `tui/src/lib.rs`
- `tui/src/app.rs`
- `tui/src/chatwidget.rs`
- `tui/src/history_cell.rs` (temporary macro compatibility workaround)
- `tui/src/core_compat.rs` (local seam file)

## Repeatable Commands

```bash
# Upstream parity audit
diff -qr ~/repos/codex/codex-rs/tui/src ~/repos/crabbot/tui/src
git diff --no-index ~/repos/codex/codex-rs/tui/src/lib.rs ~/repos/crabbot/tui/src/lib.rs | delta
git diff --no-index ~/repos/codex/codex-rs/tui/src/tui.rs ~/repos/crabbot/tui/src/tui.rs | delta
git diff --no-index ~/repos/codex/codex-rs/tui/src/app.rs ~/repos/crabbot/tui/src/app.rs | delta
git diff --no-index ~/repos/codex/codex-rs/tui/src/chatwidget.rs ~/repos/crabbot/tui/src/chatwidget.rs | delta

# Build gates
cargo check -p crabbot_tui
cargo run -p crabbot_cli -- codex --help
```
