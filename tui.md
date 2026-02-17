# TUI Upstream Port Checklist

Goal: make `crabbot` TUI match upstream `codex-rs/tui` behavior and structure, with exactly one architectural difference: backend transport uses app-server (`core_compat.rs`) instead of `codex-core`.

## Finish Plan (From Current State)

Current baseline:
- Real upstream `bottom_pane` is wired and `cargo check -p crabbot_tui` passes.
- Temporary compatibility stubs still exist (`history_cell_stub`, `exec_cell_stub`, `status_stub`, `status_indicator_widget_stub`, `skills_helpers_stub`) and must be removed.

Execution order to finish full port:

1. **History/Cell parity first**
- Replace `history_cell_stub` with real upstream `history_cell`.
- Keep only transport-facing protocol differences in `core_compat`/`lib` compatibility types.
- Exit criteria:
  - `mod history_cell` points to real module.
  - No `history_cell_stub` references in build graph.
  - `cargo check -p crabbot_tui` passes.

2. **Exec + status surface parity**
- Replace `exec_cell_stub`, `status_stub`, and `status_indicator_widget_stub` with real upstream modules.
- Port missing type/API shims in `lib.rs` so upstream modules compile unchanged.
- Exit criteria:
  - Real `exec_cell`, `status`, `status_indicator_widget` are active.
  - Footer/status rendering paths come from upstream modules.
  - `cargo check -p crabbot_tui` passes.

3. **Skill/helpers parity**
- Replace `skills_helpers_stub` with real upstream `skills_helpers`.
- Align `SkillMetadata` compatibility shape to upstream expectations used by picker/rendering.
- Exit criteria:
  - Real `skills_helpers` active.
  - Skill list/filter UI behavior matches upstream.

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
- [ ] `tui/src/lib.rs` uses upstream module graph structure.
- [x] `tui/src/tui.rs` now matches upstream file content.
- [x] Keep crate compiling while introducing runtime modules incrementally.
- [x] Keep command entry points stable for CLI integration (`crabbot_cli -> crabbot_tui`).
- [x] Verify TUI still launches after each runtime-step merge.

## Phase 2: App Layer Port (`app.rs`)

- [ ] Port upstream `app.rs` structure in place (same file name/path).
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

- [ ] Ensure all copied upstream modules are actually wired into compile/runtime graph.
- [x] Remove/avoid dead parallel runtime paths.
- [ ] Keep no `*_app_server.rs` duplicate UI files; modify upstream-path files in place.
- [ ] Keep path/name parity with upstream for all TUI source files.

## Phase 5: Diff Cleanup (Strict)

- [x] Run `diff -qr ~/repos/codex/codex-rs/tui/src ~/repos/crabbot/tui/src`.
- [x] Reduce diffs to only:
- [x] `tui/src/lib.rs`
- [x] `tui/src/app.rs`
- [x] `tui/src/chatwidget.rs`
- [x] `tui/src/core_compat.rs` (local seam file)
- [x] Confirm no unnecessary drift in other files.

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
- `tui/src/tui.rs` and `tui/src/notifications/mod.rs` now match upstream exactly.
- `tui/src/insert_history.rs` now matches upstream exactly.
- `lib.rs` provides a local compatibility namespace (`codex_core::config::types::NotificationMethod`) and a minimal `render::line_utils` bridge for wrapping support without introducing a `codex-core` dependency.

## Current Diff Inventory

- `tui/src/lib.rs`
- `tui/src/app.rs`
- `tui/src/chatwidget.rs`
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
