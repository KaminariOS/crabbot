# TUI Upstream Port Checklist

Goal: make `crabbot` TUI match upstream `codex-rs/tui` behavior and structure, with exactly one architectural difference: backend transport uses app-server (`core_compat.rs`) instead of `codex-core`.

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
