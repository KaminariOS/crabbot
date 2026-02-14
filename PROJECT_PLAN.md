What We Are Building
  It is a highly customized rewrite of the `happy` project. 
  We are building Crabbot: a Codex-only engineering assistant platform with:

  1. Frontend: React Native app (targets Android + Web).
  2. Backend: Rust services (API + realtime + session orchestration).
  3. Runtime: Rust integration with Codex App Server (not Codex MCP server).
  4. CLI: Rust CLI for Linux.
  5. Goal: replace Happy’s TS backend/CLI/agent stack with a Rust-first system while keeping RN frontend.
  6. Bonus: support heartbeat, schedule and triggers like https://github.com/HKUDS/nanobot

  Scope

  1. In scope: Android/Web RN app support, Rust API/daemon/CLI, Codex-only runtime, E2E encrypted sync model.
  2. In scope: native-Codex-like terminal UX improvements for Linux CLI. Android app should be able to use the full features of Codex cli.
  3. Out of scope: Claude/Gemini support, iOS/macOS/Windows CLI packaging.
  4. Out of scope: keeping old multi-provider abstractions.

  Target Repository Layout

  1. apps/mobile for React Native (Expo Android + Web).
  2. services/api for Rust HTTP + WebSocket API.
  3. services/daemon for Rust Codex session runtime.
  4. services/cli for Rust Linux CLI.
  5. crates/protocol for shared API/socket types.
  6. crates/codex_app_server for Codex App Server client/state machine.
  7. crates/crypto for auth/encryption primitives.
  8. crates/storage for Postgres/Redis/object storage adapters.
  9. crates/observability for logs/metrics/tracing.
  10. schemas/openapi.yaml as wire contract source.
  11. docs/adr for architecture decisions.

  Architecture Plan

  1. RN app communicates only with services/api.
  2. services/api handles auth, persistence, websocket fanout, optimistic concurrency, and sequencing.
  3. services/daemon manages Codex threads/turns/interrupts/resume through Codex App Server.
  4. services/cli controls local sessions and talks to API/daemon.
  5. Shared protocol crate defines stable payloads for RN + CLI + API.
  6. Shared crypto crate ensures one encryption/auth implementation everywhere.

  Execution Milestones

  1. M0 Foundation (Week 1): Rust workspace, CI, lint/test baseline, repo scaffolding.
  2. M1 Contract Freeze (Week 1-2): define/lock HTTP + WS schema used by RN.
  3. M2 API Core (Week 2-4): auth, sessions, machines, messages, websocket updates.
  4. M3 Storage + Reliability (Week 3-5): Postgres/Redis/object storage, retries, idempotency.
  5. M4 Codex Runtime (Week 4-6): Codex App Server adapter, stream/event mapping, approvals.
  6. M5 Linux CLI (Week 5-7): codex command, daemon controls, resume/interrupt flow.
  7. M6 TUI Parity Pass (Week 6-8): native-style footer/status/streaming presentation.
  8. M7 RN Integration (Week 7-9): app wired to Rust API with zero frontend architecture breakage.
  9. M8 Cutover + Cleanup (Week 9-10): remove TS runtime paths, codex-only cleanup, production rollout.

  Codex App Server Migration Plan

  1. Create codex_app_server crate with typed protocol client.
  2. Implement initialize/session/thread lifecycle.
  3. Implement turn start/stream consume/turn complete handling.
  4. Implement interrupt/abort semantics with resume support.
  5. Implement approval pipeline for command/file/tool actions.
  6. Map all Codex events to internal protocol events for app and CLI.
  7. Remove codex mcp-server control path from core runtime.

  RN Frontend Integration Plan

  1. Keep RN codebase; replace backend target URLs and contracts only.
  2. Generate TS API types from OpenAPI and consume in RN.
  3. Keep websocket event names/payload stability during transition.
  4. Add feature flags for staged rollout between old/new backend.
  5. Keep Android/Web build flow unchanged while backend changes.

  Data and API Plan

  1. Use Postgres as source of truth for accounts/sessions/messages/machines/artifacts.
  2. Use Redis for ephemeral presence/realtime optimization.
  3. Keep optimistic version fields for metadata/state updates.
  4. Keep per-user monotonic sequence model for reconciliation.
  5. Keep encrypted payload boundaries client-compatible.

  Testing Plan

  1. Unit tests per Rust crate.
  2. Contract tests for every API endpoint and WS event.
  3. Golden replay tests for Codex stream sessions.
  4. Integration tests for auth, sync, reconnect, abort/resume.
  5. Load tests for websocket fanout and high-frequency updates.
  6. End-to-end Android/Web smoke tests against staging.

  CI/CD Plan

  1. GitHub Actions with Rust fmt, clippy, test, security audit.
  2. API schema diff checks as merge gate.
  3. Staging deploy on every merge to main.
  4. Canary release for backend cutover.
  5. Rollback playbook tested before full production switch.

  Risk Management

  1. Risk: contract drift with RN. Mitigation: schema generation + contract tests.
  2. Risk: Codex runtime edge cases. Mitigation: replay harness + session state machine.
  3. Risk: sync ordering bugs. Mitigation: sequence/version invariants tested.
  4. Risk: migration complexity. Mitigation: phased cutover with feature flags.
  5. Risk: fork maintenance cost. Mitigation: ADRs + monthly upstream sync cadence.

  Definition of Done

  1. Android and Web app stable on Rust backend.
  2. Linux crabbot codex works with Codex App Server end-to-end.
  3. No Claude/Gemini runtime codepaths remain.
  4. API/socket contracts are documented and test-enforced.
  5. SLOs and error budgets met in production.
  6. Legacy TS runtime retired.

  First Sprint (Start Now)

  - [x] Scaffold full monorepo folders and Cargo workspace.
  - [x] Add protocol crate and initial API event schemas.
  - [x] Build services/api skeleton with health/auth stubs.
  - [x] Build codex_app_server crate skeleton with connection smoke test.
  - [x] Create RN API client package from OpenAPI generation.
  - [x] Create milestone issues M0-M8 with acceptance criteria.

  Current Sprint (M3 Kickoff)

  - [x] Implement storage domain records and in-memory adapters for accounts/sessions/messages/machines/artifacts.
  - [x] Add clear presence and object storage adapters for reliability-layer integration points.
  - [x] Integrate realtime websocket presence tracking (online/offline lifecycle) through storage adapters.
  - [x] Enforce `Idempotency-Key` replay semantics on write APIs for sessions/messages with conflict detection.
  - [x] Add load/soak harness for websocket fanout and retry-heavy traffic patterns.
  - [x] Add env-configurable manual soak test entrypoint:
        `CRABBOT_SOAK_CLIENTS=16 CRABBOT_SOAK_WRITERS=4 CRABBOT_SOAK_MESSAGES_PER_WRITER=64 cargo test -p crabbot_api realtime_websocket_soak_harness_is_env_configurable -- --ignored`

  Current Sprint (M4 Kickoff)

  - [x] Expand `crates/codex_app_server` with initialize/session/thread lifecycle primitives.
  - [x] Add deterministic mapping for turn start/delta/complete and approval-required runtime events.
  - [x] Implement abort + replay-tested resume behavior for interrupted turns.

  Current Sprint (M5 Kickoff)

  - [x] Implement `crabbot codex` CLI workflows: `start`, `resume`, `interrupt`, and `status`.
  - [x] Add local CLI config/auth management for API/daemon endpoints and auth token persistence.
  - [x] Replace local attach mirroring with real daemon stream integration.
  - [x] Add end-to-end CLI-to-daemon and CLI-to-API happy path tests.
  - [x] Route CLI `start`/`resume`/`interrupt` through daemon control endpoints with persisted local status cache.
  - [x] Route CLI `status --session-id ...` through daemon status endpoint with cache refresh semantics.
  - [x] Refresh local status cache from daemon stream session-state events during `attach`.
  - [x] Forward configured CLI auth token as `Authorization: Bearer` on daemon and API control requests.

  Current Sprint (M6 Kickoff)

  - [x] Add `crabbot codex attach --tui` mode to render daemon stream deltas as terminal text output.
  - [x] Add an attach status footer with session/state/event count/sequence metadata.
  - [x] Make attach footer responsive to terminal width by compacting fields on narrow terminals.
  - [ ] Add approval prompt and recoverable resume/interrupt TUI states.
  - [ ] Add screenshot/golden regression coverage for CLI TUI output.
