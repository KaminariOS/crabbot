# Crabbot

Crabbot exists to let you access the same Codex thread remotely from both TUI and GUI clients.

The direction in this repo is:
- keep a Codex-style TUI (ported from OpenAI Codex),
- add a daemon/relay layer for remote access,
- use Codex app-server WebSocket + JSON-RPC interfaces as the runtime boundary.

## What Is Implemented Now

### 1. `crab` CLI (`services/cli`)

Main command:

```bash
crab [PROMPT]
```

Top-level subcommands:
- `crab resume`
- `crab fork`
- `crab daemon up|down|restart|status|logs`

Behavior:
- default interactive flow goes through the TUI crate
- daemon lifecycle is managed from CLI (`crab daemon up` etc.)
- local state is persisted at `~/.crabbot/cli-state.json` (or `CRABBOT_CLI_STATE_PATH`)

### 2. Daemon (`services/daemon`)

Default bind: `127.0.0.1:8788` (`CRABBOT_DAEMON_BIND`)

Routes:
- `GET /health`
- `POST /v1/notifications/register`
- `GET /` WebSocket proxy endpoint for app-server relay

Behavior:
- proxies WebSocket traffic between clients and Codex app-server
- exposes health and device push-token registration endpoints
- supports approval notification command hooks from relayed approval requests

### 3. Shared Contracts and Runtime Crates

- `crates/protocol`: shared protocol/event types used by daemon, CLI, and TUI

### 4. Android App Repository

- Android GUI app is maintained in a separate repository:
  - `https://github.com/KaminariOS/crabbot-app`

## Quickstart (Repo Root)

Enter dev shell:

```bash
nix develop
```

Build workspace:

```bash
cargo build --workspace
```

Run CLI help:

```bash
cargo run -p crabbot_cli -- --help
```

Start daemon from CLI (recommended):

```bash
cargo run -p crabbot_cli -- daemon up
```

Run tests:

```bash
cargo test --workspace
```

## Useful Environment Variables

CLI:
- `CRABBOT_CLI_STATE_PATH`
- `CRABBOT_DAEMON_BIN`

Daemon:
- `CRABBOT_DAEMON_BIND`
- `CRABBOT_CODEX_APP_SERVER_ENDPOINT`
- `CRABBOT_DAEMON_SPAWN_CODEX_APP_SERVER`
- `CRABBOT_CODEX_BIN`
- `CRABBOT_FCM_SERVICE_ACCOUNT_JSON_PATH`
- `CRABBOT_FCM_SERVICE_ACCOUNT_JSON`

## Repo Map

- `services/daemon`
- `services/cli`
- `tui`
- `crates/protocol`
- `schemas/openapi.yaml`
- `docs/milestones`
- `docs/adr`

## Current Caveats

- many components are still migration-stage and not production-hardened
- CLI default endpoint compatibility logic is still evolving (`ws://127.0.0.1:8765` normalization path exists)
