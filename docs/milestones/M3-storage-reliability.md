# M3 Storage + Reliability

## Objective
Integrate Postgres/Redis/object storage and harden reliability semantics.

## Acceptance Criteria
- [x] Postgres models for accounts/sessions/messages/machines/artifacts are implemented.
- [x] Redis-backed presence/realtime optimization is integrated behind clear adapters.
- [x] Idempotency keys and retry semantics are enforced on write APIs.
- [x] Load and soak tests validate websocket fanout and high-frequency update stability.
