# M2 API Core

## Objective
Ship Rust API core flows for auth, sessions, machine state, messages, and websocket fanout.

## Acceptance Criteria
- [x] Auth flow stubs replaced by persisted token/session validation.
- [x] Session/message CRUD endpoints exist with optimistic version handling.
- [ ] WebSocket publish path emits stable sequence-ordered updates.
- [ ] Integration tests cover auth, session creation, message append, reconnect behavior.
