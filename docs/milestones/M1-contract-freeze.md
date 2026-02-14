# M1 Contract Freeze

## Objective
Define and freeze HTTP/WebSocket contracts for RN and CLI consumers.

## Acceptance Criteria
- [ ] `schemas/openapi.yaml` includes auth/session/message/realtime baseline endpoints and schemas.
- [ ] RN API client types are generated from OpenAPI with a reproducible command.
- [ ] WebSocket event envelopes and payloads are versioned and documented.
- [ ] Contract tests fail on breaking API/schema changes.
