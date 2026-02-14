# M1 Contract Freeze

## Objective
Define and freeze HTTP/WebSocket contracts for RN and CLI consumers.

## Acceptance Criteria
- [x] `schemas/openapi.yaml` includes auth/session/message/realtime baseline endpoints and schemas.
- [x] RN API client types are generated from OpenAPI with a reproducible command.
- [x] WebSocket event envelopes and payloads are versioned and documented.
- [x] Contract tests fail on breaking API/schema changes.
