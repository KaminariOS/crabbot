# Websocket Events Contract

## Versioning
- `schema_version` is included in every `WebSocketEnvelope`.
- Current version is `1`.
- Any breaking change to websocket event shape must increment `schema_version`.

## Envelope
- `schema_version`: websocket payload schema version.
- `sequence`: monotonic per-user event sequence for resume/reconciliation.
- `event`: discriminated event payload (`type` + `payload`).

## Event Types
- `session_created`
- `session_updated`
- `message_appended`
- `turn_stream_delta`
- `turn_completed`
- `approval_required`
- `heartbeat`

Canonical source for field-level definitions is `schemas/openapi.yaml`.

## Connection
- Bootstrap via `GET /realtime/bootstrap` to get `session_token` and last known `sequence`.
- Connect websocket at `/realtime` with either:
  - query params: `session_token`, optional `since_sequence`
  - or `Authorization: Bearer <session_token>` header
- On reconnect, pass `since_sequence=<last_seen_sequence>` to replay missed events in order.
