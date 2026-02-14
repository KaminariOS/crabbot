# M7 RN Integration

## Objective
Switch RN app traffic to Rust API without frontend architecture breakage.

## Acceptance Criteria
- [ ] RN app consumes generated API types and new Rust endpoints.
- [ ] Feature flags support staged rollout between old and new backend behavior.
- [ ] Android + Web smoke tests pass against staging Rust backend.
- [ ] Sync sequencing and encrypted payload handling remain client-compatible.

## Progress
- [x] Regenerated `apps/mobile/packages/api-client/src/generated.ts` from `schemas/openapi.yaml` to align generated contracts with current Rust API responses.
- [x] Added typed runtime endpoint wrappers in `apps/mobile/packages/api-client/src/client.ts` for RN use across auth/session/message/realtime bootstrap flows.
- [x] Added rollout helpers in `apps/mobile/packages/api-client/src/flags.ts` to gate Rust API and Rust realtime behavior using Expo public env flags.
- [ ] Integrate these runtime methods into RN Android/Web screens and state flows.
- [ ] Add staging smoke coverage for Android + Web.
