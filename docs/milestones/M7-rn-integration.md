# M7 RN Integration

## Objective
Switch RN app traffic to Rust API without frontend architecture breakage.

## Acceptance Criteria
- [ ] RN app consumes generated API types and new Rust endpoints.
- [ ] Feature flags support staged rollout between old and new backend behavior.
- [ ] Android + Web smoke tests pass against staging Rust backend.
- [ ] Sync sequencing and encrypted payload handling remain client-compatible.
