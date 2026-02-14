# @crabbot/api-client

Type-safe API contracts for the React Native app, generated from `schemas/openapi.yaml`.

## Commands

- `npm run generate` regenerates `src/generated.ts`

## Usage

```ts
import { CrabbotApiClient, readRolloutFlagsFromEnv, resolveApiRouting } from "@crabbot/api-client";

const flags = readRolloutFlagsFromEnv(process.env);
const routing = resolveApiRouting(
  {
    legacyApiBaseUrl: "https://legacy-api.crabbot.local",
    rustApiBaseUrl: "https://api.crabbot.local",
  },
  flags,
);

const client = new CrabbotApiClient({ baseUrl: routing.apiBaseUrl });
```

`CrabbotApiClient` exposes typed helpers for:

- `getHealth`
- `login`
- `refresh`
- `listSessions`
- `createSession`
- `getSession`
- `listSessionMessages`
- `appendSessionMessage`
- `getRealtimeBootstrap`

## Rollout Flags

- `EXPO_PUBLIC_CRABBOT_USE_RUST_API`: `true/false` switch for legacy vs Rust API base URL.
- `EXPO_PUBLIC_CRABBOT_USE_RUST_REALTIME`: enable Rust realtime transport only when Rust API is enabled.
