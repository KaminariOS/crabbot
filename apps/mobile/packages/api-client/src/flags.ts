export interface CrabbotApiRolloutFlags {
  useRustApi: boolean;
  useRustRealtime: boolean;
}

export interface CrabbotApiBaseUrls {
  legacyApiBaseUrl: string;
  rustApiBaseUrl: string;
}

export interface CrabbotApiRouting {
  apiBaseUrl: string;
  useRustRealtime: boolean;
}

export function readRolloutFlagsFromEnv(
  env: Record<string, string | undefined>,
): CrabbotApiRolloutFlags {
  return {
    useRustApi: parseBool(env.EXPO_PUBLIC_CRABBOT_USE_RUST_API, false),
    useRustRealtime: parseBool(env.EXPO_PUBLIC_CRABBOT_USE_RUST_REALTIME, false),
  };
}

export function resolveApiBaseUrl(
  baseUrls: CrabbotApiBaseUrls,
  flags: CrabbotApiRolloutFlags,
): string {
  return flags.useRustApi ? baseUrls.rustApiBaseUrl : baseUrls.legacyApiBaseUrl;
}

export function resolveApiRouting(
  baseUrls: CrabbotApiBaseUrls,
  flags: CrabbotApiRolloutFlags,
): CrabbotApiRouting {
  return {
    apiBaseUrl: resolveApiBaseUrl(baseUrls, flags),
    useRustRealtime: flags.useRustApi && flags.useRustRealtime,
  };
}

function parseBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  const normalized = value.trim().toLowerCase();
  if (normalized === "1" || normalized === "true" || normalized === "yes") {
    return true;
  }
  if (normalized === "0" || normalized === "false" || normalized === "no") {
    return false;
  }

  return fallback;
}
