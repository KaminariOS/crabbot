import type { components } from "./generated";

type Schemas = components["schemas"];
type HeaderRecord = Record<string, string>;

export type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface CrabbotApiClientConfig {
  baseUrl: string;
  fetchFn?: FetchLike;
  defaultHeaders?: HeaderRecord;
}

export interface CreateSessionOptions {
  idempotencyKey?: string;
}

export interface AppendSessionMessageOptions {
  ifMatch?: number;
  idempotencyKey?: string;
}

interface RequestJsonOptions {
  bearerToken?: string;
  body?: unknown;
  headers?: HeaderRecord;
  okStatuses: readonly number[];
}

export class CrabbotApiError extends Error {
  readonly status: number;
  readonly method: string;
  readonly url: string;
  readonly responseBody: unknown;

  constructor(
    message: string,
    details: { status: number; method: string; url: string; responseBody: unknown },
  ) {
    super(message);
    this.name = "CrabbotApiError";
    this.status = details.status;
    this.method = details.method;
    this.url = details.url;
    this.responseBody = details.responseBody;
  }
}

export class CrabbotApiClient {
  private readonly baseUrl: string;
  private readonly fetchFn: FetchLike;
  private readonly defaultHeaders: HeaderRecord;

  constructor(config: CrabbotApiClientConfig) {
    const normalizedBaseUrl = config.baseUrl.trim().replace(/\/+$/, "");
    if (normalizedBaseUrl.length === 0) {
      throw new Error("CrabbotApiClient requires a non-empty baseUrl");
    }

    const fetchFn = config.fetchFn ?? globalThis.fetch;
    if (typeof fetchFn !== "function") {
      throw new Error(
        "CrabbotApiClient requires fetch; pass fetchFn in environments without global fetch",
      );
    }

    this.baseUrl = normalizedBaseUrl;
    this.fetchFn = fetchFn;
    this.defaultHeaders = { ...(config.defaultHeaders ?? {}) };
  }

  async getHealth(): Promise<Schemas["HealthResponse"]> {
    return this.requestJson<Schemas["HealthResponse"]>("GET", "/health", {
      okStatuses: [200],
    });
  }

  async login(payload: Schemas["LoginRequest"]): Promise<Schemas["LoginResponse"]> {
    return this.requestJson<Schemas["LoginResponse"]>("POST", "/auth/login", {
      body: payload,
      okStatuses: [200],
    });
  }

  async refresh(refreshToken: string): Promise<Schemas["LoginResponse"]> {
    return this.requestJson<Schemas["LoginResponse"]>("POST", "/auth/refresh", {
      bearerToken: refreshToken,
      okStatuses: [200],
    });
  }

  async listSessions(sessionToken: string): Promise<Schemas["ListSessionsResponse"]> {
    return this.requestJson<Schemas["ListSessionsResponse"]>("GET", "/sessions", {
      bearerToken: sessionToken,
      okStatuses: [200],
    });
  }

  async createSession(
    sessionToken: string,
    payload: Schemas["CreateSessionRequest"],
    options: CreateSessionOptions = {},
  ): Promise<Schemas["CreateSessionResponse"]> {
    const headers: HeaderRecord = {};
    if (options.idempotencyKey) {
      headers["idempotency-key"] = options.idempotencyKey;
    }

    return this.requestJson<Schemas["CreateSessionResponse"]>("POST", "/sessions", {
      bearerToken: sessionToken,
      body: payload,
      headers,
      okStatuses: [201],
    });
  }

  async getSession(
    sessionToken: string,
    sessionId: string,
  ): Promise<Schemas["GetSessionResponse"]> {
    return this.requestJson<Schemas["GetSessionResponse"]>(
      "GET",
      `/sessions/${encodeURIComponent(sessionId)}`,
      {
        bearerToken: sessionToken,
        okStatuses: [200],
      },
    );
  }

  async listSessionMessages(
    sessionToken: string,
    sessionId: string,
  ): Promise<Schemas["ListMessagesResponse"]> {
    return this.requestJson<Schemas["ListMessagesResponse"]>(
      "GET",
      `/sessions/${encodeURIComponent(sessionId)}/messages`,
      {
        bearerToken: sessionToken,
        okStatuses: [200],
      },
    );
  }

  async appendSessionMessage(
    sessionToken: string,
    sessionId: string,
    payload: Schemas["AppendMessageRequest"],
    options: AppendSessionMessageOptions = {},
  ): Promise<Schemas["AppendMessageResponse"]> {
    const headers: HeaderRecord = {};
    if (typeof options.ifMatch === "number") {
      headers["if-match"] = options.ifMatch.toString();
    }
    if (options.idempotencyKey) {
      headers["idempotency-key"] = options.idempotencyKey;
    }

    return this.requestJson<Schemas["AppendMessageResponse"]>(
      "POST",
      `/sessions/${encodeURIComponent(sessionId)}/messages`,
      {
        bearerToken: sessionToken,
        body: payload,
        headers,
        okStatuses: [201],
      },
    );
  }

  async getRealtimeBootstrap(
    sessionToken: string,
  ): Promise<Schemas["RealtimeBootstrapResponse"]> {
    return this.requestJson<Schemas["RealtimeBootstrapResponse"]>(
      "GET",
      "/realtime/bootstrap",
      {
        bearerToken: sessionToken,
        okStatuses: [200],
      },
    );
  }

  private async requestJson<T>(
    method: string,
    path: string,
    options: RequestJsonOptions,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: HeaderRecord = {
      accept: "application/json",
      ...this.defaultHeaders,
      ...(options.headers ?? {}),
    };

    if (options.bearerToken) {
      headers.authorization = `Bearer ${options.bearerToken}`;
    }

    let body: string | undefined;
    if (options.body !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(options.body);
    }

    const response = await this.fetchFn(url, {
      method,
      headers,
      body,
    });
    const rawBody = await response.text();
    const parsedBody = parseJsonSafely(rawBody);

    if (!options.okStatuses.includes(response.status)) {
      throw new CrabbotApiError(`${method} ${path} failed with ${response.status}`, {
        status: response.status,
        method,
        url,
        responseBody: parsedBody,
      });
    }

    if (parsedBody === undefined) {
      throw new CrabbotApiError(`${method} ${path} returned empty body`, {
        status: response.status,
        method,
        url,
        responseBody: parsedBody,
      });
    }

    return parsedBody as T;
  }
}

export function buildRealtimeWebSocketUrl(
  response: Schemas["RealtimeBootstrapResponse"],
  options: { sinceSequence?: number } = {},
): string {
  const url = new URL(response.websocket_url);
  url.searchParams.set("session_token", response.session_token);
  if (typeof options.sinceSequence === "number") {
    url.searchParams.set("since_sequence", options.sinceSequence.toString());
  }
  return url.toString();
}

function parseJsonSafely(rawBody: string): unknown {
  const trimmed = rawBody.trim();
  if (trimmed.length === 0) {
    return undefined;
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    return trimmed;
  }
}
