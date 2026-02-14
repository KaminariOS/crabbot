// Generated from schemas/openapi.yaml. Do not edit manually.

export interface paths {
    "/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** API health probe */
        get: operations["getHealth"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/login": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Exchange upstream token for Crabbot session credentials */
        post: operations["postAuthLogin"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/auth/refresh": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Refresh session token */
        post: operations["postAuthRefresh"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/sessions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List user sessions */
        get: operations["getSessions"];
        put?: never;
        /** Create a new session */
        post: operations["postSessions"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/sessions/{session_id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Fetch a session by id */
        get: operations["getSessionById"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/sessions/{session_id}/messages": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List messages for a session */
        get: operations["getSessionMessages"];
        put?: never;
        /** Append a message to a session */
        post: operations["postSessionMessage"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/realtime/bootstrap": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Fetch realtime websocket bootstrap details */
        get: operations["getRealtimeBootstrap"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        HealthResponse: {
            /** @enum {string} */
            status: "ok";
            service: string;
            version: string;
        };
        LoginRequest: {
            provider: string;
            access_token: string;
        };
        LoginResponse: {
            user_id: string;
            session_token: string;
            refresh_token: string;
            /** Format: uint64 */
            expires_at_unix_ms: number;
        };
        Session: {
            session_id: string;
            machine_id: string;
            state: string;
            /** Format: uint64 */
            optimistic_version: number;
            /** Format: uint64 */
            created_at_unix_ms: number;
            /** Format: uint64 */
            updated_at_unix_ms: number;
        };
        ListSessionsResponse: {
            sessions: components["schemas"]["Session"][];
            next_cursor?: string | null;
        };
        CreateSessionRequest: {
            machine_id: string;
            title_ciphertext: string;
        };
        CreateSessionResponse: {
            session: components["schemas"]["Session"];
        };
        GetSessionResponse: {
            session: components["schemas"]["Session"];
        };
        Message: {
            message_id: string;
            session_id: string;
            role: string;
            ciphertext: string;
            /** Format: uint64 */
            optimistic_version: number;
            /** Format: uint64 */
            created_at_unix_ms: number;
        };
        ListMessagesResponse: {
            session_id: string;
            messages: components["schemas"]["Message"][];
            next_cursor?: string | null;
        };
        AppendMessageRequest: {
            role: string;
            ciphertext: string;
            client_message_id?: string | null;
        };
        AppendMessageResponse: {
            message: components["schemas"]["Message"];
        };
        RealtimeBootstrapResponse: {
            /** Format: uri */
            websocket_url: string;
            session_token: string;
            /** Format: uint64 */
            heartbeat_interval_ms: number;
            /** Format: uint64 */
            last_sequence: number;
            schema_version: number;
        };
        /** @description Envelope for every websocket event published by the API. */
        WebSocketEnvelope: {
            /** @description Incremented only for breaking event shape changes. */
            schema_version: number;
            /**
             * Format: uint64
             * @description Monotonic per-user sequence for ordering and resume.
             */
            sequence: number;
            event: components["schemas"]["ApiEvent"];
        };
        /** @description Discriminated union of websocket event variants. */
        ApiEvent: components["schemas"]["SessionCreatedEvent"] | components["schemas"]["SessionUpdatedEvent"] | components["schemas"]["MessageAppendedEvent"] | components["schemas"]["TurnStreamDeltaEvent"] | components["schemas"]["TurnCompletedEvent"] | components["schemas"]["ApprovalRequiredEvent"] | components["schemas"]["HeartbeatEvent"];
        SessionCreatedEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "SessionCreatedEvent";
            payload: {
                session_id: string;
                machine_id: string;
                /** Format: uint64 */
                created_at_unix_ms: number;
            };
        };
        SessionUpdatedEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "SessionUpdatedEvent";
            payload: {
                session_id: string;
                /** Format: uint64 */
                optimistic_version: number;
                state: string;
            };
        };
        MessageAppendedEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "MessageAppendedEvent";
            payload: {
                session_id: string;
                message_id: string;
                role: string;
                ciphertext: string;
            };
        };
        TurnStreamDeltaEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "TurnStreamDeltaEvent";
            payload: {
                session_id: string;
                turn_id: string;
                delta: string;
            };
        };
        TurnCompletedEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "TurnCompletedEvent";
            payload: {
                session_id: string;
                turn_id: string;
                output_message_id: string;
            };
        };
        ApprovalRequiredEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "ApprovalRequiredEvent";
            payload: {
                session_id: string;
                turn_id: string;
                approval_id: string;
                action_kind: string;
            };
        };
        HeartbeatEvent: {
            /**
             * @description discriminator enum property added by openapi-typescript
             * @enum {string}
             */
            type: "HeartbeatEvent";
            payload: {
                /** Format: uint64 */
                unix_ms: number;
            };
        };
    };
    responses: never;
    parameters: {
        /** @description Stable session identifier */
        SessionId: string;
    };
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    getHealth: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Service health */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthResponse"];
                };
            };
        };
    };
    postAuthLogin: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["LoginRequest"];
            };
        };
        responses: {
            /** @description Login success */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginResponse"];
                };
            };
            /** @description Invalid credentials */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    postAuthRefresh: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Refresh stub is not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getSessions: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Sessions for the authenticated user */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListSessionsResponse"];
                };
            };
        };
    };
    postSessions: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CreateSessionRequest"];
            };
        };
        responses: {
            /** @description Session created */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CreateSessionResponse"];
                };
            };
            /** @description Invalid request payload */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getSessionById: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Stable session identifier */
                session_id: components["parameters"]["SessionId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Session details */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["GetSessionResponse"];
                };
            };
            /** @description Session not found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getSessionMessages: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Stable session identifier */
                session_id: components["parameters"]["SessionId"];
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Session messages */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListMessagesResponse"];
                };
            };
            /** @description Session not found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    postSessionMessage: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Stable session identifier */
                session_id: components["parameters"]["SessionId"];
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AppendMessageRequest"];
            };
        };
        responses: {
            /** @description Message appended */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AppendMessageResponse"];
                };
            };
            /** @description Invalid request payload */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description Session not found */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
        };
    };
    getRealtimeBootstrap: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Realtime connection metadata */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RealtimeBootstrapResponse"];
                };
            };
        };
    };
}
