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
        WebSocketEnvelope: {
            /** Format: uint64 */
            sequence: number;
            event: components["schemas"]["ApiEvent"];
        };
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
    parameters: never;
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
}
