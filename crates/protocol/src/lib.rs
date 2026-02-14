use serde::{Deserialize, Serialize};

pub const WEBSOCKET_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRequest {
    pub provider: String,
    pub access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginResponse {
    pub user_id: String,
    pub session_token: String,
    pub refresh_token: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub machine_id: String,
    pub state: String,
    pub optimistic_version: u64,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListSessionsResponse {
    pub sessions: Vec<Session>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionRequest {
    pub machine_id: String,
    pub title_ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionResponse {
    pub session: Session,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetSessionResponse {
    pub session: Session,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Message {
    pub message_id: String,
    pub session_id: String,
    pub role: String,
    pub ciphertext: String,
    pub optimistic_version: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListMessagesResponse {
    pub session_id: String,
    pub messages: Vec<Message>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppendMessageRequest {
    pub role: String,
    pub ciphertext: String,
    pub client_message_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppendMessageResponse {
    pub message: Message,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealtimeBootstrapResponse {
    pub websocket_url: String,
    pub session_token: String,
    pub heartbeat_interval_ms: u64,
    pub last_sequence: u64,
    pub schema_version: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebSocketEnvelope {
    pub schema_version: u16,
    pub sequence: u64,
    pub event: ApiEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum ApiEvent {
    SessionCreated(SessionCreated),
    SessionUpdated(SessionUpdated),
    MessageAppended(MessageAppended),
    TurnStreamDelta(TurnStreamDelta),
    TurnCompleted(TurnCompleted),
    ApprovalRequired(ApprovalRequired),
    Heartbeat(Heartbeat),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCreated {
    pub session_id: String,
    pub machine_id: String,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionUpdated {
    pub session_id: String,
    pub optimistic_version: u64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageAppended {
    pub session_id: String,
    pub message_id: String,
    pub role: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnStreamDelta {
    pub session_id: String,
    pub turn_id: String,
    pub delta: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnCompleted {
    pub session_id: String,
    pub turn_id: String,
    pub output_message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequired {
    pub session_id: String,
    pub turn_id: String,
    pub approval_id: String,
    pub action_kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Heartbeat {
    pub unix_ms: u64,
}

pub const DAEMON_STREAM_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStreamEnvelope {
    pub schema_version: u16,
    pub session_id: String,
    pub sequence: u64,
    pub event: DaemonStreamEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "payload", rename_all = "snake_case")]
pub enum DaemonStreamEvent {
    SessionState(DaemonSessionState),
    TurnStreamDelta(DaemonTurnStreamDelta),
    TurnCompleted(DaemonTurnCompleted),
    Heartbeat(Heartbeat),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonSessionState {
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonTurnStreamDelta {
    pub turn_id: String,
    pub delta: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonTurnCompleted {
    pub turn_id: String,
    pub output_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStartSessionRequest {
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonSessionStatusResponse {
    pub session_id: String,
    pub state: String,
    pub last_event: String,
    pub updated_at_unix_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_event_uses_tagged_schema() {
        let envelope = WebSocketEnvelope {
            schema_version: WEBSOCKET_SCHEMA_VERSION,
            sequence: 42,
            event: ApiEvent::TurnStreamDelta(TurnStreamDelta {
                session_id: "s_1".to_string(),
                turn_id: "t_1".to_string(),
                delta: "hello".to_string(),
            }),
        };

        let value = serde_json::to_value(&envelope).expect("serialize websocket envelope");
        assert_eq!(value["schema_version"], WEBSOCKET_SCHEMA_VERSION);
        assert_eq!(value["sequence"], 42);
        assert_eq!(value["event"]["type"], "turn_stream_delta");
        assert_eq!(value["event"]["payload"]["delta"], "hello");
    }

    #[test]
    fn daemon_stream_event_uses_tagged_schema() {
        let envelope = DaemonStreamEnvelope {
            schema_version: DAEMON_STREAM_SCHEMA_VERSION,
            session_id: "s_1".to_string(),
            sequence: 3,
            event: DaemonStreamEvent::TurnCompleted(DaemonTurnCompleted {
                turn_id: "t_1".to_string(),
                output_summary: "done".to_string(),
            }),
        };

        let value = serde_json::to_value(&envelope).expect("serialize daemon envelope");
        assert_eq!(value["schema_version"], DAEMON_STREAM_SCHEMA_VERSION);
        assert_eq!(value["sequence"], 3);
        assert_eq!(value["event"]["type"], "turn_completed");
        assert_eq!(value["event"]["payload"]["output_summary"], "done");
    }

    #[test]
    fn daemon_session_status_round_trips() {
        let response = DaemonSessionStatusResponse {
            session_id: "sess_1".to_string(),
            state: "active".to_string(),
            last_event: "started".to_string(),
            updated_at_unix_ms: 123,
        };
        let value = serde_json::to_value(&response).expect("serialize daemon session status");
        assert_eq!(value["session_id"], "sess_1");
        let decoded: DaemonSessionStatusResponse =
            serde_json::from_value(value).expect("deserialize daemon session status");
        assert_eq!(decoded, response);
    }

    #[test]
    fn login_request_round_trips() {
        let request = LoginRequest {
            provider: "github".to_string(),
            access_token: "gho_example".to_string(),
        };

        let serialized = serde_json::to_string(&request).expect("serialize login request");
        let deserialized: LoginRequest =
            serde_json::from_str(&serialized).expect("deserialize login request");

        assert_eq!(request, deserialized);
    }

    #[test]
    fn openapi_contract_keeps_required_m1_paths() {
        let openapi: serde_json::Value =
            serde_yaml::from_str(include_str!("../../../schemas/openapi.yaml"))
                .expect("openapi should parse as yaml");

        assert!(openapi["paths"]["/health"]["get"].is_object());
        assert!(openapi["paths"]["/auth/login"]["post"].is_object());
        assert!(openapi["paths"]["/auth/refresh"]["post"].is_object());
        assert!(openapi["paths"]["/sessions"]["get"].is_object());
        assert!(openapi["paths"]["/sessions"]["post"].is_object());
        assert!(openapi["paths"]["/sessions/{session_id}"]["get"].is_object());
        assert!(openapi["paths"]["/sessions/{session_id}/messages"]["get"].is_object());
        assert!(openapi["paths"]["/sessions/{session_id}/messages"]["post"].is_object());
        assert!(openapi["paths"]["/realtime/bootstrap"]["get"].is_object());
        assert!(
            openapi["components"]["schemas"]["WebSocketEnvelope"]["properties"]["schema_version"]
                .is_object()
        );
    }
}
