use serde::{Deserialize, Serialize};

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
pub struct WebSocketEnvelope {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_event_uses_tagged_schema() {
        let envelope = WebSocketEnvelope {
            sequence: 42,
            event: ApiEvent::TurnStreamDelta(TurnStreamDelta {
                session_id: "s_1".to_string(),
                turn_id: "t_1".to_string(),
                delta: "hello".to_string(),
            }),
        };

        let value = serde_json::to_value(&envelope).expect("serialize websocket envelope");
        assert_eq!(value["sequence"], 42);
        assert_eq!(value["event"]["type"], "turn_stream_delta");
        assert_eq!(value["event"]["payload"]["delta"], "hello");
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
}
