use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StorageError {
    #[error("entity already exists")]
    AlreadyExists,
    #[error("entity not found")]
    NotFound,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountRecord {
    pub account_id: String,
    pub provider: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineRecord {
    pub machine_id: String,
    pub account_id: String,
    pub display_name: String,
    pub optimistic_version: u64,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: String,
    pub account_id: String,
    pub machine_id: String,
    pub state: String,
    pub optimistic_version: u64,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageRecord {
    pub message_id: String,
    pub session_id: String,
    pub role: String,
    pub ciphertext: String,
    pub optimistic_version: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub artifact_id: String,
    pub session_id: String,
    pub object_key: String,
    pub content_type: String,
    pub byte_len: u64,
    pub created_at_unix_ms: u64,
}

pub trait AccountStore {
    fn upsert_account(&mut self, account: AccountRecord);
    fn get_account(&self, account_id: &str) -> Option<AccountRecord>;
}

pub trait MachineStore {
    fn upsert_machine(&mut self, machine: MachineRecord);
    fn list_machines_for_account(&self, account_id: &str) -> Vec<MachineRecord>;
}

pub trait SessionStore {
    fn insert_session(&mut self, session: SessionRecord) -> Result<(), StorageError>;
    fn get_session(&self, session_id: &str) -> Option<SessionRecord>;
    fn list_sessions_for_account(&self, account_id: &str) -> Vec<SessionRecord>;
    fn append_message(&mut self, message: MessageRecord) -> Result<(), StorageError>;
    fn list_messages_for_session(&self, session_id: &str) -> Vec<MessageRecord>;
}

pub trait ArtifactStore {
    fn insert_artifact(&mut self, artifact: ArtifactRecord) -> Result<(), StorageError>;
    fn list_artifacts_for_session(&self, session_id: &str) -> Vec<ArtifactRecord>;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryPostgresAdapter {
    accounts: HashMap<String, AccountRecord>,
    machines: HashMap<String, MachineRecord>,
    sessions: HashMap<String, SessionRecord>,
    messages_by_session: HashMap<String, Vec<MessageRecord>>,
    artifacts_by_session: HashMap<String, Vec<ArtifactRecord>>,
}

impl AccountStore for InMemoryPostgresAdapter {
    fn upsert_account(&mut self, account: AccountRecord) {
        self.accounts.insert(account.account_id.clone(), account);
    }

    fn get_account(&self, account_id: &str) -> Option<AccountRecord> {
        self.accounts.get(account_id).cloned()
    }
}

impl MachineStore for InMemoryPostgresAdapter {
    fn upsert_machine(&mut self, machine: MachineRecord) {
        self.machines.insert(machine.machine_id.clone(), machine);
    }

    fn list_machines_for_account(&self, account_id: &str) -> Vec<MachineRecord> {
        self.machines
            .values()
            .filter(|machine| machine.account_id == account_id)
            .cloned()
            .collect()
    }
}

impl SessionStore for InMemoryPostgresAdapter {
    fn insert_session(&mut self, session: SessionRecord) -> Result<(), StorageError> {
        if self.sessions.contains_key(&session.session_id) {
            return Err(StorageError::AlreadyExists);
        }
        self.sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    fn get_session(&self, session_id: &str) -> Option<SessionRecord> {
        self.sessions.get(session_id).cloned()
    }

    fn list_sessions_for_account(&self, account_id: &str) -> Vec<SessionRecord> {
        self.sessions
            .values()
            .filter(|session| session.account_id == account_id)
            .cloned()
            .collect()
    }

    fn append_message(&mut self, message: MessageRecord) -> Result<(), StorageError> {
        if !self.sessions.contains_key(&message.session_id) {
            return Err(StorageError::NotFound);
        }
        let messages = self
            .messages_by_session
            .entry(message.session_id.clone())
            .or_default();
        if messages
            .iter()
            .any(|existing| existing.message_id == message.message_id)
        {
            return Err(StorageError::AlreadyExists);
        }
        messages.push(message);
        Ok(())
    }

    fn list_messages_for_session(&self, session_id: &str) -> Vec<MessageRecord> {
        self.messages_by_session
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }
}

impl ArtifactStore for InMemoryPostgresAdapter {
    fn insert_artifact(&mut self, artifact: ArtifactRecord) -> Result<(), StorageError> {
        let artifacts = self
            .artifacts_by_session
            .entry(artifact.session_id.clone())
            .or_default();
        if artifacts
            .iter()
            .any(|existing| existing.artifact_id == artifact.artifact_id)
        {
            return Err(StorageError::AlreadyExists);
        }
        artifacts.push(artifact);
        Ok(())
    }

    fn list_artifacts_for_session(&self, session_id: &str) -> Vec<ArtifactRecord> {
        self.artifacts_by_session
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryRedisPresenceAdapter {
    entries: HashMap<(String, String), u64>,
}

impl InMemoryRedisPresenceAdapter {
    pub fn set_presence(&mut self, account_id: &str, machine_id: &str, expires_at_unix_ms: u64) {
        self.entries.insert(
            (account_id.to_string(), machine_id.to_string()),
            expires_at_unix_ms,
        );
    }

    pub fn is_online(&self, account_id: &str, machine_id: &str, now_unix_ms: u64) -> bool {
        self.entries
            .get(&(account_id.to_string(), machine_id.to_string()))
            .is_some_and(|expires_at| *expires_at > now_unix_ms)
    }
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryObjectStoreAdapter {
    objects: HashMap<String, Vec<u8>>,
}

impl InMemoryObjectStoreAdapter {
    pub fn put(&mut self, key: impl Into<String>, bytes: Vec<u8>) {
        self.objects.insert(key.into(), bytes);
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.get(key).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session() -> SessionRecord {
        SessionRecord {
            session_id: "sess_1".to_string(),
            account_id: "acct_1".to_string(),
            machine_id: "machine_1".to_string(),
            state: "active".to_string(),
            optimistic_version: 1,
            created_at_unix_ms: 10,
            updated_at_unix_ms: 10,
        }
    }

    #[test]
    fn postgres_adapter_supports_account_session_message_machine_and_artifact_records() {
        let mut adapter = InMemoryPostgresAdapter::default();
        adapter.upsert_account(AccountRecord {
            account_id: "acct_1".to_string(),
            provider: "github".to_string(),
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        });
        adapter.upsert_machine(MachineRecord {
            machine_id: "machine_1".to_string(),
            account_id: "acct_1".to_string(),
            display_name: "workstation".to_string(),
            optimistic_version: 1,
            created_at_unix_ms: 2,
            updated_at_unix_ms: 2,
        });

        adapter
            .insert_session(sample_session())
            .expect("insert session");
        adapter
            .append_message(MessageRecord {
                message_id: "msg_1".to_string(),
                session_id: "sess_1".to_string(),
                role: "user".to_string(),
                ciphertext: "enc:1".to_string(),
                optimistic_version: 2,
                created_at_unix_ms: 3,
            })
            .expect("append message");
        adapter
            .insert_artifact(ArtifactRecord {
                artifact_id: "artifact_1".to_string(),
                session_id: "sess_1".to_string(),
                object_key: "obj://artifact_1".to_string(),
                content_type: "text/plain".to_string(),
                byte_len: 7,
                created_at_unix_ms: 4,
            })
            .expect("insert artifact");

        assert!(adapter.get_account("acct_1").is_some());
        assert_eq!(adapter.list_machines_for_account("acct_1").len(), 1);
        assert_eq!(adapter.list_sessions_for_account("acct_1").len(), 1);
        assert_eq!(adapter.list_messages_for_session("sess_1").len(), 1);
        assert_eq!(adapter.list_artifacts_for_session("sess_1").len(), 1);
    }

    #[test]
    fn append_message_requires_existing_session_and_unique_message_id() {
        let mut adapter = InMemoryPostgresAdapter::default();
        let missing = adapter.append_message(MessageRecord {
            message_id: "msg_1".to_string(),
            session_id: "missing".to_string(),
            role: "user".to_string(),
            ciphertext: "enc:1".to_string(),
            optimistic_version: 1,
            created_at_unix_ms: 1,
        });
        assert_eq!(missing, Err(StorageError::NotFound));

        adapter
            .insert_session(sample_session())
            .expect("insert session");
        adapter
            .append_message(MessageRecord {
                message_id: "msg_1".to_string(),
                session_id: "sess_1".to_string(),
                role: "user".to_string(),
                ciphertext: "enc:1".to_string(),
                optimistic_version: 2,
                created_at_unix_ms: 2,
            })
            .expect("first append");
        let duplicate = adapter.append_message(MessageRecord {
            message_id: "msg_1".to_string(),
            session_id: "sess_1".to_string(),
            role: "assistant".to_string(),
            ciphertext: "enc:2".to_string(),
            optimistic_version: 3,
            created_at_unix_ms: 3,
        });
        assert_eq!(duplicate, Err(StorageError::AlreadyExists));
    }

    #[test]
    fn redis_presence_adapter_tracks_online_status_with_expiry() {
        let mut adapter = InMemoryRedisPresenceAdapter::default();
        adapter.set_presence("acct_1", "machine_1", 200);
        assert!(adapter.is_online("acct_1", "machine_1", 100));
        assert!(!adapter.is_online("acct_1", "machine_1", 200));
        assert!(!adapter.is_online("acct_1", "machine_2", 100));
    }

    #[test]
    fn object_store_adapter_round_trips_bytes() {
        let mut adapter = InMemoryObjectStoreAdapter::default();
        adapter.put("obj://artifact_1", vec![1, 2, 3]);
        assert_eq!(adapter.get("obj://artifact_1"), Some(vec![1, 2, 3]));
        assert_eq!(adapter.get("obj://missing"), None);
    }
}
