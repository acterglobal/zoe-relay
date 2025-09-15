use serde::{Deserialize, Serialize};

use zoe_app_primitives::group::events::GroupActivityEvent;
use zoe_wire_protocol::{ChaCha20Poly1305Content, EncryptionKey, MessageId};

// GroupState and GroupMember are now unified in app-primitives
// Re-export them here for backwards compatibility
pub use zoe_app_primitives::{group::states::GroupMember, group::states::GroupState};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[derive(Debug, thiserror::Error)]
pub enum GroupSessionError {
    /// Crypto error
    #[error("Crypto error: {0}")]
    Crypto(String),
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Deserialization error
    #[error("Deserialization error: {0}")]
    Deserialization(String),
}

/// Complete group session state including both group state and encryption keys
/// Since both are stored in the same encrypted database and always used together,
/// combining them reduces complexity and eliminates synchronization issues.
#[cfg_attr(feature = "frb-api", frb(opaque, ignore_all))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSession {
    /// The group's business logic state (members, roles, metadata, etc.)
    pub state: GroupState,
    /// Current encryption key for this group
    pub current_key: EncryptionKey,
    /// Previous keys (for decrypting old messages during key rotation)
    pub previous_keys: Vec<EncryptionKey>,
}

pub fn encrypt_group_event_content<T>(
    encryption_key: &EncryptionKey,
    event: &GroupActivityEvent<T>,
) -> Result<ChaCha20Poly1305Content, GroupSessionError>
where
    T: Serialize,
{
    // Serialize the event
    let plaintext = postcard::to_stdvec(event)
        .map_err(|e| GroupSessionError::Crypto(format!("Group event serialization failed: {e}")))?;

    // Encrypt using ChaCha20-Poly1305
    encryption_key
        .encrypt_content(&plaintext)
        .map_err(|e| GroupSessionError::Crypto(format!("Group event encryption failed: {e}")))
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl GroupSession {
    /// Create a new group session with initial state and encryption key
    pub fn new(state: GroupState, encryption_key: EncryptionKey) -> Self {
        Self {
            state,
            current_key: encryption_key,
            previous_keys: Vec::new(),
        }
    }

    /// Rotate the encryption key, moving the current key to previous keys
    pub fn rotate_key(&mut self, new_key: EncryptionKey) {
        let old_key = std::mem::replace(&mut self.current_key, new_key);
        self.previous_keys.push(old_key);
    }

    /// Get all keys (current + previous) for decryption attempts
    pub fn all_keys(&self) -> impl Iterator<Item = &EncryptionKey> {
        std::iter::once(&self.current_key).chain(self.previous_keys.iter())
    }

    /// Encrypt a group event using ChaCha20-Poly1305
    pub fn encrypt_group_event_content<T>(
        &self,
        event: &GroupActivityEvent<T>,
    ) -> Result<ChaCha20Poly1305Content, GroupSessionError>
    where
        T: Serialize,
    {
        encrypt_group_event_content(&self.current_key, event)
    }

    /// Decrypt a group event using ChaCha20-Poly1305
    pub fn decrypt_group_event<T>(
        &self,
        payload: &ChaCha20Poly1305Content,
    ) -> Result<GroupActivityEvent<T>, GroupSessionError>
    where
        T: for<'de> Deserialize<'de>,
    {
        // Note: No key ID verification needed since key is determined by channel context

        // Decrypt using ChaCha20-Poly1305
        let plaintext = self.current_key.decrypt_content(payload).map_err(|e| {
            GroupSessionError::Crypto(format!("Group event decryption failed: {e}"))
        })?;
        // FIXME: cycle through older keys trying to decrypt until one succeeds

        // Deserialize the event
        let event: GroupActivityEvent<T> = postcard::from_bytes(&plaintext).map_err(|e| {
            GroupSessionError::Crypto(format!("Group event deserialization failed: {e}"))
        })?;
        Ok(event)
    }
}

/// A snapshot of a group's state at a specific point in time
#[cfg_attr(feature = "frb-api", frb(ignore))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStateSnapshot {
    pub state: GroupState,
    pub snapshot_at: u64,
    pub snapshot_event_id: MessageId,
}

// All GroupState implementation methods are now in app-primitives
