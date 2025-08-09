use blake3::Hash;
use serde::{Deserialize, Serialize};

use zoe_wire_protocol::EncryptionKey;

// GroupState and GroupMember are now unified in app-primitives
// Re-export them here for backwards compatibility
pub use zoe_app_primitives::{GroupMember, GroupState};

/// Encryption state for a group
/// This is not serialized with the group state - managed separately
#[derive(Debug, Clone)]
pub struct GroupEncryptionState {
    /// Current encryption key
    pub current_key: EncryptionKey,
    /// Previous keys (for decrypting old messages during key rotation)
    pub previous_keys: Vec<EncryptionKey>,
}

/// A snapshot of a group's state at a specific point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStateSnapshot {
    pub state: GroupState,
    pub snapshot_at: u64,
    pub snapshot_event_id: Hash,
}

// All GroupState implementation methods are now in app-primitives
