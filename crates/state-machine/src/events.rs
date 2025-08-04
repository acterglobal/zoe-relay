use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Activity events for encrypted group management in the DGA protocol
/// All events are encrypted with AES-GCM using the group's shared key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupActivityEvent {
    /// Create a new encrypted group - this is the root event that establishes the group channel
    /// The group ID will be the Blake3 hash of the message containing this event
    /// This event itself is encrypted with the group's AES key
    CreateGroup {
        /// Human-readable group name
        name: String,
        /// Optional description of the group's purpose
        description: Option<String>,
        /// Group metadata (tags, categories, etc.)
        metadata: HashMap<String, String>,
        /// Initial group settings
        settings: GroupSettings,
        /// Key derivation info or key identifier (not the actual key)
        /// Used to help participants derive or identify the correct AES key
        key_info: GroupKeyInfo,
    },

    /// Update group metadata (name, description, settings) (group identified by channel tag)
    UpdateGroup {
        /// New group name (if changing)
        name: Option<String>,
        /// New description (if changing)
        description: Option<String>,
        /// Metadata updates
        metadata_updates: HashMap<String, Option<String>>, // None value = delete key
        /// Settings updates
        settings_updates: Option<GroupSettings>,
    },

    /// Assign or change member roles (group identified by channel tag)
    /// Anyone with the group key can send this, but permissions are still enforced
    UpdateMemberRole {
        /// The member whose role is changing
        member: VerifyingKey,
        /// The new role
        role: GroupRole,
    },

    /// Announce departure from group (group identified by channel tag)
    LeaveGroup {
        /// Optional goodbye message
        message: Option<String>,
    },

    /// Post a general activity/message to the group (group identified by channel tag)
    GroupActivity {
        /// Type of activity
        activity_type: String,
        /// Activity payload (serialized custom data)
        payload: Vec<u8>,
        /// Optional activity metadata
        metadata: HashMap<String, String>,
    },
}

/// Information about the group's encryption key (not the key itself)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKeyInfo {
    /// Key identifier or derivation hint
    /// This could be a hash of the key, a key ID, or derivation parameters
    pub key_id: Vec<u8>,
    /// Algorithm information
    pub algorithm: String, // e.g., "AES-256-GCM"
    /// Optional additional parameters for key derivation
    pub derivation_params: Option<HashMap<String, String>>,
}

/// AES encryption key for a group
/// This is never sent over the wire - distributed via separate inbox system
#[derive(Debug, Clone)]
pub struct GroupEncryptionKey {
    /// The actual AES key bytes
    pub key: [u8; 32], // 256-bit AES key
    /// Key identifier matching GroupKeyInfo
    pub key_id: Vec<u8>,
    /// When this key was created/distributed
    pub created_at: u64,
}

/// Encrypted payload for group messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGroupPayload {
    /// AES-GCM encrypted data
    pub ciphertext: Vec<u8>,
    /// AES-GCM nonce/IV
    pub nonce: [u8; 12], // 96-bit nonce for AES-GCM
    /// Key identifier to help recipients know which key to use
    pub key_id: Vec<u8>,
}

/// Group settings and configuration for encrypted groups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GroupSettings {
    /// Maximum number of active participants (None = unlimited)
    /// Note: Anyone with the key can participate, but this limits tracked active members
    pub max_active_members: Option<usize>,
    /// Required permissions for various actions
    pub permissions: GroupPermissions,
    /// Group encryption and security settings
    pub encryption_settings: EncryptionSettings,
}

/// Encryption-related settings for a group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EncryptionSettings {
    /// Whether to rotate keys periodically (future feature)
    pub key_rotation_enabled: bool,
    /// Key rotation interval in seconds (if enabled)
    pub key_rotation_interval: Option<u64>,
    /// Additional authenticated data to include in encryption
    pub additional_context: Option<String>,
}

/// Permissions for group actions in encrypted groups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupPermissions {
    /// Who can update group settings
    pub update_group: Permission,
    /// Who can assign roles to other members
    pub assign_roles: Permission,
    /// Who can post activities (typically all key holders)
    pub post_activities: Permission,
    /// Who can update group encryption settings
    pub update_encryption: Permission,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    /// Only group owners
    OwnerOnly,
    /// Owners and admins
    AdminOrAbove,
    /// Owners, admins, and moderators
    ModeratorOrAbove,
    /// Any group member
    AllMembers,
}

/// Roles within a group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupRole {
    /// Group owner (highest privilege)
    Owner,
    /// Administrator
    Admin,
    /// Moderator
    Moderator,
    /// Regular member
    Member,
}

impl Default for GroupPermissions {
    fn default() -> Self {
        Self {
            update_group: Permission::AdminOrAbove,
            assign_roles: Permission::OwnerOnly,
            post_activities: Permission::AllMembers,
            update_encryption: Permission::OwnerOnly,
        }
    }
}

impl GroupRole {
    /// Check if this role has the required permission level
    pub fn has_permission(&self, required: &Permission) -> bool {
        match required {
            Permission::OwnerOnly => matches!(self, GroupRole::Owner),
            Permission::AdminOrAbove => matches!(self, GroupRole::Owner | GroupRole::Admin),
            Permission::ModeratorOrAbove => matches!(
                self,
                GroupRole::Owner | GroupRole::Admin | GroupRole::Moderator
            ),
            Permission::AllMembers => true,
        }
    }
}
