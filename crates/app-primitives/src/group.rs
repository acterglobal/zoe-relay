//! Group management primitives for Zoe applications
//!
//! This module contains types for encrypted group management in distributed
//! group applications using the DGA protocol. All events are designed to be
//! encrypted with AES-GCM using the group's shared key.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::file::Image;

/// Activity events for encrypted group management in the DGA protocol
///
/// All events are encrypted with AES-GCM using the group's shared key.
/// These events form the core primitives for managing distributed encrypted groups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupActivityEvent {
    /// Create a new encrypted group - this is the root event that establishes the group channel
    ///
    /// The group ID will be the Blake3 hash of the message containing this event.
    /// This event itself is encrypted with the group's AES key.
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
        /// Optional group avatar image
        avatar: Option<Image>,
        /// Optional group background image
        background: Option<Image>,
    },

    /// Update group metadata (name, description, settings)
    ///
    /// Group is identified by channel tag. Anyone with the group key can send this,
    /// but permissions are still enforced based on the sender's role.
    UpdateGroup {
        /// New group name (if changing)
        name: Option<String>,
        /// New description (if changing)
        description: Option<String>,
        /// Metadata updates (None value = delete key)
        metadata_updates: HashMap<String, Option<String>>,
        /// Settings updates
        settings_updates: Option<GroupSettings>,
        /// New avatar image (None to remove avatar)
        avatar: Option<Option<Image>>,
        /// New background image (None to remove background)
        background: Option<Option<Image>>,
    },

    /// Assign or change member roles
    ///
    /// Group is identified by channel tag. Anyone with the group key can send this,
    /// but permissions are still enforced based on the sender's role.
    UpdateMemberRole {
        /// The member whose role is changing
        member: VerifyingKey,
        /// The new role
        role: GroupRole,
    },

    /// Announce departure from group
    ///
    /// Group is identified by channel tag. This is a polite way to leave,
    /// but doesn't prevent the member from continuing to participate if they
    /// retain the group key.
    LeaveGroup {
        /// Optional goodbye message
        message: Option<String>,
    },

    /// Post a general activity/message to the group
    ///
    /// Group is identified by channel tag. This is the most common event type
    /// for general group communication and activities.
    GroupActivity {
        /// Type of activity (application-specific)
        activity_type: String,
        /// Activity payload (serialized custom data)
        payload: Vec<u8>,
        /// Optional activity metadata
        metadata: HashMap<String, String>,
    },
}

/// Information about the group's encryption key (not the key itself)
///
/// This structure helps participants identify or derive the correct encryption key
/// without exposing the key material itself in the event data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKeyInfo {
    /// Key identifier or derivation hint
    ///
    /// This could be a hash of the key, a key ID, or derivation parameters.
    /// It helps participants identify which key to use without revealing the key.
    pub key_id: Vec<u8>,

    /// Algorithm information
    ///
    /// Specifies the encryption algorithm used (e.g., "AES-256-GCM").
    pub algorithm: String,

    /// Optional additional parameters for key derivation
    ///
    /// Can contain additional context or parameters needed for key derivation
    /// schemes like PBKDF2, scrypt, or custom key derivation methods.
    pub derivation_params: Option<HashMap<String, String>>,
}

/// Group settings and configuration for encrypted groups
///
/// These settings control various aspects of group behavior and permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GroupSettings {
    /// Maximum number of active participants (None = unlimited)
    ///
    /// Note: Anyone with the key can participate, but this limits tracked active members.
    /// This is more of a UI/UX setting than a hard security boundary.
    pub max_active_members: Option<usize>,

    /// Required permissions for various actions
    pub permissions: GroupPermissions,

    /// Group encryption and security settings
    pub encryption_settings: EncryptionSettings,
}

/// Encryption-related settings for a group
///
/// Controls various encryption and security features for the group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EncryptionSettings {
    /// Whether to rotate keys periodically (future feature)
    ///
    /// When enabled, the group will periodically rotate its encryption keys
    /// to provide forward secrecy.
    pub key_rotation_enabled: bool,

    /// Key rotation interval in seconds (if enabled)
    ///
    /// How often to rotate keys when key rotation is enabled.
    pub key_rotation_interval: Option<u64>,

    /// Additional authenticated data to include in encryption
    ///
    /// Extra context that will be included in the authenticated encryption
    /// to provide additional security guarantees.
    pub additional_context: Option<String>,
}

/// Permissions for group actions in encrypted groups
///
/// Defines who can perform various actions within the group based on their role.
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

/// Permission levels for group actions
///
/// Defines the minimum role level required to perform certain actions.
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
///
/// Hierarchical roles that determine what actions a member can perform.
/// Roles are ordered from highest (Owner) to lowest (Member) privilege.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupRole {
    /// Group owner (highest privilege)
    ///
    /// Can perform all actions including deleting the group and managing all other roles.
    Owner,
    /// Administrator
    ///
    /// Can manage most group settings and moderate other members.
    Admin,
    /// Moderator
    ///
    /// Can moderate discussions and manage some group settings.
    Moderator,
    /// Regular member
    ///
    /// Basic participation rights, can post activities and read group content.
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
    ///
    /// Returns true if this role meets or exceeds the required permission level.
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

    /// Get a human-readable name for this role
    pub fn display_name(&self) -> &'static str {
        match self {
            GroupRole::Owner => "Owner",
            GroupRole::Admin => "Administrator",
            GroupRole::Moderator => "Moderator",
            GroupRole::Member => "Member",
        }
    }

    /// Check if this role can assign the target role to another member
    ///
    /// Generally, you can only assign roles that are lower than your own.
    pub fn can_assign_role(&self, target_role: &GroupRole) -> bool {
        match self {
            GroupRole::Owner => true, // Owners can assign any role
            GroupRole::Admin => !matches!(target_role, GroupRole::Owner),
            GroupRole::Moderator => matches!(target_role, GroupRole::Member),
            GroupRole::Member => false, // Members can't assign roles
        }
    }
}

impl GroupPermissions {
    /// Create a new GroupPermissions with custom settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set permission for updating group settings
    pub fn update_group(mut self, permission: Permission) -> Self {
        self.update_group = permission;
        self
    }

    /// Set permission for assigning roles
    pub fn assign_roles(mut self, permission: Permission) -> Self {
        self.assign_roles = permission;
        self
    }

    /// Set permission for posting activities
    pub fn post_activities(mut self, permission: Permission) -> Self {
        self.post_activities = permission;
        self
    }

    /// Set permission for updating encryption settings
    pub fn update_encryption(mut self, permission: Permission) -> Self {
        self.update_encryption = permission;
        self
    }

    /// Check if a role can perform a specific action
    pub fn can_perform_action(&self, role: &GroupRole, action: GroupAction) -> bool {
        let required_permission = match action {
            GroupAction::UpdateGroup => &self.update_group,
            GroupAction::AssignRoles => &self.assign_roles,
            GroupAction::PostActivities => &self.post_activities,
            GroupAction::UpdateEncryption => &self.update_encryption,
        };

        role.has_permission(required_permission)
    }
}

/// Actions that can be performed within a group
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupAction {
    /// Update group metadata and settings
    UpdateGroup,
    /// Assign roles to other members
    AssignRoles,
    /// Post activities and messages
    PostActivities,
    /// Update encryption settings
    UpdateEncryption,
}

impl GroupKeyInfo {
    /// Create a new GroupKeyInfo
    pub fn new(key_id: Vec<u8>, algorithm: String) -> Self {
        Self {
            key_id,
            algorithm,
            derivation_params: None,
        }
    }

    /// Add derivation parameters
    pub fn with_derivation_params(mut self, params: HashMap<String, String>) -> Self {
        self.derivation_params = Some(params);
        self
    }

    /// Check if this key info matches a given key ID
    pub fn matches_key_id(&self, other_key_id: &[u8]) -> bool {
        self.key_id == other_key_id
    }
}

impl GroupSettings {
    /// Create new group settings with default permissions
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum active members
    pub fn max_active_members(mut self, max: Option<usize>) -> Self {
        self.max_active_members = max;
        self
    }

    /// Set group permissions
    pub fn permissions(mut self, permissions: GroupPermissions) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set encryption settings
    pub fn encryption_settings(mut self, settings: EncryptionSettings) -> Self {
        self.encryption_settings = settings;
        self
    }
}

impl EncryptionSettings {
    /// Create new encryption settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable key rotation with specified interval
    pub fn with_key_rotation(mut self, interval_seconds: u64) -> Self {
        self.key_rotation_enabled = true;
        self.key_rotation_interval = Some(interval_seconds);
        self
    }

    /// Set additional authenticated context
    pub fn with_additional_context(mut self, context: String) -> Self {
        self.additional_context = Some(context);
        self
    }
}
