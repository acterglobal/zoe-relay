//! Group management primitives for Zoe applications
//!
//! This module contains types for encrypted group management in distributed
//! group applications using the DGA protocol. All events are designed to be
//! encrypted with AES-GCM using the group's shared key.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;

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
        metadata: BTreeMap<String, String>,
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
        metadata_updates: BTreeMap<String, Option<String>>,
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
        metadata: BTreeMap<String, String>,
    },
}

/// Information about the group's encryption key (not the key itself)
///
/// This enum contains typed information about different encryption algorithms
/// and their key derivation methods, without exposing the key material itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupKeyInfo {
    /// ChaCha20-Poly1305 encryption with BIP39+Argon2 key derivation
    ///
    /// This is the standard encryption method for groups, using ChaCha20-Poly1305
    /// for encryption and BIP39 mnemonics with Argon2 for key derivation.
    ChaCha20Poly1305 {
        /// Key identifier (typically a hash of the derived key)
        key_id: Vec<u8>,
        /// Key derivation information for recreating the key from a mnemonic
        derivation_info: zoe_wire_protocol::crypto::KeyDerivationInfo,
    },
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
    /// Create a new ChaCha20-Poly1305 GroupKeyInfo
    pub fn new_chacha20_poly1305(
        key_id: Vec<u8>,
        derivation_info: zoe_wire_protocol::crypto::KeyDerivationInfo,
    ) -> Self {
        Self::ChaCha20Poly1305 {
            key_id,
            derivation_info,
        }
    }

    /// Get the key ID for this key info
    pub fn key_id(&self) -> &[u8] {
        match self {
            Self::ChaCha20Poly1305 { key_id, .. } => key_id,
        }
    }

    /// Get the algorithm name for this key info
    pub fn algorithm(&self) -> &str {
        match self {
            Self::ChaCha20Poly1305 { .. } => "ChaCha20-Poly1305",
        }
    }

    /// Get the derivation info if available
    pub fn derivation_info(&self) -> Option<&zoe_wire_protocol::crypto::KeyDerivationInfo> {
        match self {
            Self::ChaCha20Poly1305 {
                derivation_info, ..
            } => Some(derivation_info),
        }
    }

    /// Check if this key info matches a given key ID
    pub fn matches_key_id(&self, other_key_id: &[u8]) -> bool {
        self.key_id() == other_key_id
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

/// Relay endpoint information for group participants
///
/// Contains the network address and public key needed to connect to a relay server.
/// Multiple relay endpoints can be provided to a group participant for redundancy,
/// with the list order indicating priority preference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Network address of the relay server
    ///
    /// This is the socket address (IP:port) where the relay server
    /// can be reached for QUIC connections.
    pub address: SocketAddr,

    /// Ed25519 public key of the relay server
    ///
    /// Used to verify the relay server's identity during the QUIC TLS handshake.
    /// This prevents man-in-the-middle attacks and ensures the client is
    /// connecting to the correct relay server.
    pub public_key: VerifyingKey,

    /// Optional human-readable name for the relay
    ///
    /// Can be used for display purposes or debugging. Examples:
    /// "Primary Relay", "EU West", "Backup Server", etc.
    pub name: Option<String>,

    /// Additional relay metadata
    ///
    /// Can store information like geographic region, performance metrics,
    /// supported features, or other relay-specific data.
    pub metadata: BTreeMap<String, String>,
}

/// Complete information needed for a participant to join an encrypted group
///
/// This structure contains everything a new participant needs to join and
/// participate in an encrypted group, including the group metadata, encryption
/// keys, channel information, and relay endpoints for communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupJoinInfo {
    /// Hash ID of the initial CreateGroup message
    ///
    /// This serves as the unique channel ID for the group and is derived
    /// from the Blake3 hash of the initial CreateGroup message.
    pub channel_id: String,

    /// Group information from the CreateGroup event
    ///
    /// Contains the group name, description, metadata, settings, and other
    /// information that was specified when the group was created.
    pub group_info: GroupInfo,

    /// Encryption key for the group
    ///
    /// The shared AES key used to encrypt and decrypt group messages.
    /// This is the raw key bytes that participants need to encrypt/decrypt
    /// group communications.
    pub encryption_key: [u8; 32],

    /// Key derivation information
    ///
    /// Contains metadata about how the encryption key was derived,
    /// including key ID and derivation parameters. This helps participants
    /// identify and manage the correct encryption keys.
    pub key_info: GroupKeyInfo,

    /// List of relay endpoints (ordered by priority)
    ///
    /// Contains the relay servers that participants can use to communicate
    /// within the group. The list is ordered by priority, with the first
    /// endpoint being the preferred relay. Participants should try relays
    /// in order until they find one that works.
    pub relay_endpoints: Vec<RelayEndpoint>,

    /// Optional invitation metadata
    ///
    /// Additional information about the invitation, such as who sent it,
    /// when it was created, expiration time, or invitation-specific settings.
    pub invitation_metadata: BTreeMap<String, String>,
}

/// Group information extracted from CreateGroup event
///
/// Contains the essential group information that participants need to know
/// about a group, derived from the original CreateGroup event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// Human-readable group name
    pub name: String,

    /// Optional description of the group's purpose
    pub description: Option<String>,

    /// Group metadata (tags, categories, etc.)
    pub metadata: BTreeMap<String, String>,

    /// Group settings and permissions
    pub settings: GroupSettings,

    /// Optional group avatar image
    pub avatar: Option<Image>,

    /// Optional group background image
    pub background: Option<Image>,
}

impl RelayEndpoint {
    /// Create a new relay endpoint with minimal required fields
    pub fn new(address: SocketAddr, public_key: VerifyingKey) -> Self {
        Self {
            address,
            public_key,
            name: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Set a human-readable name for this relay
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Add metadata to this relay endpoint
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Get the relay's display name (name if set, otherwise address)
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.address.to_string())
    }
}

impl GroupJoinInfo {
    /// Create new group join information
    pub fn new(
        channel_id: String,
        group_info: GroupInfo,
        encryption_key: [u8; 32],
        key_info: GroupKeyInfo,
        relay_endpoints: Vec<RelayEndpoint>,
    ) -> Self {
        Self {
            channel_id,
            group_info,
            encryption_key,
            key_info,
            relay_endpoints,
            invitation_metadata: BTreeMap::new(),
        }
    }

    /// Add metadata to the invitation
    pub fn with_invitation_metadata(mut self, key: String, value: String) -> Self {
        self.invitation_metadata.insert(key, value);
        self
    }

    /// Add a relay endpoint to the list
    pub fn add_relay(mut self, endpoint: RelayEndpoint) -> Self {
        self.relay_endpoints.push(endpoint);
        self
    }

    /// Get the primary (first priority) relay endpoint
    pub fn primary_relay(&self) -> Option<&RelayEndpoint> {
        self.relay_endpoints.first()
    }

    /// Get all relay endpoints ordered by priority
    pub fn relays_by_priority(&self) -> &[RelayEndpoint] {
        &self.relay_endpoints
    }

    /// Check if this invitation has any relay endpoints
    pub fn has_relays(&self) -> bool {
        !self.relay_endpoints.is_empty()
    }
}

impl GroupInfo {
    /// Create group info from a CreateGroup event
    pub fn from_create_group_event(
        name: String,
        description: Option<String>,
        metadata: BTreeMap<String, String>,
        settings: GroupSettings,
        avatar: Option<Image>,
        background: Option<Image>,
    ) -> Self {
        Self {
            name,
            description,
            metadata,
            settings,
            avatar,
            background,
        }
    }

    /// Get the group's display name
    pub fn display_name(&self) -> &str {
        &self.name
    }

    /// Check if the group has an avatar
    pub fn has_avatar(&self) -> bool {
        self.avatar.is_some()
    }

    /// Check if the group has a background image
    pub fn has_background(&self) -> bool {
        self.background.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn create_test_verifying_key() -> VerifyingKey {
        let mut csprng = rand::rngs::OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        signing_key.verifying_key()
    }

    fn create_test_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn create_test_key_derivation_info() -> zoe_wire_protocol::crypto::KeyDerivationInfo {
        zoe_wire_protocol::crypto::KeyDerivationInfo {
            method: zoe_wire_protocol::crypto::KeyDerivationMethod::Bip39Argon2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
            context: "dga-group-key".to_string(),
        }
    }

    fn create_test_group_key_info(key_id: Vec<u8>) -> GroupKeyInfo {
        GroupKeyInfo::new_chacha20_poly1305(key_id, create_test_key_derivation_info())
    }

    #[test]
    fn test_group_role_has_permission() {
        // Test Owner permissions
        assert!(GroupRole::Owner.has_permission(&Permission::OwnerOnly));
        assert!(GroupRole::Owner.has_permission(&Permission::AdminOrAbove));
        assert!(GroupRole::Owner.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Owner.has_permission(&Permission::AllMembers));

        // Test Admin permissions
        assert!(!GroupRole::Admin.has_permission(&Permission::OwnerOnly));
        assert!(GroupRole::Admin.has_permission(&Permission::AdminOrAbove));
        assert!(GroupRole::Admin.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Admin.has_permission(&Permission::AllMembers));

        // Test Moderator permissions
        assert!(!GroupRole::Moderator.has_permission(&Permission::OwnerOnly));
        assert!(!GroupRole::Moderator.has_permission(&Permission::AdminOrAbove));
        assert!(GroupRole::Moderator.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Moderator.has_permission(&Permission::AllMembers));

        // Test Member permissions
        assert!(!GroupRole::Member.has_permission(&Permission::OwnerOnly));
        assert!(!GroupRole::Member.has_permission(&Permission::AdminOrAbove));
        assert!(!GroupRole::Member.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Member.has_permission(&Permission::AllMembers));
    }

    #[test]
    fn test_group_role_display_name() {
        assert_eq!(GroupRole::Owner.display_name(), "Owner");
        assert_eq!(GroupRole::Admin.display_name(), "Administrator");
        assert_eq!(GroupRole::Moderator.display_name(), "Moderator");
        assert_eq!(GroupRole::Member.display_name(), "Member");
    }

    #[test]
    fn test_group_role_can_assign_role() {
        // Owner can assign any role
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Owner));
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Admin));
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Moderator));
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Member));

        // Admin cannot assign Owner, but can assign lower roles
        assert!(!GroupRole::Admin.can_assign_role(&GroupRole::Owner));
        assert!(GroupRole::Admin.can_assign_role(&GroupRole::Admin));
        assert!(GroupRole::Admin.can_assign_role(&GroupRole::Moderator));
        assert!(GroupRole::Admin.can_assign_role(&GroupRole::Member));

        // Moderator can only assign Member role
        assert!(!GroupRole::Moderator.can_assign_role(&GroupRole::Owner));
        assert!(!GroupRole::Moderator.can_assign_role(&GroupRole::Admin));
        assert!(!GroupRole::Moderator.can_assign_role(&GroupRole::Moderator));
        assert!(GroupRole::Moderator.can_assign_role(&GroupRole::Member));

        // Member cannot assign any roles
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Owner));
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Admin));
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Moderator));
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Member));
    }

    #[test]
    fn test_group_permissions_builder() {
        let permissions = GroupPermissions::new()
            .update_group(Permission::AdminOrAbove)
            .assign_roles(Permission::OwnerOnly)
            .post_activities(Permission::AllMembers)
            .update_encryption(Permission::OwnerOnly);

        assert_eq!(permissions.update_group, Permission::AdminOrAbove);
        assert_eq!(permissions.assign_roles, Permission::OwnerOnly);
        assert_eq!(permissions.post_activities, Permission::AllMembers);
        assert_eq!(permissions.update_encryption, Permission::OwnerOnly);
    }

    #[test]
    fn test_group_permissions_can_perform_action() {
        let permissions = GroupPermissions::default();

        // Test default permissions
        assert!(permissions.can_perform_action(&GroupRole::Owner, GroupAction::UpdateGroup));
        assert!(permissions.can_perform_action(&GroupRole::Admin, GroupAction::UpdateGroup));
        assert!(!permissions.can_perform_action(&GroupRole::Moderator, GroupAction::UpdateGroup));
        assert!(!permissions.can_perform_action(&GroupRole::Member, GroupAction::UpdateGroup));

        assert!(permissions.can_perform_action(&GroupRole::Owner, GroupAction::AssignRoles));
        assert!(!permissions.can_perform_action(&GroupRole::Admin, GroupAction::AssignRoles));

        assert!(permissions.can_perform_action(&GroupRole::Member, GroupAction::PostActivities));

        assert!(permissions.can_perform_action(&GroupRole::Owner, GroupAction::UpdateEncryption));
        assert!(!permissions.can_perform_action(&GroupRole::Admin, GroupAction::UpdateEncryption));
    }

    #[test]
    fn test_group_key_info() {
        let key_id = vec![1, 2, 3, 4];
        let derivation_info = zoe_wire_protocol::crypto::KeyDerivationInfo {
            method: zoe_wire_protocol::crypto::KeyDerivationMethod::Bip39Argon2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
            context: "dga-group-key".to_string(),
        };

        let key_info = GroupKeyInfo::new_chacha20_poly1305(key_id.clone(), derivation_info.clone());

        assert_eq!(key_info.key_id(), &key_id);
        assert_eq!(key_info.algorithm(), "ChaCha20-Poly1305");
        assert_eq!(key_info.derivation_info(), Some(&derivation_info));
    }

    #[test]
    fn test_group_key_info_matches_key_id() {
        let key_id = vec![1, 2, 3, 4];
        let derivation_info = zoe_wire_protocol::crypto::KeyDerivationInfo {
            method: zoe_wire_protocol::crypto::KeyDerivationMethod::Bip39Argon2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
            context: "dga-group-key".to_string(),
        };
        let key_info = GroupKeyInfo::new_chacha20_poly1305(key_id.clone(), derivation_info);

        assert!(key_info.matches_key_id(&key_id));
        assert!(!key_info.matches_key_id(&[5, 6, 7, 8]));
    }

    #[test]
    fn test_group_settings_builder() {
        let permissions = GroupPermissions::default();
        let encryption_settings = EncryptionSettings::default();

        let settings = GroupSettings::new()
            .max_active_members(Some(100))
            .permissions(permissions.clone())
            .encryption_settings(encryption_settings.clone());

        assert_eq!(settings.max_active_members, Some(100));
        assert_eq!(settings.permissions, permissions);
        assert_eq!(settings.encryption_settings, encryption_settings);
    }

    #[test]
    fn test_encryption_settings_builder() {
        let settings = EncryptionSettings::new()
            .with_key_rotation(3600)
            .with_additional_context("test context".to_string());

        assert!(settings.key_rotation_enabled);
        assert_eq!(settings.key_rotation_interval, Some(3600));
        assert_eq!(
            settings.additional_context,
            Some("test context".to_string())
        );
    }

    #[test]
    fn test_relay_endpoint() {
        let address = create_test_socket_addr();
        let public_key = create_test_verifying_key();

        let endpoint = RelayEndpoint::new(address, public_key)
            .with_name("Test Relay".to_string())
            .with_metadata("region".to_string(), "us-west".to_string());

        assert_eq!(endpoint.address, address);
        assert_eq!(endpoint.public_key, public_key);
        assert_eq!(endpoint.name, Some("Test Relay".to_string()));
        assert_eq!(
            endpoint.metadata.get("region"),
            Some(&"us-west".to_string())
        );
    }

    #[test]
    fn test_relay_endpoint_display_name() {
        let address = create_test_socket_addr();
        let public_key = create_test_verifying_key();

        // Without name, should use address
        let endpoint_no_name = RelayEndpoint::new(address, public_key);
        assert_eq!(endpoint_no_name.display_name(), address.to_string());

        // With name, should use name
        let endpoint_with_name = endpoint_no_name.with_name("Test Relay".to_string());
        assert_eq!(endpoint_with_name.display_name(), "Test Relay");
    }

    #[test]
    fn test_group_join_info() {
        let channel_id = "test_channel_123".to_string();
        let group_info = GroupInfo {
            name: "Test Group".to_string(),
            description: Some("A test group".to_string()),
            metadata: BTreeMap::new(),
            settings: GroupSettings::default(),
            avatar: None,
            background: None,
        };
        let encryption_key = [42u8; 32];
        let key_info = create_test_group_key_info(vec![1, 2, 3]);
        let relay_endpoint =
            RelayEndpoint::new(create_test_socket_addr(), create_test_verifying_key());

        let join_info = GroupJoinInfo::new(
            channel_id.clone(),
            group_info.clone(),
            encryption_key,
            key_info.clone(),
            vec![relay_endpoint.clone()],
        )
        .with_invitation_metadata("inviter".to_string(), "alice".to_string());

        assert_eq!(join_info.channel_id, channel_id);
        assert_eq!(join_info.group_info, group_info);
        assert_eq!(join_info.encryption_key, encryption_key);
        assert_eq!(join_info.key_info, key_info);
        assert_eq!(join_info.relay_endpoints, vec![relay_endpoint]);
        assert_eq!(
            join_info.invitation_metadata.get("inviter"),
            Some(&"alice".to_string())
        );
    }

    #[test]
    fn test_group_join_info_relay_methods() {
        let relay1 = RelayEndpoint::new(create_test_socket_addr(), create_test_verifying_key())
            .with_name("Primary".to_string());
        let relay2 = RelayEndpoint::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            create_test_verifying_key(),
        )
        .with_name("Secondary".to_string());

        let mut join_info = GroupJoinInfo::new(
            "test".to_string(),
            GroupInfo {
                name: "Test".to_string(),
                description: None,
                metadata: BTreeMap::new(),
                settings: GroupSettings::default(),
                avatar: None,
                background: None,
            },
            [0u8; 32],
            create_test_group_key_info(vec![1]),
            vec![relay1.clone()],
        );

        // Test initial state
        assert!(join_info.has_relays());
        assert_eq!(join_info.primary_relay(), Some(&relay1));
        assert_eq!(join_info.relays_by_priority().len(), 1);

        // Add another relay
        join_info = join_info.add_relay(relay2.clone());
        assert_eq!(join_info.relays_by_priority().len(), 2);
        assert_eq!(join_info.primary_relay(), Some(&relay1)); // First one is still primary

        // Test with no relays
        let empty_join_info = GroupJoinInfo::new(
            "test".to_string(),
            GroupInfo {
                name: "Test".to_string(),
                description: None,
                metadata: BTreeMap::new(),
                settings: GroupSettings::default(),
                avatar: None,
                background: None,
            },
            [0u8; 32],
            create_test_group_key_info(vec![1]),
            vec![],
        );

        assert!(!empty_join_info.has_relays());
        assert_eq!(empty_join_info.primary_relay(), None);
        assert!(empty_join_info.relays_by_priority().is_empty());
    }

    #[test]
    fn test_group_info() {
        let group_info = GroupInfo::from_create_group_event(
            "Test Group".to_string(),
            Some("A test group".to_string()),
            BTreeMap::new(),
            GroupSettings::default(),
            None,
            None,
        );

        assert_eq!(group_info.display_name(), "Test Group");
        assert!(!group_info.has_avatar());
        assert!(!group_info.has_background());

        // Test with avatar and background
        let file_ref = crate::FileRef::new(
            "test_hash".to_string(),
            zoe_encrypted_storage::ConvergentEncryptionInfo {
                key: [0u8; 32],
                was_compressed: false,
                source_size: 1024,
            },
            Some("avatar.png".to_string()),
        );
        let avatar = Some(crate::Image::new(file_ref.clone()));
        let background = Some(crate::Image::new(file_ref));

        let group_info_with_images = GroupInfo::from_create_group_event(
            "Test Group".to_string(),
            None,
            BTreeMap::new(),
            GroupSettings::default(),
            avatar,
            background,
        );

        assert!(group_info_with_images.has_avatar());
        assert!(group_info_with_images.has_background());
    }

    #[test]
    fn test_group_permissions_default() {
        let permissions = GroupPermissions::default();

        assert_eq!(permissions.update_group, Permission::AdminOrAbove);
        assert_eq!(permissions.assign_roles, Permission::OwnerOnly);
        assert_eq!(permissions.post_activities, Permission::AllMembers);
        assert_eq!(permissions.update_encryption, Permission::OwnerOnly);
    }

    #[test]
    fn test_encryption_settings_default() {
        let settings = EncryptionSettings::default();

        assert!(!settings.key_rotation_enabled);
        assert_eq!(settings.key_rotation_interval, None);
        assert_eq!(settings.additional_context, None);
    }

    #[test]
    fn test_group_settings_default() {
        let settings = GroupSettings::default();

        assert_eq!(settings.max_active_members, None);
        assert_eq!(settings.permissions, GroupPermissions::default());
        assert_eq!(settings.encryption_settings, EncryptionSettings::default());
    }

    #[test]
    fn test_postcard_serialization_group_activity_event() {
        let event = GroupActivityEvent::CreateGroup {
            name: "Test Group".to_string(),
            description: Some("Test Description".to_string()),
            metadata: BTreeMap::new(),
            settings: GroupSettings::default(),
            key_info: create_test_group_key_info(vec![1, 2, 3]),
            avatar: None,
            background: None,
        };

        let serialized = postcard::to_stdvec(&event).expect("Failed to serialize");
        let deserialized: GroupActivityEvent =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_postcard_serialization_group_role() {
        for role in [
            GroupRole::Owner,
            GroupRole::Admin,
            GroupRole::Moderator,
            GroupRole::Member,
        ] {
            let serialized = postcard::to_stdvec(&role).expect("Failed to serialize");
            let deserialized: GroupRole =
                postcard::from_bytes(&serialized).expect("Failed to deserialize");
            assert_eq!(role, deserialized);
        }
    }

    #[test]
    fn test_postcard_serialization_permission() {
        for permission in [
            Permission::OwnerOnly,
            Permission::AdminOrAbove,
            Permission::ModeratorOrAbove,
            Permission::AllMembers,
        ] {
            let serialized = postcard::to_stdvec(&permission).expect("Failed to serialize");
            let deserialized: Permission =
                postcard::from_bytes(&serialized).expect("Failed to deserialize");
            assert_eq!(permission, deserialized);
        }
    }

    #[test]
    fn test_postcard_serialization_group_join_info() {
        let join_info = GroupJoinInfo::new(
            "test_channel".to_string(),
            GroupInfo::from_create_group_event(
                "Test".to_string(),
                None,
                BTreeMap::new(),
                GroupSettings::default(),
                None,
                None,
            ),
            [42u8; 32],
            create_test_group_key_info(vec![1, 2, 3]),
            vec![RelayEndpoint::new(
                create_test_socket_addr(),
                create_test_verifying_key(),
            )],
        );

        let serialized = postcard::to_stdvec(&join_info).expect("Failed to serialize");
        let deserialized: GroupJoinInfo =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(join_info, deserialized);
    }
}
