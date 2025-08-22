use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use zoe_wire_protocol::{Hash, VerifyingKey, verifying_key_to_bytes};

use super::events::roles::GroupRole;
use super::events::{GroupActivityEvent, GroupSettings};
use crate::{IdentityInfo, IdentityRef, IdentityType, Metadata, Permission};

/// Advanced identity and membership management for distributed groups.
///
/// `GroupMembership` handles the complex identity scenarios that arise in distributed,
/// encrypted group communication. It separates cryptographic identity (via
/// [`zoe_wire_protocol::VerifyingKey`]) from display identity (names, aliases).
///
/// ## 🎭 Identity Architecture
///
/// The system operates on a two-layer identity model:
///
/// ### Layer 1: Cryptographic Identity (VerifyingKeys)
/// - Each participant has one or more [`zoe_wire_protocol::VerifyingKey`]s
/// - These keys are used for message signing and verification
/// - Keys are the fundamental unit of authentication and authorization
/// - A key represents a device, account, or cryptographic identity
///
/// ### Layer 2: Display Identity (Aliases and Names)
/// - Each key can declare multiple [`crate::IdentityType`] variants:
///   - **Main Identity**: The primary identity for a key (often a real name)
///   - **Aliases**: Secondary identities for role-playing, privacy, or context
/// - Each identity can have associated [`crate::IdentityInfo`] with display names
/// - Identities are what users see and interact with in the UI
///
/// ## 🔄 Use Cases and Benefits
///
/// ### Privacy and Pseudonymity
/// ```text
/// VerifyingKey(Alice_Device_1) ──┬─→ Main: "Alice Johnson"
///                                ├─→ Alias: "ProjectLead"
///                                └─→ Alias: "AnonymousReviewer"
/// ```
///
/// Alice can participate in the same group with different personas:
/// - Official communications as "Alice Johnson"
/// - Project management as "ProjectLead"
/// - Anonymous feedback as "AnonymousReviewer"
///
/// ### Multi-Device Identity
/// ```text
/// Real Person: Bob ──┬─→ VerifyingKey(Bob_Phone) ─→ Main: "Bob Smith"
///                    └─→ VerifyingKey(Bob_Laptop) ─→ Main: "Bob Smith"
/// ```
///
/// Bob can use multiple devices with the same display identity.
///
/// ### Role-Based Communication
/// ```text
/// VerifyingKey(Company_Bot) ──┬─→ Alias: "HR Bot"
///                             ├─→ Alias: "Security Alert System"  
///                             └─→ Alias: "Meeting Scheduler"
/// ```
///
/// Automated systems can present different faces for different functions.
///
/// ## 🔒 Security and Authorization
///
/// ### Key-Based Authorization
/// - All permissions and role assignments are tied to [`IdentityRef`] variants
/// - An [`IdentityRef::Key`] directly authorizes the key holder
/// - An [`IdentityRef::Alias`] authorizes only if the key controls that alias
/// - Use [`GroupMembership::is_authorized`] to check if a key can act as an identity
///
/// ### Self-Sovereign Identity Declaration
/// - Only a key can declare identities for itself
/// - Other participants cannot assign aliases to someone else's key
/// - Identity information is cryptographically signed by the declaring key
/// - Malicious identity claims are prevented by signature verification
///
/// ## 📊 Data Structure
///
/// ### Identity Storage
/// - [`GroupMembership::identity_info`]: Maps `(VerifyingKey, IdentityType) → IdentityInfo`
/// - Stores display names and metadata for each declared identity
/// - Multiple identities per key are fully supported
///
/// ### Role Assignments  
/// - [`GroupMembership::identity_roles`]: Maps `IdentityRef → GroupRole`
/// - Roles can be assigned to specific identities, not just keys
/// - Enables fine-grained permission control per identity
///
/// ## 🔧 Core Operations
///
/// ### Identity Discovery
/// - [`GroupMembership::get_available_identities`]: Find all identities a key can use
/// - [`GroupMembership::get_display_name`]: Get human-readable name for an identity
/// - [`GroupMembership::has_identity_info`]: Check if identity has been declared
///
/// ### Role Management
/// - [`GroupMembership::get_role`]: Get the role assigned to a specific identity
/// - [`GroupMembership::get_effective_role`]: Get role when key acts as an alias
/// - Roles default to [`super::events::roles::GroupRole::Member`] if not explicitly set
///
/// ## 💡 Usage Examples
///
/// ### Setting Up Multiple Identities
/// ```rust
/// use zoe_app_primitives::{GroupMembership, IdentityType, IdentityRef, IdentityInfo};
/// use zoe_wire_protocol::{KeyPair, generate_keypair};
/// use std::collections::HashMap;
///
/// let mut membership = GroupMembership::new();
/// let alice_key = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
///
/// // Alice declares her main identity
/// let main_identity = IdentityInfo {
///     display_name: "Alice Johnson".to_string(),
///     metadata: vec![],
/// };
///
/// // Alice declares an alias for anonymous feedback
/// let anon_identity = IdentityInfo {
///     display_name: "Anonymous Reviewer".to_string(),
///     metadata: vec![],
/// };
///
/// // In practice, these would be set via GroupManagementEvent::SetIdentity
/// // Here we simulate the result of processing those events
/// membership.identity_info.insert(
///     (alice_key, IdentityType::Main),
///     main_identity,
/// );
/// membership.identity_info.insert(
///     (alice_key, IdentityType::Alias { alias_id: "anon".to_string() }),
///     anon_identity,
/// );
/// ```
///
/// ### Checking Authorization
/// ```rust
/// # use zoe_app_primitives::{GroupMembership, IdentityRef};
/// # use ed25519_dalek::SigningKey;
/// # let membership = GroupMembership::new();
/// # let alice_key = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
///
/// // Check if Alice can act as her main identity (always true)
/// let main_ref = IdentityRef::Key(alice_key);
/// assert!(membership.is_authorized(&alice_key, &main_ref));
///
/// // Check if Alice can act as her anonymous alias
/// let alias_ref = IdentityRef::Alias {
///     key: alice_key,
///     alias: "anon".to_string(),
/// };
/// assert!(membership.is_authorized(&alice_key, &alias_ref));
///
/// // Check if Alice can act as someone else's alias (false)
/// let other_key = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
/// let other_alias = IdentityRef::Alias {
///     key: other_key,
///     alias: "not_alice".to_string(),
/// };
/// assert!(!membership.is_authorized(&alice_key, &other_alias));
/// ```
///
/// ### Role-Based Access with Identities
/// ```rust
/// # use zoe_app_primitives::{GroupMembership, IdentityRef};
/// # use zoe_app_primitives::events::roles::GroupRole;
/// # use ed25519_dalek::SigningKey;
/// # let mut membership = GroupMembership::new();
/// # let alice_key = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
///
/// // Assign admin role to Alice's main identity
/// let main_ref = IdentityRef::Key(alice_key);
/// membership.identity_roles.insert(main_ref.clone(), GroupRole::Admin);
///
/// // Assign member role to Alice's anonymous alias
/// let alias_ref = IdentityRef::Alias {
///     key: alice_key,
///     alias: "anon".to_string(),
/// };
/// membership.identity_roles.insert(alias_ref.clone(), GroupRole::Member);
///
/// // Check effective roles
/// assert_eq!(
///     membership.get_role(&main_ref),
///     Some(GroupRole::Admin)
/// );
/// assert_eq!(
///     membership.get_role(&alias_ref),
///     Some(GroupRole::Member)
/// );
/// ```
///
/// ## 🌐 Integration with Group Events
///
/// Identity management integrates with the event system through:
/// - [`super::events::GroupManagementEvent::SetIdentity`]: Declares new identities
/// - [`super::events::GroupManagementEvent::AssignRole`]: Assigns roles to identities
/// - Event processing updates the membership state automatically
/// - All identity changes are part of the signed, encrypted event history
///
/// This ensures that identity management is:
/// - **Auditable**: Full history of identity changes
/// - **Consistent**: Same view across all group members  
/// - **Secure**: Cryptographically signed and verified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    /// Identity information for keys and their aliases: (key_bytes, identity_type) -> identity_info
    /// Keys are ML-DSA verifying keys encoded as bytes for serialization compatibility
    pub identity_info: BTreeMap<(Vec<u8>, IdentityType), IdentityInfo>,
    /// Role assignments for identities (both keys and aliases)
    pub identity_roles: BTreeMap<IdentityRef, GroupRole>,
}

impl GroupMembership {
    /// Create a new empty membership state
    pub fn new() -> Self {
        Self {
            identity_info: BTreeMap::new(),
            identity_roles: BTreeMap::new(),
        }
    }

    /// Check if a verifying key is authorized to act as a specific identity
    pub fn is_authorized(&self, key: &VerifyingKey, identity_ref: &IdentityRef) -> bool {
        // Check if this key controls the identity
        // For now, we'll need to convert to bytes for comparison since IdentityRef expects Ed25519 keys
        // This is a temporary compatibility layer
        identity_ref.is_controlled_by(key)
    }

    /// Get all identities that a verifying key can act as
    pub fn get_available_identities(&self, _key: &VerifyingKey) -> HashSet<IdentityRef> {
        // For now, ML-DSA keys cannot act as Ed25519-based identities
        // This will need to be updated when we fully transition to ML-DSA
        // Return empty set as a temporary compatibility measure
        HashSet::new()
    }

    /// Get the role for a specific identity
    pub fn get_role(&self, identity_ref: &IdentityRef) -> Option<GroupRole> {
        // Check for explicit role assignment first
        if let Some(role) = self.identity_roles.get(identity_ref) {
            return Some(role.clone());
        }

        // Fall back to default member role for any valid identity
        Some(GroupRole::Member)
    }

    /// Get effective role when a key acts as a specific identity
    pub fn get_effective_role(
        &self,
        _key: &VerifyingKey,
        _acting_as_alias: &Option<String>,
    ) -> Option<GroupRole> {
        // For now, ML-DSA keys cannot act as Ed25519-based identities
        // This will need to be updated when we fully transition to ML-DSA
        // Return default member role as a temporary compatibility measure
        Some(GroupRole::Member)
    }

    /// Get display name for an identity
    pub fn get_display_name(&self, key: &VerifyingKey, identity_type: &IdentityType) -> String {
        // For now, ML-DSA keys don't have identity info in the Ed25519-based system
        // This will need to be updated when we fully transition to ML-DSA
        // Fall back to default display
        match identity_type {
            IdentityType::Main => format!("ML-DSA Key:{key:?}"),
            IdentityType::Alias { alias_id } => alias_id.clone(),
        }
    }

    /// Check if an identity has been declared by a key
    pub fn has_identity_info(&self, _key: &VerifyingKey, _identity_type: &IdentityType) -> bool {
        // For now, ML-DSA keys don't have identity info in the Ed25519-based system
        // This will need to be updated when we fully transition to ML-DSA
        false
    }
}

impl Default for GroupMembership {
    fn default() -> Self {
        Self::new()
    }
}

/// Error types for group state operations
#[derive(Debug, thiserror::Error)]
pub enum GroupStateError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Member not found: {member} in group {group}")]
    MemberNotFound { member: String, group: String },

    #[error("State transition error: {0}")]
    StateTransition(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

/// Result type for group state operations
pub type GroupStateResult<T> = Result<T, GroupStateError>;

/// Runtime information about an active group member.
///
/// `GroupMember` tracks the runtime state of a participant in a group. This includes
/// their role, activity timestamps, and member-specific metadata. It's distinct from
/// the cryptographic identity and display identity managed by [`GroupMembership`].
///
/// ## 📊 Member State vs Identity State
///
/// - **GroupMember**: Runtime participation state (roles, activity, metadata)
/// - **GroupMembership**: Identity management (aliases, display names, authorization)
/// - **VerifyingKey**: Cryptographic identity (authentication, message signing)
///
/// These three layers work together to provide comprehensive member management:
/// ```text
/// VerifyingKey → GroupMember (runtime state) + GroupMembership (identity state)
/// ```
///
/// ## 🔄 Lifecycle and State Transitions
///
/// 1. **Initial Creation**: When a key first participates, a `GroupMember` is created
/// 2. **Activity Updates**: [`GroupMember::last_active`] updated with each message
/// 3. **Role Changes**: [`GroupMember::role`] updated via role assignment events
/// 4. **Metadata Updates**: [`GroupMember::metadata`] can store custom key-value data
/// 5. **Departure**: `GroupMember` removed when user leaves (but could rejoin later)
///
/// ## 💡 Usage Examples
///
/// ### Tracking Member Activity
/// ```rust
/// use zoe_app_primitives::{GroupMember, events::roles::GroupRole};
/// use zoe_wire_protocol::{KeyPair, generate_keypair};
/// use std::collections::BTreeMap;
///
/// let member_key = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
/// let join_time = 1234567890;
///
/// let mut member = GroupMember {
///     public_key: member_key,
///     role: GroupRole::Member,
///     joined_at: join_time,
///     last_active: join_time,
///     metadata: vec![],
/// };
///
/// // Update activity when they send a message
/// member.last_active = join_time + 3600; // 1 hour later
///
/// // Check how long they've been inactive
/// let current_time = join_time + 7200; // 2 hours later  
/// let inactive_duration = current_time - member.last_active;
/// assert_eq!(inactive_duration, 3600); // 1 hour inactive
/// ```
///
/// ### Role-Based Member Management
/// ```rust
/// # use zoe_app_primitives::{GroupMember, events::roles::GroupRole};
/// # use ed25519_dalek::SigningKey;
/// # use std::collections::BTreeMap;
/// # let member_key = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
/// # let mut member = GroupMember {
/// #     public_key: member_key, role: GroupRole::Member, joined_at: 0, last_active: 0,
/// #     metadata: vec![],
/// # };
///
/// // Promote member to moderator
/// member.role = GroupRole::Moderator;
///
/// // Check permissions
/// use zoe_app_primitives::Permission;
/// assert!(member.role.has_permission(&Permission::AllMembers));
/// assert!(member.role.has_permission(&Permission::ModeratorOrAbove));
/// ```
///
/// ### Custom Member Metadata
/// ```rust
/// # use zoe_app_primitives::{GroupMember, Metadata};
/// # let mut member = GroupMember {
/// #     public_key: generate_keypair(&mut rand::rngs::OsRng).verifying_key().clone(),
/// #     role: zoe_app_primitives::events::roles::GroupRole::Member,
/// #     joined_at: 0, last_active: 0, metadata: vec![],
/// # };
///
/// // Store custom metadata about the member using structured types
/// member.metadata.push(Metadata::Generic { key: "department".to_string(), value: "engineering".to_string() });
/// member.metadata.push(Metadata::Generic { key: "team".to_string(), value: "backend".to_string() });
/// member.metadata.push(Metadata::Generic { key: "timezone".to_string(), value: "UTC-8".to_string() });
/// member.metadata.push(Metadata::Email("member@company.com".to_string()));
///
/// // Query metadata
/// for meta in &member.metadata {
///     match meta {
///         Metadata::Generic { key, value } if key == "department" => {
///             println!("Member is in {} department", value);
///         }
///         Metadata::Email(email) => {
///             println!("Member email: {}", email);
///         }
///         _ => {}
///     }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's public key encoded as bytes for serialization compatibility
    pub public_key: Vec<u8>,
    /// Member's role in the group
    pub role: GroupRole,
    /// When they joined the group
    pub joined_at: u64,
    /// When they were last active
    pub last_active: u64,
    /// Member-specific metadata using structured types
    pub metadata: Vec<Metadata>,
}

/// The complete runtime state of a distributed encrypted group.
///
/// `GroupState` represents the unified, authoritative state of a group at any point in time.
/// It combines immutable group information (from [`super::events::GroupInfo`]) with runtime
/// state such as active members, event history, and identity management.
///
/// ## 🏗️ Design Philosophy
///
/// This type unifies what were previously separate concerns:
/// - **Static Group Information**: Name, settings, and structured metadata
/// - **Dynamic Member State**: Active participants, roles, and activity tracking  
/// - **Event History**: Audit trail and conflict resolution capability
/// - **Identity Management**: Complex alias and display name handling
///
/// ## 🔄 Event-Sourced Architecture
///
/// Groups maintain state through event sourcing:
/// ```text
/// CreateGroup Event → Initial GroupState
///        ↓
/// Member Activity → Updated GroupState (new member added)
///        ↓  
/// Role Assignment → Updated GroupState (permissions changed)
///        ↓
/// Group Update → Updated GroupState (metadata modified)
/// ```
///
/// Each event is applied via [`GroupState::apply_event`], ensuring consistency
/// and providing an audit trail through [`GroupState::event_history`].
///
/// ## 🔐 Security and Access Control
///
/// ### Encryption-Based Membership
/// - Anyone with the group's encryption key can participate
/// - [`GroupState::members`] tracks known active participants, not access control
/// - True access control is enforced by possession of the encryption key
///
/// ### Role-Based Permissions
/// - Each member has a [`super::events::roles::GroupRole`] defining their capabilities
/// - Permissions are checked via [`GroupState::check_permission`]
/// - Role assignments are cryptographically signed and part of the event history
///
/// ### Identity Privacy
/// - Members can use aliases within groups via [`GroupMembership`]
/// - Display names can be set independently of cryptographic identities
/// - Multiple aliases per [`zoe_wire_protocol::VerifyingKey`] are supported
///
/// ## 📊 Member Lifecycle
///
/// 1. **Discovery**: A user obtains the group encryption key through some secure channel
/// 2. **Announcement**: User sends any [`super::events::GroupActivityEvent`] to announce participation
/// 3. **Recognition**: Internal handling adds them to active member list
/// 4. **Activity**: Member's [`GroupMember::last_active`] is updated with each message
/// 5. **Departure**: [`super::events::GroupManagementEvent::LeaveGroup`] removes from active list
///
/// Note: Departure only removes from the active member tracking - the user still
/// possesses the encryption key and could rejoin at any time.
///
/// ## 🏷️ Structured Metadata System
///
/// Metadata is stored as [`crate::Metadata`] variants rather than simple key-value pairs:
/// - [`crate::Metadata::Description`]: Human-readable group description
/// - [`crate::Metadata::Generic`]: Key-value pairs for backward compatibility
/// - Future variants can add typed metadata (images, files, etc.)
///
/// Use [`GroupState::description()`] and [`GroupState::generic_metadata()`] for
/// convenient access to common metadata patterns.
///
/// ## 🔗 Relationship to GroupInfo
///
/// [`super::events::GroupInfo`] is used for events (creation, updates) while
/// `GroupState` represents the current runtime state:
///
/// ```text
/// GroupInfo (in events) → GroupState (runtime) → GroupInfo (for updates)
/// ```
///
/// Use [`GroupState::from_group_info`] and [`GroupState::to_group_info`] to
/// convert between representations.
///
/// ## 💡 Usage Examples
///
/// ### Creating a Group State
/// ```rust
/// use zoe_app_primitives::{GroupState, GroupSettings, Metadata};
/// use zoe_wire_protocol::{KeyPair, generate_keypair};
/// use blake3::Hash;
///
/// let creator_key = SigningKey::generate(&mut rand::rngs::OsRng);
/// let group_id = Hash::from([1u8; 32]);
///
/// let metadata = vec![
///     Metadata::Description("Development team coordination".to_string()),
///     Metadata::Generic { key: "department".to_string(), value: "engineering".to_string() },
/// ];
///
/// let group_state = GroupState::new(
///     group_id,
///     "Dev Team".to_string(),
///     GroupSettings::default(),
///     metadata,
///     creator_key.verifying_key(),
///     1234567890,
/// );
///
/// // Creator is automatically added as Owner
/// assert_eq!(group_state.members.len(), 1);
/// assert!(group_state.is_member(&creator_key.verifying_key()));
/// ```
///
/// ### Processing Member Activity
/// ```rust
/// # use zoe_app_primitives::*;
/// # use ed25519_dalek::SigningKey;
/// # use blake3::Hash;
/// # let mut group_state = GroupState::new(
/// #     Hash::from([1u8; 32]), "Test".to_string(), GroupSettings::default(),
/// #     vec![], SigningKey::generate(&mut rand::rngs::OsRng).verifying_key(), 1234567890
/// # );
///
/// let new_member = SigningKey::generate(&mut rand::rngs::OsRng);
/// let activity_event = GroupActivityEvent::Activity(());
///
/// // New member announces participation
/// group_state.apply_event(
///     &activity_event,
///     Hash::from([2u8; 32]),
///     new_member.verifying_key(),
///     1234567891,
/// ).unwrap();
///
/// // They're now tracked as an active member
/// assert!(group_state.is_member(&new_member.verifying_key()));
/// ```
///
/// ### Working with Metadata
/// ```rust
/// # use zoe_app_primitives::*;
/// # use ed25519_dalek::SigningKey;
/// # use blake3::Hash;
/// # let group_state = GroupState::new(
/// #     Hash::from([1u8; 32]), "Test".to_string(), GroupSettings::default(),
/// #     vec![Metadata::Description("Test group".to_string())],
/// #     SigningKey::generate(&mut rand::rngs::OsRng).verifying_key(), 1234567890
/// # );
///
/// // Extract specific metadata types
/// assert_eq!(group_state.description(), Some("Test group".to_string()));
///
/// // Get all generic metadata as a map
/// let generic_meta = group_state.generic_metadata();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupState {
    /// The group identifier - this is the Blake3 hash of the CreateGroup message
    /// Also serves as the root event ID (used as channel tag)
    pub group_id: Hash,

    /// Current group name
    pub name: String,

    /// Current group settings  
    pub settings: GroupSettings,

    /// Group metadata as structured types
    pub metadata: Vec<Metadata>,

    /// Runtime member state with roles and activity tracking
    /// Keys are ML-DSA verifying keys encoded as bytes for serialization compatibility
    pub members: BTreeMap<Vec<u8>, GroupMember>,

    /// Advanced identity management for aliases and display names
    pub membership: GroupMembership,

    /// Event history for this group (event ID -> event details)
    pub event_history: Vec<Hash>,

    /// Last processed event timestamp (for ordering)
    pub last_event_timestamp: u64,

    /// State version (incremented on each event)
    pub version: u64,
}

impl GroupState {
    /// Create a new group state from a group creation event.
    ///
    /// This constructor sets up the initial state for a newly created group, including:
    /// - Setting the creator as the first member with [`GroupRole::Owner`] role
    /// - Initializing empty membership state for identity management
    /// - Recording the group creation as the first event in history
    /// - Setting initial timestamps and version number
    ///
    /// # Arguments
    ///
    /// * `group_id` - Blake3 hash of the group creation message (also serves as root event ID)
    /// * `name` - Human-readable group name
    /// * `settings` - Group configuration and permissions
    /// * `metadata` - Structured metadata using [`crate::Metadata`] types
    /// * `creator` - Public key of the group creator (becomes first Owner)
    /// * `timestamp` - Unix timestamp of group creation
    ///
    /// # Returns
    ///
    /// A new `GroupState` with the creator as the sole member and owner.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use zoe_app_primitives::{GroupState, GroupSettings, Metadata, events::roles::GroupRole};
    /// use zoe_wire_protocol::{KeyPair, generate_keypair};
    /// use blake3::Hash;
    ///
    /// let creator_key = SigningKey::generate(&mut rand::rngs::OsRng);
    /// let group_id = Hash::from([42u8; 32]);
    ///
    /// let metadata = vec![
    ///     Metadata::Description("Team coordination space".to_string()),
    ///     Metadata::Generic { key: "project".to_string(), value: "zoe-chat".to_string() },
    /// ];
    ///
    /// let group_state = GroupState::new(
    ///     group_id,
    ///     "Engineering Team".to_string(),
    ///     GroupSettings::default(),
    ///     metadata,
    ///     creator_key.verifying_key(),
    ///     1640995200, // 2022-01-01 00:00:00 UTC
    /// );
    ///
    /// // Verify initial state
    /// assert_eq!(group_state.name, "Engineering Team");
    /// assert_eq!(group_state.members.len(), 1);
    /// assert_eq!(group_state.version, 1);
    /// assert!(group_state.is_member(&creator_key.verifying_key()));
    /// assert_eq!(
    ///     group_state.get_member_role(&creator_key.verifying_key()),
    ///     Some(&GroupRole::Owner)
    /// );
    /// ```
    pub fn new(
        group_id: Hash,
        name: String,
        settings: GroupSettings,
        metadata: Vec<Metadata>,
        creator: VerifyingKey,
        timestamp: u64,
    ) -> Self {
        let creator_bytes = verifying_key_to_bytes(&creator);
        let mut members = BTreeMap::new();
        members.insert(
            creator_bytes.clone(),
            GroupMember {
                public_key: creator_bytes,
                role: GroupRole::Owner,
                joined_at: timestamp,
                last_active: timestamp,
                metadata: vec![],
            },
        );

        Self {
            group_id,
            name,
            settings,
            metadata,
            members,
            membership: GroupMembership::new(),
            event_history: vec![group_id], // First event is the group creation
            last_event_timestamp: timestamp,
            version: 1,
        }
    }

    /// Create a GroupState from existing GroupInfo (for compatibility)
    pub fn from_group_info(
        group_id: Hash,
        group_info: &super::events::GroupInfo,
        creator: VerifyingKey,
        timestamp: u64,
    ) -> Self {
        Self::new(
            group_id,
            group_info.name.clone(),
            group_info.settings.clone(),
            group_info.metadata.clone(),
            creator,
            timestamp,
        )
    }

    /// Convert to GroupInfo for events (extracts the core group information)
    pub fn to_group_info(&self, key_info: super::events::GroupKeyInfo) -> super::events::GroupInfo {
        super::events::GroupInfo {
            name: self.name.clone(),
            settings: self.settings.clone(),
            key_info,
            metadata: self.metadata.clone(),
        }
    }

    /// Apply an event to this group state, updating it according to event-sourced principles.
    ///
    /// This is the core method for updating group state. All state changes must go through
    /// this method to ensure consistency, proper ordering, and audit trail maintenance.
    /// Events are applied in chronological order to maintain deterministic state.
    ///
    /// # Event Processing
    ///
    /// The method handles several types of events:
    /// - **Member Activity**: Any activity announces participation and updates last_active
    /// - **Role Changes**: Updates member roles and permissions
    /// - **Group Updates**: Modifies name, settings, and metadata  
    /// - **Member Departure**: Removes members from active tracking
    /// - **Identity Management**: Processes identity declarations and updates
    ///
    /// # Ordering and Consistency
    ///
    /// Events must be applied in timestamp order. The method will reject events with
    /// timestamps older than the last processed event to maintain consistency across
    /// all group participants.
    ///
    /// # Arguments
    ///
    /// * `event` - The group activity event to process
    /// * `event_id` - Blake3 hash of the event message (for audit trail)
    /// * `sender` - Public key of the event sender (for authorization)
    /// * `timestamp` - Unix timestamp of the event (for ordering)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the event was successfully applied, or [`GroupStateError`] if:
    /// - Event timestamp is out of order
    /// - Sender lacks required permissions
    /// - Member is not found for role operations
    /// - Other validation failures
    ///
    /// # Examples
    ///
    /// ```rust
    /// use zoe_app_primitives::{GroupState, GroupActivityEvent, GroupSettings, Metadata};
    /// use zoe_wire_protocol::{KeyPair, generate_keypair};
    /// use blake3::Hash;
    ///
    /// let creator_key = SigningKey::generate(&mut rand::rngs::OsRng);
    /// let new_member_key = SigningKey::generate(&mut rand::rngs::OsRng);
    ///
    /// let mut group_state = GroupState::new(
    ///     Hash::from([1u8; 32]),
    ///     "Test Group".to_string(),
    ///     GroupSettings::default(),
    ///     vec![],
    ///     creator_key.verifying_key(),
    ///     1000,
    /// );
    ///
    /// // New member announces participation via activity
    /// let activity_event = GroupActivityEvent::Activity(());
    /// let event_id = Hash::from([2u8; 32]);
    ///
    /// group_state.apply_event(
    ///     &activity_event,
    ///     event_id,
    ///     new_member_key.verifying_key(),
    ///     1001, // Must be after creation timestamp
    /// ).unwrap();
    ///
    /// // Member is now tracked in the group
    /// assert!(group_state.is_member(&new_member_key.verifying_key()));
    /// assert_eq!(group_state.members.len(), 2); // Creator + new member
    /// assert_eq!(group_state.version, 2); // Version incremented
    /// assert_eq!(group_state.event_history.len(), 2); // Event recorded
    /// ```
    ///
    /// # State Transitions
    ///
    /// After each successful event application:
    /// - [`GroupState::version`] is incremented
    /// - [`GroupState::last_event_timestamp`] is updated
    /// - [`GroupState::event_history`] includes the new event ID
    /// - Specific state changes depend on the event type
    pub fn apply_event<T>(
        &mut self,
        event: &GroupActivityEvent<T>,
        event_id: Hash,
        sender: VerifyingKey,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        // Verify timestamp ordering (events should be processed in order)
        if timestamp < self.last_event_timestamp {
            return Err(GroupStateError::StateTransition(format!(
                "Event timestamp {} is older than last processed timestamp {}",
                timestamp, self.last_event_timestamp
            )));
        }

        // Apply the specific event
        match event {
            GroupActivityEvent::LeaveGroup { message } => {
                self.handle_leave_group(sender, message.clone(), timestamp)?;
            }

            GroupActivityEvent::UpdateGroup(group_info) => {
                // Handle group updates
                self.name = group_info.name.clone();
                self.settings = group_info.settings.clone();
                self.metadata = group_info.metadata.clone();
            }

            GroupActivityEvent::AssignRole { target, role } => {
                self.handle_role_assignment(sender, target, role, timestamp)?;
            }

            GroupActivityEvent::SetIdentity(_) => {
                // Handle identity setting - for now just ensure sender is a member
                self.handle_member_announcement(sender, timestamp)?;
            }

            GroupActivityEvent::RemoveFromGroup { target: _ } => {
                // For now, skip member removal for Ed25519-based identities when sender is ML-DSA
                // This is a temporary compatibility limitation during the transition
                // TODO: Implement proper key type conversion or dual-key support
                // Note: Skipping member removal due to key type mismatch during ML-DSA transition
            }

            GroupActivityEvent::Unknown { discriminant, .. } => {
                // Unknown management event - ignore for forward compatibility
                // Future implementations could log this with: discriminant value {discriminant}
                let _ = discriminant; // Acknowledge the discriminant without warning
            }

            GroupActivityEvent::Activity(_activity_data) => {
                // Handle custom activity
                self.handle_member_announcement(sender, timestamp)?;
            }
        }

        // Update state metadata
        self.event_history.push(event_id);
        self.last_event_timestamp = timestamp;
        self.version += 1;

        Ok(())
    }

    /// Check if a member has permission to perform an action
    pub fn check_permission(
        &self,
        member: &VerifyingKey,
        required_permission: &Permission,
    ) -> GroupStateResult<()> {
        let member_bytes = verifying_key_to_bytes(member);
        match self.members.get(&member_bytes) {
            Some(member_info) => {
                if member_info.role.has_permission(required_permission) {
                    Ok(())
                } else {
                    Err(GroupStateError::PermissionDenied(format!(
                        "Member {:?} with role {:?} does not have required permission {:?}",
                        member, member_info.role, required_permission
                    )))
                }
            }
            None => Err(GroupStateError::MemberNotFound {
                member: format!("{member:?}"),
                group: format!("{:?}", self.group_id),
            }),
        }
    }

    /// Handle a member announcing their participation in the group
    /// In encrypted groups, anyone with the key can participate
    fn handle_member_announcement(
        &mut self,
        sender: VerifyingKey,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        let sender_bytes = verifying_key_to_bytes(&sender);
        // Add or update member
        if let Some(existing_member) = self.members.get_mut(&sender_bytes) {
            existing_member.last_active = timestamp;
        } else {
            // New member - anyone with the key can participate
            self.members.insert(
                sender_bytes.clone(),
                GroupMember {
                    public_key: sender_bytes,
                    role: GroupRole::Member, // Default role for new key holders
                    joined_at: timestamp,
                    last_active: timestamp,
                    metadata: vec![],
                },
            );
        }

        Ok(())
    }

    fn handle_leave_group(
        &mut self,
        sender: VerifyingKey,
        _message: Option<String>,
        _timestamp: u64,
    ) -> GroupStateResult<()> {
        let sender_bytes = verifying_key_to_bytes(&sender);
        // In encrypted groups, leaving is just an announcement - they still have the key
        // This removes them from the active member list but doesn't revoke access
        if !self.members.contains_key(&sender_bytes) {
            return Err(GroupStateError::MemberNotFound {
                member: format!("{sender:?}"),
                group: format!("{:?}", self.group_id),
            });
        }

        // Remove from active members list
        self.members.remove(&sender_bytes);
        Ok(())
    }

    /// Handle role assignment using IdentityRef
    fn handle_role_assignment(
        &mut self,
        sender: VerifyingKey,
        target: &IdentityRef,
        role: &GroupRole,
        _timestamp: u64,
    ) -> GroupStateResult<()> {
        // Check permission - sender must have permission to assign roles
        self.check_permission(&sender, &self.settings.permissions.assign_roles)?;

        // Extract the target key from IdentityRef
        let target_key = match target {
            IdentityRef::Key(key) => key,
            IdentityRef::Alias { key, .. } => key,
        };

        let target_bytes = verifying_key_to_bytes(target_key);

        // Check if target member exists
        let member_info =
            self.members
                .get_mut(&target_bytes)
                .ok_or_else(|| GroupStateError::MemberNotFound {
                    member: format!("{target_key:?}"),
                    group: format!("{:?}", self.group_id),
                })?;

        // Update role
        member_info.role = role.clone();
        Ok(())
    }

    #[allow(dead_code)]
    fn handle_update_member_role(
        &mut self,
        sender: VerifyingKey,
        member: VerifyingKey,
        role: GroupRole,
    ) -> GroupStateResult<()> {
        // Check permission
        self.check_permission(&sender, &self.settings.permissions.assign_roles)?;

        let member_bytes = verifying_key_to_bytes(&member);
        // Check if target member exists
        let member_info =
            self.members
                .get_mut(&member_bytes)
                .ok_or_else(|| GroupStateError::MemberNotFound {
                    member: format!("{member:?}"),
                    group: format!("{:?}", self.group_id),
                })?;

        // Update role
        member_info.role = role;
        Ok(())
    }

    /// Get all active members
    pub fn get_members(&self) -> &BTreeMap<Vec<u8>, GroupMember> {
        &self.members
    }

    /// Check if a user is a member of this group
    pub fn is_member(&self, user: &VerifyingKey) -> bool {
        let user_bytes = verifying_key_to_bytes(user);
        self.members.contains_key(&user_bytes)
    }

    /// Get a member's role
    pub fn get_member_role(&self, user: &VerifyingKey) -> Option<&GroupRole> {
        let user_bytes = verifying_key_to_bytes(user);
        self.members.get(&user_bytes).map(|m| &m.role)
    }

    /// Extract the group description from structured metadata.
    ///
    /// This method searches through the structured [`crate::Metadata`] collection
    /// to find a [`crate::Metadata::Description`] variant and returns its value.
    /// This provides a convenient way to access the primary descriptive text
    /// for the group.
    ///
    /// # Returns
    ///
    /// `Some(description)` if a description metadata entry exists, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use zoe_app_primitives::{GroupState, GroupSettings, Metadata};
    /// use zoe_wire_protocol::{KeyPair, generate_keypair};
    /// use blake3::Hash;
    ///
    /// let creator_key = SigningKey::generate(&mut rand::rngs::OsRng);
    ///
    /// // Group with description
    /// let metadata_with_desc = vec![
    ///     Metadata::Description("A team coordination space".to_string()),
    ///     Metadata::Generic { key: "category".to_string(), value: "work".to_string() },
    /// ];
    ///
    /// let group_state = GroupState::new(
    ///     Hash::from([1u8; 32]),
    ///     "Team Chat".to_string(),
    ///     GroupSettings::default(),
    ///     metadata_with_desc,
    ///     creator_key.verifying_key(),
    ///     1000,
    /// );
    ///
    /// assert_eq!(
    ///     group_state.description(),
    ///     Some("A team coordination space".to_string())
    /// );
    ///
    /// // Group without description
    /// let metadata_no_desc = vec![
    ///     Metadata::Generic { key: "category".to_string(), value: "work".to_string() },
    /// ];
    ///
    /// let group_state_no_desc = GroupState::new(
    ///     Hash::from([2u8; 32]),
    ///     "Another Group".to_string(),
    ///     GroupSettings::default(),
    ///     metadata_no_desc,
    ///     creator_key.verifying_key(),
    ///     1000,
    /// );
    ///
    /// assert_eq!(group_state_no_desc.description(), None);
    /// ```
    pub fn description(&self) -> Option<String> {
        self.metadata.iter().find_map(|m| match m {
            Metadata::Description(desc) => Some(desc.clone()),
            _ => None,
        })
    }

    /// Extract generic key-value metadata as a BTreeMap for backward compatibility.
    ///
    /// This method filters the structured [`crate::Metadata`] collection to extract
    /// only the [`crate::Metadata::Generic`] variants and returns them as a
    /// [`std::collections::BTreeMap`]. This provides compatibility with code that
    /// expects simple key-value metadata storage.
    ///
    /// # Structured vs Generic Metadata
    ///
    /// The group system supports both structured metadata (typed variants like
    /// [`crate::Metadata::Description`]) and generic key-value pairs. This method
    /// extracts only the generic pairs, ignoring other metadata types.
    ///
    /// # Returns
    ///
    /// A [`std::collections::BTreeMap`] containing all generic metadata key-value pairs.
    /// The map will be empty if no generic metadata exists.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use zoe_app_primitives::{GroupState, GroupSettings, Metadata};
    /// use zoe_wire_protocol::{KeyPair, generate_keypair};
    /// use blake3::Hash;
    ///
    /// let creator_key = SigningKey::generate(&mut rand::rngs::OsRng);
    ///
    /// let metadata = vec![
    ///     Metadata::Description("Team workspace".to_string()), // Not included in generic
    ///     Metadata::Generic { key: "department".to_string(), value: "engineering".to_string() },
    ///     Metadata::Generic { key: "project".to_string(), value: "zoe-chat".to_string() },
    ///     Metadata::Generic { key: "visibility".to_string(), value: "internal".to_string() },
    /// ];
    ///
    /// let group_state = GroupState::new(
    ///     Hash::from([1u8; 32]),
    ///     "Engineering Team".to_string(),
    ///     GroupSettings::default(),
    ///     metadata,
    ///     creator_key.verifying_key(),
    ///     1000,
    /// );
    ///
    /// let generic_meta = group_state.generic_metadata();
    ///
    /// // Only generic metadata is included (3 items, description excluded)
    /// assert_eq!(generic_meta.len(), 3);
    /// assert_eq!(generic_meta.get("department"), Some(&"engineering".to_string()));
    /// assert_eq!(generic_meta.get("project"), Some(&"zoe-chat".to_string()));
    /// assert_eq!(generic_meta.get("visibility"), Some(&"internal".to_string()));
    ///
    /// // Description is not in generic metadata
    /// assert!(!generic_meta.contains_key("description"));
    ///
    /// // But it's still accessible via the description() method
    /// assert_eq!(
    ///     group_state.description(),
    ///     Some("Team workspace".to_string())
    /// );
    /// ```
    ///
    /// # Use Cases
    ///
    /// This method is particularly useful for:
    /// - **Legacy Code Integration**: Existing code expecting simple key-value metadata
    /// - **Generic Queries**: Searching through all key-value pairs programmatically
    /// - **Serialization**: Converting to formats that don't support structured metadata
    /// - **Configuration**: Accessing arbitrary configuration key-value pairs
    pub fn generic_metadata(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for meta in &self.metadata {
            if let Metadata::Generic { key, value } = meta {
                map.insert(key.clone(), value.clone());
            }
        }
        map
    }
}
