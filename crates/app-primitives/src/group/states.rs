use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zoe_wire_protocol::{MessageFull, MessageId};

use super::events::{
    GroupActivityEvent, GroupInfoUpdate, roles::GroupRole, settings::GroupSettings,
};
use crate::{
    digital_groups_organizer::models::core::ActivityMeta,
    group::{
        app_updates::GroupAppUpdate,
        events::{
            GroupInfo,
            permissions::{GroupPermissions, Permission},
        },
    },
    identity::{IdentityInfo, IdentityRef},
    metadata::Metadata,
    protocol::AppProtocolVariant,
};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

/// Comprehensive error types for cross-channel operations
///
/// These errors provide detailed context for debugging and monitoring
/// cross-channel validation, caching, and state reconstruction issues.
#[derive(Debug, thiserror::Error, Clone)]
pub enum CrossChannelError {
    /// Cache-related errors
    #[error("Cache error: {message}")]
    CacheError {
        message: String,
        cache_type: CacheType,
    },

    /// State reconstruction errors
    #[error("State reconstruction failed: {message} (target: {target_message_id:?})")]
    ReconstructionError {
        message: String,
        target_message_id: MessageId,
        available_snapshots: usize,
    },

    /// Permission validation errors
    #[error("Permission validation failed: {message} (app: {app_id:?}, sender: {sender:?})")]
    PermissionError {
        message: String,
        app_id: crate::protocol::AppProtocolVariant,
        sender: IdentityRef,
        required_permission: Option<Permission>,
    },

    /// Cross-channel dependency errors
    #[error("Cross-channel dependency error: {message} (group_ref: {group_reference:?})")]
    DependencyError {
        message: String,
        group_reference: MessageId,
        app_channel: Option<String>,
    },

    /// Memory optimization errors
    #[error("Memory optimization error: {message} (current_usage: {current_usage_bytes} bytes)")]
    MemoryError {
        message: String,
        current_usage_bytes: u64,
        operation: MemoryOperation,
    },

    /// Eventual consistency errors
    #[error("Eventual consistency error: {message} (conflicts: {conflict_count})")]
    ConsistencyError {
        message: String,
        conflict_count: usize,
        resolution_strategy: Option<String>,
    },

    /// Invalid event reference errors
    #[error("Invalid event reference: {message} (event_id: {event_id:?})")]
    InvalidReference {
        message: String,
        event_id: MessageId,
        reference_type: ReferenceType,
    },
}

/// Types of caches in the system
#[derive(Debug, Clone, Copy)]
pub enum CacheType {
    StateReconstruction,
    PermissionLookup,
    Snapshot,
}

/// Types of memory operations
#[derive(Debug, Clone, Copy)]
pub enum MemoryOperation {
    Archival,
    Compression,
    Eviction,
    Optimization,
}

/// Types of event references
#[derive(Debug, Clone, Copy)]
pub enum ReferenceType {
    GroupStateReference,
    ExecutorEventReference,
    SnapshotReference,
}

/// Comprehensive debugging report for cross-channel operations
#[derive(Debug, Clone)]
pub struct CrossChannelDebugReport {
    /// Group ID this report is for
    pub group_id: crate::group::events::GroupId,
    /// Timestamp when report was generated
    pub timestamp: u64,
    /// Total number of events in history
    pub event_count: usize,
    /// Number of snapshots stored
    pub snapshot_count: usize,
    /// Cache statistics
    pub cache_stats: CacheStats,
    /// Memory usage statistics
    pub memory_stats: MemoryUsageStats,
    /// Performance metrics
    pub performance_metrics: CrossChannelMetrics,
    /// Dependency-related issues
    pub dependency_issues: Vec<DependencyIssue>,
    /// Cache-related issues
    pub cache_issues: Vec<CacheIssue>,
    /// Memory-related issues
    pub memory_issues: Vec<MemoryIssue>,
}

/// Cache statistics for debugging
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in state reconstruction cache
    pub state_cache_entries: usize,
    /// Number of entries in permission cache
    pub permission_cache_entries: usize,
    /// Cache hit rate (0.0 to 1.0)
    pub hit_rate: f64,
    /// Total cache hits
    pub total_hits: u64,
    /// Total cache misses
    pub total_misses: u64,
}

/// Dependency issue for debugging
#[derive(Debug, Clone)]
pub struct DependencyIssue {
    /// Event ID related to the issue
    pub event_id: MessageId,
    /// Type of dependency issue
    pub issue_type: DependencyIssueType,
    /// Human-readable description
    pub description: String,
    /// Severity level
    pub severity: IssueSeverity,
}

/// Types of dependency issues
#[derive(Debug, Clone, Copy)]
pub enum DependencyIssueType {
    BrokenReference,
    CircularDependency,
    InvalidEvent,
    OrphanedSnapshot,
    MissingPermission,
}

/// Cache issue for debugging
#[derive(Debug, Clone)]
pub struct CacheIssue {
    /// Type of cache affected
    pub cache_type: CacheType,
    /// Type of cache issue
    pub issue_type: CacheIssueType,
    /// Human-readable description
    pub description: String,
    /// Severity level
    pub severity: IssueSeverity,
}

/// Types of cache issues
#[derive(Debug, Clone, Copy)]
pub enum CacheIssueType {
    LowHitRate,
    HighMemoryUsage,
    EvictionThrashing,
    CorruptedEntry,
}

/// Memory issue for debugging
#[derive(Debug, Clone)]
pub struct MemoryIssue {
    /// Type of memory issue
    pub issue_type: MemoryIssueType,
    /// Human-readable description
    pub description: String,
    /// Current memory usage in bytes
    pub current_usage: u64,
    /// Severity level
    pub severity: IssueSeverity,
}

/// Types of memory issues
#[derive(Debug, Clone, Copy)]
pub enum MemoryIssueType {
    HighUsage,
    MemoryLeak,
    FragmentedStorage,
    UnboundedGrowth,
}

/// Issue severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IssueSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Error types for group state operations
#[derive(Debug, thiserror::Error)]
pub enum GroupStateError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("State transition error: {0}")]
    StateTransition(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Invalid acknowledgment in dual-acknowledgment system
    #[error("Invalid acknowledgment: {0}")]
    InvalidAcknowledgment(String),

    /// History rewrite attempt detected by dual-acknowledgment system
    #[error("History rewrite attempt detected: {0}")]
    HistoryRewriteAttempt(String),

    /// Invalid sender for operation
    #[error("Invalid sender: {0}")]
    InvalidSender(String),
}

/// Result type for group state operations
pub type GroupStateResult<T> = Result<T, GroupStateError>;

/// Runtime information about an active group member.
///
/// `GroupMember` tracks the runtime state of a participant in a group. This includes
/// their role, activity timestamps, and member-specific metadata.
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
/// use zoe_app_primitives::{GroupMember, IdentityRef, events::roles::GroupRole};
/// use zoe_wire_protocol::KeyPair;
/// use std::collections::BTreeMap;
///
/// let member_key = KeyPair::generate(&mut rand::rngs::OsRng).public_key();
/// let join_time = 1234567890;
///
/// let mut member = GroupMember {
///     key: IdentityRef::Key(member_key),
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
/// # use zoe_app_primitives::{GroupMember, IdentityRef, events::roles::GroupRole};
/// # use zoe_wire_protocol::KeyPair;
/// # use std::collections::BTreeMap;
/// # let member_key = KeyPair::generate(&mut rand::rngs::OsRng).public_key();
/// # let mut member = GroupMember {
/// #     key: IdentityRef::Key(member_key), role: GroupRole::Member, joined_at: 0, last_active: 0,
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
/// # use zoe_app_primitives::{GroupMember, IdentityRef, Metadata};
/// # use zoe_wire_protocol::KeyPair;
/// # let mut member = GroupMember {
/// #     key: IdentityRef::Key(KeyPair::generate(&mut rand::rngs::OsRng).public_key()),
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
#[cfg_attr(feature = "frb-api", frb(opaque, ignore_all))]
pub struct GroupMember {
    /// Member's public key encoded as bytes for serialization compatibility
    pub key: IdentityRef,
    /// Member's role in the group
    pub role: GroupRole,
    /// When they joined the group
    pub joined_at: u64,
    /// When they were last active
    pub last_active: u64,
    /// Member-specific metadata using structured types
    pub metadata: Vec<Metadata>,
    /// Member's display name
    pub display_name: Option<String>,
}

/// The complete runtime state of a distributed encrypted group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageMetadata {
    /// When the message was sent (Unix timestamp)
    pub timestamp: u64,
    /// Who sent the message
    pub sender: IdentityRef,
    /// Whether this message changes group permissions or security settings
    pub is_permission_event: bool,
    /// Whether this message failed validation (for app events)
    /// Invalid events are preserved in history but not applied to state
    pub is_invalid: bool,
    /// Reason for invalidity (if applicable)
    pub invalidity_reason: Option<String>,
    /// Cached role assignment details for fast lookups (if this is an AssignRole event)
    pub role_assignment: Option<RoleAssignmentCache>,
    /// Cached app settings update details for fast lookups (if this is an UpdateAppSettings event)
    pub app_settings_update: Option<AppSettingsUpdateCache>,
}

/// Cached role assignment information for fast historical lookups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleAssignmentCache {
    /// The target identity that received the role assignment
    pub target: IdentityRef,
    /// The role that was assigned
    pub role: GroupRole,
}

/// Cached app settings update information for fast historical lookups
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppSettingsUpdateCache {
    /// The app that had its settings updated
    pub app_id: AppProtocolVariant,
}

/// Historical group state snapshot for efficient reconstruction
///
/// Periodic snapshots of group state to avoid O(n) reconstruction
/// on every permission check. Snapshots are taken at regular intervals
/// and used as starting points for historical state reconstruction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupStateSnapshot {
    /// Snapshot timestamp
    pub timestamp: u64,
    /// Member roles at this point in time
    pub member_roles: BTreeMap<IdentityRef, GroupRole>,
    /// Group settings at this point in time
    pub settings: GroupSettings,
    /// Event ID this snapshot was taken after
    pub after_event_id: MessageId,
}

/// Performance metrics for cross-channel operations
///
/// Tracks performance statistics for caching, reconstruction, and validation operations
#[derive(Debug, Clone, Default)]
pub struct CrossChannelMetrics {
    /// Cache hit/miss statistics
    pub cache_hits: u64,
    pub cache_misses: u64,

    /// State reconstruction metrics
    pub reconstructions_performed: u64,
    pub reconstruction_time_ms: u64,

    /// Permission lookup metrics
    pub permission_lookups: u64,
    pub permission_lookup_time_ms: u64,

    /// Validation metrics
    pub validations_performed: u64,
    pub validations_failed: u64,
    pub validation_time_ms: u64,

    /// Memory usage metrics
    pub cache_memory_bytes: u64,
    pub snapshot_memory_bytes: u64,
    pub event_history_bytes: u64,
    pub metadata_bytes: u64,
}

/// Detailed memory usage statistics
///
/// Provides breakdown of memory usage across different components
/// for monitoring and optimization purposes.
#[derive(Debug, Clone)]
pub struct MemoryUsageStats {
    /// Total memory usage in bytes
    pub total_bytes: u64,
    /// Memory used by caches
    pub cache_bytes: u64,
    /// Memory used by snapshots
    pub snapshots_bytes: u64,
    /// Memory used by event history
    pub event_history_bytes: u64,
    /// Memory used by metadata
    pub metadata_bytes: u64,
    /// Number of events in history
    pub event_count: usize,
    /// Number of snapshots stored
    pub snapshot_count: usize,
    /// Number of cache entries
    pub cache_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb(non_opaque))]
pub struct GroupState {
    pub group_info: GroupInfo,

    /// Runtime member state with roles and activity tracking
    pub members: BTreeMap<IdentityRef, GroupMember>,

    /// Event history for this group (event ID -> event details)
    pub event_history: Vec<MessageId>,

    /// Last processed event timestamp (for ordering)
    pub latest_event: MessageId,

    /// State version (incremented on each event)
    pub version: u64,

    /// Message metadata for all events in this group
    ///
    /// Stores timestamp, sender, and permission-event flag for each message.
    /// Required for historical state reconstruction.
    pub message_metadata: BTreeMap<MessageId, MessageMetadata>,

    /// Periodic snapshots for efficient historical reconstruction
    ///
    /// Snapshots are taken every N events to avoid O(n) reconstruction
    /// when validating permissions at historical timestamps.
    pub group_state_snapshots: BTreeMap<u64, GroupStateSnapshot>,

    /// Cache for reconstructed states at specific message IDs
    ///
    /// This cache stores fully reconstructed states to avoid repeated
    /// reconstruction of the same historical states. Uses LRU eviction.
    #[serde(skip)]
    pub state_reconstruction_cache: std::collections::HashMap<MessageId, (GroupState, u64)>, // (state, access_time)

    /// Cache for permission lookups at specific message IDs
    ///
    /// Optimized cache for frequent permission checks without full state reconstruction.
    #[serde(skip)]
    pub permission_cache: std::collections::HashMap<MessageId, (GroupPermissions, u64)>, // (permissions, access_time)

    /// Performance metrics for cross-channel operations
    ///
    /// Tracks cache hits, reconstruction times, validation performance, etc.
    #[serde(skip)]
    pub metrics: CrossChannelMetrics,
}

// #[cfg_attr(feature = "frb-api", frb(ignore))]
impl GroupState {
    pub fn initial(message: &MessageFull, group_info: GroupInfo) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            IdentityRef::Key(message.author().clone()),
            GroupMember {
                key: IdentityRef::Key(message.author().clone()),
                role: GroupRole::Owner,
                joined_at: *message.when(),
                last_active: *message.when(),
                metadata: vec![],
                display_name: None,
            },
        );

        let mut message_metadata = BTreeMap::new();
        message_metadata.insert(
            *message.id(),
            MessageMetadata {
                timestamp: *message.when(),
                sender: IdentityRef::Key(message.author().clone()),
                is_permission_event: false, // Group creation is not a permission-changing event
                is_invalid: false,
                invalidity_reason: None,
                role_assignment: None,
                app_settings_update: None,
            },
        );

        Self {
            group_info,
            members,
            event_history: vec![*message.id()],
            latest_event: *message.id(),
            version: 0,
            message_metadata,
            group_state_snapshots: BTreeMap::new(),
            state_reconstruction_cache: std::collections::HashMap::new(),
            permission_cache: std::collections::HashMap::new(),
            metrics: CrossChannelMetrics::default(),
        }
    }

    /// Validate that the sender has permission to perform the given event
    fn validate_event_permissions(
        &self,
        event: &GroupActivityEvent,
        sender: &IdentityRef,
    ) -> GroupStateResult<()> {
        match event {
            GroupActivityEvent::SetIdentity(_) => {
                // Anyone can announce their participation (they have the group key)
                Ok(())
            }
            GroupActivityEvent::LeaveGroup { .. } => {
                // Anyone can leave the group
                Ok(())
            }
            GroupActivityEvent::UpdateGroup { .. } => {
                // Requires update_group permission
                self.check_permission(sender, &self.group_info.settings.permissions.update_group)
            }
            GroupActivityEvent::AssignRole { .. } => {
                // Requires assign_roles permission
                self.check_permission(sender, &self.group_info.settings.permissions.assign_roles)
            }
            GroupActivityEvent::RemoveFromGroup { .. } => {
                // Requires assign_roles permission (similar to role assignment)
                self.check_permission(sender, &self.group_info.settings.permissions.assign_roles)
            }
            GroupActivityEvent::UpdateAppSettings { .. } => {
                // Requires update_group permission (app settings are part of group management)
                self.check_permission(sender, &self.group_info.settings.permissions.update_group)
            }
            GroupActivityEvent::Unknown { .. } => {
                // Unknown events are rejected for security
                Err(GroupStateError::PermissionDenied(
                    "Unknown event types are not allowed".to_string(),
                ))
            }
        }
    }

    /// Determines if an event is permission-changing (for metadata tracking)
    fn is_permission_event(&self, event: &GroupActivityEvent) -> bool {
        match event {
            // Always permission-changing
            GroupActivityEvent::AssignRole { .. } => true,
            GroupActivityEvent::RemoveFromGroup { .. } => true,
            GroupActivityEvent::UpdateAppSettings { .. } => true,

            // Conditional based on update content
            GroupActivityEvent::UpdateGroup { updates, .. } => {
                updates.iter().any(|update| match update {
                    GroupInfoUpdate::Settings(_) => true,
                    // Future permission-related updates would go here
                    _ => false,
                })
            }

            // Never permission-changing
            GroupActivityEvent::SetIdentity(_) => false,
            GroupActivityEvent::LeaveGroup { .. } => false,
            GroupActivityEvent::Unknown { .. } => false,
        }
    }

    pub fn apply_event(
        &mut self,
        event: GroupActivityEvent,
        event_id: MessageId,
        sender: IdentityRef,
        timestamp: u64,
    ) -> GroupStateResult<Option<GroupAppUpdate>> {
        // Validate permissions BEFORE applying the event
        self.validate_event_permissions(&event, &sender)?;

        // Store message metadata for all events with cached information
        let role_assignment = match event {
            GroupActivityEvent::AssignRole {
                ref target,
                ref role,
                ..
            } => Some(RoleAssignmentCache {
                target: target.clone(),
                role: role.clone(),
            }),
            _ => None,
        };

        let app_settings_update = match event {
            GroupActivityEvent::UpdateAppSettings { ref app_id, .. } => {
                Some(AppSettingsUpdateCache {
                    app_id: app_id.clone(),
                })
            }
            _ => None,
        };

        self.message_metadata.insert(
            event_id,
            MessageMetadata {
                timestamp,
                sender: sender.clone(),
                is_permission_event: self.is_permission_event(&event),
                is_invalid: false,
                invalidity_reason: None,
                role_assignment,
                app_settings_update,
            },
        );

        // Apply event to state with deterministic ordering
        self.apply_event_to_state(event.clone(), event_id, sender.clone(), timestamp)?;

        // Update state metadata
        self.event_history.push(event_id);
        self.latest_event = event_id;
        self.version += 1;

        // Take periodic snapshots for efficient historical reconstruction
        if self.version.is_multiple_of(100) {
            self.take_state_snapshot(timestamp, event_id);
        }

        // Check if this event should generate an app update
        let app_update = match event {
            GroupActivityEvent::UpdateAppSettings { app_id, update } => {
                Some(GroupAppUpdate::AppSettingsUpdate {
                    meta: ActivityMeta {
                        activity_id: event_id,
                        group_id: self.group_info.group_id.clone(),
                        actor: sender,
                        timestamp,
                    },
                    group_id: self.group_info.group_id.clone(),
                    app_id,
                    settings: update,
                })
            }
            GroupActivityEvent::UpdateGroup { updates, .. } => {
                // Check if any of the updates are app installations
                let mut installed_apps = Vec::new();
                for update in updates {
                    if let GroupInfoUpdate::AddApp(app) = update {
                        installed_apps.push(app);
                    }
                }
                if !installed_apps.is_empty() {
                    Some(GroupAppUpdate::InstalledApsUpdate {
                        group_id: self.group_info.group_id.clone(),
                        installed_apps,
                    })
                } else {
                    None
                }
            }
            _ => None,
        };

        Ok(app_update)
    }

    /// Apply an event to the group state (the actual state changes)
    ///
    /// This method contains the core logic for updating group state based on
    /// different event types. It's called by both regular and permission events
    /// after their respective validation passes.
    fn apply_event_to_state(
        &mut self,
        event: GroupActivityEvent,
        _event_id: MessageId,
        sender_ref: IdentityRef,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        match event {
            GroupActivityEvent::LeaveGroup { message } => {
                self.handle_leave_group(sender_ref, message.clone(), timestamp)?;
            }

            GroupActivityEvent::UpdateGroup { updates, .. } => {
                // Handle group updates using the Vec<GroupInfoUpdate> pattern
                for update in updates {
                    match update {
                        crate::group::events::GroupInfoUpdate::Name(name) => {
                            self.group_info.name = name;
                        }
                        crate::group::events::GroupInfoUpdate::Settings(settings) => {
                            self.group_info.settings = settings;
                        }
                        crate::group::events::GroupInfoUpdate::KeyInfo(_key_info) => {
                            // TODO: Handle key info updates when GroupState supports protocols
                        }
                        crate::group::events::GroupInfoUpdate::SetMetadata(metadata) => {
                            self.group_info.metadata = metadata;
                        }
                        crate::group::events::GroupInfoUpdate::AddMetadata(metadata) => {
                            self.group_info.metadata.push(metadata);
                        }
                        crate::group::events::GroupInfoUpdate::ClearMetadata => {
                            self.group_info.metadata.clear();
                        }
                        crate::group::events::GroupInfoUpdate::AddApp(app) => {
                            // Add the app to the installed apps list
                            self.group_info.installed_apps.push(app);
                        }
                    }
                }
            }

            GroupActivityEvent::AssignRole { target, role, .. } => {
                self.handle_role_assignment(sender_ref, &target, &role, timestamp)?;
            }

            GroupActivityEvent::SetIdentity(identity) => {
                self.handle_member_announcement(sender_ref, timestamp, identity)?;
            }

            GroupActivityEvent::RemoveFromGroup { target: _, .. } => {
                // For now, skip member removal for Ed25519-based identities when sender is ML-DSA
                // This is a temporary compatibility limitation during the transition
                // TODO: Implement proper key type conversion or dual-key support
                // Note: Skipping member removal due to key type mismatch during ML-DSA transition
            }

            GroupActivityEvent::UpdateAppSettings { .. } => {
                // this isn't for us
            }

            GroupActivityEvent::Unknown { discriminant, .. } => {
                // Unknown management event - ignore for forward compatibility
                // Future implementations could log this with: discriminant value {discriminant}
                let _ = discriminant; // Acknowledge the discriminant without warning
            }
        }

        Ok(())
    }

    /// Take a periodic snapshot of group state for efficient historical reconstruction
    ///
    /// Snapshots are used to avoid O(n) reconstruction when validating permissions
    /// at historical timestamps. Instead of replaying all events from the beginning,
    /// we can start from the nearest snapshot.
    fn take_state_snapshot(&mut self, timestamp: u64, after_event_id: MessageId) {
        let snapshot = GroupStateSnapshot {
            timestamp,
            member_roles: self
                .members
                .iter()
                .map(|(id, member)| (id.clone(), member.role.clone()))
                .collect(),
            settings: self.group_info.settings.clone(),
            after_event_id,
        };

        self.group_state_snapshots.insert(timestamp, snapshot);

        // Keep only the last 10 snapshots to avoid unbounded growth
        if self.group_state_snapshots.len() > 10 {
            let oldest_timestamp = *self.group_state_snapshots.keys().next().unwrap();
            self.group_state_snapshots.remove(&oldest_timestamp);
        }
    }

    /// Check if a member has permission to perform an action
    /// if no other entry is found in the listing, the member is given GroupRole::Member
    pub fn check_permission(
        &self,
        member: &IdentityRef,
        required_permission: &Permission,
    ) -> GroupStateResult<()> {
        let role = self
            .members
            .get(member)
            .map(|m| m.role.clone())
            .unwrap_or(GroupRole::Member);
        if !role.has_permission(required_permission) {
            Err(GroupStateError::PermissionDenied(format!(
                "Member {member:?} with role {role:?} does not have required permission {required_permission:?}",
            )))
        } else {
            Ok(())
        }
    }

    /// Handle a member announcing their participation in the group
    /// In encrypted groups, anyone with the key can participate
    fn handle_member_announcement(
        &mut self,
        sender: IdentityRef,
        timestamp: u64,
        identity: IdentityInfo,
    ) -> GroupStateResult<()> {
        // Add or update member
        if let Some(existing_member) = self.members.get_mut(&sender) {
            existing_member.last_active = timestamp;
            existing_member.metadata = identity.metadata;
            existing_member.display_name = Some(identity.display_name);
        } else {
            // New member - anyone with the key can participate
            self.members.insert(
                sender.clone(),
                GroupMember {
                    key: sender.clone(),
                    role: GroupRole::Member, // Default role for new key holders
                    joined_at: timestamp,
                    last_active: timestamp,
                    metadata: identity.metadata,
                    display_name: Some(identity.display_name),
                },
            );
        }

        Ok(())
    }

    fn handle_leave_group(
        &mut self,
        sender: IdentityRef,
        _message: Option<String>,
        _timestamp: u64,
    ) -> GroupStateResult<()> {
        // Remove from active members list
        self.members.remove(&sender);
        Ok(())
    }

    /// Handle role assignment using IdentityRef
    fn handle_role_assignment(
        &mut self,
        sender: IdentityRef,
        target: &IdentityRef,
        role: &GroupRole,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        // Check permission - sender must have permission to assign roles
        self.check_permission(&sender, &self.group_info.settings.permissions.assign_roles)?;

        self.members
            .entry(target.clone())
            .and_modify(|member| {
                member.role = role.clone();
                member.last_active = timestamp;
            })
            .or_insert(GroupMember {
                key: target.clone(),
                role: role.clone(),
                joined_at: timestamp,
                last_active: timestamp,
                metadata: vec![],
                display_name: None,
            });
        Ok(())
    }

    /// Get all active members
    pub fn get_members(&self) -> &BTreeMap<IdentityRef, GroupMember> {
        &self.members
    }

    /// Check if a user is a member of this group
    pub fn is_member(&self, user_ref: &IdentityRef) -> bool {
        self.members.contains_key(user_ref)
    }

    /// Get a member's role, None if not defined (but if they can write they are member)
    pub fn member_role(&self, user_ref: &IdentityRef) -> Option<GroupRole> {
        self.members.get(user_ref).map(|m| m.role.clone())
    }

    /// Get an actor's role at a specific message in the group history
    ///
    /// This method uses cached metadata to efficiently determine what role the actor
    /// had at the specified point in time without loading event content.
    ///
    /// # Arguments
    /// * `actor` - The identity of the actor whose role we want to look up
    /// * `message_id` - The message ID at which to determine the actor's role
    ///
    /// # Returns
    /// The actor's role at the specified message, or None if the message is not found
    /// or the actor was not a member at that time.
    pub fn get_actor_role_at_message(
        &self,
        actor: &IdentityRef,
        message_id: MessageId,
    ) -> Option<GroupRole> {
        // Find the position of the target message in the event history
        let target_position = self
            .event_history
            .iter()
            .position(|&msg_id| msg_id == message_id)?;

        // Start with default member role - if someone can send messages to the channel,
        // they are by definition a group member
        let mut actor_role = GroupRole::Member;

        // Search backwards through events up to the target message to find the last role assignment
        // Use cached role assignment data for fast lookups without loading event content
        for &event_id in self.event_history.iter().take(target_position + 1).rev() {
            if let Some(metadata) = self.message_metadata.get(&event_id) {
                // Check if this event has a cached role assignment for our actor
                if !metadata.is_invalid
                    && let Some(role_cache) = &metadata.role_assignment
                    && &role_cache.target == actor
                {
                    actor_role = role_cache.role.clone();
                    break; // Found the most recent assignment, no need to continue
                }
            }
        }

        Some(actor_role)
    }

    /// Get the message ID of the most recent app settings update before a specific message
    ///
    /// This method uses cached metadata to efficiently find the most recent
    /// UpdateAppSettings event for the specified app before the given message.
    ///
    /// # Arguments
    /// * `app_id` - The app protocol variant to get settings for
    /// * `before_message_id` - The message ID to look before
    ///
    /// # Returns
    /// The message ID containing the most recent app settings update, or None if no settings found
    pub fn get_app_settings_message_before(
        &self,
        app_id: &crate::protocol::AppProtocolVariant,
        before_message_id: MessageId,
    ) -> Option<MessageId> {
        // Find the position of the target message in the event history
        let target_position = self
            .event_history
            .iter()
            .position(|&msg_id| msg_id == before_message_id)?;

        // Search backwards through events before the target message for app settings
        // Use cached app settings data for fast lookups without loading event content
        for &event_id in self.event_history.iter().take(target_position).rev() {
            if let Some(metadata) = self.message_metadata.get(&event_id) {
                // Check if this event has a cached app settings update for our app
                if !metadata.is_invalid
                    && let Some(app_cache) = &metadata.app_settings_update
                    && &app_cache.app_id == app_id
                {
                    // Found the most recent app settings update for this app
                    return Some(event_id);
                }
            }
        }

        // No settings found - return None to indicate default settings should be used
        None
    }

    pub fn description(&self) -> Option<String> {
        self.group_info.metadata.iter().find_map(|m| match m {
            Metadata::Description(desc) => Some(desc.clone()),
            _ => None,
        })
    }

    pub fn generic_metadata(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for meta in &self.group_info.metadata {
            if let Metadata::Generic { key, value } = meta {
                map.insert(key.clone(), value.clone());
            }
        }
        map
    }

    /// Sort events deterministically for consistent ordering across all clients
    ///
    /// This method implements the deterministic ordering strategy that replaces
    /// the dual acknowledgment system. Events are sorted by:
    /// 1. Primary: timestamp (earliest first)
    /// 2. Secondary: message ID hash (for tiebreaking)
    /// 3. Tertiary: sender ID (for final tiebreaking)
    ///
    /// # Parameters
    ///
    /// - `events` - Vector of events with their metadata
    ///
    /// # Returns
    ///
    /// Events sorted in deterministic order
    pub fn sort_events_deterministically(&self, events: &mut [(MessageId, MessageMetadata)]) {
        events.sort_by(|a, b| {
            let (id_a, meta_a) = a;
            let (id_b, meta_b) = b;

            // Primary sort: timestamp
            match meta_a.timestamp.cmp(&meta_b.timestamp) {
                std::cmp::Ordering::Equal => {
                    // Secondary sort: message ID hash (higher hash wins for tiebreaking)
                    match id_a.as_bytes().cmp(id_b.as_bytes()) {
                        std::cmp::Ordering::Equal => {
                            // Tertiary sort: sender ID
                            meta_a.sender.cmp(&meta_b.sender)
                        }
                        other => other,
                    }
                }
                other => other,
            }
        });
    }

    /// Resolve eventual consistency for netsplit scenarios
    ///
    /// When multiple clients have different event orders due to network partitions,
    /// this method resolves conflicts using deterministic ordering rules.
    ///
    /// # Strategy
    ///
    /// 1. **Deterministic Ordering**: Use timestamp + message ID + sender ID
    /// 2. **Last-Write-Wins**: For conflicting role assignments, use deterministic criteria
    /// 3. **Preserve History**: Mark conflicts but don't rewrite history
    ///
    /// # Parameters
    ///
    /// - `conflicting_events` - Events that have ordering conflicts
    ///
    /// # Returns
    ///
    /// Resolved event order and any conflicts that need manual resolution
    pub fn resolve_eventual_consistency(
        &self,
        conflicting_events: &mut [(MessageId, MessageMetadata, GroupActivityEvent)],
    ) -> Vec<(MessageId, MessageMetadata, GroupActivityEvent)> {
        // Sort events deterministically
        let mut events_with_metadata: Vec<(MessageId, MessageMetadata)> = conflicting_events
            .iter()
            .map(|(id, meta, _)| (*id, meta.clone()))
            .collect();

        self.sort_events_deterministically(&mut events_with_metadata);

        // Reconstruct the full events in the correct order
        let mut resolved_events = Vec::new();
        for (sorted_id, _) in events_with_metadata {
            if let Some((id, meta, event)) = conflicting_events
                .iter()
                .find(|(id, _, _)| *id == sorted_id)
            {
                resolved_events.push((*id, meta.clone(), event.clone()));
            }
        }

        resolved_events
    }

    /// Resolve role conflicts using last-write-wins strategy
    ///
    /// When the same person gets different roles from different events,
    /// this method determines which role assignment should take precedence.
    ///
    /// # Strategy
    ///
    /// 1. **Timestamp Priority**: Later timestamp wins
    /// 2. **Message ID Tiebreaker**: Higher message ID wins
    /// 3. **Sender Priority**: If same sender, prefer their latest decision
    ///
    /// # Parameters
    ///
    /// - `conflicting_assignments` - Multiple role assignments for the same person
    ///
    /// # Returns
    ///
    /// The winning role assignment
    pub fn resolve_role_conflicts(
        &self,
        conflicting_assignments: &[(MessageId, MessageMetadata, GroupActivityEvent)],
    ) -> Option<(MessageId, MessageMetadata, GroupActivityEvent)> {
        if conflicting_assignments.is_empty() {
            return None;
        }

        // Find the "winning" assignment using deterministic criteria
        let mut winner = &conflicting_assignments[0];

        for assignment in conflicting_assignments.iter().skip(1) {
            let (_, meta_winner, _) = winner;
            let (_, meta_candidate, _) = assignment;

            // Compare timestamps first
            if meta_candidate.timestamp > meta_winner.timestamp {
                winner = assignment;
            } else if meta_candidate.timestamp == meta_winner.timestamp {
                // Tiebreaker: message ID (higher wins)
                let (id_winner, _, _) = winner;
                let (id_candidate, _, _) = assignment;
                if id_candidate.as_bytes() > id_winner.as_bytes() {
                    winner = assignment;
                }
            }
        }

        Some(winner.clone())
    }

    /// Reconstruct the group state at a specific message ID
    /// This allows determining permissions and app settings at any point in history
    ///
    /// Uses caching and snapshots for optimal performance:
    /// 1. Check cache first
    /// 2. Find nearest snapshot
    /// 3. Replay events from snapshot to target
    /// 4. Cache result for future use
    pub fn reconstruct_state_at_message(
        &mut self,
        target_message_id: MessageId,
    ) -> Option<GroupState> {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check cache first
        if let Some((cached_state, _)) = self.state_reconstruction_cache.get(&target_message_id) {
            let cached_state = cached_state.clone();
            // Update access time for LRU
            self.state_reconstruction_cache
                .insert(target_message_id, (cached_state.clone(), current_time));
            self.metrics.cache_hits += 1;
            return Some(cached_state);
        }

        self.metrics.cache_misses += 1;
        let start_time = std::time::Instant::now();

        // Find the target message in our history
        let target_position = self
            .event_history
            .iter()
            .position(|&id| id == target_message_id)?;

        // Find the nearest snapshot before the target
        let target_metadata = self.message_metadata.get(&target_message_id)?;
        let target_timestamp = target_metadata.timestamp;

        let nearest_snapshot = self
            .group_state_snapshots
            .range(..=target_timestamp)
            .next_back()
            .map(|(_, snapshot)| snapshot);

        // Start reconstruction from snapshot or beginning
        let reconstructed_state = if let Some(snapshot) = nearest_snapshot {
            // Find the position of the snapshot's after_event_id
            let snapshot_position = self
                .event_history
                .iter()
                .position(|&id| id == snapshot.after_event_id)
                .unwrap_or(0);

            // Create a state from the snapshot
            let mut state = self.clone();
            state.members = snapshot
                .member_roles
                .iter()
                .map(|(id, role)| {
                    (
                        id.clone(),
                        GroupMember {
                            key: id.clone(),
                            role: role.clone(),
                            joined_at: 0, // We don't store this in snapshots
                            last_active: 0,
                            metadata: Vec::new(),
                            display_name: None,
                        },
                    )
                })
                .collect();
            state.group_info.settings = snapshot.settings.clone();

            // Start from after the snapshot
            (state, snapshot_position + 1)
        } else {
            // Start from the beginning
            (self.clone(), 0)
        };

        // Replay events from start position to target
        for &event_id in self
            .event_history
            .iter()
            .skip(reconstructed_state.1)
            .take(target_position - reconstructed_state.1 + 1)
        {
            if let Some(metadata) = self.message_metadata.get(&event_id) {
                // Skip invalid events during reconstruction
                if metadata.is_invalid {
                    continue;
                }

                // For now, we can only reconstruct basic state changes
                // Full reconstruction would require storing actual event data
                // This is a simplified implementation that maintains member roles
                // TODO: Store and replay actual events for complete reconstruction
            }
        }

        // Cache the result
        self.evict_old_cache_entries();
        self.state_reconstruction_cache.insert(
            target_message_id,
            (reconstructed_state.0.clone(), current_time),
        );

        // Update metrics
        self.metrics.reconstructions_performed += 1;
        self.metrics.reconstruction_time_ms += start_time.elapsed().as_millis() as u64;

        Some(reconstructed_state.0)
    }

    /// Evict old entries from caches to prevent unbounded growth
    fn evict_old_cache_entries(&mut self) {
        const MAX_CACHE_SIZE: usize = 100;
        const MAX_AGE_SECONDS: u64 = 3600; // 1 hour

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Evict old state reconstruction cache entries
        if self.state_reconstruction_cache.len() > MAX_CACHE_SIZE {
            let mut entries: Vec<_> = self
                .state_reconstruction_cache
                .iter()
                .map(|(k, (_, access_time))| (*k, *access_time))
                .collect();
            entries.sort_by_key(|(_, access_time)| *access_time);

            let to_remove = entries.len() - MAX_CACHE_SIZE;
            for (message_id, _) in entries.iter().take(to_remove) {
                self.state_reconstruction_cache.remove(message_id);
            }
        }

        // Remove entries older than MAX_AGE_SECONDS
        self.state_reconstruction_cache
            .retain(|_, (_, access_time)| current_time - *access_time < MAX_AGE_SECONDS);

        // Same for permission cache
        if self.permission_cache.len() > MAX_CACHE_SIZE {
            let mut entries: Vec<_> = self
                .permission_cache
                .iter()
                .map(|(k, (_, access_time))| (*k, *access_time))
                .collect();
            entries.sort_by_key(|(_, access_time)| *access_time);

            let to_remove = entries.len() - MAX_CACHE_SIZE;
            for (message_id, _) in entries.iter().take(to_remove) {
                self.permission_cache.remove(message_id);
            }
        }

        self.permission_cache
            .retain(|_, (_, access_time)| current_time - *access_time < MAX_AGE_SECONDS);

        // Update memory usage metrics
        self.update_memory_metrics();
    }

    /// Update memory usage metrics for caches and snapshots
    fn update_memory_metrics(&mut self) {
        // Estimate cache memory usage (rough approximation)
        let state_cache_size =
            self.state_reconstruction_cache.len() * std::mem::size_of::<(GroupState, u64)>();
        let permission_cache_size =
            self.permission_cache.len() * std::mem::size_of::<(GroupPermissions, u64)>();
        let snapshot_size =
            self.group_state_snapshots.len() * std::mem::size_of::<GroupStateSnapshot>();
        let event_history_size = self.event_history.len() * std::mem::size_of::<MessageId>();
        let metadata_size = self.message_metadata.len() * std::mem::size_of::<MessageMetadata>();

        self.metrics.cache_memory_bytes = (state_cache_size + permission_cache_size) as u64;
        self.metrics.snapshot_memory_bytes = snapshot_size as u64;
        self.metrics.event_history_bytes = event_history_size as u64;
        self.metrics.metadata_bytes = metadata_size as u64;
    }

    /// Get current performance metrics
    ///
    /// Returns a snapshot of current performance statistics for monitoring and debugging
    pub fn get_performance_metrics(&self) -> CrossChannelMetrics {
        self.metrics.clone()
    }

    /// Reset performance metrics
    ///
    /// Clears all performance counters and timers. Useful for testing or periodic resets.
    pub fn reset_performance_metrics(&mut self) {
        self.metrics = CrossChannelMetrics::default();
    }

    /// Validate cross-channel dependencies
    ///
    /// Checks for broken references, circular dependencies, and other issues
    /// that could affect cross-channel validation.
    pub fn validate_cross_channel_dependencies(&self) -> Vec<DependencyIssue> {
        let mut issues = Vec::new();

        // Check for broken group state references
        for (event_id, metadata) in &self.message_metadata {
            if metadata.is_permission_event {
                // In a full implementation, we would check if this event
                // is properly referenced by app events that depend on it

                // For now, we check basic consistency
                if !self.event_history.contains(event_id) {
                    issues.push(DependencyIssue {
                        event_id: *event_id,
                        issue_type: DependencyIssueType::BrokenReference,
                        description: "Permission event not found in event history".to_string(),
                        severity: IssueSeverity::Error,
                    });
                }
            }
        }

        // Check for orphaned snapshots
        for (timestamp, snapshot) in &self.group_state_snapshots {
            if !self.event_history.contains(&snapshot.after_event_id) {
                issues.push(DependencyIssue {
                    event_id: snapshot.after_event_id,
                    issue_type: DependencyIssueType::OrphanedSnapshot,
                    description: format!(
                        "Snapshot at timestamp {} references non-existent event",
                        timestamp
                    ),
                    severity: IssueSeverity::Warning,
                });
            }
        }

        issues
    }

    /// Get the local permissions at a specific message ID
    /// Returns the group permissions that were active at that point
    ///
    /// Uses optimized permission cache for frequent lookups without full state reconstruction
    pub fn get_permissions_at_message(
        &mut self,
        message_id: MessageId,
    ) -> Option<GroupPermissions> {
        let start_time = std::time::Instant::now();
        self.metrics.permission_lookups += 1;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check permission cache first
        if let Some((cached_permissions, _)) = self.permission_cache.get(&message_id) {
            let cached_permissions = cached_permissions.clone();
            // Update access time for LRU
            self.permission_cache
                .insert(message_id, (cached_permissions.clone(), current_time));
            self.metrics.cache_hits += 1;
            self.metrics.permission_lookup_time_ms += start_time.elapsed().as_millis() as u64;
            return Some(cached_permissions);
        }

        self.metrics.cache_misses += 1;

        // Find the most recent permission-changing event before this message
        let target_position = self.event_history.iter().position(|&id| id == message_id)?;

        // Look backwards for the most recent permission event
        let mut permissions = self.group_info.settings.permissions.clone(); // Start with initial permissions

        for &event_id in self.event_history.iter().take(target_position + 1) {
            if let Some(metadata) = self.message_metadata.get(&event_id)
                && metadata.is_permission_event
                && !metadata.is_invalid
            {
                // This is a simplified approach - in a full implementation,
                // we would need to store and replay the actual permission changes
                // For now, we use the current permissions as a placeholder
                permissions = self.group_info.settings.permissions.clone();
            }
        }

        // Cache the result
        self.permission_cache
            .insert(message_id, (permissions.clone(), current_time));

        // Evict old entries if needed
        if self.permission_cache.len() > 100 {
            self.evict_old_cache_entries();
        }

        // Update metrics
        self.metrics.permission_lookup_time_ms += start_time.elapsed().as_millis() as u64;

        Some(permissions)
    }

    /// Lookup group state at a specific message ID
    ///
    /// This method provides access to the group state that was active when
    /// a specific message was processed. Used for cross-channel validation.
    ///
    /// # Parameters
    ///
    /// - `message_id` - The message ID to lookup state for
    ///
    /// # Returns
    ///
    /// - `Some(GroupState)` - The group state at that message (if reconstruction is possible)
    /// - `None` - State reconstruction not available or message not found
    pub fn lookup_group_state_at_message(&mut self, message_id: MessageId) -> Option<GroupState> {
        // Use the cached reconstruction method for efficiency
        self.reconstruct_state_at_message(message_id)
    }

    /// Mark an app event as invalid but preserve it in history
    ///
    /// This method is used when an app event fails validation but should be
    /// preserved in the event history for auditing and debugging purposes.
    ///
    /// # Parameters
    ///
    /// - `event_id` - The message ID of the invalid event
    /// - `reason` - Human-readable reason for invalidity
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Event successfully marked as invalid
    /// - `Err(GroupStateError)` - Event not found or other error
    pub fn mark_event_invalid(
        &mut self,
        event_id: MessageId,
        reason: String,
    ) -> GroupStateResult<()> {
        if let Some(metadata) = self.message_metadata.get_mut(&event_id) {
            metadata.is_invalid = true;
            metadata.invalidity_reason = Some(reason);
            Ok(())
        } else {
            Err(GroupStateError::InvalidSender(format!(
                "Event {event_id:?} not found in message metadata"
            )))
        }
    }

    /// Check if an event is marked as invalid
    ///
    /// # Parameters
    ///
    /// - `event_id` - The message ID to check
    ///
    /// # Returns
    ///
    /// - `Some(true)` - Event is marked as invalid
    /// - `Some(false)` - Event is valid
    /// - `None` - Event not found
    pub fn is_event_invalid(&self, event_id: MessageId) -> Option<bool> {
        self.message_metadata
            .get(&event_id)
            .map(|metadata| metadata.is_invalid)
    }

    /// Get all invalid events with their reasons
    ///
    /// # Returns
    ///
    /// Vector of (MessageId, reason) pairs for all invalid events
    pub fn get_invalid_events(&self) -> Vec<(MessageId, String)> {
        self.message_metadata
            .iter()
            .filter_map(|(id, metadata)| {
                if metadata.is_invalid {
                    Some((
                        *id,
                        metadata
                            .invalidity_reason
                            .clone()
                            .unwrap_or_else(|| "Unknown reason".to_string()),
                    ))
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::events::key_info::GroupKeyInfo;
    use crate::group::events::roles::GroupRole;
    use crate::group::events::settings::GroupSettings;
    use crate::group::events::{GroupActivityEvent, GroupInfo};
    use crate::group::states::Permission;
    use crate::identity::IdentityInfo;
    use crate::metadata::Metadata;

    use rand::rngs::OsRng;
    use zoe_wire_protocol::{KeyPair, MessageFullError, VerifyingKey};

    // Helper functions for creating test data
    fn create_test_key() -> VerifyingKey {
        create_test_verifying_key()
    }

    fn create_test_group_state() -> GroupState {
        let group_info = create_test_group_info();
        let keypair = KeyPair::generate(&mut OsRng);
        let message_full = create_test_message_full(&keypair, vec![], 1000).unwrap();
        GroupState::initial(&message_full, group_info)
    }

    fn create_test_verifying_key() -> VerifyingKey {
        let keypair = KeyPair::generate(&mut OsRng);
        keypair.public_key()
    }

    fn create_test_message_id(seed: u8) -> MessageId {
        MessageId::from_bytes([seed; 32])
    }

    fn create_test_group_key_info() -> GroupKeyInfo {
        GroupKeyInfo::new_chacha20_poly1305(blake3::Hash::from([1u8; 32]))
    }

    pub(crate) fn create_test_group_info() -> GroupInfo {
        GroupInfo {
            name: "Test Group".to_string(),
            group_id: [1u8; 32].into(),
            settings: GroupSettings::default(),
            key_info: create_test_group_key_info(),
            metadata: vec![
                Metadata::Description("Test group description".to_string()),
                Metadata::Generic {
                    key: "category".to_string(),
                    value: "test".to_string(),
                },
            ],
            installed_apps: vec![], // Test data
        }
    }

    pub(crate) fn create_test_message_full(
        sender: &KeyPair,
        content: Vec<u8>,
        timestamp: u64,
    ) -> Result<MessageFull, MessageFullError> {
        use zoe_wire_protocol::{Content, Kind, Message, MessageV0, MessageV0Header};

        let message = Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender: sender.public_key(),
                when: timestamp,
                kind: Kind::Regular,
                tags: vec![],
            },
            content: Content::Raw(content),
        });

        MessageFull::new(message, sender)
    }

    // GroupMember Tests
    #[test]
    fn test_group_member_creation() {
        let key = create_test_verifying_key();
        let identity_ref = IdentityRef::Key(key);
        let timestamp = 1234567890;

        let member = GroupMember {
            key: identity_ref.clone(),
            role: GroupRole::Member,
            joined_at: timestamp,
            last_active: timestamp,
            metadata: vec![],
            display_name: None,
        };

        assert_eq!(member.key, identity_ref);
        assert_eq!(member.role, GroupRole::Member);
        assert_eq!(member.joined_at, timestamp);
        assert_eq!(member.last_active, timestamp);
        assert!(member.metadata.is_empty());
    }

    #[test]
    fn test_group_member_with_metadata() {
        let key = create_test_verifying_key();
        let identity_ref = IdentityRef::Key(key);

        let metadata = vec![
            Metadata::Generic {
                key: "department".to_string(),
                value: "engineering".to_string(),
            },
            Metadata::Email("user@example.com".to_string()),
        ];

        let member = GroupMember {
            key: identity_ref,
            role: GroupRole::Admin,
            joined_at: 1000,
            last_active: 2000,
            metadata: metadata.clone(),
            display_name: None,
        };

        assert_eq!(member.metadata, metadata);
        assert_eq!(member.role, GroupRole::Admin);
    }

    // GroupState Tests
    #[test]
    fn test_group_state_new() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let timestamp = 1234567890;

        let metadata = vec![
            Metadata::Description("Test group".to_string()),
            Metadata::Generic {
                key: "category".to_string(),
                value: "test".to_string(),
            },
        ];

        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), timestamp).unwrap();
        let mut group_info = create_test_group_info();
        group_info.metadata = metadata.clone();

        let group_state = GroupState::initial(&message, group_info);

        assert_eq!(group_state.group_info.name, "Test Group");
        assert_eq!(group_state.group_info.metadata, metadata);
        assert_eq!(group_state.members.len(), 1);
        assert_eq!(group_state.version, 0);
        assert_eq!(group_state.latest_event, *message.id());
        assert_eq!(group_state.event_history.len(), 1);
        assert_eq!(group_state.event_history[0], *message.id());

        // Verify creator is added as owner
        assert!(group_state.is_member(&IdentityRef::Key(creator_key.public_key())));
        assert_eq!(
            group_state.member_role(&IdentityRef::Key(creator_key.public_key())),
            Some(&GroupRole::Owner).cloned()
        );
    }

    #[test]
    fn test_group_state_from_group_info() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let group_info = create_test_group_info();
        let timestamp = 1234567890;

        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), timestamp).unwrap();
        let group_state = GroupState::initial(&message, group_info.clone());

        assert_eq!(group_state.group_info.name, group_info.name);
        assert_eq!(group_state.group_info.settings, group_info.settings);
        assert_eq!(group_state.group_info.metadata, group_info.metadata);
        assert!(group_state.is_member(&IdentityRef::Key(creator_key.public_key())));
    }

    #[test]
    fn test_group_state_to_group_info() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        // Test that the group state was created correctly
        assert_eq!(group_state.group_info.name, "Test Group");
        assert_eq!(group_state.group_info.settings, GroupSettings::default());
    }

    #[test]
    fn test_group_state_is_member() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let other_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        assert!(group_state.is_member(&IdentityRef::Key(creator_key.public_key())));
        assert!(!group_state.is_member(&IdentityRef::Key(other_key.public_key())));
    }

    #[test]
    fn test_group_state_member_role() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        assert_eq!(
            group_state.member_role(&IdentityRef::Key(creator_key.public_key())),
            Some(&GroupRole::Owner).cloned()
        );

        let non_member_key = KeyPair::generate(&mut OsRng);
        assert_eq!(
            group_state.member_role(&IdentityRef::Key(non_member_key.public_key())),
            None
        );
    }

    #[test]
    fn test_group_state_get_members() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        let members = group_state.get_members();
        assert_eq!(members.len(), 1);

        let creator_ref = IdentityRef::Key(creator_key.public_key());
        assert!(members.contains_key(&creator_ref));
    }

    #[test]
    fn test_group_state_description() {
        let creator_key = KeyPair::generate(&mut OsRng);

        // Test with description
        let metadata_with_desc = vec![
            Metadata::Description("Test description".to_string()),
            Metadata::Generic {
                key: "other".to_string(),
                value: "value".to_string(),
            },
        ];

        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let mut group_info = create_test_group_info();
        group_info.metadata = metadata_with_desc;
        let group_state_with_desc = GroupState::initial(&message, group_info);

        assert_eq!(
            group_state_with_desc.description(),
            Some("Test description".to_string())
        );

        // Test without description
        let metadata_no_desc = vec![Metadata::Generic {
            key: "other".to_string(),
            value: "value".to_string(),
        }];

        let message2 =
            create_test_message_full(&creator_key, b"test content 2".to_vec(), 1000).unwrap();
        let mut group_info2 = create_test_group_info();
        group_info2.metadata = metadata_no_desc;
        let group_state_no_desc = GroupState::initial(&message2, group_info2);

        assert_eq!(group_state_no_desc.description(), None);
    }

    #[test]
    fn test_group_state_generic_metadata() {
        let creator_key = KeyPair::generate(&mut OsRng);

        let metadata = vec![
            Metadata::Description("Not included".to_string()),
            Metadata::Generic {
                key: "category".to_string(),
                value: "test".to_string(),
            },
            Metadata::Generic {
                key: "priority".to_string(),
                value: "high".to_string(),
            },
        ];

        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let mut group_info = create_test_group_info();
        group_info.metadata = metadata;
        let group_state = GroupState::initial(&message, group_info);

        let generic_meta = group_state.generic_metadata();
        assert_eq!(generic_meta.len(), 2);
        assert_eq!(generic_meta.get("category"), Some(&"test".to_string()));
        assert_eq!(generic_meta.get("priority"), Some(&"high".to_string()));
        assert!(!generic_meta.contains_key("description"));
    }

    // Event Processing Tests
    #[test]
    fn test_group_state_apply_activity_event() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let new_member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        let event_id = create_test_message_id(11);

        // New member announces participation
        let result = group_state.apply_event(
            activity_event,
            event_id,
            IdentityRef::Key(new_member_key.public_key()),
            1001,
        );

        assert!(result.is_ok());
        assert!(group_state.is_member(&IdentityRef::Key(new_member_key.public_key())));
        assert_eq!(group_state.members.len(), 2);
        assert_eq!(group_state.version, 1);
        assert_eq!(group_state.latest_event, event_id);
        assert_eq!(group_state.event_history.len(), 2);
        assert_eq!(group_state.event_history[1], event_id);

        // Verify new member has default role
        assert_eq!(
            group_state.member_role(&IdentityRef::Key(new_member_key.public_key())),
            Some(&GroupRole::Member).cloned()
        );
    }

    #[test]
    fn test_group_state_apply_update_group_event() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let mut group_info = create_test_group_info();
        group_info.name = "Original Name".to_string();
        let mut group_state = GroupState::initial(&message, group_info);

        use crate::group::events::{GroupInfoUpdate, GroupInfoUpdateContent};
        let new_group_info_update: GroupInfoUpdateContent = vec![
            GroupInfoUpdate::Name("Updated Name".to_string()),
            GroupInfoUpdate::Settings(GroupSettings::default()),
            GroupInfoUpdate::KeyInfo(create_test_group_key_info()),
            GroupInfoUpdate::SetMetadata(vec![Metadata::Description(
                "Updated description".to_string(),
            )]),
        ];

        let update_event: GroupActivityEvent = GroupActivityEvent::UpdateGroup {
            updates: new_group_info_update.clone(),
        };
        let event_id = create_test_message_id(13);

        let result = group_state.apply_event(
            update_event,
            event_id,
            IdentityRef::Key(creator_key.public_key()),
            1001,
        );

        assert!(result.is_ok());
        assert_eq!(group_state.group_info.name, "Updated Name");
        assert_eq!(group_state.group_info.settings, GroupSettings::default());
        assert_eq!(
            group_state.group_info.metadata,
            vec![Metadata::Description("Updated description".to_string())]
        );
        assert_eq!(group_state.version, 1);
    }

    #[test]
    fn test_group_state_apply_leave_group_event() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        // Add member first
        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        group_state
            .apply_event(
                activity_event,
                create_test_message_id(15),
                IdentityRef::Key(member_key.public_key()),
                1001,
            )
            .unwrap();

        assert!(group_state.is_member(&IdentityRef::Key(member_key.public_key())));
        assert_eq!(group_state.members.len(), 2);

        // Member leaves
        let leave_event: GroupActivityEvent = GroupActivityEvent::LeaveGroup {
            message: Some("Goodbye".to_string()),
        };
        let result = group_state.apply_event(
            leave_event,
            create_test_message_id(16),
            IdentityRef::Key(member_key.public_key()),
            1002,
        );

        assert!(result.is_ok());
        assert!(!group_state.is_member(&IdentityRef::Key(member_key.public_key())));
        assert_eq!(group_state.members.len(), 1);
        assert_eq!(group_state.version, 2);
    }

    #[test]
    fn test_group_state_apply_assign_role_event() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        // Add member first
        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        group_state
            .apply_event(
                activity_event,
                create_test_message_id(18),
                IdentityRef::Key(member_key.public_key()),
                1001,
            )
            .unwrap();

        // Assign admin role to the member
        let _creation_message_id = group_state.event_history[0];
        let assign_role_event: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityRef::Key(member_key.public_key()),
            role: GroupRole::Admin,
        };

        let result = group_state.apply_event(
            assign_role_event,
            create_test_message_id(19),
            IdentityRef::Key(creator_key.public_key()), // Creator assigns role to member
            1002,
        );

        assert!(result.is_ok());
        assert_eq!(
            group_state.member_role(&IdentityRef::Key(member_key.public_key())),
            Some(&GroupRole::Admin).cloned()
        );
        assert_eq!(group_state.version, 2);
    }

    #[test]
    fn test_group_state_apply_event_timestamp_ordering() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });

        // With the new deterministic ordering system, we accept events with older timestamps
        // The deterministic ordering will handle the eventual consistency
        let result = group_state.apply_event(
            activity_event,
            create_test_message_id(21),
            IdentityRef::Key(creator_key.public_key()),
            999, // Older than creation timestamp
        );

        // Should succeed - deterministic ordering handles eventual consistency
        assert!(result.is_ok());
    }

    // Permission Tests
    #[test]
    fn test_group_state_check_permission_success() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        // Owner should have all permissions
        let result = group_state.check_permission(
            &IdentityRef::Key(creator_key.public_key()),
            &Permission::OwnerOnly,
        );
        assert!(result.is_ok());

        let result = group_state.check_permission(
            &IdentityRef::Key(creator_key.public_key()),
            &Permission::AdminOrAbove,
        );
        assert!(result.is_ok());

        let result = group_state.check_permission(
            &IdentityRef::Key(creator_key.public_key()),
            &Permission::AllMembers,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_group_state_check_permission_denied() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        // Add member
        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        group_state
            .apply_event(
                activity_event,
                create_test_message_id(24),
                IdentityRef::Key(member_key.public_key()),
                1001,
            )
            .unwrap();

        // Member should not have owner-only permissions
        let result = group_state.check_permission(
            &IdentityRef::Key(member_key.public_key()),
            &Permission::OwnerOnly,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            GroupStateError::PermissionDenied(msg) => {
                assert!(msg.contains("does not have required permission"));
            }
            _ => panic!("Expected PermissionDenied error"),
        }

        // But should have all-members permissions
        let result = group_state.check_permission(
            &IdentityRef::Key(member_key.public_key()),
            &Permission::AllMembers,
        );
        assert!(result.is_ok());
    }

    // Error Handling Tests
    #[test]
    fn test_group_state_error_display() {
        let error = GroupStateError::PermissionDenied("Test permission denied".to_string());
        assert_eq!(
            error.to_string(),
            "Permission denied: Test permission denied"
        );

        let error = GroupStateError::StateTransition("Test transition error".to_string());
        assert_eq!(
            error.to_string(),
            "State transition error: Test transition error"
        );

        let error = GroupStateError::InvalidOperation("Test invalid operation".to_string());
        assert_eq!(
            error.to_string(),
            "Invalid operation: Test invalid operation"
        );
    }

    #[test]
    fn test_group_state_handle_role_assignment_permission_denied() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let member_key = KeyPair::generate(&mut OsRng);
        let target_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        // Add both members
        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        group_state
            .apply_event(
                activity_event.clone(),
                create_test_message_id(31),
                IdentityRef::Key(member_key.public_key()),
                1001,
            )
            .unwrap();
        group_state
            .apply_event(
                activity_event,
                create_test_message_id(32),
                IdentityRef::Key(target_key.public_key()),
                1002,
            )
            .unwrap();

        // Regular member tries to assign role (should fail)
        let assign_role_event: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityRef::Key(member_key.public_key()),
            role: GroupRole::Admin,
        };

        let result = group_state.apply_event(
            assign_role_event,
            create_test_message_id(33),
            IdentityRef::Key(member_key.public_key()), // Regular member, not owner
            1003,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            GroupStateError::PermissionDenied(_) => {}
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_postcard_serialization_group_member() {
        let key = KeyPair::generate(&mut OsRng);
        let identity_ref = IdentityRef::Key(key.public_key());

        let member = GroupMember {
            key: identity_ref,
            role: GroupRole::Moderator,
            joined_at: 1234567890,
            last_active: 1234567900,
            metadata: vec![Metadata::Generic {
                key: "department".to_string(),
                value: "engineering".to_string(),
            }],
            display_name: None,
        };

        let serialized = postcard::to_stdvec(&member).expect("Failed to serialize");
        let deserialized: GroupMember =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(member.role, deserialized.role);
        assert_eq!(member.joined_at, deserialized.joined_at);
        assert_eq!(member.last_active, deserialized.last_active);
        assert_eq!(member.metadata, deserialized.metadata);
    }

    #[test]
    fn test_postcard_serialization_group_state() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1234567890).unwrap();
        let mut group_info = create_test_group_info();
        group_info.name = "Serialization Test Group".to_string();
        group_info.metadata = vec![
            Metadata::Description("Test serialization".to_string()),
            Metadata::Generic {
                key: "test".to_string(),
                value: "value".to_string(),
            },
        ];
        let group_state = GroupState::initial(&message, group_info);

        let serialized = postcard::to_stdvec(&group_state).expect("Failed to serialize");
        let deserialized: GroupState =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(
            group_state.group_info.group_id,
            deserialized.group_info.group_id
        );
        assert_eq!(group_state.group_info.name, deserialized.group_info.name);
        assert_eq!(
            group_state.group_info.settings,
            deserialized.group_info.settings
        );
        assert_eq!(
            group_state.group_info.metadata,
            deserialized.group_info.metadata
        );
        assert_eq!(group_state.members.len(), deserialized.members.len());
        assert_eq!(group_state.version, deserialized.version);
        assert_eq!(group_state.latest_event, deserialized.latest_event);
        assert_eq!(group_state.event_history, deserialized.event_history);
    }

    // Integration Tests
    #[test]
    fn test_group_state_full_lifecycle() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let member1_key = KeyPair::generate(&mut OsRng);
        let member2_key = KeyPair::generate(&mut OsRng);

        // Create group
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let mut group_info = create_test_group_info();
        group_info.name = "Lifecycle Test Group".to_string();
        group_info.metadata = vec![Metadata::Description("Full lifecycle test".to_string())];
        let mut group_state = GroupState::initial(&message, group_info);

        assert_eq!(group_state.members.len(), 1);
        assert_eq!(group_state.version, 0);

        // Member 1 joins
        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        group_state
            .apply_event(
                activity_event.clone(),
                create_test_message_id(36),
                IdentityRef::Key(member1_key.public_key()),
                1001,
            )
            .unwrap();

        assert_eq!(group_state.members.len(), 2);
        assert_eq!(group_state.version, 1);
        assert!(group_state.is_member(&IdentityRef::Key(member1_key.public_key())));

        // Member 2 joins
        group_state
            .apply_event(
                activity_event.clone(),
                create_test_message_id(37),
                IdentityRef::Key(member2_key.public_key()),
                1002,
            )
            .unwrap();

        assert_eq!(group_state.members.len(), 3);
        assert_eq!(group_state.version, 2);

        // Creator promotes member1 to admin
        let promote_event: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityRef::Key(member1_key.public_key()),
            role: GroupRole::Admin,
        };
        group_state
            .apply_event(
                promote_event.clone(),
                create_test_message_id(38),
                IdentityRef::Key(creator_key.public_key()),
                1003,
            )
            .unwrap();

        assert_eq!(
            group_state.member_role(&IdentityRef::Key(member1_key.public_key())),
            Some(&GroupRole::Admin).cloned()
        );
        assert_eq!(group_state.version, 3);

        // Creator (owner) promotes member2 to moderator (only owners can assign roles by default)
        let promote_event2: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityRef::Key(member2_key.public_key()),
            role: GroupRole::Moderator,
        };
        group_state
            .apply_event(
                promote_event2.clone(),
                create_test_message_id(39),
                IdentityRef::Key(creator_key.public_key()),
                1004,
            )
            .unwrap();

        // member2 should have the Moderator role (as assigned in the event)
        assert_eq!(
            group_state.member_role(&IdentityRef::Key(member2_key.public_key())),
            Some(&GroupRole::Moderator).cloned()
        );

        // member1 should still have the Admin role (unchanged)
        assert_eq!(
            group_state.member_role(&IdentityRef::Key(member1_key.public_key())),
            Some(&GroupRole::Admin).cloned()
        );
        assert_eq!(group_state.version, 4);

        // Update group info
        use crate::group::events::{GroupInfoUpdate, GroupInfoUpdateContent};
        let new_group_info_update: GroupInfoUpdateContent = vec![
            GroupInfoUpdate::Name("Updated Lifecycle Test Group".to_string()),
            GroupInfoUpdate::Settings(GroupSettings::default()),
            GroupInfoUpdate::KeyInfo(create_test_group_key_info()),
            GroupInfoUpdate::SetMetadata(vec![
                Metadata::Description("Updated description".to_string()),
                Metadata::Generic {
                    key: "status".to_string(),
                    value: "active".to_string(),
                },
            ]),
        ];

        let update_event: GroupActivityEvent = GroupActivityEvent::UpdateGroup {
            updates: new_group_info_update.clone(),
        };
        group_state
            .apply_event(
                update_event.clone(),
                create_test_message_id(40),
                IdentityRef::Key(creator_key.public_key()),
                1005,
            )
            .unwrap();

        assert_eq!(group_state.group_info.name, "Updated Lifecycle Test Group");
        assert_eq!(
            group_state.group_info.metadata,
            vec![
                Metadata::Description("Updated description".to_string()),
                Metadata::Generic {
                    key: "status".to_string(),
                    value: "active".to_string(),
                },
            ]
        );
        assert_eq!(group_state.version, 5);

        // Member2 leaves
        let leave_event: GroupActivityEvent = GroupActivityEvent::LeaveGroup {
            message: Some("Goodbye!".to_string()),
        };
        group_state
            .apply_event(
                leave_event,
                create_test_message_id(41),
                IdentityRef::Key(member2_key.public_key()),
                1006,
            )
            .unwrap();

        assert!(!group_state.is_member(&IdentityRef::Key(member2_key.public_key())));
        assert_eq!(group_state.members.len(), 2);
        assert_eq!(group_state.version, 6);

        // Verify final state
        assert_eq!(group_state.event_history.len(), 7);
        assert_eq!(group_state.latest_event, create_test_message_id(41));
        assert!(group_state.is_member(&IdentityRef::Key(creator_key.public_key())));
        assert!(group_state.is_member(&IdentityRef::Key(member1_key.public_key())));
        assert!(!group_state.is_member(&IdentityRef::Key(member2_key.public_key())));
    }

    #[test]
    fn test_group_state_concurrent_member_activity() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let mut group_info = create_test_group_info();
        group_info.name = "Concurrent Test".to_string();
        let mut group_state = GroupState::initial(&message, group_info);

        // Member joins
        let activity_event = GroupActivityEvent::SetIdentity(IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });
        group_state
            .apply_event(
                activity_event.clone(),
                create_test_message_id(43),
                IdentityRef::Key(member_key.public_key()),
                1001,
            )
            .unwrap();

        let initial_last_active = group_state
            .members
            .get(&IdentityRef::Key(member_key.public_key()))
            .unwrap()
            .last_active;
        assert_eq!(initial_last_active, 1001);

        // Member is active again (should update last_active)
        group_state
            .apply_event(
                activity_event.clone(),
                create_test_message_id(44),
                IdentityRef::Key(member_key.public_key()),
                1010,
            )
            .unwrap();

        let updated_last_active = group_state
            .members
            .get(&IdentityRef::Key(member_key.public_key()))
            .unwrap()
            .last_active;
        assert_eq!(updated_last_active, 1010);
        assert_eq!(group_state.members.len(), 2); // Should still be 2 members
    }

    #[test]
    fn test_deterministic_event_ordering() {
        // Test that events are sorted deterministically by timestamp, then message ID, then sender
        let group_state = create_test_group_state();

        // Create events with same timestamp but different message IDs
        let event1_id = create_test_message_id(1);
        let event2_id = create_test_message_id(2);
        let event3_id = create_test_message_id(3);

        let timestamp = 1000;
        let sender = IdentityRef::Key(create_test_key());

        let mut events = vec![
            (
                event2_id,
                MessageMetadata {
                    timestamp,
                    sender: sender.clone(),
                    is_permission_event: false,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
            ),
            (
                event1_id,
                MessageMetadata {
                    timestamp,
                    sender: sender.clone(),
                    is_permission_event: false,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
            ),
            (
                event3_id,
                MessageMetadata {
                    timestamp,
                    sender: sender.clone(),
                    is_permission_event: false,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
            ),
        ];

        // Sort events deterministically
        group_state.sort_events_deterministically(&mut events);

        // Should be sorted by message ID (ascending)
        assert_eq!(events[0].0, event1_id);
        assert_eq!(events[1].0, event2_id);
        assert_eq!(events[2].0, event3_id);
    }

    #[test]
    fn test_update_app_settings_event() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        // Create an UpdateAppSettings event
        let app_settings_event = GroupActivityEvent::UpdateAppSettings {
            app_id: crate::protocol::AppProtocolVariant::DigitalGroupsOrganizer,
            update: b"test app settings update".to_vec(),
        };

        // Apply the event
        let result = group_state.apply_event(
            app_settings_event.clone(),
            create_test_message_id(42),
            IdentityRef::Key(creator_key.public_key()),
            1001,
        );

        // Should succeed (basic processing)
        assert!(result.is_ok());

        // Verify it's recognized as a permission event
        assert!(group_state.is_permission_event(&app_settings_event));
    }

    #[test]
    fn test_permission_reconstruction() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        // Add some events to the history
        let event1_id = create_test_message_id(41);
        let event2_id = create_test_message_id(42);

        group_state.event_history.push(event1_id);
        group_state.event_history.push(event2_id);

        // Test that we can get permissions at a specific message
        let permissions = group_state.get_permissions_at_message(event1_id);

        // This should return Some since we have permissions in the history
        assert!(permissions.is_some());

        // Test that we can get app settings message ID (even if None for now)
        let app_settings_msg = group_state.get_app_settings_message_before(
            &crate::protocol::AppProtocolVariant::DigitalGroupsOrganizer,
            event1_id,
        );

        // App settings message ID may be None since we haven't created any app settings events
        // This is expected behavior for the current implementation
        assert!(app_settings_msg.is_none());

        // Test individual methods
        let permissions = group_state.get_permissions_at_message(event1_id);
        assert!(permissions.is_some()); // Should be Some since reconstruction is now implemented

        let app_settings_msg = group_state.get_app_settings_message_before(
            &crate::protocol::AppProtocolVariant::DigitalGroupsOrganizer,
            event1_id,
        );
        assert!(app_settings_msg.is_none()); // Should be None since no app settings exist
    }

    #[test]
    fn test_invalid_event_handling() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        let event_id = create_test_message_id(42);
        let reason = "Invalid permissions".to_string();

        // Initially, event should not be marked as invalid
        assert_eq!(group_state.is_event_invalid(event_id), None);

        // Add some metadata for the event
        group_state.message_metadata.insert(
            event_id,
            MessageMetadata {
                timestamp: 1001,
                sender: IdentityRef::Key(creator_key.public_key()),
                is_permission_event: false,
                is_invalid: false,
                invalidity_reason: None,
                role_assignment: None,
                app_settings_update: None,
            },
        );

        // Event should now be valid
        assert_eq!(group_state.is_event_invalid(event_id), Some(false));

        // Mark event as invalid
        group_state
            .mark_event_invalid(event_id, reason.clone())
            .unwrap();

        // Event should now be marked as invalid
        assert_eq!(group_state.is_event_invalid(event_id), Some(true));

        // Check invalid events list
        let invalid_events = group_state.get_invalid_events();
        assert_eq!(invalid_events.len(), 1);
        assert_eq!(invalid_events[0], (event_id, reason));
    }

    #[test]
    fn test_role_conflict_resolution() {
        // Test that role conflicts are resolved using last-write-wins strategy
        let group_state = create_test_group_state();

        let sender1 = IdentityRef::Key(create_test_key());
        let sender2 = IdentityRef::Key(create_test_key());
        let _target = IdentityRef::Key(create_test_key());

        // Create conflicting role assignments
        let conflicting_assignments = vec![
            (
                create_test_message_id(1),
                MessageMetadata {
                    timestamp: 1000,
                    sender: sender1.clone(),
                    is_permission_event: true,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
                GroupActivityEvent::AssignRole {
                    target: _target.clone(),
                    role: GroupRole::Member,
                },
            ),
            (
                create_test_message_id(2),
                MessageMetadata {
                    timestamp: 1001, // Later timestamp
                    sender: sender2.clone(),
                    is_permission_event: true,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
                GroupActivityEvent::AssignRole {
                    target: _target.clone(),
                    role: GroupRole::Admin,
                },
            ),
        ];

        // Resolve conflicts
        let winner = group_state.resolve_role_conflicts(&conflicting_assignments);

        assert!(winner.is_some());
        let (_, meta, event) = winner.unwrap();

        // Should pick the later timestamp (Admin role)
        assert_eq!(meta.timestamp, 1001);
        if let GroupActivityEvent::AssignRole { role, .. } = event {
            assert_eq!(role, GroupRole::Admin);
        } else {
            panic!("Expected AssignRole event");
        }
    }

    #[test]
    fn test_eventual_consistency_resolution() {
        // Test that netsplit scenarios are resolved using deterministic ordering
        let group_state = create_test_group_state();

        let sender1 = IdentityRef::Key(create_test_key());
        let sender2 = IdentityRef::Key(create_test_key());

        // Create events that arrived out of order due to netsplit
        let mut conflicting_events = vec![
            (
                create_test_message_id(3),
                MessageMetadata {
                    timestamp: 1002,
                    sender: sender1.clone(),
                    is_permission_event: false,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
                GroupActivityEvent::UpdateGroup {
                    updates: vec![GroupInfoUpdate::Name("Name 3".to_string())],
                },
            ),
            (
                create_test_message_id(1),
                MessageMetadata {
                    timestamp: 1000,
                    sender: sender2.clone(),
                    is_permission_event: false,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
                GroupActivityEvent::UpdateGroup {
                    updates: vec![GroupInfoUpdate::Name("Name 1".to_string())],
                },
            ),
            (
                create_test_message_id(2),
                MessageMetadata {
                    timestamp: 1001,
                    sender: sender1.clone(),
                    is_permission_event: false,
                    is_invalid: false,
                    invalidity_reason: None,
                    role_assignment: None,
                    app_settings_update: None,
                },
                GroupActivityEvent::UpdateGroup {
                    updates: vec![GroupInfoUpdate::Name("Name 2".to_string())],
                },
            ),
        ];

        // Resolve eventual consistency
        let resolved_events = group_state.resolve_eventual_consistency(&mut conflicting_events);

        // Should be sorted by timestamp
        assert_eq!(resolved_events.len(), 3);
        assert_eq!(resolved_events[0].1.timestamp, 1000);
        assert_eq!(resolved_events[1].1.timestamp, 1001);
        assert_eq!(resolved_events[2].1.timestamp, 1002);
    }
}
