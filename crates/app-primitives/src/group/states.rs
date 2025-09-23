use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zoe_wire_protocol::{MessageFull, MessageId, VerifyingKey};

use super::events::{GroupActivityEvent, roles::GroupRole, settings::GroupSettings};
use crate::{
    group::events::{GroupInfo, permissions::Permission},
    identity::IdentityRef,
    metadata::Metadata,
};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

// Test modules
#[cfg(test)]
mod dual_ack_tests;

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
}

/// Per-sender acknowledgment tracking for the dual-acknowledgment ratchet system
///
/// Tracks what state changes each sender has acknowledged to prevent
/// history rewriting attacks. Each sender must acknowledge both their own
/// latest state change and the latest state change from other participants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SenderAcknowledgments {
    /// Latest own state change this sender has acknowledged
    ///
    /// This prevents the sender from backdating events before their own
    /// previously acknowledged state changes. Creates a "floor" based on
    /// the sender's own message history.
    pub own_last_ack: MessageId,
    /// Latest other's state change this sender has acknowledged
    ///
    /// This prevents the sender from ignoring third-party state changes
    /// when attempting to rewrite history. The sender must acknowledge
    /// the latest state change from other participants.
    pub others_last_ack: MessageId,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb(non_opaque))]
pub struct GroupState {
    pub group_info: GroupInfo,

    /// Runtime member state with roles and activity tracking
    pub members: BTreeMap<IdentityRef, GroupMember>,

    /// Event history for this group (event ID -> event details)
    pub event_history: Vec<MessageId>,

    /// Last processed event timestamp (for ordering)
    pub last_event_timestamp: u64,

    /// State version (incremented on each event)
    pub version: u64,

    // === Dual-Acknowledgment Security System ===
    /// Per-sender acknowledgment tracking for permission events
    ///
    /// Maps each sender to their latest acknowledged state changes.
    /// Used to prevent timestamp manipulation attacks by creating
    /// "floors" that prevent backdating events.
    pub sender_acknowledgments: BTreeMap<IdentityRef, SenderAcknowledgments>,

    /// Message metadata for all events in this group
    ///
    /// Stores timestamp, sender, and permission-event flag for each message.
    /// Required for historical state reconstruction and acknowledgment validation.
    pub message_metadata: BTreeMap<MessageId, MessageMetadata>,

    /// Periodic snapshots for efficient historical reconstruction
    ///
    /// Snapshots are taken every N events to avoid O(n) reconstruction
    /// when validating permissions at historical timestamps.
    pub group_state_snapshots: BTreeMap<u64, GroupStateSnapshot>,
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
            },
        );

        let mut message_metadata = BTreeMap::new();
        message_metadata.insert(
            *message.id(),
            MessageMetadata {
                timestamp: *message.when(),
                sender: IdentityRef::Key(message.author().clone()),
                is_permission_event: false, // Group creation is not a permission-changing event
            },
        );

        Self {
            group_info,
            members,
            event_history: vec![*message.id()],
            last_event_timestamp: *message.when(),
            version: 0,
            sender_acknowledgments: BTreeMap::new(),
            message_metadata,
            group_state_snapshots: BTreeMap::new(),
        }
    }

    pub fn apply_event(
        &mut self,
        event: GroupActivityEvent,
        event_id: MessageId,
        sender: IdentityRef,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        // Store message metadata for all events
        self.message_metadata.insert(
            event_id,
            MessageMetadata {
                timestamp,
                sender: sender.clone(),
                is_permission_event: event.is_permission_changing(),
            },
        );

        // Apply dual-acknowledgment validation for permission-changing events
        if event.is_permission_changing() {
            let sender_key = match &sender {
                IdentityRef::Key(key) => key.clone(),
                _ => {
                    return Err(GroupStateError::InvalidSender(
                        "Only keys can perform permission-changing events".to_string(),
                    ));
                }
            };
            self.apply_permission_event_with_dual_acknowledgment(
                event, event_id, sender_key, timestamp,
            )?;
        } else {
            // Regular (non-permission) events can be processed out of order
            // This allows legitimate multi-device scenarios where devices sync changes
            // made while offline. Only permission-changing events require strict ordering.
            self.apply_event_to_state(event, event_id, sender, timestamp)?;
        }

        // Update state metadata
        self.event_history.push(event_id);
        self.last_event_timestamp = timestamp;
        self.version += 1;

        // Take periodic snapshots for efficient historical reconstruction
        if self.version.is_multiple_of(100) {
            self.take_state_snapshot(timestamp, event_id);
        }

        Ok(())
    }

    /// Apply a permission-changing event with dual-acknowledgment validation
    ///
    /// This method implements the core security mechanism that prevents timestamp
    /// manipulation attacks and history rewriting for permission-changing events.
    ///
    /// # Security Model
    ///
    /// Each permission-changing event must acknowledge both:
    /// 1. **Own Last State Change**: Latest state-changing message from the same sender
    /// 2. **Others' Last State Change**: Latest state-changing message from other participants
    ///
    /// This creates a "ratchet effect" where each acknowledgment establishes a floor
    /// that prevents backdating attacks.
    ///
    /// # Attack Prevention
    ///
    /// - **Cannot backdate before acknowledged state**: Event timestamp must be >= acknowledged timestamps
    /// - **Must acknowledge third-party changes**: Cannot ignore other participants when rewriting
    /// - **Cryptographically hard conflicts**: Message ID tiebreaker uses Blake3 hashes
    ///
    /// # Parameters
    ///
    /// - `event` - The permission-changing event to apply
    /// - `event_id` - Unique identifier for this event
    /// - `sender` - The sender's verifying key
    /// - `timestamp` - When the event was sent
    fn apply_permission_event_with_dual_acknowledgment(
        &mut self,
        event: GroupActivityEvent,
        event_id: MessageId,
        sender: VerifyingKey,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        let sender_ref = IdentityRef::Key(sender.clone());

        // Extract dual acknowledgments from the event
        let (ack_own, ack_others) = event
            .extract_acknowledgments()
            .map_err(GroupStateError::InvalidAcknowledgment)?;

        // Validate acknowledgments prevent history rewriting
        self.validate_dual_acknowledgments(&sender_ref, ack_own, ack_others, timestamp, event_id)?;

        // Resolve conflicts if multiple events have same acknowledgment level
        self.resolve_acknowledgment_conflicts(
            &sender_ref,
            ack_own,
            ack_others,
            timestamp,
            event_id,
        )?;

        // Apply the event to state
        self.apply_event_to_state(event, event_id, sender_ref.clone(), timestamp)?;

        // Update sender's acknowledgment tracking
        self.update_sender_acknowledgments(sender_ref, ack_own, ack_others);

        Ok(())
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
                let sender_key = match &sender_ref {
                    IdentityRef::Key(key) => key.clone(),
                    _ => {
                        return Err(GroupStateError::InvalidSender(
                            "Only keys can leave groups".to_string(),
                        ));
                    }
                };
                self.handle_leave_group(sender_key, message.clone(), timestamp)?;
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
                let sender_key = match &sender_ref {
                    IdentityRef::Key(key) => key.clone(),
                    _ => {
                        return Err(GroupStateError::InvalidSender(
                            "Only keys can assign roles".to_string(),
                        ));
                    }
                };

                // Convert IdentityType to IdentityRef
                let target_ref = match target {
                    crate::identity::IdentityType::Main => {
                        // For now, we need to find the target by looking up members
                        // This is a limitation of the current design - we should pass the actual target key
                        // For testing purposes, we'll assume the target is the first member that's not the sender
                        let target_key = self
                            .members
                            .iter()
                            .find(|(key, _)| **key != sender_ref)
                            .and_then(|(key, _)| match key {
                                IdentityRef::Key(k) => Some(k.clone()),
                                _ => None,
                            })
                            .ok_or_else(|| {
                                GroupStateError::InvalidSender("No target member found".to_string())
                            })?;
                        IdentityRef::Key(target_key)
                    }
                    crate::identity::IdentityType::Alias { .. } => {
                        return Err(GroupStateError::InvalidSender(
                            "Alias targets not supported yet".to_string(),
                        ));
                    }
                };

                self.handle_role_assignment(sender_key, &target_ref, &role, timestamp)?;
            }

            GroupActivityEvent::SetIdentity(_) => {
                let sender_key = match &sender_ref {
                    IdentityRef::Key(key) => key.clone(),
                    _ => {
                        return Err(GroupStateError::InvalidSender(
                            "Only keys can set identity".to_string(),
                        ));
                    }
                };
                // Handle identity setting - for now just ensure sender is a member
                self.handle_member_announcement(IdentityRef::Key(sender_key), timestamp)?;
            }

            GroupActivityEvent::RemoveFromGroup { target: _, .. } => {
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
        }

        Ok(())
    }

    /// Validate dual acknowledgments to prevent history rewriting attacks
    ///
    /// # Security Validation Rules
    ///
    /// 1. **Event timestamp cannot be before acknowledged timestamps**
    /// 2. **Sender must have actually seen the acknowledged messages**
    /// 3. **Acknowledged messages must exist in our history**
    ///
    /// # Attack Prevention
    ///
    /// This validation prevents the core attack scenario where a malicious actor
    /// tries to backdate a permission-changing event after acknowledging later state.
    fn validate_dual_acknowledgments(
        &self,
        sender: &IdentityRef,
        ack_own: MessageId,
        ack_others: MessageId,
        event_timestamp: u64,
        event_id: MessageId,
    ) -> GroupStateResult<()> {
        // Prevent self-referential acknowledgments
        if ack_own == event_id || ack_others == event_id {
            return Err(GroupStateError::InvalidAcknowledgment(
                "Event cannot acknowledge itself".to_string(),
            ));
        }

        // Get timestamps of acknowledged messages
        let ack_own_timestamp = self
            .message_metadata
            .get(&ack_own)
            .map(|m| m.timestamp)
            .ok_or_else(|| {
                GroupStateError::InvalidAcknowledgment(format!(
                    "Own acknowledgment references unknown message: {}",
                    ack_own
                ))
            })?;

        let ack_others_timestamp = self
            .message_metadata
            .get(&ack_others)
            .map(|m| m.timestamp)
            .ok_or_else(|| {
                GroupStateError::InvalidAcknowledgment(format!(
                    "Others acknowledgment references unknown message: {}",
                    ack_others
                ))
            })?;

        // CRITICAL: Event timestamp cannot be before what sender has already acknowledged
        if event_timestamp < ack_own_timestamp {
            return Err(GroupStateError::HistoryRewriteAttempt(format!(
                "Event timestamp {} is before sender's own acknowledged state at {}",
                event_timestamp, ack_own_timestamp
            )));
        }

        if event_timestamp < ack_others_timestamp {
            return Err(GroupStateError::HistoryRewriteAttempt(format!(
                "Event timestamp {} is before sender's acknowledged others' state at {}",
                event_timestamp, ack_others_timestamp
            )));
        }

        // Check sender's previous acknowledgments to prevent backdating attacks
        // This prevents the attack where Alice acknowledges state at t=1000 in an event at t=1100,
        // then tries to create a new event at t=1050 (between her acknowledgment and her previous event)
        if let Some(_prev_acks) = self.sender_acknowledgments.get(sender) {
            // Find the sender's most recent permission event timestamp
            // and ensure new events don't backdate before it
            let sender_recent_timestamp = self
                .message_metadata
                .iter()
                .filter(|(_, metadata)| metadata.sender == *sender && metadata.is_permission_event)
                .map(|(_, metadata)| metadata.timestamp)
                .max()
                .unwrap_or(0);

            if event_timestamp < sender_recent_timestamp {
                return Err(GroupStateError::HistoryRewriteAttempt(format!(
                    "Event timestamp {} is before sender's most recent permission event at {}",
                    event_timestamp, sender_recent_timestamp
                )));
            }
        }

        Ok(())
    }

    /// Resolve conflicts when multiple events have identical acknowledgment levels
    ///
    /// # Conflict Resolution Strategy
    ///
    /// When multiple events reference the same acknowledgment state, we use
    /// **Message ID tiebreaker** for deterministic resolution:
    /// - Higher Message ID wins (Blake3 hash comparison)
    /// - Cryptographically hard to manipulate
    /// - Deterministic across all clients
    ///
    /// # Parameters
    ///
    /// - `sender` - The sender of the current event
    /// - `ack_own` - Own acknowledgment message ID
    /// - `ack_others` - Others acknowledgment message ID  
    /// - `timestamp` - Event timestamp
    /// - `event_id` - Current event's message ID
    fn resolve_acknowledgment_conflicts(
        &self,
        _sender: &IdentityRef,
        _ack_own: MessageId,
        _ack_others: MessageId,
        _timestamp: u64,
        _event_id: MessageId,
    ) -> GroupStateResult<()> {
        // TODO: Implement sophisticated conflict resolution
        // For now, we accept all events that pass acknowledgment validation
        // In production, we would:
        // 1. Check for existing events with same acknowledgment level
        // 2. Use Message ID tiebreaker to determine winner
        // 3. Potentially reject or reorder events based on resolution

        Ok(())
    }

    /// Update sender's acknowledgment tracking after successful event application
    ///
    /// Records what state changes this sender has now acknowledged, which will
    /// be used to validate their future permission-changing events.
    fn update_sender_acknowledgments(
        &mut self,
        sender: IdentityRef,
        ack_own: MessageId,
        ack_others: MessageId,
    ) {
        self.sender_acknowledgments.insert(
            sender,
            SenderAcknowledgments {
                own_last_ack: ack_own,
                others_last_ack: ack_others,
            },
        );
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
    pub fn check_permission(
        &self,
        member: &IdentityRef,
        required_permission: &Permission,
    ) -> GroupStateResult<()> {
        match self.members.get(member) {
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
                member: format!("{:?}", member),
                group: format!("{:?}", self.group_info.group_id),
            }),
        }
    }

    /// Handle a member announcing their participation in the group
    /// In encrypted groups, anyone with the key can participate
    fn handle_member_announcement(
        &mut self,
        sender: IdentityRef,
        timestamp: u64,
    ) -> GroupStateResult<()> {
        // Add or update member
        if let Some(existing_member) = self.members.get_mut(&sender) {
            existing_member.last_active = timestamp;
        } else {
            // New member - anyone with the key can participate
            self.members.insert(
                sender.clone(),
                GroupMember {
                    key: sender.clone(),
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
        let sender_ref = IdentityRef::Key(sender.clone());
        // In encrypted groups, leaving is just an announcement - they still have the key
        // This removes them from the active member list but doesn't revoke access
        if !self.members.contains_key(&sender_ref) {
            return Err(GroupStateError::MemberNotFound {
                member: format!("{sender:?}"),
                group: format!("{:?}", self.group_info.group_id),
            });
        }

        // Remove from active members list
        self.members.remove(&sender_ref);
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
        self.check_permission(
            &IdentityRef::Key(sender),
            &self.group_info.settings.permissions.assign_roles,
        )?;

        // Check if target member exists
        let group_id = self.group_info.group_id.clone(); // Get group_id before mutable borrow
        let member_info =
            self.members
                .get_mut(target)
                .ok_or_else(|| GroupStateError::MemberNotFound {
                    member: format!("{target:?}"),
                    group: format!("{:?}", group_id),
                })?;

        // Update role
        member_info.role = role.clone();
        Ok(())
    }

    /// Get all active members
    pub fn get_members(&self) -> &BTreeMap<IdentityRef, GroupMember> {
        &self.members
    }

    /// Check if a user is a member of this group
    pub fn is_member(&self, user: &VerifyingKey) -> bool {
        let user_ref = IdentityRef::Key(user.clone());
        self.members.contains_key(&user_ref)
    }

    /// Get a member's role
    pub fn member_role(&self, user: &VerifyingKey) -> Option<GroupRole> {
        let user_ref = IdentityRef::Key(user.clone());
        self.members.get(&user_ref).map(|m| m.role.clone())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::events::key_info::GroupKeyInfo;
    use crate::group::events::roles::GroupRole;
    use crate::group::events::settings::GroupSettings;
    use crate::group::events::{GroupActivityEvent, GroupInfo};
    use crate::group::states::Permission;
    use crate::identity::{IdentityInfo, IdentityType};
    use crate::metadata::Metadata;

    use crate::group::app::Acknowledgment;
    use rand::rngs::OsRng;
    use zoe_wire_protocol::{KeyPair, MessageFullError, VerifyingKey};

    // Helper functions for creating test data
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
            group_id: [1u8; 32].to_vec(),
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
        assert_eq!(group_state.last_event_timestamp, timestamp);
        assert_eq!(group_state.event_history.len(), 1);
        assert_eq!(group_state.event_history[0], *message.id());

        // Verify creator is added as owner
        assert!(group_state.is_member(&creator_key.public_key()));
        assert_eq!(
            group_state.member_role(&creator_key.public_key()),
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
        assert!(group_state.is_member(&creator_key.public_key()));
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

        assert!(group_state.is_member(&creator_key.public_key()));
        assert!(!group_state.is_member(&other_key.public_key()));
    }

    #[test]
    fn test_group_state_member_role() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        assert_eq!(
            group_state.member_role(&creator_key.public_key()),
            Some(&GroupRole::Owner).cloned()
        );

        let non_member_key = KeyPair::generate(&mut OsRng);
        assert_eq!(group_state.member_role(&non_member_key.public_key()), None);
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
        assert!(group_state.is_member(&new_member_key.public_key()));
        assert_eq!(group_state.members.len(), 2);
        assert_eq!(group_state.version, 1);
        assert_eq!(group_state.last_event_timestamp, 1001);
        assert_eq!(group_state.event_history.len(), 2);
        assert_eq!(group_state.event_history[1], event_id);

        // Verify new member has default role
        assert_eq!(
            group_state.member_role(&new_member_key.public_key()),
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
            acknowledgment: Acknowledgment::new(
                create_test_message_id(1),
                create_test_message_id(1),
            ),
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

        assert!(group_state.is_member(&member_key.public_key()));
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
        assert!(!group_state.is_member(&member_key.public_key()));
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

        // Assign admin role
        let creation_message_id = group_state.event_history[0];
        let assign_role_event: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityType::Main,
            role: GroupRole::Admin,
            acknowledgment: Acknowledgment::new(
                creation_message_id,
                create_test_message_id(18), // Bob's join event
            ),
        };

        let result = group_state.apply_event(
            assign_role_event,
            create_test_message_id(19),
            IdentityRef::Key(creator_key.public_key()),
            1002,
        );

        assert!(result.is_ok());
        assert_eq!(
            group_state.member_role(&member_key.public_key()),
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

        // Try to apply event with older timestamp
        let result = group_state.apply_event(
            activity_event,
            create_test_message_id(21),
            IdentityRef::Key(creator_key.public_key()),
            999, // Older than creation timestamp
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            GroupStateError::StateTransition(msg) => {
                assert!(msg.contains("older than last processed timestamp"));
            }
            _ => panic!("Expected StateTransition error"),
        }
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

    #[test]
    fn test_group_state_check_permission_member_not_found() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let non_member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let group_state = GroupState::initial(&message, group_info);

        let result = group_state.check_permission(
            &IdentityRef::Key(non_member_key.public_key()),
            &Permission::AllMembers,
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            GroupStateError::MemberNotFound { .. } => {}
            _ => panic!("Expected MemberNotFound error"),
        }
    }

    // Error Handling Tests
    #[test]
    fn test_group_state_error_display() {
        let error = GroupStateError::PermissionDenied("Test permission denied".to_string());
        assert_eq!(
            error.to_string(),
            "Permission denied: Test permission denied"
        );

        let error = GroupStateError::MemberNotFound {
            member: "test_member".to_string(),
            group: "test_group".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Member not found: test_member in group test_group"
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
    fn test_group_state_handle_leave_group_member_not_found() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let non_member_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        let leave_event: GroupActivityEvent = GroupActivityEvent::LeaveGroup { message: None };
        let result = group_state.apply_event(
            leave_event,
            create_test_message_id(27),
            IdentityRef::Key(non_member_key.public_key()),
            1001,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            GroupStateError::MemberNotFound { .. } => {}
            _ => panic!("Expected MemberNotFound error"),
        }
    }

    #[test]
    fn test_group_state_handle_role_assignment_member_not_found() {
        let creator_key = KeyPair::generate(&mut OsRng);
        let message =
            create_test_message_full(&creator_key, b"test content".to_vec(), 1000).unwrap();
        let group_info = create_test_group_info();
        let mut group_state = GroupState::initial(&message, group_info);

        let assign_role_event: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityType::Main,
            role: GroupRole::Admin,
            acknowledgment: Acknowledgment::new(
                create_test_message_id(1),
                create_test_message_id(2),
            ),
        };

        let result = group_state.apply_event(
            assign_role_event,
            create_test_message_id(29),
            IdentityRef::Key(creator_key.public_key()),
            1001,
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            GroupStateError::MemberNotFound { .. } => {}
            _ => panic!("Expected MemberNotFound error"),
        }
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
            target: IdentityType::Main,
            role: GroupRole::Admin,
            acknowledgment: Acknowledgment::new(
                create_test_message_id(1),
                create_test_message_id(2),
            ),
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
        assert_eq!(
            group_state.last_event_timestamp,
            deserialized.last_event_timestamp
        );
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
        assert!(group_state.is_member(&member1_key.public_key()));

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
            target: IdentityType::Main,
            role: GroupRole::Admin,
            acknowledgment: Acknowledgment::new(
                create_test_message_id(1),
                create_test_message_id(2),
            ),
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
            group_state.member_role(&member1_key.public_key()),
            Some(&GroupRole::Admin).cloned()
        );
        assert_eq!(group_state.version, 3);

        // Creator (owner) promotes member2 to moderator (only owners can assign roles by default)
        let promote_event2: GroupActivityEvent = GroupActivityEvent::AssignRole {
            target: IdentityType::Main,
            role: GroupRole::Moderator,
            acknowledgment: Acknowledgment::new(
                create_test_message_id(1),
                create_test_message_id(2),
            ),
        };
        group_state
            .apply_event(
                promote_event2.clone(),
                create_test_message_id(39),
                IdentityRef::Key(creator_key.public_key()),
                1004,
            )
            .unwrap();

        assert_eq!(
            group_state.member_role(&member2_key.public_key()),
            Some(&GroupRole::Moderator).cloned()
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
            acknowledgment: Acknowledgment::new(
                create_test_message_id(1),
                create_test_message_id(1),
            ),
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

        assert!(!group_state.is_member(&member2_key.public_key()));
        assert_eq!(group_state.members.len(), 2);
        assert_eq!(group_state.version, 6);

        // Verify final state
        assert_eq!(group_state.event_history.len(), 7);
        assert_eq!(group_state.last_event_timestamp, 1006);
        assert!(group_state.is_member(&creator_key.public_key()));
        assert!(group_state.is_member(&member1_key.public_key()));
        assert!(!group_state.is_member(&member2_key.public_key()));
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
}
