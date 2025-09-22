use crate::protocol::InstalledApp;
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::group::app::GroupEvent;

use super::events::{roles::GroupRole, settings::GroupSettings};
use crate::{
    identity::{IdentityInfo, IdentityRef},
    metadata::Metadata,
};

pub mod join_info;
pub mod key_info;
pub mod permissions;
pub mod roles;
pub mod settings;

use key_info::GroupKeyInfo;

// Re-export Acknowledgment from the common location
pub use crate::group::app::Acknowledgment;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// Human-readable group name
    pub name: String,
    // initial group settings
    pub settings: GroupSettings,
    /// Key derivation info or key identifier (not the actual key)
    /// Used to help participants derive or identify the correct key
    pub key_info: GroupKeyInfo,
    /// Optional group avatar image
    pub metadata: Vec<Metadata>,
    /// Installed applications in this group with channel-per-app support
    /// Each app gets its own communication channel for isolated messaging
    pub installed_apps: Vec<InstalledApp>,
}

/// Individual group info update operations using the efficient Vec<UpdateEnum> pattern
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupInfoUpdate {
    /// Update the group name
    Name(String),
    /// Update the group settings
    Settings(GroupSettings),
    /// Update the key derivation info
    KeyInfo(GroupKeyInfo),
    /// Replace all metadata with a new list
    SetMetadata(Vec<Metadata>),
    /// Add metadata to the list
    AddMetadata(Metadata),
    /// Clear all metadata
    ClearMetadata,
    /// Add an application to the installed apps list
    /// Each app gets its own communication channel for isolated messaging
    AddApp(InstalledApp),
}

/// Content for updating group info - vector of specific updates
///
/// This follows the same efficient pattern used in DGO events, allowing
/// for compact, targeted updates to specific group properties without
/// requiring the entire group info structure to be passed.
///
/// # Example
/// ```rust
/// let updates = vec![
///     GroupInfoUpdate::Name("New Group Name".to_string()),
///     GroupInfoUpdate::AddApp(InstalledApp::new_simple(
///         "calendar".to_string(),
///         1, 0
///     )),
/// ];
/// ```
#[cfg_attr(feature = "frb-api", frb(non_opaque))]
pub type GroupInfoUpdateContent = Vec<GroupInfoUpdate>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupEventWrapper {
    /// which identity are we sending this event as
    idenitity: IdentityRef,
    /// the event we are sending
    event: Box<GroupActivityEvent>,
}

#[derive(Debug, Clone, PartialEq, ForwardCompatibleEnum)]
pub enum GroupActivityEvent {
    #[discriminant(11)]
    CreateGroup(GroupInfo),

    /// Update group metadata (name, description, settings)
    ///
    /// This event can be either a **permission-changing event** or a regular event,
    /// depending on the updates being made:
    ///
    /// # Permission-Changing Updates (Require Dual Acknowledgments)
    ///
    /// Updates that affect group permissions or security settings:
    /// - [`GroupInfoUpdate::Settings`] - Changes to group permission settings
    /// - Future permission-related updates
    ///
    /// # Regular Updates (No Acknowledgments Required)
    ///
    /// Updates that don't affect permissions:
    /// - [`GroupInfoUpdate::Name`] - Group name changes
    /// - [`GroupInfoUpdate::SetMetadata`] / [`GroupInfoUpdate::AddMetadata`] - Metadata changes
    /// - [`GroupInfoUpdate::AddApp`] - Adding applications
    ///
    /// # Dual-Acknowledgment Security
    ///
    /// When this event contains permission-changing updates, it uses the same
    /// dual-acknowledgment system as [`AssignRole`] and [`RemoveFromGroup`].
    /// The acknowledgment fields are optional and only required when the update
    /// affects group permissions.
    ///
    /// # Example Usage
    ///
    /// ```rust
    /// // Regular update (no acknowledgments needed)
    /// let name_update = GroupActivityEvent::UpdateGroup {
    ///     updates: vec![GroupInfoUpdate::Name("New Name".to_string())],
    ///     acknowledges_own_last_state_change: None,
    ///     acknowledges_others_last_state_change: None,
    /// };
    ///
    /// // Permission update (acknowledgments required)
    /// let permission_update = GroupActivityEvent::UpdateGroup {
    ///     updates: vec![GroupInfoUpdate::Settings(new_settings)],
    ///     acknowledges_own_last_state_change: Some(last_own_msg),
    ///     acknowledges_others_last_state_change: Some(last_others_msg),
    /// };
    /// ```
    #[discriminant(12)]
    UpdateGroup {
        /// The specific updates to apply to the group (with required acknowledgments)
        ///
        /// All group updates now require acknowledgments to maintain consistency
        /// and prevent timestamp manipulation attacks. The acknowledgments can
        /// reference events from either:
        ///
        /// 1. **Group Stream**: Events in the main group event stream (role assignments,
        ///    member additions, other group updates)
        /// 2. **App Stream**: Events in local application streams (DGO events, app-specific
        ///    state changes within the group context)
        ///
        /// This dual-stream acknowledgment system allows apps to maintain their own
        /// event ordering while still participating in the group's security model.
        ///
        /// # Example Acknowledgment Sources
        ///
        /// - Group creation event (always available as fallback)
        /// - Previous role assignments or member changes
        /// - Previous group setting updates
        /// - DGO events (text blocks, calendar events, tasks)
        /// - App-specific events within the group
        ///
        /// The system will validate that acknowledged events exist and have appropriate
        /// timestamps to prevent backdating attacks across both streams.
        /// The specific updates to apply to the group
        updates: GroupInfoUpdateContent,
        /// Required acknowledgments for permission-changing updates
        acknowledgment: Option<Acknowledgment>,
    },

    /// Set identity information for the sending identity
    #[discriminant(20)]
    SetIdentity(IdentityInfo),

    /// Announce departure from group
    #[discriminant(21)]
    LeaveGroup {
        /// Optional goodbye message
        message: Option<String>,
    },

    /// Assign a role to an identity (key or key+alias)
    ///
    /// This is a **permission-changing event** that uses the dual-acknowledgment attestation
    /// system to prevent timestamp manipulation attacks and history rewriting.
    ///
    /// # Dual-Acknowledgment Security System
    ///
    /// Each role assignment must acknowledge both:
    /// 1. **Own Last State Change**: The latest state-changing message from the same sender
    /// 2. **Others' Last State Change**: The latest state-changing message from any other sender
    ///
    /// This creates a "ratchet effect" where each acknowledgment establishes a floor that
    /// prevents backdating attacks. An attacker cannot send a backdated role revocation
    /// if they have already acknowledged seeing later third-party state changes.
    ///
    /// # Attack Prevention Example
    ///
    /// ```text
    /// Timeline:
    /// t=100: Alice creates group
    /// t=200: Alice assigns Bob as Admin { ack_own: msg_1, ack_others: msg_1 }
    /// t=300: Charlie joins group (no ack needed, not permission change)
    /// t=400: Alice updates settings { ack_own: msg_2, ack_others: msg_1 }
    ///        -> Alice acknowledges she's seen Charlie join!
    ///
    /// t=500: Alice tries: RevokeRole(Bob) { ack_own: msg_2, ack_others: msg_1, timestamp: 250 }
    /// System rejects: timestamp=250 is before Charlie's join at t=300,
    /// but Alice already acknowledged seeing Charlie at t=400
    /// This is clearly a history rewrite attempt!
    /// ```
    ///
    /// # Offline Operation Support
    ///
    /// The system maintains offline operation by:
    /// - Using deterministic conflict resolution (Message ID tiebreaker)
    /// - Allowing legitimate multi-device scenarios
    /// - Only requiring acknowledgments for permission-changing events
    ///
    /// # Permissions Required
    ///
    /// Requires appropriate permissions based on group settings (typically Admin or Owner).
    #[discriminant(30)]
    AssignRole {
        /// The identity to assign a role to
        target: IdentityRef,
        /// The new role to assign
        role: GroupRole,
        /// Required acknowledgments for this permission-changing event
        acknowledgment: Acknowledgment,
    },

    /// Remove an identity from the group
    ///
    /// This is a **permission-changing event** that uses the dual-acknowledgment attestation
    /// system to prevent timestamp manipulation attacks and history rewriting.
    ///
    /// # Security Properties
    ///
    /// Same dual-acknowledgment system as [`AssignRole`]. This event cannot be backdated
    /// before acknowledged state changes from the sender or other participants.
    ///
    /// # Use Cases
    ///
    /// - Remove misbehaving members
    /// - Clean up inactive accounts
    /// - Enforce group policies
    ///
    /// # Permissions Required
    ///
    /// Requires appropriate permissions based on group settings (typically Admin or Owner).
    /// Members cannot remove themselves - use [`LeaveGroup`] instead.
    #[discriminant(31)]
    RemoveFromGroup {
        /// The identity to remove from the group
        target: IdentityRef,
        /// Required acknowledgments for this permission-changing event
        acknowledgment: Acknowledgment,
    },

    /// Unknown management event for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

impl GroupActivityEvent {
    /// Determines if this event is a permission-changing event that requires dual acknowledgments
    ///
    /// # Permission-Changing Events
    ///
    /// Events that modify group permissions, roles, or security settings:
    /// - [`AssignRole`] - Always permission-changing
    /// - [`RemoveFromGroup`] - Always permission-changing  
    /// - [`UpdateGroup`] - Only when updates contain [`GroupInfoUpdate::Settings`]
    ///
    /// # Regular Events
    ///
    /// Events that don't affect permissions:
    /// - [`CreateGroup`] - Initial group creation (no prior state to validate)
    /// - [`SetIdentity`] - Identity announcements
    /// - [`LeaveGroup`] - Member departure (self-action)
    /// - [`UpdateGroup`] - When updates only contain name, metadata, or app changes
    ///
    /// # Usage in State Machine
    ///
    /// The state machine uses this method to determine whether to apply
    /// dual-acknowledgment validation or simple timestamp validation.
    ///
    /// ```rust
    /// if event.is_permission_changing() {
    ///     // Apply dual-acknowledgment validation
    ///     self.apply_permission_event_with_dual_acknowledgment(event, ...)?;
    /// } else {
    ///     // Apply simple timestamp validation
    ///     self.apply_regular_event(event, ...)?;
    /// }
    /// ```
    pub fn is_permission_changing(&self) -> bool {
        match self {
            // Always permission-changing
            GroupActivityEvent::AssignRole { .. } => true,
            GroupActivityEvent::RemoveFromGroup { .. } => true,

            // Conditional based on update content
            GroupActivityEvent::UpdateGroup { updates, .. } => {
                updates.iter().any(|update| match update {
                    GroupInfoUpdate::Settings(_) => true,
                    // Future permission-related updates would go here
                    _ => false,
                })
            }

            // Never permission-changing
            GroupActivityEvent::CreateGroup(_) => false,
            GroupActivityEvent::SetIdentity(_) => false,
            GroupActivityEvent::LeaveGroup { .. } => false,
            GroupActivityEvent::Unknown { .. } => false,
        }
    }

    /// Extracts dual acknowledgments from permission-changing events
    ///
    /// # Returns
    ///
    /// - `Ok((own_ack, others_ack))` - The acknowledgment message IDs
    /// - `Err(String)` - If the event is not permission-changing or has invalid acknowledgments
    ///
    /// # Usage
    ///
    /// ```rust
    /// if event.is_permission_changing() {
    ///     let (own_ack, others_ack) = event.extract_acknowledgments()?;
    ///     // Validate acknowledgments...
    /// }
    /// ```
    ///
    /// # Validation Rules
    ///
    /// - [`AssignRole`] and [`RemoveFromGroup`] must have acknowledgments
    /// - [`UpdateGroup`] must have acknowledgments only if it contains permission changes
    /// - Regular events should not call this method
    pub fn extract_acknowledgments(&self) -> Result<(MessageId, MessageId), String> {
        match self {
            GroupActivityEvent::AssignRole { acknowledgment, .. } => Ok((
                acknowledgment.acknowledges_own_last_state_change,
                acknowledgment.acknowledges_others_last_state_change,
            )),

            GroupActivityEvent::RemoveFromGroup { acknowledgment, .. } => Ok((
                acknowledgment.acknowledges_own_last_state_change,
                acknowledgment.acknowledges_others_last_state_change,
            )),

            GroupActivityEvent::UpdateGroup {
                acknowledgment: Some(ack),
                ..
            } => Ok((
                ack.acknowledges_own_last_state_change,
                ack.acknowledges_others_last_state_change,
            )),

            GroupActivityEvent::UpdateGroup {
                acknowledgment: None,
                ..
            } => Err(
                "UpdateGroup event has no acknowledgments (not a permission-changing update)"
                    .to_string(),
            ),

            _ => Err(format!(
                "Event {self:?} is not permission-changing and has no acknowledgments"
            )),
        }
    }

    /// Creates a new AssignRole event with dual acknowledgments
    ///
    /// # Parameters
    ///
    /// - `target` - The identity to assign a role to
    /// - `role` - The new role to assign
    /// - `own_ack` - Last state-changing message from the sender (group or app stream)
    /// - `others_ack` - Last state-changing message from other participants (group or app stream)
    ///
    /// # Example
    ///
    /// ```rust
    /// let event = GroupActivityEvent::new_assign_role(
    ///     target_identity,
    ///     GroupRole::Admin,
    ///     last_own_message_id,
    ///     last_others_message_id,
    /// );
    /// ```
    pub fn new_assign_role(
        target: IdentityRef,
        role: GroupRole,
        own_ack: MessageId,
        others_ack: MessageId,
    ) -> Self {
        GroupActivityEvent::AssignRole {
            target,
            role,
            acknowledgment: Acknowledgment::new(own_ack, others_ack),
        }
    }

    /// Creates a new RemoveFromGroup event with dual acknowledgments
    ///
    /// # Parameters
    ///
    /// - `target` - The identity to remove from the group
    /// - `own_ack` - Last state-changing message from the sender (group or app stream)
    /// - `others_ack` - Last state-changing message from other participants (group or app stream)
    ///
    /// # Example
    ///
    /// ```rust
    /// let event = GroupActivityEvent::new_remove_from_group(
    ///     target_identity,
    ///     last_own_message_id,
    ///     last_others_message_id,
    /// );
    /// ```
    pub fn new_remove_from_group(
        target: IdentityRef,
        own_ack: MessageId,
        others_ack: MessageId,
    ) -> Self {
        GroupActivityEvent::RemoveFromGroup {
            target,
            acknowledgment: Acknowledgment::new(own_ack, others_ack),
        }
    }

    /// Creates a new UpdateGroup event with dual acknowledgments
    ///
    /// # Parameters
    ///
    /// - `updates` - The group updates to apply
    /// - `own_ack` - Last state-changing message from this sender (group or app stream)
    /// - `others_ack` - Last state-changing message from other senders (group or app stream)
    ///
    /// # Cross-Stream Acknowledgments
    ///
    /// The acknowledgments can reference events from either:
    /// - **Group Stream**: Role assignments, member changes, group updates
    /// - **App Stream**: DGO events, application-specific events within the group
    ///
    /// This allows applications to maintain their own event ordering while
    /// participating in the group's security model.
    ///
    /// # Example
    ///
    /// ```rust
    /// // Update acknowledging group creation (fallback)
    /// let event = GroupActivityEvent::new_update_group(
    ///     vec![GroupInfoUpdate::Name("New Name".to_string())],
    ///     group_creation_id,
    ///     group_creation_id,
    /// );
    ///
    /// // Update acknowledging mixed streams
    /// let event = GroupActivityEvent::new_update_group(
    ///     vec![GroupInfoUpdate::Settings(new_settings)],
    ///     last_own_group_event_id,    // From group stream
    ///     last_dgo_event_id,          // From app stream
    /// );
    /// ```
    pub fn new_update_group(
        updates: GroupInfoUpdateContent,
        own_ack: MessageId,
        others_ack: MessageId,
    ) -> Self {
        GroupActivityEvent::UpdateGroup {
            updates,
            acknowledgment: Some(Acknowledgment::new(own_ack, others_ack)),
        }
    }
}

impl GroupEvent for GroupActivityEvent {
    fn applies_to(&self) -> Option<Vec<MessageId>> {
        match self {
            // Create events don't affect existing models
            GroupActivityEvent::CreateGroup(_) => None,

            // All other events affect the group state
            GroupActivityEvent::UpdateGroup { .. }
            | GroupActivityEvent::SetIdentity(_)
            | GroupActivityEvent::LeaveGroup { .. }
            | GroupActivityEvent::AssignRole { .. }
            | GroupActivityEvent::RemoveFromGroup { .. } => {
                // For group events, we need the group ID to be passed from the executor
                // Since the group ID is derived from the CreateGroup message hash,
                // we'll return None here and let the executor handle group identification
                None
            }

            GroupActivityEvent::Unknown { .. } => None,
        }
    }

    fn acknowledgment(&self) -> Option<Acknowledgment> {
        match self {
            GroupActivityEvent::AssignRole { acknowledgment, .. } => Some(acknowledgment.clone()),
            GroupActivityEvent::RemoveFromGroup { acknowledgment, .. } => {
                Some(acknowledgment.clone())
            }
            GroupActivityEvent::UpdateGroup { acknowledgment, .. } => acknowledgment.clone(),
            _ => None,
        }
    }
}
