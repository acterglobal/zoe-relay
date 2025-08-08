use serde::{Deserialize, Serialize};

use super::roles::GroupRole;
use crate::{IdentityInfo, IdentityRef, IdentityType, Metadata};

pub mod join_info;
pub mod key_info;
pub mod permissions;
pub mod roles;
pub mod settings;

pub use join_info::*;
pub use key_info::*;
pub use permissions::*;
pub use settings::*;

/// Activity events for encrypted group management in the DGA protocol
///
/// All events are encrypted with AES-GCM using the group's shared key.
/// These events form the core primitives for managing distributed encrypted groups.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateGroup(GroupInfo);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// Human-readable group name
    pub name: String,
    // initial group settings
    pub settings: GroupSettings,
    /// Key derivation info or key identifier (not the actual key)
    /// Used to help participants derive or identify the correct AES key
    pub key_info: GroupKeyInfo,
    /// Optional group avatar image
    pub metadata: Vec<Metadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupEvent<T> {
    /// which identity are we sending this event as
    idenitity: IdentityType,
    /// the event we are sending
    event: GroupActivityEvent<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupActivityEvent<T> {
    Management(Box<GroupManagementEvent>),
    Activity(T),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupManagementEvent {
    /// Update group metadata (name, description, settings)
    UpdateGroup(GroupInfo),

    /// Set identity information for the sending identity
    SetIdentity(IdentityInfo),

    /// Announce departure from group
    LeaveGroup {
        /// Optional goodbye message
        message: Option<String>,
    },

    /// Assign a role to an identity (key or key+alias)
    ///
    /// Requires appropriate permissions based on group settings.
    AssignRole {
        /// The identity to assign a role to
        target: IdentityRef,
        /// The new role
        role: GroupRole,
    },

    RemoveFromGroup {
        /// The identity to remove
        target: IdentityRef,
    },
}
