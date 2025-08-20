use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound(deserialize = "T: DeserializeOwned", serialize = "T : Serialize"))]
pub struct GroupEvent<T> {
    /// which identity are we sending this event as
    idenitity: IdentityType,
    /// the event we are sending
    event: Box<GroupActivityEvent<T>>,
}

#[derive(Debug, Clone, PartialEq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize",
    serde_deserialize = "T: DeserializeOwned"
)]
pub enum GroupActivityEvent<T> {
    #[discriminant(0)]
    Activity(T),

    /// Update group metadata (name, description, settings)
    #[discriminant(1)]
    UpdateGroup(GroupInfo),

    /// Set identity information for the sending identity
    #[discriminant(2)]
    SetIdentity(IdentityInfo),

    /// Announce departure from group
    #[discriminant(3)]
    LeaveGroup {
        /// Optional goodbye message
        message: Option<String>,
    },

    /// Assign a role to an identity (key or key+alias)
    ///
    /// Requires appropriate permissions based on group settings.
    #[discriminant(4)]
    AssignRole {
        /// The identity to assign a role to
        target: IdentityRef,
        /// The new role
        role: GroupRole,
    },

    #[discriminant(5)]
    RemoveFromGroup {
        /// The identity to remove
        target: IdentityRef,
    },

    /// Unknown management event for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

impl CreateGroup {
    /// Create a new CreateGroup event
    pub fn new(group_info: GroupInfo) -> Self {
        Self(group_info)
    }

    /// Get a reference to the inner GroupInfo
    pub fn group_info(&self) -> &GroupInfo {
        &self.0
    }

    /// Consume the CreateGroup and return the inner GroupInfo
    pub fn into_group_info(self) -> GroupInfo {
        self.0
    }
}
