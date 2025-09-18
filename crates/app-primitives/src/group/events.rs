use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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
}

#[cfg_attr(feature = "frb-api", frb(non_opaque))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfoUpdate {
    /// Human-readable group name
    pub name: Option<String>,
    // initial group settings
    pub settings: Option<GroupSettings>,
    /// Key derivation info or key identifier (not the actual key)
    /// Used to help participants derive or identify the correct AES key
    pub key_info: Option<GroupKeyInfo>,
    /// Optional group avatar image
    pub metadata: Option<Vec<Metadata>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(bound(deserialize = "T: DeserializeOwned", serialize = "T : Serialize"))]
pub struct GroupEvent<T> {
    /// which identity are we sending this event as
    idenitity: IdentityRef,
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

    #[discriminant(11)]
    CreateGroup(GroupInfo),

    /// Update group metadata (name, description, settings)
    #[discriminant(12)]
    UpdateGroup(GroupInfoUpdate),

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
    /// Requires appropriate permissions based on group settings.
    #[discriminant(30)]
    AssignRole {
        /// The identity to assign a role to
        target: IdentityRef,
        /// The new role
        role: GroupRole,
    },

    #[discriminant(31)]
    RemoveFromGroup {
        /// The identity to remove
        target: IdentityRef,
    },

    /// Unknown management event for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}
