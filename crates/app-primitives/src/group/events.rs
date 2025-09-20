use crate::protocol::InstalledApp;
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize};

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
pub struct GroupEvent {
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
    #[discriminant(12)]
    UpdateGroup(GroupInfoUpdateContent),

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
