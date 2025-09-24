use crate::protocol::{AppProtocolVariant, InstalledApp};
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::ChannelId;

// GroupActivityEvent no longer implements any executor traits

use super::events::{roles::GroupRole, settings::GroupSettings};
use crate::{
    identity::{IdentityInfo, IdentityType},
    metadata::Metadata,
};

pub mod join_info;
pub mod key_info;
pub mod permissions;
pub mod roles;
pub mod settings;

use key_info::GroupKeyInfo;

pub type GroupId = ChannelId;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// Human-readable group name
    pub name: String,
    /// The  id we use to identify the group, also the channel tag
    pub group_id: GroupId,
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

/// Special initialization event for creating a new group
///
/// This is separate from GroupActivityEvent because it requires special handling
/// with the initial message and decryption keys. It's not part of the regular
/// event processing pipeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupInitialization {
    /// The group information for the new group
    pub group_info: GroupInfo,
}

#[derive(Debug, Clone, PartialEq, ForwardCompatibleEnum)]
pub enum GroupActivityEvent {
    /// Update group metadata (name, description, settings)
    ///
    /// This event updates group information including name, description, settings,
    /// metadata, and installed applications.
    ///
    /// # Example Usage
    ///
    /// ```rust
    /// let name_update = GroupActivityEvent::UpdateGroup {
    ///     updates: vec![GroupInfoUpdate::Name("New Name".to_string())],
    /// };
    ///
    /// let settings_update = GroupActivityEvent::UpdateGroup {
    ///     updates: vec![GroupInfoUpdate::Settings(new_settings)],
    /// };
    /// ```
    #[discriminant(11)]
    UpdateGroup {
        /// The specific updates to apply to the group
        updates: GroupInfoUpdateContent,
    },

    /// Set identity information for the sending identity
    #[discriminant(12)]
    SetIdentity(IdentityInfo),

    /// Announce departure from group
    #[discriminant(13)]
    LeaveGroup {
        /// Optional goodbye message
        message: Option<String>,
    },

    /// Assign a role to an identity (key or key+alias)
    ///
    /// This event assigns a specific role to a group member, affecting their
    /// permissions within the group.
    ///
    /// # Permissions Required
    ///
    /// Requires appropriate permissions based on group settings (typically Admin or Owner).
    #[discriminant(14)]
    AssignRole {
        /// The identity to assign a role to
        target: IdentityType,
        /// The new role to assign
        role: GroupRole,
    },

    /// Remove an identity from the group
    ///
    /// This event removes a member from the group, revoking their access
    /// and permissions.
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
    #[discriminant(15)]
    RemoveFromGroup {
        /// The identity to remove from the group
        target: IdentityType,
    },

    /// Update app-specific settings for an installed application
    ///
    /// This event allows updating settings for a specific app installed in the group.
    /// The update data is app-specific and will be handled by the app's model factory.
    ///
    /// # Use Cases
    ///
    /// - Update app permissions
    /// - Change app configuration
    /// - Modify app-specific group settings
    ///
    /// # Permissions Required
    ///
    /// Requires appropriate permissions based on group settings and app-specific rules.
    #[discriminant(16)]
    UpdateAppSettings {
        /// The app protocol variant identifying which app to update
        app_id: AppProtocolVariant,
        /// App-specific update data to be handled by the model factory
        update: Vec<u8>,
    },

    /// Unknown management event for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}
