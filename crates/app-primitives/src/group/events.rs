use std::ops::Deref;

use crate::{
    identity::IdentityRef,
    protocol::{AppProtocolVariant, InstalledApp},
};
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::{ChannelId, Hash};

use super::events::{roles::GroupRole, settings::GroupSettings};
use crate::{identity::IdentityInfo, metadata::Metadata};

pub mod join_info;
pub mod key_info;
pub mod permissions;
pub mod roles;
pub mod settings;

use key_info::GroupKeyInfo;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct GroupId(Hash);

impl From<Hash> for GroupId {
    fn from(value: Hash) -> Self {
        Self(value)
    }
}

impl GroupId {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    pub fn from_hex(hex: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex).map_err(|e| format!("Decoding hex failed: {e}"))?;
        let hash = Hash::from_slice(&bytes).map_err(|e| format!("Invalid hash: {e}"))?;
        Ok(Self(hash))
    }
}

impl From<GroupId> for ChannelId {
    fn from(val: GroupId) -> Self {
        ChannelId::from(val.0.as_bytes().to_vec())
    }
}

impl From<&GroupId> for ChannelId {
    fn from(val: &GroupId) -> Self {
        ChannelId::from(val.0.as_bytes().to_vec())
    }
}

impl From<[u8; 32]> for GroupId {
    fn from(value: [u8; 32]) -> Self {
        Self(Hash::from_bytes(value))
    }
}

impl TryFrom<ChannelId> for GroupId {
    type Error = ();

    fn try_from(value: ChannelId) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(());
        }
        let (bytes, _) = value.as_chunks::<32>();
        Ok(Self::from(bytes[0]))
    }
}

impl Deref for GroupId {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialOrd for GroupId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GroupId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

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
        target: IdentityRef,
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
        target: IdentityRef,
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

impl From<GroupInfoUpdateContent> for GroupActivityEvent {
    fn from(updates: GroupInfoUpdateContent) -> Self {
        Self::UpdateGroup { updates }
    }
}
