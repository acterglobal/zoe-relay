//! App-specific update events that can be emitted from group state changes
//!
//! This module defines the types for app-related updates that can be emitted
//! when group events are processed. These updates are only emitted when the
//! user has proper permissions to make the changes.

use serde::{Deserialize, Serialize};

use crate::{
    digital_groups_organizer::models::core::ActivityMeta,
    group::events::GroupId,
    protocol::{AppProtocolVariant, InstalledApp},
};

/// App-specific updates that can be emitted from group state changes
///
/// These updates are only emitted when the user has proper permissions
/// to make the changes. The group state validates permissions before
/// emitting these updates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupAppUpdate {
    /// New apps have been installed in the group
    InstalledApsUpdate {
        group_id: GroupId,
        installed_apps: Vec<InstalledApp>,
    },
    /// App settings have been updated
    AppSettingsUpdate {
        meta: ActivityMeta,
        group_id: GroupId,
        app_id: AppProtocolVariant,
        settings: Vec<u8>,
    },
}

impl GroupAppUpdate {
    /// Get the group ID for this update
    pub fn group_id(&self) -> &GroupId {
        match self {
            GroupAppUpdate::InstalledApsUpdate { group_id, .. } => group_id,
            GroupAppUpdate::AppSettingsUpdate { group_id, .. } => group_id,
        }
    }

    /// Get the app ID for this update (if applicable)
    pub fn app_id(&self) -> Option<&AppProtocolVariant> {
        match self {
            GroupAppUpdate::InstalledApsUpdate { .. } => None,
            GroupAppUpdate::AppSettingsUpdate { app_id, .. } => Some(app_id),
        }
    }
}
