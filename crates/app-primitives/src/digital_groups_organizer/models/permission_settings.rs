//! DGO Permission Settings model implementation
//!
//! This module provides the DgoPermissionSettings model - an event-sourced
//! model that manages granular permissions for DGO features within encrypted groups.

use crate::digital_groups_organizer::events::core::DgoSettingsEvent;
use crate::digital_groups_organizer::indexing::core::GroupParam;
use crate::digital_groups_organizer::indexing::keys::{ExecuteReference, IndexKey};
use crate::group::app::{ExecuteError, ExecutionUpdateInfo, GroupStateModel};
use crate::group::events::GroupId;
use crate::identity::IdentityRef;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::digital_groups_organizer::models::core::{ActivityMeta, DgoPermissionContext};

use crate::digital_groups_organizer::events::admin::{
    DgoFeatureSettings, DgoFeatureType, DgoOperationType, FeaturePermission, PermissionUpdate,
};

/// A DGO permission settings model - manages granular permissions for all DGO features
///
/// This model follows the event-sourced pattern and is updated through
/// CreateDgoSettings and UpdateDgoSettings events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DgoPermissionSettings {
    /// Metadata for this permission settings creation activity
    pub meta: ActivityMeta,
    /// Current version number (incremented on updates)
    pub version: u32,
    /// The actual permission settings
    pub settings: DgoFeatureSettings,
}

impl DgoPermissionSettings {
    /// Create new permission settings
    pub fn new(meta: ActivityMeta, settings: DgoFeatureSettings) -> Self {
        Self {
            meta,
            version: 1,
            settings,
        }
    }

    /// Get the current version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Get the permission settings
    pub fn settings(&self) -> &DgoFeatureSettings {
        &self.settings
    }

    /// Check if a user can perform a specific operation on a specific feature type
    pub fn can_perform_operation(
        &self,
        feature_type: DgoFeatureType,
        operation: DgoOperationType,
        user_role: &crate::group::events::roles::GroupRole,
    ) -> bool {
        self.settings
            .can_perform_operation(feature_type, operation, user_role)
    }

    /// Get the permission requirement for a specific operation on a feature type
    pub fn get_permission_for_operation(
        &self,
        feature_type: DgoFeatureType,
        operation: DgoOperationType,
    ) -> &FeaturePermission {
        self.settings
            .get_permission_for_operation(feature_type, operation)
    }

    /// Apply permission updates to create a new version
    pub fn apply_updates(&mut self, updates: Vec<PermissionUpdate>) {
        self.settings.apply_updates(updates);
        self.version += 1;
    }

    /// Get the unique identifier for this model
    pub fn model_id(&self) -> MessageId {
        self.meta.activity_id
    }

    /// Get the group this model belongs to
    pub fn group_id(&self) -> &GroupId {
        &self.meta.group_id
    }

    /// Get the actor who created this model
    pub fn creator(&self) -> &IdentityRef {
        &self.meta.actor
    }
}

impl GroupStateModel for DgoPermissionSettings {
    type Event = DgoSettingsEvent;
    type PermissionState = DgoPermissionContext;
    type Error = ExecuteError;
    type ExecutiveKey = ExecuteReference;
    type IndexKey = IndexKey;

    fn default_model(group_meta: ActivityMeta) -> Self {
        Self::new(group_meta, DgoFeatureSettings::default())
    }

    fn activity_meta(&self) -> &ActivityMeta {
        &self.meta
    }

    fn execute(
        &mut self,
        event: &Self::Event,
        context: &Self::PermissionState,
    ) -> Result<
        Vec<crate::group::app::ExecutionUpdateInfo<Self, Self::ExecutiveKey, Self::IndexKey>>,
        Self::Error,
    > {
        if !context.is_admin_or_above() {
            return Err(ExecuteError::PermissionDenied(
                "Only admins can change app settings".to_string(),
            ));
        }

        let mut current_permissions = context.dgo_settings.clone();
        current_permissions.apply_updates(event.content().clone());
        self.settings = current_permissions; // we just overwrite the settings, it's easiest
        Ok(vec![
            ExecutionUpdateInfo::new()
                .add_model(self.clone())
                .add_reference(ExecuteReference::GroupParam(
                    self.group_id().clone(),
                    GroupParam::GroupSettings,
                )), // alert the outer world about a settings update
        ])
    }

    fn redact(&self, _context: &Self::PermissionState) -> Result<Vec<Self>, Self::Error> {
        Ok(vec![]) // we never do anything
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use zoe_wire_protocol::{KeyPair, MessageId};

    fn create_test_permission_settings() -> DgoPermissionSettings {
        let mut rng = OsRng;
        let keypair = KeyPair::generate(&mut rng);
        let actor = keypair.public_key();
        let group_id = [1u8; 32].into();

        let meta = ActivityMeta {
            activity_id: MessageId::from_bytes([2; 32]),
            group_id,
            actor: IdentityRef::Key(actor),
            timestamp: 1703001600,
        };

        let settings = DgoFeatureSettings::default();

        DgoPermissionSettings::new(meta, settings)
    }

    #[test]
    fn test_permission_settings_creation() {
        let settings = create_test_permission_settings();

        assert_eq!(settings.version(), 1);
        assert!(settings.settings().text_blocks.create == FeaturePermission::AllMembers);
        assert!(settings.settings().calendar.create == FeaturePermission::AllMembers);
        assert!(settings.settings().tasks.create_task_list == FeaturePermission::AllMembers);
    }
}
