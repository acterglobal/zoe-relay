//! DGO Permission Settings model implementation
//!
//! This module provides the DgoPermissionSettings model - an event-sourced
//! model that manages granular permissions for DGO features within encrypted groups.

use crate::identity::IdentityRef;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::digital_groups_organizer::models::core::{
    ActivityMeta, DgoAppModel, DgoModelError, DgoOperation, DgoPermissionContext, DgoResult,
};

use crate::digital_groups_organizer::{
    capabilities::{CapabilitySet, DgoCapability},
    events::{
        admin::{
            DgoFeatureSettings, DgoFeatureType, DgoOperationType, FeaturePermission,
            PermissionUpdate,
        },
        core::{DgoActivityEvent, DgoActivityEventContent},
    },
    indexing::keys::IndexKey,
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
    pub fn group_id(&self) -> MessageId {
        self.meta.group_id
    }

    /// Get the actor who created this model
    pub fn creator(&self) -> &IdentityRef {
        &self.meta.actor
    }
}

// Note: DgoPermissionSettings doesn't implement GroupStateModel directly.
// Only AnyDgoModel implements GroupStateModel to work with the unified executor.

impl DgoAppModel for DgoPermissionSettings {
    fn activity_meta(&self) -> &ActivityMeta {
        &self.meta
    }

    fn indexes(&self, _user_id: &IdentityRef) -> Vec<IndexKey> {
        vec![]
    }

    fn capabilities(&self) -> CapabilitySet {
        // Permission settings support comments and reactions for discussion
        CapabilitySet::from(vec![DgoCapability::Commentable, DgoCapability::Reactable])
    }

    fn get_feature_type(&self) -> crate::digital_groups_organizer::events::admin::DgoFeatureType {
        // Permission settings are a special administrative feature
        // We'll treat them as a special case that requires admin permissions
        DgoFeatureType::TextBlock // Placeholder - this will be handled specially
    }

    fn check_permission(
        &self,
        context: &DgoPermissionContext,
        operation: DgoOperation,
    ) -> DgoResult<()> {
        // Permission settings require special handling
        match operation {
            DgoOperation::Create => {
                // Only admins or above can create permission settings
                if context.is_admin_or_above() {
                    Ok(())
                } else {
                    Err(DgoModelError::PermissionDenied {
                        message: "Only admins can create permission settings".to_string(),
                    })
                }
            }
            DgoOperation::Update => {
                // Only the creator or admins can update permission settings
                let is_creator = context.actor == self.meta.actor;
                if is_creator || context.is_admin_or_above() {
                    Ok(())
                } else {
                    Err(DgoModelError::PermissionDenied {
                        message: "Only the creator or admins can update permission settings"
                            .to_string(),
                    })
                }
            }
            DgoOperation::Delete => {
                // Only owners can delete permission settings (very restrictive)
                if context.is_owner() {
                    Ok(())
                } else {
                    Err(DgoModelError::PermissionDenied {
                        message: "Only group owners can delete permission settings".to_string(),
                    })
                }
            }
            DgoOperation::Comment | DgoOperation::React => {
                // All members can comment/react on permission settings for discussion
                if context.is_group_member {
                    Ok(())
                } else {
                    Err(DgoModelError::PermissionDenied {
                        message: "Group membership required to comment on permission settings"
                            .to_string(),
                    })
                }
            }
            _ => {
                // Other operations not supported
                Err(DgoModelError::PermissionDenied {
                    message: format!(
                        "{operation:?} operation is not supported for permission settings"
                    ),
                })
            }
        }
    }

    fn apply_dgo_transition(
        &mut self,
        event: &DgoActivityEvent,
        context: &DgoPermissionContext,
    ) -> DgoResult<bool> {
        match event.content() {
            DgoActivityEventContent::UpdateDgoSettings { target_id, content } => {
                if *target_id == self.model_id() {
                    // Check permissions
                    self.check_permission(context, DgoOperation::Update)?;

                    // Apply the updates
                    self.apply_updates(content.clone());
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false), // This event doesn't affect permission settings
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::events::roles::GroupRole;
    use rand::rngs::OsRng;
    use zoe_wire_protocol::{KeyPair, MessageId};

    fn create_test_permission_settings() -> DgoPermissionSettings {
        let mut rng = OsRng;
        let keypair = KeyPair::generate(&mut rng);
        let actor = keypair.public_key();
        let group_id = MessageId::from_bytes([1; 32]);

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

    #[test]
    fn test_permission_settings_capabilities() {
        let settings = create_test_permission_settings();
        let capabilities = settings.capabilities();

        assert!(capabilities.contains(&DgoCapability::Commentable));
        assert!(capabilities.contains(&DgoCapability::Reactable));
        assert!(!capabilities.contains(&DgoCapability::Attachmentable));
    }

    #[test]
    fn test_permission_settings_admin_only_create() {
        let settings = create_test_permission_settings();
        let mut rng = OsRng;
        let member_keypair = KeyPair::generate(&mut rng);
        let admin_keypair = KeyPair::generate(&mut rng);

        let member_context = DgoPermissionContext::new(
            IdentityRef::Key(member_keypair.public_key()),
            settings.group_id(),
            GroupRole::Member,
            true,
            DgoFeatureSettings::default(),
        );

        let admin_context = DgoPermissionContext::new(
            IdentityRef::Key(admin_keypair.public_key()),
            settings.group_id(),
            GroupRole::Admin,
            true,
            DgoFeatureSettings::default(),
        );

        // Members cannot create permission settings
        assert!(
            settings
                .check_permission(&member_context, DgoOperation::Create)
                .is_err()
        );

        // Admins can create permission settings
        assert!(
            settings
                .check_permission(&admin_context, DgoOperation::Create)
                .is_ok()
        );
    }

    #[test]
    fn test_permission_settings_update_permissions() {
        let settings = create_test_permission_settings();
        let mut rng = OsRng;
        let creator_key = settings.creator().clone();
        let other_keypair = KeyPair::generate(&mut rng);
        let admin_keypair = KeyPair::generate(&mut rng);

        let creator_context = DgoPermissionContext::new(
            creator_key,
            settings.group_id(),
            GroupRole::Member, // Creator is just a member
            true,
            DgoFeatureSettings::default(),
        );

        let other_context = DgoPermissionContext::new(
            IdentityRef::Key(other_keypair.public_key()),
            settings.group_id(),
            GroupRole::Member,
            true,
            DgoFeatureSettings::default(),
        );

        let admin_context = DgoPermissionContext::new(
            IdentityRef::Key(admin_keypair.public_key()),
            settings.group_id(),
            GroupRole::Admin,
            true,
            DgoFeatureSettings::default(),
        );

        // Creator can update their own permission settings
        assert!(
            settings
                .check_permission(&creator_context, DgoOperation::Update)
                .is_ok()
        );

        // Other members cannot update permission settings
        assert!(
            settings
                .check_permission(&other_context, DgoOperation::Update)
                .is_err()
        );

        // Admins can update permission settings
        assert!(
            settings
                .check_permission(&admin_context, DgoOperation::Update)
                .is_ok()
        );
    }
}
