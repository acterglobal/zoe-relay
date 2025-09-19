//! Core model trait and types for Digital Groups Organizer
//!
//! This module defines the core trait that all DGO models must implement,
//! along with error handling and permission types.

use crate::identity::IdentityRef;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zoe_wire_protocol::MessageId;

use crate::group::events::{permissions::Permission, roles::GroupRole};

/// Operations that can be performed on DGO models
///
/// This enum maps directly to the granular permission system in admin.rs
/// for consistent permission checking across the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DgoOperation {
    /// Create a new model instance
    Create,
    /// Update/modify the model
    Update,
    /// Delete/redact the model
    Delete,
    /// Add comments to the model
    Comment,
    /// Add reactions to the model
    React,
    /// Attach files to the model
    Attach,
    /// Manage RSVP responses (for events)
    Rsvp,
    /// Assign tasks (for task models)
    Assign,
    /// Mark as read (for read tracking)
    MarkRead,
}

impl DgoOperation {
    /// Convert to the granular permission system operation type
    pub fn to_operation_type(
        &self,
    ) -> crate::digital_groups_organizer::events::admin::DgoOperationType {
        use crate::digital_groups_organizer::events::admin::DgoOperationType;
        match self {
            DgoOperation::Create => DgoOperationType::Create,
            DgoOperation::Update => DgoOperationType::Update,
            DgoOperation::Delete => DgoOperationType::Delete,
            DgoOperation::Comment => DgoOperationType::Comment,
            DgoOperation::React => DgoOperationType::React,
            DgoOperation::Attach => DgoOperationType::Attach,
            DgoOperation::Rsvp => DgoOperationType::Rsvp,
            DgoOperation::Assign => DgoOperationType::Assign,
            DgoOperation::MarkRead => DgoOperationType::MarkRead,
        }
    }
}

use crate::digital_groups_organizer::{
    capabilities::CapabilitySet,
    events::core::DgoActivityEvent,
    indexing::{keys::ExecuteReference, keys::IndexKey},
};

/// Activity metadata extracted from the wire-protocol Message envelope
///
/// This metadata is derived from the encrypted message and is not part of the
/// event content itself. It's provided by the state machine when processing events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActivityMeta {
    /// Unique identifier for this activity (Blake3 hash of encrypted message)
    pub activity_id: MessageId,
    /// The encrypted group this activity belongs to (from Channel tag)
    pub group_id: MessageId,
    /// The cryptographic identity that created this activity (from message.sender)
    pub actor: IdentityRef,
    /// Unix timestamp when this activity was created (from message.when)
    pub timestamp: u64,
}

/// Errors that can occur during DGO model operations
#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum DgoModelError {
    /// Permission denied for the requested operation
    #[error("Permission denied: {message}")]
    PermissionDenied { message: String },

    /// Referenced object not found
    #[error("Object not found: {object_id}")]
    ObjectNotFound { object_id: MessageId },

    /// Invalid state transition
    #[error("Invalid state transition: {message}")]
    InvalidTransition { message: String },

    /// Validation error
    #[error("Validation error: {message}")]
    ValidationError { message: String },

    /// Serialization/deserialization error
    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    /// Custom error for application-specific cases
    #[error("Custom error: {message}")]
    Custom { message: String },
}

/// Result type for DGO model operations
pub type DgoResult<T> = Result<T, DgoModelError>;

/// Permission context for evaluating whether an operation is allowed
///
/// This context contains the information needed to make permission decisions
/// using the existing group role system and the current DGO permission settings model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionContext {
    /// The actor attempting the operation
    pub actor: IdentityRef,
    /// The group context
    pub group_id: MessageId,
    /// The actor's role in this group
    pub actor_role: GroupRole,
    /// Whether the actor is confirmed as a group member
    pub is_group_member: bool,
    /// The group's current DGO permission settings (event-sourced model)
    pub dgo_settings: crate::digital_groups_organizer::events::admin::DgoFeatureSettings,
}

impl PermissionContext {
    /// Create a new permission context
    pub fn new(
        actor: IdentityRef,
        group_id: MessageId,
        actor_role: GroupRole,
        is_group_member: bool,
        dgo_settings: crate::digital_groups_organizer::events::admin::DgoFeatureSettings,
    ) -> Self {
        Self {
            actor,
            group_id,
            actor_role,
            is_group_member,
            dgo_settings,
        }
    }

    /// Check if the actor has the required permission level
    pub fn has_permission(&self, required: Permission) -> bool {
        self.is_group_member && self.actor_role.has_permission(&required)
    }

    /// Check if the actor can perform admin-level operations
    pub fn is_admin_or_above(&self) -> bool {
        self.has_permission(Permission::AdminOrAbove)
    }

    /// Check if the actor is the group owner
    pub fn is_owner(&self) -> bool {
        self.has_permission(Permission::OwnerOnly)
    }

    /// Check if the actor can perform a specific operation on a specific feature type
    /// using the granular permission system
    pub fn can_perform_dgo_operation(
        &self,
        feature_type: crate::digital_groups_organizer::events::admin::DgoFeatureType,
        operation: &DgoOperation,
    ) -> bool {
        if !self.is_group_member {
            return false;
        }

        self.dgo_settings.can_perform_operation(
            feature_type,
            operation.to_operation_type(),
            &self.actor_role,
        )
    }

    /// Check if the actor can perform a DGO operation, with creator override
    ///
    /// This method implements the common pattern where:
    /// 1. The creator of an object can always perform certain operations on it
    /// 2. Other users must meet the group's permission requirements
    pub fn can_perform_dgo_operation_with_creator_override(
        &self,
        feature_type: crate::digital_groups_organizer::events::admin::DgoFeatureType,
        operation: &DgoOperation,
        creator: &IdentityRef,
    ) -> bool {
        if !self.is_group_member {
            return false;
        }

        // Creator can always update/delete their own content
        if matches!(operation, DgoOperation::Update | DgoOperation::Delete)
            && self.actor == *creator
        {
            return true;
        }

        // Otherwise, check the group's permission settings
        self.can_perform_dgo_operation(feature_type, operation)
    }
}

/// Core trait that all DGO models must implement
///
/// This trait defines the interface for event-sourced models in the
/// Digital Groups Organizer system. It's inspired by Acter's ActerModel
/// but enhanced with permission checking and activity tracking.
pub trait DgoModel: Clone + Send + Sync + std::fmt::Debug {
    /// Get the metadata for this model's creation activity
    fn activity_meta(&self) -> &ActivityMeta;

    /// Get the unique identifier for this model
    fn model_id(&self) -> MessageId {
        self.activity_meta().activity_id
    }

    /// Get the group this model belongs to
    fn group_id(&self) -> MessageId {
        self.activity_meta().group_id
    }

    /// Get the actor who created this model
    fn creator(&self) -> &IdentityRef {
        &self.activity_meta().actor
    }

    /// Get the creation timestamp
    fn created_at(&self) -> u64 {
        self.activity_meta().timestamp
    }

    /// Get the indexes this model should be stored under for the given user
    fn indexes(&self, user_id: &IdentityRef) -> Vec<IndexKey>;

    /// Get the capabilities this model declares
    fn capabilities(&self) -> CapabilitySet;

    /// Get the models this model belongs to (parent-child relationships)
    fn belongs_to(&self) -> Option<Vec<MessageId>> {
        None
    }

    /// Check if a permission context can perform an operation on this model
    ///
    /// This method should be overridden by individual models to implement
    /// domain-specific permission logic using the granular permission system.
    fn check_permission(
        &self,
        context: &PermissionContext,
        operation: DgoOperation,
    ) -> DgoResult<()> {
        // Default implementation uses the granular permission system
        // with creator override for update/delete operations
        let feature_type = self.get_feature_type();

        if context.can_perform_dgo_operation_with_creator_override(
            feature_type,
            &operation,
            self.creator(),
        ) {
            Ok(())
        } else {
            Err(DgoModelError::PermissionDenied {
                message: format!(
                    "Permission denied: {} role cannot perform {:?} operation on {:?}",
                    context.actor_role.display_name(),
                    operation,
                    feature_type
                ),
            })
        }
    }

    /// Get the feature type for this model (used for permission checking)
    ///
    /// This method must be implemented by each model type to specify
    /// which feature type it belongs to for permission checking.
    fn get_feature_type(&self) -> crate::digital_groups_organizer::events::admin::DgoFeatureType;

    /// Apply a state transition from an activity event
    ///
    /// This method is called when an event that affects this model is processed.
    /// It should validate the transition and update the model's state accordingly.
    fn apply_transition(
        &mut self,
        event: &DgoActivityEvent,
        context: &PermissionContext,
    ) -> DgoResult<bool>;

    /// Handle redaction of this model
    ///
    /// This method is called when the model needs to be redacted (deleted/hidden).
    /// It should clean up any associated data and return appropriate references.
    fn redact(&self, context: &PermissionContext) -> DgoResult<Vec<ExecuteReference>> {
        // Default implementation just returns a reference to this model
        self.check_permission(context, DgoOperation::Delete)?;
        Ok(vec![ExecuteReference::Model(self.model_id())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Helper to test postcard serialization round-trip
    fn test_postcard_roundtrip<T>(value: &T) -> postcard::Result<()>
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let serialized = postcard::to_stdvec(value)?;
        let deserialized: T = postcard::from_bytes(&serialized)?;
        assert_eq!(*value, deserialized);
        Ok(())
    }

    // Note: ActivityMeta and PermissionContext tests are skipped because VerifyingKey
    // requires proper key generation, not simple byte arrays. These types are tested
    // in integration tests where proper keys are available.

    #[test]
    fn test_dgo_model_error_postcard() {
        let error = DgoModelError::PermissionDenied {
            message: "Access denied".to_string(),
        };

        test_postcard_roundtrip(&error).expect("DgoModelError should serialize/deserialize");
    }

    #[test]
    fn test_dgo_operation_postcard() {
        let operations = vec![
            DgoOperation::Create,
            DgoOperation::Update,
            DgoOperation::Delete,
            DgoOperation::Comment,
            DgoOperation::React,
            DgoOperation::Attach,
            DgoOperation::Rsvp,
            DgoOperation::Assign,
            DgoOperation::MarkRead,
        ];

        for operation in operations {
            test_postcard_roundtrip(&operation).unwrap_or_else(|_| {
                panic!("DgoOperation::{:?} should serialize/deserialize", operation)
            });
        }
    }

    #[test]
    fn test_permission_context_granular_permissions() {
        use crate::digital_groups_organizer::events::admin::{DgoFeatureSettings, DgoFeatureType};
        use crate::group::events::roles::GroupRole;
        use rand::rngs::OsRng;
        use zoe_wire_protocol::KeyPair;

        // Create test actors using proper key generation
        let mut rng = OsRng;
        let member_keypair = KeyPair::generate(&mut rng);
        let moderator_keypair = KeyPair::generate(&mut rng);
        let admin_keypair = KeyPair::generate(&mut rng);
        let owner_keypair = KeyPair::generate(&mut rng);

        let member_key = member_keypair.public_key();
        let moderator_key = moderator_keypair.public_key();
        let admin_key = admin_keypair.public_key();
        let owner_key = owner_keypair.public_key();
        let group_id = MessageId::from_bytes([10; 32]);

        // Test with default settings
        let default_settings = DgoFeatureSettings::default();

        let member_context = PermissionContext::new(
            IdentityRef::Key(member_key),
            group_id,
            GroupRole::Member,
            true,
            default_settings.clone(),
        );

        let moderator_context = PermissionContext::new(
            IdentityRef::Key(moderator_key),
            group_id,
            GroupRole::Moderator,
            true,
            default_settings.clone(),
        );

        let admin_context = PermissionContext::new(
            IdentityRef::Key(admin_key),
            group_id,
            GroupRole::Admin,
            true,
            default_settings.clone(),
        );

        let owner_context = PermissionContext::new(
            IdentityRef::Key(owner_key),
            group_id,
            GroupRole::Owner,
            true,
            default_settings,
        );

        // Test text block permissions with default settings
        // Members can create text blocks
        assert!(
            member_context
                .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Create)
        );

        // Members can now update text blocks (changed to AllMembers)
        assert!(
            member_context
                .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Update)
        );

        // Moderators can update text blocks
        assert!(
            moderator_context
                .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Update)
        );

        // Members can comment on text blocks
        assert!(
            member_context
                .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Comment)
        );

        // Test task list permissions with default settings
        // Members can now create task lists (changed to AllMembers)
        assert!(
            member_context
                .can_perform_dgo_operation(DgoFeatureType::TaskList, &DgoOperation::Create)
        );

        // Moderators can create task lists
        assert!(
            moderator_context
                .can_perform_dgo_operation(DgoFeatureType::TaskList, &DgoOperation::Create)
        );

        // Members cannot delete task lists (requires moderator by default)
        assert!(
            !member_context
                .can_perform_dgo_operation(DgoFeatureType::TaskList, &DgoOperation::Delete)
        );

        // Moderators can now delete task lists (changed to ModeratorOrAbove)
        assert!(
            moderator_context
                .can_perform_dgo_operation(DgoFeatureType::TaskList, &DgoOperation::Delete)
        );

        // Admins can delete task lists
        assert!(
            admin_context
                .can_perform_dgo_operation(DgoFeatureType::TaskList, &DgoOperation::Delete)
        );

        // Owners can delete task lists
        assert!(
            owner_context
                .can_perform_dgo_operation(DgoFeatureType::TaskList, &DgoOperation::Delete)
        );
    }

    #[test]
    fn test_permission_context_creator_override() {
        use crate::digital_groups_organizer::events::admin::{DgoFeatureSettings, DgoFeatureType};
        use crate::group::events::roles::GroupRole;
        use rand::rngs::OsRng;
        use zoe_wire_protocol::KeyPair;

        let mut rng = OsRng;
        let creator_keypair = KeyPair::generate(&mut rng);
        let other_keypair = KeyPair::generate(&mut rng);

        let creator_key = creator_keypair.public_key();
        let other_key = other_keypair.public_key();
        let group_id = MessageId::from_bytes([10; 32]);

        let settings = DgoFeatureSettings::default();

        // Creator context (member role)
        let creator_context = PermissionContext::new(
            IdentityRef::Key(creator_key.clone()),
            group_id,
            GroupRole::Member,
            true,
            settings.clone(),
        );

        // Other user context (member role)
        let other_context = PermissionContext::new(
            IdentityRef::Key(other_key),
            group_id,
            GroupRole::Member,
            true,
            settings,
        );

        // Test creator override for update operations
        // Creator can update their own text block even though members normally can't
        assert!(
            creator_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Update,
                &IdentityRef::Key(creator_key.clone())
            )
        );

        // Other user can now update text blocks (changed to AllMembers)
        assert!(
            other_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Update,
                &IdentityRef::Key(creator_key.clone())
            )
        );

        // Creator can delete their own text block even though members normally can't
        assert!(
            creator_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Delete,
                &IdentityRef::Key(creator_key.clone())
            )
        );

        // Other user cannot delete the text block (not creator, not moderator)
        assert!(
            !other_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Delete,
                &IdentityRef::Key(creator_key.clone())
            )
        );

        // Both can comment (no creator override needed, members can comment)
        assert!(
            creator_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Comment,
                &IdentityRef::Key(creator_key.clone())
            )
        );

        assert!(
            other_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Comment,
                &IdentityRef::Key(creator_key.clone())
            )
        );
    }

    #[test]
    fn test_permission_context_non_member() {
        use crate::digital_groups_organizer::events::admin::{DgoFeatureSettings, DgoFeatureType};
        use crate::group::events::roles::GroupRole;
        use rand::rngs::OsRng;
        use zoe_wire_protocol::KeyPair;

        let mut rng = OsRng;
        let non_member_keypair = KeyPair::generate(&mut rng);
        let non_member_key = non_member_keypair.public_key();
        let group_id = MessageId::from_bytes([10; 32]);

        let settings = DgoFeatureSettings::default();

        // Non-member context (even with admin role, not a group member)
        let non_member_context = PermissionContext::new(
            IdentityRef::Key(non_member_key.clone()),
            group_id,
            GroupRole::Admin, // High role but not a member
            false,            // Not a group member
            settings,
        );

        // Non-members cannot perform any operations, regardless of role
        assert!(
            !non_member_context
                .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Create)
        );

        assert!(
            !non_member_context
                .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Comment)
        );

        assert!(
            !non_member_context.can_perform_dgo_operation_with_creator_override(
                DgoFeatureType::TextBlock,
                &DgoOperation::Update,
                &IdentityRef::Key(non_member_key.clone())
            )
        );
    }
}
