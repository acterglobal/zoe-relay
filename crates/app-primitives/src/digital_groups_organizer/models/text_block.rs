//! Text block model implementation
//!
//! This module provides the TextBlock model - a simple rich text content
//! object within encrypted groups.

use crate::identity::IdentityRef;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::digital_groups_organizer::{
    capabilities::{CapabilitySet, DgoCapability},
    events::{content::TextBlockUpdate, core::DgoActivityEvent, core::ObjectCore},
    indexing::{core::SectionIndex, keys::IndexKey},
};

use super::core::{
    ActivityMeta, DgoAppModel, DgoModelError, DgoOperation, DgoPermissionContext, DgoResult,
};

/// A text block model - simple rich text content within a group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TextBlock {
    /// Metadata for this text block's creation activity
    pub meta: ActivityMeta,
    /// Title of the text block
    pub title: String,
    /// Optional description (HTML formatted)
    pub description: Option<String>,
    /// Optional icon (emoji)
    pub icon: Option<String>,
    /// Optional parent object (for threading/nesting)
    pub parent_id: Option<zoe_wire_protocol::MessageId>,
    /// Current version number (incremented on updates)
    pub version: u32,
}

impl TextBlock {
    /// Create a new text block
    pub fn new(meta: ActivityMeta, core: ObjectCore) -> Self {
        Self {
            meta,
            title: core.title,
            description: core.description,
            icon: core.icon,
            parent_id: core.parent_id,
            version: 1,
        }
    }

    /// Get the title of this text block
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the description of this text block
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the icon of this text block
    pub fn icon(&self) -> Option<&str> {
        self.icon.as_deref()
    }

    /// Get the current version
    pub fn version(&self) -> u32 {
        self.version
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

// Note: TextBlock doesn't implement GroupStateModel directly.
// Only AnyDgoModel implements GroupStateModel to work with the unified executor.

impl DgoAppModel for TextBlock {
    fn activity_meta(&self) -> &ActivityMeta {
        &self.meta
    }

    fn indexes(&self, _user_id: &IdentityRef) -> Vec<IndexKey> {
        vec![
            // Add to text blocks section
            IndexKey::Section(SectionIndex::TextBlocks),
            IndexKey::GroupSection(self.group_id(), SectionIndex::TextBlocks),
            // Add to object and group history
            IndexKey::ObjectHistory(self.model_id()),
            IndexKey::GroupHistory(self.group_id()),
            IndexKey::AllHistory,
        ]
    }

    fn capabilities(&self) -> CapabilitySet {
        CapabilitySet::with_capabilities(vec![
            DgoCapability::Commentable,
            DgoCapability::Reactable,
            DgoCapability::Attachmentable,
            DgoCapability::ReadTracking,
            DgoCapability::Taggable,
        ])
    }

    fn apply_dgo_transition(
        &mut self,
        event: &DgoActivityEvent,
        context: &DgoPermissionContext,
    ) -> DgoResult<bool> {
        match event {
            DgoActivityEvent::UpdateTextBlock {
                target_id: _,
                content: updates,
            } => {
                // Check permissions first
                self.check_permission(context, DgoOperation::Update)?;
                if updates.is_empty() {
                    return Ok(false);
                }

                // Apply each update operation
                for update in updates {
                    match update {
                        TextBlockUpdate::Title(title) => {
                            self.title = title.clone();
                        }
                        TextBlockUpdate::Description(description) => {
                            self.description = Some(description.clone());
                        }
                        TextBlockUpdate::ClearDescription => {
                            self.description = None;
                        }
                        TextBlockUpdate::Icon(icon) => {
                            self.icon = Some(icon.clone());
                        }
                        TextBlockUpdate::ClearIcon => {
                            self.icon = None;
                        }
                        TextBlockUpdate::ParentId(parent_id) => {
                            self.parent_id = Some(*parent_id);
                        }
                        TextBlockUpdate::ClearParentId => {
                            self.parent_id = None;
                        }
                    }
                }

                Ok(true)
            }
            _ => Ok(false), // This event doesn't affect text blocks
        }
    }

    fn get_feature_type(&self) -> crate::digital_groups_organizer::events::admin::DgoFeatureType {
        crate::digital_groups_organizer::events::admin::DgoFeatureType::TextBlock
    }

    fn check_permission(
        &self,
        context: &DgoPermissionContext,
        operation: DgoOperation,
    ) -> DgoResult<()> {
        // Use the new granular permission system with creator override
        let feature_type = self.get_feature_type();

        if context.can_perform_dgo_operation_with_creator_override(
            feature_type,
            &operation,
            &self.meta.actor,
        ) {
            Ok(())
        } else {
            Err(DgoModelError::PermissionDenied {
                message: format!(
                    "Permission denied: {} role cannot perform {:?} operation on text blocks. Required permission: {:?}",
                    context.actor_role.display_name(),
                    operation,
                    context
                        .dgo_settings
                        .get_permission_for_operation(feature_type, operation.to_operation_type())
                ),
            })
        }
    }
}
