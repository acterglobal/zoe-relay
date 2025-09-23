//! Top-level enum for all DGO models
//!
//! This module provides the `AnyDgoModel` enum that wraps all concrete DGO model types,
//! enabling type-safe dispatch and storage while maintaining strong typing throughout
//! the executor system.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::{
    digital_groups_organizer::{
        events::core::{DgoActivityEvent, DgoActivityEventContent},
        models::core::{ActivityMeta, DgoAppModel, DgoPermissionContext},
    },
    group::app::{ExecuteError, GroupStateModel},
};

use super::{permission_settings::DgoPermissionSettings, text_block::TextBlock};

/// Top-level enum containing all DGO model types
///
/// This enum enables the executor to work with strongly-typed models while
/// maintaining the ability to store and dispatch to different model types.
/// Each variant corresponds to a concrete model implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnyDgoModel {
    /// Text block content model
    TextBlock(TextBlock),

    /// DGO permission settings model
    DgoPermissionSettings(DgoPermissionSettings),
    // Future models will be added here:
    // CommentsManager(CommentsManager),
    // ReactionsManager(ReactionsManager),
    // CalendarEvent(CalendarEvent),
    // Task(Task),
    // TaskList(TaskList),
}

impl GroupStateModel for AnyDgoModel {
    type Event = DgoActivityEvent;
    type PermissionContext = DgoPermissionContext;
    type Error = ExecuteError;
    type ExecutiveKey = MessageId;

    fn activity_meta(&self) -> &ActivityMeta {
        match self {
            AnyDgoModel::TextBlock(m) => DgoAppModel::activity_meta(m),
            AnyDgoModel::DgoPermissionSettings(m) => DgoAppModel::activity_meta(m),
        }
    }

    fn execute(
        &mut self,
        event: &Self::Event,
        context: &Self::PermissionContext,
    ) -> Result<Vec<crate::group::app::ExecutionUpdateInfo<Self, Self::ExecutiveKey>>, Self::Error>
    {
        use crate::group::app::ExecutionUpdateInfo;

        // For Create events, the model was just created and should return itself
        match event.content() {
            DgoActivityEventContent::CreateTextBlock { .. }
            | DgoActivityEventContent::CreateDgoSettings { .. } => {
                let update_info = ExecutionUpdateInfo::new()
                    .add_model(self.clone())
                    .add_reference(self.activity_meta().activity_id);
                return Ok(vec![update_info]);
            }
            _ => {
                // For other events, use the normal transition logic
            }
        }

        match self {
            AnyDgoModel::TextBlock(m) => {
                // Use DGO-specific transition method
                match m.apply_dgo_transition(event, context) {
                    Ok(true) => {
                        let update_info = ExecutionUpdateInfo::new()
                            .add_model(self.clone())
                            .add_reference(self.activity_meta().activity_id); // Use activity_id as executive key
                        Ok(vec![update_info])
                    }
                    Ok(false) => Ok(vec![]), // No change
                    Err(e) => Err(ExecuteError::PermissionDenied(format!("{e:?}"))),
                }
            }
            AnyDgoModel::DgoPermissionSettings(m) => {
                // Use DGO-specific transition method
                match m.apply_dgo_transition(event, context) {
                    Ok(true) => {
                        let update_info = ExecutionUpdateInfo::new()
                            .add_model(self.clone())
                            .add_reference(self.activity_meta().activity_id); // Use activity_id as executive key
                        Ok(vec![update_info])
                    }
                    Ok(false) => Ok(vec![]), // No change
                    Err(e) => Err(ExecuteError::PermissionDenied(format!("{e:?}"))),
                }
            }
        }
    }

    fn redact(&self, context: &Self::PermissionContext) -> Result<Vec<Self>, Self::Error> {
        match self {
            AnyDgoModel::TextBlock(m) => {
                match m.redact_dgo(context) {
                    Ok(_refs) => Ok(vec![]), // Model is deleted (empty vec)
                    Err(e) => Err(ExecuteError::PermissionDenied(format!("{e:?}"))),
                }
            }
            AnyDgoModel::DgoPermissionSettings(m) => {
                match m.redact_dgo(context) {
                    Ok(_refs) => Ok(vec![]), // Model is deleted (empty vec)
                    Err(e) => Err(ExecuteError::PermissionDenied(format!("{e:?}"))),
                }
            }
        }
    }
}

impl AnyDgoModel {
    /// Get the model ID
    pub fn model_id(&self) -> MessageId {
        self.activity_meta().activity_id
    }

    /// Get the group ID
    pub fn group_id(&self) -> MessageId {
        self.activity_meta().group_id
    }

    /// Get the creation timestamp
    pub fn created_at(&self) -> u64 {
        self.activity_meta().timestamp
    }

    /// Create a new model from a concrete type
    pub fn from_text_block(model: TextBlock) -> Self {
        AnyDgoModel::TextBlock(model)
    }

    /// Create a new model from a concrete type
    pub fn from_permission_settings(model: DgoPermissionSettings) -> Self {
        AnyDgoModel::DgoPermissionSettings(model)
    }

    /// Try to extract a specific model type
    pub fn as_text_block(&self) -> Option<&TextBlock> {
        match self {
            AnyDgoModel::TextBlock(m) => Some(m),
            _ => None,
        }
    }

    /// Try to extract a specific model type mutably
    pub fn as_text_block_mut(&mut self) -> Option<&mut TextBlock> {
        match self {
            AnyDgoModel::TextBlock(m) => Some(m),
            _ => None,
        }
    }

    /// Try to extract a specific model type
    pub fn as_permission_settings(&self) -> Option<&DgoPermissionSettings> {
        match self {
            AnyDgoModel::DgoPermissionSettings(m) => Some(m),
            _ => None,
        }
    }

    /// Try to extract a specific model type mutably
    pub fn as_permission_settings_mut(&mut self) -> Option<&mut DgoPermissionSettings> {
        match self {
            AnyDgoModel::DgoPermissionSettings(m) => Some(m),
            _ => None,
        }
    }

    /// Get the model type as a string (useful for debugging and storage)
    pub fn model_type(&self) -> &'static str {
        match self {
            AnyDgoModel::TextBlock(_) => "TextBlock",
            AnyDgoModel::DgoPermissionSettings(_) => "DgoPermissionSettings",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digital_groups_organizer::models::core::ActivityMeta;
    use crate::identity::IdentityRef;

    #[test]
    fn test_any_dgo_model_dispatch() {
        let meta = ActivityMeta {
            activity_id: MessageId::from([1u8; 32]),
            group_id: MessageId::from([2u8; 32]),
            actor: IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: 1000,
        };

        let text_block = TextBlock {
            meta,
            title: "Test".to_string(),
            description: None,
            icon: None,
            parent_id: None,
            version: 1,
        };

        let any_model = AnyDgoModel::from_text_block(text_block);

        // Test that we can call trait methods
        assert_eq!(any_model.model_type(), "TextBlock");
        assert_eq!(any_model.created_at(), 1000);

        // Test that we can extract the specific type
        assert!(any_model.as_text_block().is_some());
        assert!(any_model.as_permission_settings().is_none());
    }
}
