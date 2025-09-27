//! Top-level enum for all DGO models
//!
//! This module provides the `AnyDgoModel` enum that wraps all concrete DGO model types,
//! enabling type-safe dispatch and storage while maintaining strong typing throughout
//! the executor system.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::{
    digital_groups_organizer::{
        events::{
            admin::DgoFeatureType,
            core::{DgoActivityEvent, DgoActivityEventContent},
        },
        indexing::{
            core::SectionIndex,
            keys::{ExecuteReference, IndexKey},
        },
        models::core::{ActivityMeta, DgoAppModel, DgoOperation, DgoPermissionContext},
    },
    group::{
        app::{ExecuteError, ExecutionUpdateInfo, GroupStateModel, IndexChange},
        events::GroupId,
    },
};

use super::text_block::TextBlock;

/// Top-level enum containing all DGO content model types
///
/// This enum enables the executor to work with strongly-typed content models while
/// maintaining the ability to store and dispatch to different model types.
/// Each variant corresponds to a concrete content model implementation.
///
/// Note: Settings models (like DgoPermissionSettings) are handled separately
/// and are not included in this enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AnyDgoModel {
    Default(ActivityMeta), // only the group metadata
    /// Text block content model
    TextBlock(TextBlock),
    // Future content models will be added here:
    // CommentsManager(CommentsManager),
    // ReactionsManager(ReactionsManager),
    // CalendarEvent(CalendarEvent),
    // Task(Task),
    // TaskList(TaskList),
}

impl GroupStateModel for AnyDgoModel {
    type Event = DgoActivityEvent;
    type PermissionState = DgoPermissionContext;
    type Error = ExecuteError;
    type ExecutiveKey = ExecuteReference;
    type IndexKey = IndexKey;

    fn default_model(group_meta: ActivityMeta) -> Self {
        AnyDgoModel::Default(group_meta)
    }

    fn activity_meta(&self) -> &ActivityMeta {
        match self {
            AnyDgoModel::Default(m) => m,
            AnyDgoModel::TextBlock(m) => DgoAppModel::activity_meta(m),
        }
    }

    fn execute(
        &mut self,
        event: &Self::Event,
        context: &Self::PermissionState,
    ) -> Result<Vec<ExecutionUpdateInfo<Self, Self::ExecutiveKey, Self::IndexKey>>, Self::Error>
    {
        match self {
            AnyDgoModel::Default(meta) => match event.content() {
                DgoActivityEventContent::CreateTextBlock { content } => {
                    if !context
                        .can_perform_dgo_operation(DgoFeatureType::TextBlock, &DgoOperation::Create)
                    {
                        return Err(ExecuteError::PermissionDenied(format!(
                            "Permission denied: {} role cannot perform {:?} operation on text blocks",
                            context.actor_role.display_name(),
                            DgoOperation::Create
                        )));
                    }
                    // Create a new TextBlock model with the event's content
                    let mut new_text_block = TextBlock {
                        meta: meta.clone(),
                        title: content.title.clone(),
                        description: content.description.clone(),
                        icon: content.icon.clone(),
                        parent_id: content.parent_id,
                        version: 1,
                    };

                    // Update the activity_id to match the event's activity_id
                    new_text_block.meta.activity_id = meta.activity_id; // Use the activity_id from the default model

                    let new_model = AnyDgoModel::from_text_block(new_text_block);
                    Ok(vec![
                        ExecutionUpdateInfo::new()
                            .add_model_with_index_changes(
                                new_model,
                                vec![
                                    IndexChange::Added(IndexKey::Section(SectionIndex::TextBlocks)),
                                    IndexChange::Added(IndexKey::GroupSection(
                                        meta.group_id.clone(),
                                        SectionIndex::TextBlocks,
                                    )),
                                    IndexChange::Added(IndexKey::GroupHistory(
                                        meta.group_id.clone(),
                                    )),
                                    IndexChange::Added(IndexKey::AllHistory),
                                ],
                            )
                            .add_reference(ExecuteReference::Model(meta.activity_id)),
                    ])
                }
                _ => Err(ExecuteError::EventNotApplicable(format!(
                    "Event not a create event: {:?}",
                    event.content()
                ))),
            },
            AnyDgoModel::TextBlock(m) => {
                // Use DGO-specific transition method
                Ok(
                    if m.apply_dgo_transition(event, context)
                        .map_err(|e| ExecuteError::PermissionDenied(format!("{e:?}")))?
                    {
                        vec![
                            ExecutionUpdateInfo::new()
                                .add_reference(ExecuteReference::Model(m.model_id()))
                                .add_reference(ExecuteReference::Index(IndexKey::ObjectHistory(
                                    m.model_id(),
                                )))
                                .add_reference(ExecuteReference::Index(IndexKey::GroupHistory(
                                    m.group_id().clone(),
                                )))
                                .add_reference(ExecuteReference::Index(IndexKey::AllHistory))
                                .add_model(self.clone()),
                        ]
                    } else {
                        vec![]
                    },
                )
            }
        }
    }

    fn redact(&self, context: &Self::PermissionState) -> Result<Vec<Self>, Self::Error> {
        match self {
            AnyDgoModel::Default(_) => Ok(vec![]), // nothing to be done
            AnyDgoModel::TextBlock(m) => {
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
    pub fn group_id(&self) -> GroupId {
        self.activity_meta().group_id.clone()
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
    /// Try to extract a specific model type
    pub fn as_text_block(&self) -> Option<&TextBlock> {
        match self {
            AnyDgoModel::TextBlock(m) => Some(m),
            AnyDgoModel::Default(_) => None,
        }
    }

    /// Try to extract a specific model type mutably
    pub fn as_text_block_mut(&mut self) -> Option<&mut TextBlock> {
        match self {
            AnyDgoModel::TextBlock(m) => Some(m),
            AnyDgoModel::Default(_) => None,
        }
    }

    /// Get the model type as a string (useful for debugging and storage)
    pub fn model_type(&self) -> &'static str {
        match self {
            AnyDgoModel::TextBlock(_) => "TextBlock",
            AnyDgoModel::Default(_) => "Default",
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
            group_id: vec![2u8; 32],
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
    }
}
