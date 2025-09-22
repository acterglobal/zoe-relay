//! Digital Groups Organizer (DGO) Executor Implementation
//!
//! This module provides DGO-specific type aliases and store implementation
//! for use with the generic executor. It demonstrates how to specialize
//! the generic executor for a specific domain.

use async_trait::async_trait;
use zoe_wire_protocol::MessageId;

use zoe_app_primitives::{
    digital_groups_organizer::{
        events::core::DgoActivityEvent,
        models::{
            any::AnyDgoModel,
            core::{ActivityMeta, DgoPermissionContext},
            permission_settings::DgoPermissionSettings,
            text_block::TextBlock,
        },
    },
    group::app::GroupStateModel,
    identity::IdentityRef,
};

use crate::generic_executor::{
    ExecutorError, ExecutorStore, GenericExecutor, InMemoryStore, ModelFactory,
};

// ============================================================================
// Type Aliases for DGO Executor
// ============================================================================

/// Type alias for the DGO executor using the unified generic executor
pub type DgoExecutor = GenericExecutor<DgoFactory, InMemoryStore>;

/// Type alias for DGO events (for consistency)
pub type DgoEvent = DgoActivityEvent;

/// Type alias for DGO models (for consistency)  
pub type DgoModel = AnyDgoModel;

/// Factory for creating DGO models from events
#[derive(Debug, Clone)]
pub struct DgoFactory;

#[async_trait]
impl ModelFactory for DgoFactory {
    type Model = AnyDgoModel;
    type Error = ExecutorError;

    async fn load_state<T: ExecutorStore>(_store: &T) -> Result<Box<Self>, Self::Error> {
        // For now, just create a new factory
        Ok(Box::new(DgoFactory))
    }

    async fn create_model_from_event(
        &self,
        event: &<Self::Model as GroupStateModel>::Event,
        activity_id: MessageId,
    ) -> Result<Option<Self::Model>, Self::Error> {
        match event {
            DgoActivityEvent::CreateTextBlock { content } => {
                // Create a new text block from the event
                let meta = ActivityMeta {
                    activity_id,
                    group_id: MessageId::from([0u8; 32]), // TODO: Get from context
                    actor: IdentityRef::Key(
                        zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
                    ), // TODO: Get from context
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let text_block = TextBlock {
                    meta,
                    title: content.title.clone(),
                    description: content.description.clone(),
                    icon: content.icon.clone(),
                    parent_id: content.parent_id,
                    version: 1,
                };

                Ok(Some(AnyDgoModel::from_text_block(text_block)))
            }

            DgoActivityEvent::CreateDgoSettings { content } => {
                // Create new permission settings from the event
                let meta = ActivityMeta {
                    activity_id,
                    group_id: MessageId::from([0u8; 32]), // TODO: Get from context
                    actor: IdentityRef::Key(
                        zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
                    ), // TODO: Get from context
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let settings = content.initial_settings.clone()
                    .unwrap_or_else(zoe_app_primitives::digital_groups_organizer::events::admin::DgoFeatureSettings::default);
                let permission_settings = DgoPermissionSettings::new(meta, settings);
                Ok(Some(AnyDgoModel::from_permission_settings(
                    permission_settings,
                )))
            }

            _ => {
                // Other events don't create new models
                Ok(None)
            }
        }
    }

    async fn load_permission_context(
        &self,
        actor: &IdentityRef,
        group_id: MessageId,
    ) -> Result<Option<<Self::Model as GroupStateModel>::PermissionContext>, Self::Error> {
        // For now, create a basic permission context
        // In a real implementation, this would query the group state
        Ok(Some(DgoPermissionContext::new(
            actor.clone(),
            group_id,
            zoe_app_primitives::group::events::roles::GroupRole::Member, // Default role
            true, // Assume member
            zoe_app_primitives::digital_groups_organizer::events::admin::DgoFeatureSettings::default(),
        )))
    }

    async fn add_to_index<K, E>(
        &self,
        store: &impl ExecutorStore,
        list_id: K,
        executive_refs: &[E],
    ) -> Result<(), Self::Error>
    where
        K: serde::Serialize + Send + Sync + Clone,
        E: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Clone,
    {
        // Load existing index or create new one
        let mut index: Vec<E> = store
            .load_index(list_id.clone())
            .await
            .map_err(|e| e.into())?
            .unwrap_or_default();

        // Add new executive references
        for exec_ref in executive_refs {
            index.push(exec_ref.clone());
        }

        // Store updated index
        store
            .store_index(list_id, &index)
            .await
            .map_err(|e| e.into())?;

        Ok(())
    }

    async fn remove_from_index<K, E>(
        &self,
        store: &impl ExecutorStore,
        list_id: K,
        executive_refs: &[E],
    ) -> Result<(), Self::Error>
    where
        K: serde::Serialize + Send + Sync + Clone,
        E: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Clone + PartialEq,
    {
        // Load existing index
        let mut index: Vec<E> = store
            .load_index(list_id.clone())
            .await
            .map_err(|e| e.into())?
            .unwrap_or_default();

        // Remove executive references
        for exec_ref in executive_refs {
            index.retain(|item| item != exec_ref);
        }

        // Store updated index
        store
            .store_index(list_id, &index)
            .await
            .map_err(|e| e.into())?;

        Ok(())
    }

    async fn load_models_from_index<K>(
        &self,
        store: &impl ExecutorStore,
        list_id: K,
    ) -> Result<Vec<Self::Model>, Self::Error>
    where
        K: serde::Serialize + Send + Sync + Clone,
    {
        // Load index data
        let index: Vec<MessageId> = store
            .load_index(list_id)
            .await
            .map_err(|e| e.into())?
            .unwrap_or_default();

        // Load models from the executive references
        let models = store.load_many(&index).await.map_err(|e| e.into())?;

        // Filter out None values and return the models
        Ok(models.into_iter().flatten().collect())
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Create a new DGO executor with default store
pub fn create_dgo_executor() -> DgoExecutor {
    let factory = DgoFactory;
    let store = InMemoryStore::new();
    GenericExecutor::new(factory, store)
}

/// Create a DGO executor with custom store
pub fn create_dgo_executor_with_store(store: InMemoryStore) -> DgoExecutor {
    let factory = DgoFactory;
    GenericExecutor::new(factory, store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_app_primitives::digital_groups_organizer::events::content::CreateTextBlockContent;

    #[tokio::test]
    async fn test_dgo_executor_create_text_block() {
        let executor = create_dgo_executor();

        let event = DgoActivityEvent::CreateTextBlock {
            content: CreateTextBlockContent {
                title: "Test Block".to_string(),
                description: Some("Test description".to_string()),
                icon: Some("📝".to_string()),
                parent_id: None,
            },
        };

        let activity_id = MessageId::from([1u8; 32]);

        let refs = executor.execute_event(event, activity_id).await.unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], activity_id);

        // Verify the model was created
        let model: Option<AnyDgoModel> = executor.store().load(activity_id).await.unwrap();
        assert!(model.is_some());

        let model = model.unwrap();
        assert_eq!(model.model_id(), activity_id);

        if let Some(text_block) = model.as_text_block() {
            assert_eq!(text_block.title, "Test Block");
            assert_eq!(text_block.description, Some("Test description".to_string()));
            assert_eq!(text_block.icon, Some("📝".to_string()));
        } else {
            panic!("Expected TextBlock model");
        }
    }

    #[tokio::test]
    async fn test_dgo_executor_update_text_block() {
        let executor = create_dgo_executor();

        // First create a text block
        let create_event = DgoActivityEvent::CreateTextBlock {
            content: CreateTextBlockContent {
                title: "Original Title".to_string(),
                description: None,
                icon: None,
                parent_id: None,
            },
        };

        let model_id = MessageId::from([1u8; 32]);
        executor
            .execute_event(create_event, model_id)
            .await
            .unwrap();

        // Now update it
        let update_event = DgoActivityEvent::UpdateTextBlock {
            target_id: model_id,
            content: vec![
                zoe_app_primitives::digital_groups_organizer::events::content::TextBlockUpdate::Title("Updated Title".to_string()),
                zoe_app_primitives::digital_groups_organizer::events::content::TextBlockUpdate::Description("New description".to_string()),
            ],
        };

        let activity_id = MessageId::from([2u8; 32]);
        let refs = executor
            .execute_event(update_event, activity_id)
            .await
            .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], model_id);

        // Verify the model was updated
        let model: AnyDgoModel = executor.store().load(model_id).await.unwrap().unwrap();

        if let Some(text_block) = model.as_text_block() {
            assert_eq!(text_block.title, "Updated Title");
            assert_eq!(text_block.description, Some("New description".to_string()));
        } else {
            panic!("Expected TextBlock model");
        }
    }
}
