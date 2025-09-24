//! Digital Groups Organizer (DGO) Executor Implementation
//!
//! This module provides DGO-specific type aliases and store implementation
//! for use with the generic executor. It demonstrates how to specialize
//! the generic executor for a specific domain.

use async_trait::async_trait;
use zoe_wire_protocol::MessageId;

use crate::execution::ExecutorResult;
use zoe_app_primitives::group::events::{GroupId, roles::GroupRole};

use zoe_app_primitives::{
    digital_groups_organizer::{
        events::core::DgoActivityEvent,
        models::{
            any::AnyDgoModel, core::DgoPermissionContext,
            permission_settings::DgoPermissionSettings,
        },
    },
    group::app::GroupStateModel,
    identity::IdentityRef,
};

use crate::execution::{ExecutorError, ExecutorStore, GenericExecutor, ModelFactory};
// ============================================================================
// Type Aliases for DGO Executor
// ============================================================================

/// Type alias for the DGO executor using the unified generic executor
pub type DgoExecutor<S> = GenericExecutor<DgoFactory, S>;

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
    type SettingsModel = DgoPermissionSettings;
    type Error = ExecutorError;

    async fn load_state<T: ExecutorStore>(_store: &T) -> Result<Box<Self>, Self::Error> {
        // FIXME: For now, just create a new factory
        Ok(Box::new(DgoFactory))
    }

    async fn load_permission_context(
        &self,
        actor: &IdentityRef,
        _group_id: GroupId,
        actor_role: GroupRole,
        state_message_id: MessageId,
    ) -> ExecutorResult<Option<<Self::Model as GroupStateModel>::PermissionState>> {
        // Create DGO-specific permission context with provided parameters
        // The group state has already looked up the actor's role and app state message

        // Load DGO-specific settings from the app state at state_message_id
        // TODO: Implement actual DGO settings loading from app state
        // For now, use default settings as the app state loading infrastructure is not yet complete
        let dgo_settings = zoe_app_primitives::digital_groups_organizer::events::admin::DgoFeatureSettings::default();

        // Load group permissions - use default for now
        // TODO: Load actual group permissions from the group state at the state message ID
        let group_permissions =
            zoe_app_primitives::group::events::permissions::GroupPermissions::default();

        // Create the DGO permission context with all the required information
        // This context now has the correct actor role from historical lookup
        let permission_context = DgoPermissionContext::new(
            actor.clone(),
            state_message_id,
            actor_role, // This is now the actual role from group state historical lookup
            dgo_settings,
            group_permissions,
        );

        Ok(Some(permission_context))
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

#[cfg(test)]
mod tests {
    use super::*;

    use zoe_app_primitives::digital_groups_organizer::events::content::CreateTextBlockContent;
    use zoe_app_primitives::digital_groups_organizer::events::core::DgoActivityEventContent;
    use zoe_app_primitives::digital_groups_organizer::indexing::keys::ExecuteReference;
    use zoe_app_primitives::digital_groups_organizer::models::core::ActivityMeta;

    use zoe_wire_protocol::MessageId;

    #[tokio::test]
    async fn test_dgo_executor_create_text_block() {
        let store = crate::execution::InMemoryStore::new();
        let executor = DgoExecutor::new(DgoFactory, store);

        let event_content = DgoActivityEventContent::CreateTextBlock {
            content: CreateTextBlockContent {
                title: "Test Block".to_string(),
                description: Some("Test description".to_string()),
                icon: Some("📝".to_string()),
                parent_id: None,
            },
        };
        let event = DgoActivityEvent::new(
            zoe_app_primitives::identity::IdentityType::Main,
            event_content,
            zoe_wire_protocol::MessageId::from([1u8; 32]), // Mock group state reference
        );

        let activity_id = MessageId::from([1u8; 32]);
        let group_meta = ActivityMeta {
            activity_id,
            group_id: vec![0u8; 32],
            actor: IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let actor_role = zoe_app_primitives::group::events::roles::GroupRole::Member;
        let state_message_id = zoe_wire_protocol::MessageId::from([2u8; 32]);
        let refs = executor
            .execute_event(event, group_meta, actor_role, state_message_id)
            .await
            .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], ExecuteReference::Model(activity_id));

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
        let store = crate::execution::InMemoryStore::new();
        let executor = DgoExecutor::new(DgoFactory, store);

        // First create a text block
        let create_event_content = DgoActivityEventContent::CreateTextBlock {
            content: CreateTextBlockContent {
                title: "Original Title".to_string(),
                description: None,
                icon: None,
                parent_id: None,
            },
        };
        let create_event = DgoActivityEvent::new(
            zoe_app_primitives::identity::IdentityType::Main,
            create_event_content,
            zoe_wire_protocol::MessageId::from([1u8; 32]), // Mock group state reference
        );

        let model_id = MessageId::from([1u8; 32]);
        let create_group_meta = ActivityMeta {
            activity_id: model_id,
            group_id: vec![0u8; 32],
            actor: IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let actor_role = zoe_app_primitives::group::events::roles::GroupRole::Member;
        let state_message_id = zoe_wire_protocol::MessageId::from([2u8; 32]);
        executor
            .execute_event(
                create_event,
                create_group_meta,
                actor_role.clone(),
                state_message_id,
            )
            .await
            .unwrap();

        // Now update it
        let update_event_content = DgoActivityEventContent::UpdateTextBlock {
            target_id: model_id,
            content: vec![
                zoe_app_primitives::digital_groups_organizer::events::content::TextBlockUpdate::Title("Updated Title".to_string()),
                zoe_app_primitives::digital_groups_organizer::events::content::TextBlockUpdate::Description("New description".to_string()),
            ],
        };
        let update_event = DgoActivityEvent::new(
            zoe_app_primitives::identity::IdentityType::Main,
            update_event_content,
            zoe_wire_protocol::MessageId::from([1u8; 32]), // Mock group state reference
        );

        let activity_id = MessageId::from([2u8; 32]);
        let update_group_meta = ActivityMeta {
            activity_id,
            group_id: vec![0u8; 32],
            actor: IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        let refs = executor
            .execute_event(
                update_event,
                update_group_meta,
                actor_role,
                state_message_id,
            )
            .await
            .unwrap();

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], ExecuteReference::Model(model_id));

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
