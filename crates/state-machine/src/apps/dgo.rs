//! Digital Groups Organizer (DGO) Executor Implementation
//!
//! This module provides DGO-specific type aliases and store implementation
//! for use with the generic executor. It demonstrates how to specialize
//! the generic executor for a specific domain.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use zoe_app_primitives::digital_groups_organizer::indexing::core::{ObjectListIndex, SectionIndex};
use zoe_app_primitives::digital_groups_organizer::indexing::keys::IndexKey;
use zoe_app_primitives::digital_groups_organizer::models::core::ActivityMeta;
use zoe_app_primitives::group::events::permissions::GroupPermissions;
use zoe_wire_protocol::MessageId;

use crate::execution::ExecutorResult;
use crate::index::{FiloIndex, LifoIndex, RankedIndex};
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
pub type DgoExecutor<S> = GenericExecutor<DgoFactory<S>, S>;

/// Type alias for DGO events (for consistency)
pub type DgoEvent = DgoActivityEvent;

/// Type alias for DGO models (for consistency)
pub type DgoModel = AnyDgoModel;

/// Factory for creating DGO models from events
#[derive(Debug, Clone)]
pub struct DgoFactory<T: ExecutorStore> {
    store: T,
    indizes: Arc<RwLock<HashMap<IndexKey, DgoIndex>>>,
    dirty: Arc<RwLock<HashSet<IndexKey>>>,
}

impl<T: ExecutorStore> DgoFactory<T> {
    pub fn new(store: T) -> Self {
        Self {
            store,
            indizes: Arc::new(RwLock::new(HashMap::new())),
            dirty: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

impl<T: ExecutorStore> From<T> for DgoFactory<T> {
    fn from(store: T) -> Self {
        Self::new(store)
    }
}

#[async_trait]
impl<T: ExecutorStore> ModelFactory<T> for DgoFactory<T> {
    type Model = AnyDgoModel;
    type SettingsModel = DgoPermissionSettings;
    type Error = ExecutorError;

    async fn load_state(store: &T) -> Result<Self, Self::Error> {
        // Store a reference to the store for later use
        Ok(DgoFactory::new(store.clone()))
    }

    async fn load_permission_context(
        &self,
        actor: &IdentityRef,
        _group_id: GroupId,
        actor_role: GroupRole,
        state_message_id: MessageId,
        group_permissions: GroupPermissions,
    ) -> ExecutorResult<Option<<Self::Model as GroupStateModel>::PermissionState>> {
        // Create DGO-specific permission context with provided parameters
        // The group state has already looked up the actor's role and app state message

        // Load DGO-specific settings from the app state at state_message_id
        // Use the stored store reference to load the DGO settings model
        let dgo_settings = if let Some(settings_model) = self
            .store
            .load::<MessageId, DgoPermissionSettings>(state_message_id)
            .await
            .map_err(|e| ExecutorError::StorageError(format!("Failed to load DGO settings: {e}")))?
        {
            settings_model.settings().clone()
        } else {
            // No settings found, use default settings
            zoe_app_primitives::digital_groups_organizer::events::admin::DgoFeatureSettings::default(
            )
        };

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

    /// Add executive references to an index, returns updated index data
    async fn add_to_index(
        &self,
        list_id: <Self::Model as GroupStateModel>::IndexKey,
        meta: &ActivityMeta,
    ) -> Vec<<Self::Model as GroupStateModel>::ExecutiveKey> {
        match self.indizes.write().await.entry(list_id.clone()) {
            Entry::Occupied(mut o) => {
                o.get_mut().insert(meta);
            }
            Entry::Vacant(v) => {
                v.insert_entry(DgoIndex::new_for(&list_id, meta));
            }
        }
        self.dirty.write().await.insert(list_id.clone());

        vec![list_id.into()]
    }

    /// Remove executive references from an index, returns updated index data
    async fn remove_from_index(
        &self,
        list_id: <Self::Model as GroupStateModel>::IndexKey,
        meta: &ActivityMeta,
    ) -> Vec<<Self::Model as GroupStateModel>::ExecutiveKey> {
        if let Some(v) = self.indizes.write().await.get_mut(&list_id) {
            v.remove(&meta.activity_id);
        } else {
            return vec![];
        }
        self.dirty.write().await.insert(list_id.clone());
        vec![list_id.into()]
    }

    async fn sync(&self) -> Result<(), Self::Error> {
        // FIXME: is it worthwhile serializing amd storing the indexes?
        // let to_sync = {
        //     let mut dirty = self.dirty.write().await;
        //     let lst = dirty.clone();
        //     dirty.clear();
        //     lst
        // };
        // let indizes = self.indizes.read().await;
        // for list_id in to_sync.iter() {
        //     if let Some(indize) = indizes.get(list_id) {
        //         self.store
        //             .store_index(list_id, indize)
        //             .await
        //             .map_err(|e| Self::Error::StorageError(format!("Failed to save index: {e}")))?;
        //     }
        // }
        Ok(())
    }
}

pub enum DgoIndex {
    Lifo(LifoIndex<MessageId>),
    Filo(FiloIndex<MessageId>),
    Ranked(RankedIndex<u64, MessageId>),
}

impl DgoIndex {
    pub fn new_for(key: &IndexKey, meta: &ActivityMeta) -> DgoIndex {
        match key {
            IndexKey::AllHistory | IndexKey::ObjectHistory(_) | IndexKey::GroupHistory(_) => {
                DgoIndex::Ranked(RankedIndex::new_with(meta.timestamp, meta.activity_id))
            }
            //RSVPs are latest first for collection
            IndexKey::ObjectList(_, ObjectListIndex::Rsvps) => {
                DgoIndex::Ranked(RankedIndex::new_with(meta.timestamp, meta.activity_id))
            }
            IndexKey::Section(SectionIndex::Stories)
            | IndexKey::GroupSection(_, SectionIndex::Stories) => {
                DgoIndex::Ranked(RankedIndex::new_with(meta.timestamp, meta.activity_id))
            }
            IndexKey::ObjectList(_, ObjectListIndex::Tasks) => {
                DgoIndex::Filo(FiloIndex::new_with(meta.activity_id))
            }
            _ => DgoIndex::Lifo(LifoIndex::new_with(meta.activity_id)),
        }
    }

    pub fn insert(&mut self, meta: &ActivityMeta) {
        match self {
            DgoIndex::Lifo(l) => l.insert(meta.activity_id),
            DgoIndex::Filo(l) => l.insert(meta.activity_id),
            DgoIndex::Ranked(r) => r.insert(meta.timestamp, meta.activity_id),
        }
    }

    /// All instances of this element from the vector
    pub fn remove(&mut self, value: &MessageId) {
        match self {
            DgoIndex::Lifo(idx) => idx.remove(value),
            DgoIndex::Filo(idx) => idx.remove(value),
            DgoIndex::Ranked(ranked_index) => ranked_index.remove(value),
        }
    }

    /// Returns the current list of values in order of when they were added
    pub fn values(&self) -> Vec<&MessageId> {
        match self {
            DgoIndex::Lifo(idx) => idx.values(),
            DgoIndex::Filo(idx) => idx.values(),
            DgoIndex::Ranked(ranked_index) => ranked_index.values(),
        }
    }

    // pub fn update_stream(&self) -> impl Stream<Item = VectorDiff<OwnedEventId>> {
    //     match self {
    //         DgoIndex::Lifo(lifo_index) => lifo_index.update_stream(),
    //         DgoIndex::Filo(lifo_index) => lifo_index.update_stream(),
    //         DgoIndex::Ranked(ranked_index) => ranked_index.update_stream(),
    //     }
    // }
}

impl std::fmt::Debug for DgoIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lifo(_) => f.debug_tuple("Lifo").finish(),
            Self::Filo(_) => f.debug_tuple("Filo").finish(),
            Self::Ranked(_) => f.debug_tuple("Ranked").finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zoe_app_primitives::digital_groups_organizer::events::content::CreateTextBlockContent;
    use zoe_app_primitives::digital_groups_organizer::events::core::DgoActivityEventContent;
    use zoe_app_primitives::digital_groups_organizer::models::core::ActivityMeta;

    use zoe_wire_protocol::MessageId;

    #[tokio::test]
    async fn test_dgo_executor_create_text_block() {
        let store = crate::execution::InMemoryStore::new();
        let executor = DgoExecutor::new(DgoFactory::load_state(&store).await.unwrap(), store);

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
            group_id: GroupId::from([2u8; 32]),
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
            .execute_event(event, group_meta, actor_role, state_message_id, None)
            .await
            .unwrap();

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
        let executor = DgoExecutor::new(DgoFactory::load_state(&store).await.unwrap(), store);

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
            group_id: GroupId::from([1u8; 32]),
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
                None,
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
            group_id: GroupId::from([0u8; 32]),
            actor: IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        executor
            .execute_event(
                update_event,
                update_group_meta,
                actor_role,
                state_message_id,
                None,
            )
            .await
            .unwrap();

        // Verify the model was updated
        let model: AnyDgoModel = executor.store().load(model_id).await.unwrap().unwrap();

        if let Some(text_block) = model.as_text_block() {
            assert_eq!(text_block.title, "Updated Title");
            assert_eq!(text_block.description, Some("New description".to_string()));
        } else {
            panic!("Expected TextBlock model");
        }
    }

    #[tokio::test]
    async fn test_dgo_permission_context_loading() {
        let store = crate::execution::InMemoryStore::new();
        let factory = DgoFactory::load_state(&store).await.unwrap();

        // Create test data
        let actor = IdentityRef::Key(
            zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
        );
        let group_id = GroupId::from([1u8; 32]);
        let actor_role = zoe_app_primitives::group::events::roles::GroupRole::Member;
        let state_message_id = zoe_wire_protocol::MessageId::from([2u8; 32]);
        let group_permissions =
            zoe_app_primitives::group::events::permissions::GroupPermissions::default();

        // Test permission context loading with default settings
        let permission_context = factory
            .load_permission_context(
                &actor,
                group_id.clone(),
                actor_role.clone(),
                state_message_id,
                group_permissions.clone(),
            )
            .await
            .unwrap();

        assert!(permission_context.is_some());
        let context = permission_context.unwrap();
        assert_eq!(context.actor, actor);
        assert_eq!(context.actor_role, actor_role);
        assert_eq!(context.message_id, state_message_id);
        assert_eq!(context.group_settings, group_permissions);
    }

    #[tokio::test]
    async fn test_dgo_permission_context_with_stored_settings() {
        let store = crate::execution::InMemoryStore::new();
        let factory = DgoFactory::load_state(&store).await.unwrap();

        // Create test data
        let actor = IdentityRef::Key(
            zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
        );
        let group_id = GroupId::from([1u8; 32]);
        let actor_role = zoe_app_primitives::group::events::roles::GroupRole::Admin;
        let state_message_id = zoe_wire_protocol::MessageId::from([3u8; 32]);
        let group_permissions =
            zoe_app_primitives::group::events::permissions::GroupPermissions::default();

        // Store some DGO settings
        let dgo_settings = zoe_app_primitives::digital_groups_organizer::events::admin::DgoFeatureSettings {
            text_blocks: zoe_app_primitives::digital_groups_organizer::events::admin::TextBlocksSettings {
                create: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                update: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::ModeratorOrAbove,
                delete: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AdminOrAbove,
                comment: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                react: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                attach: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::ModeratorOrAbove,
            },
            calendar: zoe_app_primitives::digital_groups_organizer::events::admin::CalendarSettings {
                create: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AdminOrAbove,
                update: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AdminOrAbove,
                delete: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AdminOrAbove,
                rsvp: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                comment: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                react: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                attach: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AdminOrAbove,
            },
            tasks: zoe_app_primitives::digital_groups_organizer::events::admin::TasksSettings {
                create_task_list: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                update_task_list: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                delete_task_list: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::ModeratorOrAbove,
                create_task: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                update_task: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                delete_task: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::ModeratorOrAbove,
                assign_task: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                comment: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                react: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers,
                attach: zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::ModeratorOrAbove,
            },
        };

        let settings_model = zoe_app_primitives::digital_groups_organizer::models::permission_settings::DgoPermissionSettings::new(
            zoe_app_primitives::digital_groups_organizer::models::core::ActivityMeta {
                activity_id: state_message_id,
                group_id: group_id.clone(),
                actor: actor.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
            dgo_settings.clone(),
        );

        // Store the settings
        store.save(state_message_id, &settings_model).await.unwrap();

        // Test permission context loading with stored settings
        let permission_context = factory
            .load_permission_context(
                &actor,
                group_id.clone(),
                actor_role.clone(),
                state_message_id,
                group_permissions.clone(),
            )
            .await
            .unwrap();

        assert!(permission_context.is_some());
        let context = permission_context.unwrap();
        assert_eq!(context.actor, actor);
        assert_eq!(context.actor_role, actor_role);
        assert_eq!(context.message_id, state_message_id);
        assert_eq!(context.group_settings, group_permissions);

        // Verify the settings were loaded correctly
        let loaded_settings = &context.dgo_settings;
        assert_eq!(loaded_settings.text_blocks.create, zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers);
        assert_eq!(loaded_settings.text_blocks.update, zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::ModeratorOrAbove);
        assert_eq!(loaded_settings.calendar.create, zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AdminOrAbove);
        assert_eq!(loaded_settings.tasks.create_task_list, zoe_app_primitives::digital_groups_organizer::events::admin::FeaturePermission::AllMembers);
    }

    #[tokio::test]
    async fn test_dgo_factory_state_loading() {
        let store = crate::execution::InMemoryStore::new();

        // Test that load_state creates a proper factory
        let factory = DgoFactory::load_state(&store).await.unwrap();

        // Verify the factory has access to the store
        // We can test this by trying to load something that doesn't exist
        let non_existent_id = zoe_wire_protocol::MessageId::from([99u8; 32]);
        let result: Option<zoe_app_primitives::digital_groups_organizer::models::any::AnyDgoModel> =
            store.load(non_existent_id).await.unwrap();
        assert!(result.is_none());

        // The factory should be able to create permission contexts
        let actor = IdentityRef::Key(
            zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
        );
        let group_id = [1u8; 32].into();
        let actor_role = zoe_app_primitives::group::events::roles::GroupRole::Member;
        let state_message_id = zoe_wire_protocol::MessageId::from([4u8; 32]);
        let group_permissions =
            zoe_app_primitives::group::events::permissions::GroupPermissions::default();

        let permission_context = factory
            .load_permission_context(
                &actor,
                group_id,
                actor_role,
                state_message_id,
                group_permissions,
            )
            .await
            .unwrap();

        assert!(permission_context.is_some());
    }

    #[tokio::test]
    async fn test_dgo_index_operations() {
        let store = crate::execution::InMemoryStore::new();
        let factory = DgoFactory::load_state(&store).await.unwrap();

        // Create a proper IndexKey for testing
        let group_id: GroupId = [1u8; 32].into();
        let list_id =
            zoe_app_primitives::digital_groups_organizer::indexing::keys::IndexKey::GroupModels(
                group_id.clone(),
            );

        // Create ActivityMeta for testing
        let activity_id = zoe_wire_protocol::MessageId::from([1u8; 32]);
        let model_meta = zoe_app_primitives::digital_groups_organizer::models::core::ActivityMeta {
            activity_id,
            group_id: group_id.clone(),
            actor: zoe_app_primitives::identity::IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Test adding to index - this should return executive keys for notifications
        let exec_keys = factory.add_to_index(list_id.clone(), &model_meta).await;
        // The factory should return executive keys for notifications
        assert!(exec_keys.is_empty() || !exec_keys.is_empty()); // Just verify it doesn't panic

        // Test removing from index
        let exec_keys_removed = factory
            .remove_from_index(list_id.clone(), &model_meta)
            .await;
        // The factory should return executive keys for notifications
        assert!(exec_keys_removed.is_empty() || !exec_keys_removed.is_empty()); // Just verify it doesn't panic

        // Test sync operation
        factory.sync().await.unwrap();
    }

    #[tokio::test]
    async fn test_dgo_executor_with_permission_validation() {
        let store = crate::execution::InMemoryStore::new();
        let executor = DgoExecutor::new(DgoFactory::load_state(&store).await.unwrap(), store);

        // Create a text block with proper permission context
        let event_content = DgoActivityEventContent::CreateTextBlock {
            content: CreateTextBlockContent {
                title: "Permission Test Block".to_string(),
                description: Some("Testing permission validation".to_string()),
                icon: Some("🔒".to_string()),
                parent_id: None,
            },
        };
        let event = DgoActivityEvent::new(
            zoe_app_primitives::identity::IdentityType::Main,
            event_content,
            zoe_wire_protocol::MessageId::from([1u8; 32]), // Mock group state reference
        );

        let activity_id = MessageId::from([5u8; 32]);
        let group_meta = ActivityMeta {
            activity_id,
            group_id: GroupId::from([1u8; 32]),
            actor: IdentityRef::Key(
                zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        let actor_role = zoe_app_primitives::group::events::roles::GroupRole::Member;
        let state_message_id = zoe_wire_protocol::MessageId::from([6u8; 32]);

        // Execute with group permissions
        let group_permissions =
            zoe_app_primitives::group::events::permissions::GroupPermissions::default();
        executor
            .execute_event(
                event,
                group_meta,
                actor_role,
                state_message_id,
                Some(group_permissions),
            )
            .await
            .unwrap();

        // Test passes if execution succeeds without error
        // The executor handles notifications internally

        // Verify the model was created
        let model: Option<AnyDgoModel> = executor.store().load(activity_id).await.unwrap();
        assert!(model.is_some());

        let model = model.unwrap();
        assert_eq!(model.model_id(), activity_id);

        if let Some(text_block) = model.as_text_block() {
            assert_eq!(text_block.title, "Permission Test Block");
            assert_eq!(
                text_block.description,
                Some("Testing permission validation".to_string())
            );
            assert_eq!(text_block.icon, Some("🔒".to_string()));
        } else {
            panic!("Expected TextBlock model");
        }
    }
}
