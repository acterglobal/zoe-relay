//! Unified generic executor for event-sourced models
//!
//! This module provides a unified executor that works with the new GroupStateModel trait,
//! supporting both synchronous and asynchronous execution patterns with flexible
//! permission context handling.

use async_broadcast::{Receiver, Sender, broadcast};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use zoe_wire_protocol::MessageId;

use super::{error::ExecutorError, model_factory::ModelFactory, store::ExecutorStore};
use zoe_app_primitives::{
    digital_groups_organizer::models::core::ActivityMeta,
    group::{
        app::{ExecutorEvent, GroupStateModel, IndexChange, ModelExecutionUpdateInfo},
        events::roles::GroupRole,
    },
};
type Notifiers<E> = Arc<RwLock<BTreeMap<E, Sender<()>>>>;
/// Unified generic executor for event-sourced models
///
/// This executor works with any ModelFactory and ExecutorStore combination.
/// It handles model creation, execution, storage, and notifications.
#[derive(Debug, Clone)]
pub struct GenericExecutor<TFactory, TStore>
where
    TFactory: ModelFactory<TStore> + Send + Sync + 'static,
    TStore: ExecutorStore + Send + Sync + 'static,
{
    factory: TFactory,
    store: TStore,
    notifiers: Notifiers<<TFactory::Model as GroupStateModel>::ExecutiveKey>,
}

impl<TFactory, TStore> GenericExecutor<TFactory, TStore>
where
    TFactory: ModelFactory<TStore> + Send + Sync + 'static,
    TStore: ExecutorStore + Send + Sync + 'static,
    TFactory::SettingsModel: GroupStateModel<
        PermissionState = <<TFactory as ModelFactory<TStore>>::Model as GroupStateModel>::PermissionState,
        ExecutiveKey = <<TFactory as ModelFactory<TStore>>::Model as GroupStateModel>::ExecutiveKey,
    >,
{
    /// Create a new generic executor
    pub fn new(factory: TFactory, store: TStore) -> Self {
        Self {
            factory,
            store,
            notifiers: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Subscribe to notifications for a specific executive key
    pub async fn subscribe(
        &self,
        key: <TFactory::Model as GroupStateModel>::ExecutiveKey,
    ) -> Receiver<()> {
        let mut notifiers = self.notifiers.write().await;

        if let Some(sender) = notifiers.get(&key)
            && !sender.is_closed() { // closed senders need to be dropped and restarted
                return sender.new_receiver();
            }

        let (sender, receiver) = broadcast(16);
        notifiers.insert(key, sender);
        receiver
    }

    async fn notify_many(&self, keys: &[<TFactory::Model as GroupStateModel>::ExecutiveKey]) {
        let mut notifiers = self.notifiers.write().await;
        for key in keys {
            if let Some(sender) = notifiers.get(key)
                && let Err(async_broadcast::TrySendError::Closed(_)) = sender.try_broadcast(()) {
                    // the receivers have all dropped and the sender is closed. let's evict to spare
                    // memory and computational resources.
                    notifiers.remove(key);
                }
        }
    }

    async fn save_and_notify(&self,
        execution_results: Vec<ModelExecutionUpdateInfo<TFactory::Model>>
    ) -> Result<(), ExecutorError>
    {

        let mut all_exec_keys: Vec<<TFactory::Model as GroupStateModel>::ExecutiveKey> =
            Vec::new();

        // Process execution results
        for execution_info in execution_results.into_iter() {
            // Store any models created by the default settings model
            for (updated_model, index_changes) in execution_info.updated_models.into_iter() {
                let model_meta = updated_model.activity_meta().clone();
                self.store
                    .save(model_meta.activity_id, &updated_model)
                    .await
                    .map_err(|e| e.into())?;

                for index_change in index_changes.into_iter() {
                    // apply the index changes and add any further executive keys to the list to notify about
                    all_exec_keys.extend( match index_change {
                        IndexChange::Added(index_key) => {
                            self.factory.add_to_index(index_key, &model_meta).await
                        }
                        IndexChange::Removed(index_key) => {
                            self.factory.remove_from_index(index_key, &model_meta).await
                        }
                    });
                }
            }

            // Add any executive references to indexes
            all_exec_keys.extend(execution_info.updated_references);
        }

        all_exec_keys.dedup(); // we only want to notify about each once.

        // Send notifications
        self.notify_many(&all_exec_keys).await;
        self.factory.sync().await.map_err(|e| e.into())?;

        Ok(())
    }

    /// Execute a settings event and return the executive keys for broadcasting
    ///
    /// This method handles settings events separately from regular content events.
    /// Settings events are processed using the default settings model pattern.
    pub async fn execute_settings_event(
        &self,
        event: <TFactory::SettingsModel as  GroupStateModel>::Event,
        group_meta: ActivityMeta,
        actor_role: GroupRole,
        state_message_id: MessageId,
    ) -> Result<(), ExecutorError>
    {

        let permission_context = self
            .factory
            .load_permission_context(
                &group_meta.actor,
                group_meta.group_id.clone(),
                actor_role.clone(),
                state_message_id,
                zoe_app_primitives::group::events::permissions::GroupPermissions::default(), // Settings events use default permissions for now
            )
            .await
            .map_err(|e| {
                ExecutorError::PermissionError(format!("Failed to load permission context: {e:?}"))
            })?
            .ok_or_else(|| {
                ExecutorError::PermissionError(
                    "No permission context available for settings event execution".to_string(),
                )
            })?;

        let mut default_settings_model = TFactory::SettingsModel::default_model(group_meta);
        // Execute the settings event on the default settings model
        // Both Model and SettingsModel use the same PermissionState type
        let execution_results = default_settings_model.execute(&event, &permission_context).map_err(|e| {
                ExecutorError::EventExecutionFailed(format!(
                    "Settings event execution failed: {:?}",
                    e.into()
                ))
            })?;
        // FIXME: due to the serttings model not having indixes, this has a slightly different layout
        let mut all_exec_keys: Vec<<TFactory::SettingsModel as GroupStateModel>::ExecutiveKey> =
            Vec::new();
        for execution_info in execution_results.into_iter() {
            // Store any models created by the default settings model
            for (updated_model, _) in execution_info.updated_models.into_iter() {
                // It feels like we might want to clean this up more, as settings have no indexes we care about
                let model_meta = updated_model.activity_meta().clone();
                self.store
                    .save(model_meta.activity_id, &updated_model)
                    .await
                    .map_err(|e| e.into())?;
            }
            all_exec_keys.extend(execution_info.updated_references);
        }
        self.notify_many(&all_exec_keys).await;
        Ok(())
    }

    /// Execute an event and return the executive keys for broadcasting
    ///
    /// This is the main entry point for event processing. The executor:
    /// 1. Determines which models the event affects
    /// 2. Loads those models from storage or creates new ones
    /// 3. Applies the event to each model
    /// 4. Saves all modified models and updates lists
    /// 5. Sends notifications and returns executive keys
    pub async fn execute_event(
        &self,
        event: <TFactory::Model as GroupStateModel>::Event,
        group_meta: ActivityMeta,
        actor_role: GroupRole,
        state_message_id: MessageId,
        group_permissions: Option<zoe_app_primitives::group::events::permissions::GroupPermissions>,
    ) -> Result<(), ExecutorError> {
        let permission_context = self
            .factory
            .load_permission_context(
                &group_meta.actor,
                group_meta.group_id.clone(),
                actor_role.clone(),
                state_message_id,
                group_permissions.unwrap_or_default(),
            )
            .await
            .map_err(|e| {
                ExecutorError::PermissionError(format!("Failed to load permission context: {e:?}"))
            })?
            .ok_or_else(|| {
                ExecutorError::PermissionError(
                    "No permission context available for settings event execution".to_string(),
                )
            })?;

        let execution_results = if let Some(model_ids) = event.applies_to() {

            let loaded_models = self
                .store
                .load_many::<MessageId, TFactory::Model>(&model_ids)
                .await
                .map_err(|e| e.into())?;

            let mut execution_results = vec![];

            // 5. Apply event to all affected models
            for mut model in loaded_models.into_iter().flatten() {
                // Apply the event to this model
                let execution_result = model.execute(&event, &permission_context).map_err(|e| {
                    ExecutorError::EventExecutionFailed(format!(
                        "Event execution failed: {:?}",
                        e.into()
                    ))
                })?;
                execution_results.extend(execution_result);
            }
            execution_results
        } else {
            let mut default_model = TFactory::Model::default_model(group_meta);
            default_model
                .execute(&event, &permission_context)
                .map_err(|e| {
                    ExecutorError::EventExecutionFailed(format!(
                        "Event execution failed: {:?}",
                        e.into()
                    ))
                })?
        };
        self.save_and_notify(execution_results).await?;
        Ok(())
    }

    /// Get access to the store for direct operations
    pub fn store(&self) -> &TStore {
        &self.store
    }

    /// Get access to the factory for direct operations  
    pub fn factory(&self) -> &TFactory {
        &self.factory
    }
}

// Test implementations and mock types
#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde::{Deserialize, Serialize};

    use zoe_app_primitives::{
        digital_groups_organizer::{
            indexing::keys::{ExecuteReference, IndexKey},
            models::core::ActivityMeta,
        },
        identity::IdentityRef,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MockModel {
        meta: ActivityMeta,
        data: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MockSettingsModel {
        meta: ActivityMeta,
        settings: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum MockEvent {
        Create {
            data: String,
        },
        Update {
            target_id: MessageId,
            new_data: String,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    enum MockSettingsEvent {
        UpdateSettings { new_settings: String },
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MockPermissionContext {
        actor: IdentityRef,
        group_id: MessageId,
        is_member: bool,
    }

    impl zoe_app_primitives::group::app::AppPermissionState for MockPermissionContext {}

    impl zoe_app_primitives::group::app::ExecutorEvent for MockSettingsEvent {
        fn applies_to(&self) -> Option<Vec<MessageId>> {
            None // Settings events don't apply to specific models
        }

        fn group_state_reference(&self) -> MessageId {
            // Return a mock group state reference
            MessageId::from_bytes([2; 32])
        }
    }

    impl zoe_app_primitives::group::app::ExecutorEvent for MockEvent {
        fn applies_to(&self) -> Option<Vec<MessageId>> {
            match self {
                MockEvent::Create { .. } => None, // Create events don't affect existing models
                MockEvent::Update { target_id, .. } => Some(vec![*target_id]),
            }
        }

        fn group_state_reference(&self) -> MessageId {
            // Return a mock group state reference
            MessageId::from_bytes([1; 32])
        }
    }

    impl GroupStateModel for MockSettingsModel {
        type Event = MockSettingsEvent;
        type PermissionState = MockPermissionContext;
        type Error = zoe_app_primitives::group::app::ExecuteError;
        type ExecutiveKey = ExecuteReference;
        type IndexKey = IndexKey;

        fn default_model(group_meta: ActivityMeta) -> Self {
            MockSettingsModel {
                meta: group_meta,
                settings: "default".to_string(),
            }
        }

        fn activity_meta(&self) -> &ActivityMeta {
            &self.meta
        }

        fn execute(
            &mut self,
            event: &Self::Event,
            _context: &Self::PermissionState,
        ) -> Result<
            Vec<
                zoe_app_primitives::group::app::ExecutionUpdateInfo<
                    Self,
                    Self::ExecutiveKey,
                    Self::IndexKey,
                >,
            >,
            Self::Error,
        > {
            use zoe_app_primitives::group::app::ExecutionUpdateInfo;

            match event {
                MockSettingsEvent::UpdateSettings { new_settings } => {
                    self.settings = new_settings.clone();
                    let update_info = ExecutionUpdateInfo::new()
                        .add_model(self.clone())
                        .add_reference(ExecuteReference::Model(self.meta.activity_id));
                    Ok(vec![update_info])
                }
            }
        }

        fn redact(&self, _context: &Self::PermissionState) -> Result<Vec<Self>, Self::Error> {
            Ok(vec![])
        }
    }

    impl GroupStateModel for MockModel {
        type Event = MockEvent;
        type PermissionState = MockPermissionContext;
        type Error = zoe_app_primitives::group::app::ExecuteError;
        type ExecutiveKey = ExecuteReference;
        type IndexKey = IndexKey;

        fn default_model(group_meta: ActivityMeta) -> Self {
            MockModel {
                meta: group_meta,
                data: "default".to_string(),
            }
        }

        fn activity_meta(&self) -> &ActivityMeta {
            &self.meta
        }

        fn execute(
            &mut self,
            event: &Self::Event,
            _context: &Self::PermissionState,
        ) -> Result<
            Vec<
                zoe_app_primitives::group::app::ExecutionUpdateInfo<
                    Self,
                    Self::ExecutiveKey,
                    Self::IndexKey,
                >,
            >,
            Self::Error,
        > {
            use zoe_app_primitives::group::app::ExecutionUpdateInfo;

            match event {
                MockEvent::Update {
                    target_id,
                    new_data,
                } => {
                    if *target_id == self.meta.activity_id {
                        self.data = new_data.clone();
                        let update_info = ExecutionUpdateInfo::new()
                            .add_model(self.clone())
                            .add_reference(ExecuteReference::Model(self.meta.activity_id));
                        Ok(vec![update_info])
                    } else {
                        Ok(vec![])
                    }
                }
                MockEvent::Create { .. } => {
                    // For create events, return the model itself
                    let update_info = ExecutionUpdateInfo::new()
                        .add_model(self.clone())
                        .add_reference(ExecuteReference::Model(self.meta.activity_id));
                    Ok(vec![update_info])
                }
            }
        }

        fn redact(&self, _context: &Self::PermissionState) -> Result<Vec<Self>, Self::Error> {
            Ok(vec![])
        }
    }

    // For backwards compatibility in tests
    type MockStore = crate::execution::InMemoryStore;

    struct MockFactory;

    #[async_trait]
    impl<T: ExecutorStore> ModelFactory<T> for MockFactory {
        type Model = MockModel;
        type SettingsModel = MockSettingsModel; // Separate settings model
        type Error = ExecutorError;

        async fn load_state(_store: &T) -> Result<Self, Self::Error> {
            Ok(MockFactory)
        }

        async fn load_permission_context(
            &self,
            actor: &IdentityRef,
            group_id: zoe_app_primitives::group::events::GroupId,
            _actor_role: zoe_app_primitives::group::events::roles::GroupRole,
            _state_message_id: MessageId,
            _group_permissions: zoe_app_primitives::group::events::permissions::GroupPermissions,
        ) -> Result<Option<MockPermissionContext>, Self::Error> {
            Ok(Some(MockPermissionContext {
                actor: actor.clone(),
                group_id: MessageId::from_bytes(group_id.as_slice().try_into().unwrap_or([0; 32])), // Convert GroupId back to MessageId for mock
                is_member: true,
            }))
        }

        /// Add executive references to an index, returns updated index data
        async fn add_to_index(
            &self,
            _list_id: <Self::Model as GroupStateModel>::IndexKey,
            _model_keys: &ActivityMeta,
        ) -> Vec<<Self::Model as GroupStateModel>::ExecutiveKey> {
            vec![]
        }

        /// Remove executive references from an index, returns updated index data
        async fn remove_from_index(
            &self,
            _list_id: <Self::Model as GroupStateModel>::IndexKey,
            _model_keys: &ActivityMeta,
        ) -> Vec<<Self::Model as GroupStateModel>::ExecutiveKey> {
            vec![]
        }

        async fn sync(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_generic_executor_create_event() {
        let store = MockStore::new();
        let factory = MockFactory;
        let executor = GenericExecutor::new(factory, store);

        let event = MockEvent::Create {
            data: "test data".to_string(),
        };
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
        let state_message_id = MessageId::from([2u8; 32]);
        executor
            .execute_event(event, group_meta, actor_role, state_message_id, None)
            .await
            .unwrap();
        // Test passes if execution succeeds without error
    }
}
