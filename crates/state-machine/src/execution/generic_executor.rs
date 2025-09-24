//! Unified generic executor for event-sourced models
//!
//! This module provides a unified executor that works with the new GroupStateModel trait,
//! supporting both synchronous and asynchronous execution patterns with flexible
//! permission context handling.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use zoe_wire_protocol::MessageId;

use super::{error::ExecutorError, model_factory::ModelFactory, store::ExecutorStore};
use zoe_app_primitives::{
    digital_groups_organizer::models::core::ActivityMeta,
    group::{
        app::{ExecutionUpdateInfo, ExecutorEvent, GroupStateModel},
        events::roles::GroupRole,
    },
};
type Notifiers<E> = Arc<RwLock<HashMap<String, broadcast::Sender<E>>>>;
/// Unified generic executor for event-sourced models
///
/// This executor works with any ModelFactory and ExecutorStore combination.
/// It handles model creation, execution, storage, and notifications.
#[derive(Debug, Clone)]
pub struct GenericExecutor<TFactory, TStore>
where
    TFactory: ModelFactory + Send + Sync + 'static,
    TStore: ExecutorStore + Send + Sync + 'static,
{
    factory: TFactory,
    store: TStore,
    notifiers: Notifiers<<TFactory::Model as GroupStateModel>::ExecutiveKey>,
}

impl<TFactory, TStore> GenericExecutor<TFactory, TStore>
where
    TFactory: ModelFactory + Send + Sync + 'static,
    TStore: ExecutorStore + Send + Sync + 'static,
    TFactory::SettingsModel: GroupStateModel<
        PermissionState = <<TFactory as ModelFactory>::Model as GroupStateModel>::PermissionState,
        ExecutiveKey = <<TFactory as ModelFactory>::Model as GroupStateModel>::ExecutiveKey,
    >,
{
    /// Create a new generic executor
    pub fn new(factory: TFactory, store: TStore) -> Self {
        Self {
            factory,
            store,
            notifiers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Subscribe to notifications for a specific executive key
    pub async fn subscribe(
        &self,
        key: <TFactory::Model as GroupStateModel>::ExecutiveKey,
    ) -> broadcast::Receiver<<TFactory::Model as GroupStateModel>::ExecutiveKey> {
        let mut notifiers = self.notifiers.write().await;
        let key_string = format!("{key:?}");

        match notifiers.get(&key_string) {
            Some(sender) => sender.subscribe(),
            None => {
                let (sender, receiver) = broadcast::channel(16);
                notifiers.insert(key_string, sender);
                receiver
            }
        }
    }

    /// Send a notification for the given executive key
    async fn notify(&self, key: &<TFactory::Model as GroupStateModel>::ExecutiveKey) {
        let notifiers = self.notifiers.read().await;
        let key_string = format!("{key:?}");
        if let Some(sender) = notifiers.get(&key_string) {
            // Ignore errors - if there are no receivers, that's fine
            let _ = sender.send(key.clone());
        }
    }

    async fn save_and_notify<M: GroupStateModel>(&self,
        execution_results: Vec<ExecutionUpdateInfo<M, <TFactory::Model as GroupStateModel>::ExecutiveKey>>
    ) -> Result<Vec<<TFactory::SettingsModel as GroupStateModel>::ExecutiveKey>, ExecutorError>
    {

        let mut all_exec_keys: Vec<<TFactory::SettingsModel as GroupStateModel>::ExecutiveKey> =
            Vec::new();

        // Process execution results
        for execution_info in execution_results {
            // Store any models created by the default settings model
            for updated_model in &execution_info.updated_models {
                self.store
                    .save(updated_model.activity_meta().activity_id, updated_model)
                    .await
                    .map_err(|e| e.into())?;
            }

            // Add any executive references to indexes
            all_exec_keys.extend(execution_info.updated_references);
        }

        all_exec_keys.dedup(); // we only want to notify about each once.

        // Send notifications
        // Both Model and SettingsModel use the same ExecutiveKey type
        for key in &all_exec_keys {
            self.notify(key).await;
        }

        Ok(all_exec_keys)
    }

    /// Execute a settings event and return the executive keys for broadcasting
    ///
    /// This method handles settings events separately from regular content events.
    /// Settings events are processed using the default settings model pattern.
    pub async fn execute_settings_event(
        &self,
        event: <TFactory::SettingsModel as GroupStateModel>::Event,
        group_meta: ActivityMeta,
        actor_role: GroupRole,
        state_message_id: MessageId,
    ) -> Result<Vec<<TFactory::SettingsModel as GroupStateModel>::ExecutiveKey>, ExecutorError>
    {

        let permission_context = self
            .factory
            .load_permission_context(
                &group_meta.actor,
                group_meta.group_id.clone(),
                actor_role.clone(),
                state_message_id,
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

        self.save_and_notify(execution_results).await
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
    ) -> Result<Vec<<TFactory::Model as GroupStateModel>::ExecutiveKey>, ExecutorError> {
        let permission_context = self
            .factory
            .load_permission_context(
                &group_meta.actor,
                group_meta.group_id.clone(),
                actor_role.clone(),
                state_message_id,
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
        self.save_and_notify(execution_results).await
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
        digital_groups_organizer::models::core::ActivityMeta, identity::IdentityRef,
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
        type ExecutiveKey = MessageId;

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
            Vec<zoe_app_primitives::group::app::ExecutionUpdateInfo<Self, Self::ExecutiveKey>>,
            Self::Error,
        > {
            use zoe_app_primitives::group::app::ExecutionUpdateInfo;

            match event {
                MockSettingsEvent::UpdateSettings { new_settings } => {
                    self.settings = new_settings.clone();
                    let update_info = ExecutionUpdateInfo::new()
                        .add_model(self.clone())
                        .add_reference(self.meta.activity_id);
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
        type ExecutiveKey = MessageId;

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
            Vec<zoe_app_primitives::group::app::ExecutionUpdateInfo<Self, Self::ExecutiveKey>>,
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
                            .add_reference(self.meta.activity_id);
                        Ok(vec![update_info])
                    } else {
                        Ok(vec![])
                    }
                }
                MockEvent::Create { .. } => {
                    // For create events, return the model itself
                    let update_info = ExecutionUpdateInfo::new()
                        .add_model(self.clone())
                        .add_reference(self.meta.activity_id);
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
    impl ModelFactory for MockFactory {
        type Model = MockModel;
        type SettingsModel = MockSettingsModel; // Separate settings model
        type Error = ExecutorError;

        async fn load_state<T: ExecutorStore>(_store: &T) -> Result<Box<Self>, Self::Error> {
            Ok(Box::new(MockFactory))
        }

        async fn load_permission_context(
            &self,
            actor: &IdentityRef,
            group_id: zoe_app_primitives::group::events::GroupId,
            _actor_role: zoe_app_primitives::group::events::roles::GroupRole,
            _state_message_id: MessageId,
        ) -> Result<Option<MockPermissionContext>, Self::Error> {
            Ok(Some(MockPermissionContext {
                actor: actor.clone(),
                group_id: MessageId::from_bytes(group_id.as_slice().try_into().unwrap_or([0; 32])), // Convert GroupId back to MessageId for mock
                is_member: true,
            }))
        }

        async fn add_to_index<K, E>(
            &self,
            _store: &impl ExecutorStore,
            _list_id: K,
            _executive_refs: &[E],
        ) -> Result<(), ExecutorError>
        where
            K: serde::Serialize + Send + Sync + Clone,
            E: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Clone,
        {
            // Mock implementation - do nothing
            Ok(())
        }

        async fn remove_from_index<K, E>(
            &self,
            _store: &impl ExecutorStore,
            _list_id: K,
            _executive_refs: &[E],
        ) -> Result<(), ExecutorError>
        where
            K: serde::Serialize + Send + Sync + Clone,
            E: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Clone + PartialEq,
        {
            // Mock implementation - do nothing
            Ok(())
        }

        async fn load_models_from_index<K>(
            &self,
            _store: &impl ExecutorStore,
            _list_id: K,
        ) -> Result<Vec<Self::Model>, Self::Error>
        where
            K: serde::Serialize + Send + Sync + Clone,
        {
            // Mock implementation - return empty list
            Ok(vec![])
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
        let refs = executor
            .execute_event(event, group_meta, actor_role, state_message_id)
            .await
            .unwrap();
        assert!(!refs.is_empty());
    }
}
