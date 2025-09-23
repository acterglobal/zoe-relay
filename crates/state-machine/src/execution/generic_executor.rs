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
use zoe_app_primitives::group::app::{GroupEvent, GroupStateModel};
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
        let key_string = format!("{:?}", key);

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
        let key_string = format!("{:?}", key);
        if let Some(sender) = notifiers.get(&key_string) {
            // Ignore errors - if there are no receivers, that's fine
            let _ = sender.send(key.clone());
        }
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
        activity_id: MessageId,
    ) -> Result<Vec<<TFactory::Model as GroupStateModel>::ExecutiveKey>, ExecutorError> {
        // 1. Check if event has acknowledgments that need validation
        if event.acknowledgment().is_some() {
            // TODO: Add full acknowledgment validation logic here
            // For now, we just extract and validate that acknowledgments exist
            let _acknowledgment = event.acknowledgment().ok_or_else(|| {
                ExecutorError::EventExecutionFailed(
                    "Event should have acknowledgment but none found".to_string(),
                )
            })?;

            // Future: Add timestamp validation, sender tracking, etc.
        }

        // 2. Get all model IDs that this event affects
        let affected_model_ids = event.applies_to();
        let mut all_exec_keys: Vec<<TFactory::Model as GroupStateModel>::ExecutiveKey> = Vec::new();

        // 3. Check if this is a create event (no existing models affected)
        if affected_model_ids.is_none() {
            // Try to create a new model from the factory
            if let Some(new_model) = self
                .factory
                .create_model_from_event(&event, activity_id)
                .await
                .map_err(|e| {
                    ExecutorError::ModelCreationFailed(format!("Model creation failed: {:?}", e))
                })?
            {
                // Create default permission context for execution
                let default_context = self
                    .factory
                    .load_permission_context(
                        &new_model.activity_meta().actor,
                        new_model.activity_meta().group_id,
                    )
                    .await
                    .map_err(|e| {
                        ExecutorError::PermissionError(format!(
                            "Failed to load permission context: {:?}",
                            e
                        ))
                    })?
                    .ok_or_else(|| {
                        ExecutorError::PermissionError(
                            "No permission context available for event execution".to_string(),
                        )
                    })?;

                let mut model = new_model;
                let execution_results = model.execute(&event, &default_context).map_err(|e| {
                    ExecutorError::EventExecutionFailed(format!(
                        "Event execution failed: {:?}",
                        e.into()
                    ))
                })?;

                // Process execution results
                for execution_info in execution_results {
                    // Clone the models before iterating to avoid move issues
                    let _models_to_store = execution_info.updated_models.clone();

                    for updated_model in &execution_info.updated_models {
                        self.store
                            .save(updated_model.activity_meta().activity_id, updated_model)
                            .await
                            .map_err(|e| e.into())?;
                    }

                    for exec_ref in &execution_info.updated_references {
                        // Use the pre-cloned models
                        self.factory
                            .add_to_index(&self.store, (*exec_ref).clone(), &[(*exec_ref).clone()])
                            .await?;

                        all_exec_keys.push((*exec_ref).clone());
                    }
                }

                // Send notifications
                for key in &all_exec_keys {
                    self.notify(key).await;
                }

                return Ok(all_exec_keys);
            }

            // No model created, return empty references
            return Ok(vec![]);
        }

        // 4. Load existing models from the affected IDs
        let model_ids = affected_model_ids.unwrap();
        let loaded_models = self
            .store
            .load_many::<MessageId, TFactory::Model>(&model_ids)
            .await
            .map_err(|e| e.into())?;

        // 5. Apply event to all affected models
        for mut model in loaded_models.into_iter().flatten() {
            // Create a default permission context for this execution
            let default_context = self
                .factory
                .load_permission_context(
                    &model.activity_meta().actor,
                    model.activity_meta().group_id,
                )
                .await
                .map_err(|e| {
                    ExecutorError::PermissionError(format!(
                        "Failed to load permission context: {:?}",
                        e
                    ))
                })?
                .ok_or_else(|| {
                    ExecutorError::PermissionError(
                        "No permission context available for event execution".to_string(),
                    )
                })?;

            // Apply the event to this model
            let execution_results = model.execute(&event, &default_context).map_err(|e| {
                ExecutorError::EventExecutionFailed(format!(
                    "Event execution failed: {:?}",
                    e.into()
                ))
            })?;

            // Process execution results
            for execution_info in execution_results {
                // Clone the models before iterating to avoid move issues
                let _models_to_store = execution_info.updated_models.clone();

                // Store each updated model
                for updated_model in &execution_info.updated_models {
                    self.store
                        .save(updated_model.activity_meta().activity_id, updated_model)
                        .await
                        .map_err(|e| e.into())?;
                }

                // Update lists based on execute references
                for exec_ref in &execution_info.updated_references {
                    // Use the pre-cloned models
                    self.factory
                        .add_to_index(&self.store, (*exec_ref).clone(), &[(*exec_ref).clone()])
                        .await?;

                    all_exec_keys.push((*exec_ref).clone());
                }
            }
        }

        // 5. Send notifications
        for key in &all_exec_keys {
            self.notify(key).await;
        }

        Ok(all_exec_keys)
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
    struct MockPermissionContext {
        actor: IdentityRef,
        group_id: MessageId,
        is_member: bool,
    }

    impl zoe_app_primitives::group::app::PermissionContext for MockPermissionContext {
        fn actor(&self) -> &IdentityRef {
            &self.actor
        }

        fn group_id(&self) -> MessageId {
            self.group_id
        }

        fn is_group_member(&self) -> bool {
            self.is_member
        }
    }

    impl zoe_app_primitives::group::app::GroupEvent for MockEvent {
        fn applies_to(&self) -> Option<Vec<MessageId>> {
            match self {
                MockEvent::Create { .. } => None, // Create events don't affect existing models
                MockEvent::Update { target_id, .. } => Some(vec![*target_id]),
            }
        }

        fn acknowledgment(&self) -> Option<zoe_app_primitives::group::app::Acknowledgment> {
            // Mock events don't use acknowledgments for testing simplicity
            None
        }
    }

    impl GroupStateModel for MockModel {
        type Event = MockEvent;
        type PermissionContext = MockPermissionContext;
        type Error = zoe_app_primitives::group::app::ExecuteError;
        type ExecutiveKey = MessageId;

        fn activity_meta(&self) -> &ActivityMeta {
            &self.meta
        }

        fn execute(
            &mut self,
            event: &Self::Event,
            _context: &Self::PermissionContext,
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

        fn redact(&self, _context: &Self::PermissionContext) -> Result<Vec<Self>, Self::Error> {
            Ok(vec![])
        }
    }

    // For backwards compatibility in tests
    type MockStore = crate::execution::InMemoryStore;

    struct MockFactory;

    #[async_trait]
    impl ModelFactory for MockFactory {
        type Model = MockModel;
        type Error = ExecutorError;

        async fn load_state<T: ExecutorStore>(_store: &T) -> Result<Box<Self>, Self::Error> {
            Ok(Box::new(MockFactory))
        }

        async fn create_model_from_event(
            &self,
            event: &MockEvent,
            activity_id: MessageId,
        ) -> Result<Option<Self::Model>, Self::Error> {
            match event {
                MockEvent::Create { data } => {
                    let meta = ActivityMeta {
                        activity_id,
                        group_id: MessageId::from([0u8; 32]),
                        actor: IdentityRef::Key(
                            zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng())
                                .public_key(),
                        ),
                        timestamp: 1000,
                    };

                    Ok(Some(MockModel {
                        meta,
                        data: data.clone(),
                    }))
                }
                _ => Ok(None),
            }
        }

        async fn load_permission_context(
            &self,
            actor: &IdentityRef,
            group_id: MessageId,
        ) -> Result<Option<MockPermissionContext>, Self::Error> {
            Ok(Some(MockPermissionContext {
                actor: actor.clone(),
                group_id,
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

        let refs = executor.execute_event(event, activity_id).await.unwrap();
        assert!(!refs.is_empty());
    }
}
