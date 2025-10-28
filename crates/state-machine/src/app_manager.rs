//! Application Manager - Handles app-specific message processing
//!
//! The AppManager is responsible for:
//! - Subscribing to application channels based on notifications from GroupManager
//! - Processing app-specific messages through appropriate executors
//! - Coordinating with GroupManager for decryption and attestation
//! - Managing the lifecycle of app-specific subscriptions

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use zoe_app_primitives::group::events::GroupId;
use zoe_wire_protocol::ChannelId;

use crate::{
    apps::dgo::DgoExecutor, error::GroupResult, execution::ExecutorStore,
    messages::MessagesManagerTrait,
};

mod app_state;
mod dgo;
mod group_service;
mod sync;

pub use app_state::AppState;
pub use group_service::GroupAppService;

/// Manages app-specific message processing, decoupled from group management

#[derive(Clone)]
pub struct AppManager<
    M: MessagesManagerTrait,
    G: GroupAppService + 'static,
    S: ExecutorStore + 'static,
> {
    /// Message manager for subscribing to app channels
    message_manager: Arc<M>,

    /// Service for requesting decryption from GroupManager
    group_service: Arc<G>,

    /// DGO executor - always available for DGO app messages
    dgo_executor: Arc<DgoExecutor<S>>,

    /// Currently subscribed app channels
    /// Key: (group_id, app_tag) -> InstalledApp
    app_states: Arc<RwLock<HashMap<ChannelId, AppState>>>,

    // background handle
    handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl<
    M: MessagesManagerTrait + Clone + 'static,
    G: GroupAppService + Clone + 'static,
    S: ExecutorStore + Clone + 'static,
> AppManager<M, G, S>
{
    /// Create a new AppManager
    pub async fn new(message_manager: Arc<M>, group_service: Arc<G>, store: S) -> Self {
        let dgo_executor = Arc::new(Self::init_dgo_executor(&store).await);

        let app_states = Arc::new(RwLock::new(
            Self::load_app_states(group_service.clone()).await,
        ));

        let app_manager = Self {
            message_manager,
            group_service,
            dgo_executor,
            app_states,
            handle: Arc::new(RwLock::new(None)),
        };

        let task_handle = app_manager.start_background_tasks();
        *app_manager.handle.write().await = Some(task_handle);

        app_manager
    }

    /// Publish an app event to a group
    ///
    /// This is a generic method that delegates to the GroupService's publish_app_event method.
    /// App-specific logic (like DGO event creation) should be handled by the caller.
    ///
    /// # Arguments
    /// * `group_id` - The group to publish the event to
    /// * `app_tag` - The app channel tag to publish to
    /// * `event` - The app event to publish
    /// * `sender` - The keypair of the user publishing the event
    ///
    /// # Returns
    /// The published message containing the app event
    pub async fn publish_app_event<T: serde::Serialize + Send>(
        &self,
        group_id: &GroupId,
        app_tag: zoe_wire_protocol::ChannelId,
        event: T,
        sender: &zoe_wire_protocol::KeyPair,
    ) -> GroupResult<zoe_wire_protocol::MessageFull> {
        self.group_service
            .publish_app_event(group_id, app_tag, event, sender)
            .await
    }

    /// Get access to the DGO executor for testing and advanced operations
    pub fn dgo_executor(&self) -> &Arc<DgoExecutor<S>> {
        &self.dgo_executor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::GroupError, messages::MockMessagesManagerTrait};
    use serde::de::DeserializeOwned;
    use std::sync::Arc;
    use zoe_app_primitives::{
        group::{
            events::{permissions::GroupPermissions, roles::GroupRole},
            states::GroupState,
        },
        identity::IdentityRef,
        protocol::AppProtocolVariant,
    };
    use zoe_wire_protocol::{ChaCha20Poly1305Content, Filter, MessageId, PublishResult};

    #[derive(Clone)]
    struct MockGroupAppService;

    #[async_trait::async_trait]
    impl GroupAppService for MockGroupAppService {
        fn group_app_updates(
            &self,
        ) -> async_broadcast::Receiver<zoe_app_primitives::group::app_updates::GroupAppUpdate>
        {
            let (_tx, rx) = async_broadcast::broadcast(1000);
            rx
        }

        async fn current_group_states(&self) -> Vec<GroupState> {
            Vec::new()
        }

        async fn decrypt_app_message<T: DeserializeOwned>(
            &self,
            _group_id: &GroupId,
            _encrypted_content: &ChaCha20Poly1305Content,
        ) -> GroupResult<T> {
            // Mock decryption - return a default value
            Err(GroupError::InvalidEvent(
                "Mock decryption not implemented".to_string(),
            ))
        }

        async fn group_state_at_message(
            &self,
            _group_id: &GroupId,
            _message_id: MessageId,
        ) -> Option<GroupState> {
            // Mock implementation - return None for testing
            None
        }

        async fn current_group_state(&self, _group_id: &GroupId) -> Option<GroupState> {
            None
        }

        async fn get_permission_context(
            &self,
            _group_id: &GroupId,
            _actor_identity_ref: &IdentityRef,
            _group_state_reference: Option<MessageId>,
            _app_id: &AppProtocolVariant,
        ) -> GroupResult<(GroupRole, MessageId, GroupPermissions)> {
            // Return default values for tests
            Ok((
                GroupRole::Member,
                MessageId::from([0u8; 32]),
                GroupPermissions::default(),
            ))
        }

        async fn publish_app_event<T: serde::Serialize + Send>(
            &self,
            _group_id: &GroupId,
            _app_tag: zoe_wire_protocol::ChannelId,
            _event: T,
            _sender: &zoe_wire_protocol::KeyPair,
        ) -> GroupResult<zoe_wire_protocol::MessageFull> {
            // Mock implementation - return an error for tests
            Err(GroupError::InvalidOperation(
                "Mock publish_app_event not implemented".to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn test_app_manager_creation() {
        use PublishResult;
        use mockall::predicate::function;

        let mut mock_manager = MockMessagesManagerTrait::new();

        // Set up default expectations for subscription calls
        mock_manager
            .expect_ensure_contains_filter()
            .with(function(|filter: &Filter| {
                matches!(filter, Filter::Channel(_))
            }))
            .returning(|_| Ok(()));

        // Set up default expectations for publish calls
        mock_manager.expect_publish().returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_id".to_string(),
            })
        });

        // Set up default expectations for messages_stream calls
        mock_manager.expect_message_events_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            // Close the sender immediately to create an empty stream
            drop(tx);
            rx
        });

        // Set up default expectations for catch_up_stream calls
        mock_manager.expect_catch_up_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            // Close the sender immediately to create an empty stream
            drop(tx);
            rx
        });

        let message_manager = Arc::new(mock_manager);
        let group_service = Arc::new(MockGroupAppService);
        let store = crate::execution::InMemoryStore::new();

        let _app_manager = AppManager::new(message_manager, group_service, store).await;

        // For now, just test that the app manager was created successfully
    }
}
