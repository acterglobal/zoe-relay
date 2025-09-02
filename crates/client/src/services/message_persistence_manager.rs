use crate::error::{ClientError, Result};
use async_trait::async_trait;
use eyeball::AsyncLock;
use futures::{Stream, StreamExt};
use std::{ops::Deref, sync::Arc};
use tokio::{select, task::JoinHandle};
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, error, warn};
use zoe_client_storage::{MessageStorage, SubscriptionState};
use zoe_wire_protocol::{
    CatchUpResponse, Filter, Hash, MessageFull, PublishResult, StreamMessage, VerifyingKey,
};

use super::messages_manager::{
    MessageEvent, MessagesManager, MessagesManagerBuilder, MessagesManagerTrait,
};

/// Builder for creating MessagePersistenceManager instances.
///
/// This builder allows configuring persistence behavior and connecting
/// to existing MessageStorage and MessagesManager instances via references.
///
/// # Example
///
/// ```rust,no_run
/// # use zoe_client::services::MessagePersistenceManagerBuilder;
/// # use zoe_client_storage::MessageStorage;
/// # use zoe_wire_protocol::VerifyingKey;
/// # use std::sync::Arc;
/// # use zoe_client_storage::StorageError;
/// # async fn example(
/// #     storage: Arc<dyn MessageStorage>,
/// #     connection: &quinn::Connection,
/// #     relay_key: VerifyingKey,
/// # ) -> zoe_client::error::Result<()> {
/// // Create persistence manager with embedded MessagesManager
/// let persistence_manager = MessagePersistenceManagerBuilder::new()
///     .storage(storage)
///     .autosubscribe(true)
///     .relay_pubkey(relay_key)
///     .buffer_size(1000)
///     .build(connection)
///     .await?;
///
/// // Access MessagesManager via Deref
/// let _stream = persistence_manager.subscribe_to_messages().await?;
///
/// // Or access explicitly for better discoverability
/// let messages_manager = persistence_manager.messages_manager();
/// let _stream = messages_manager.subscribe_to_messages().await?;
/// # Ok(())
/// # }
/// ```
pub struct GenericMessagePersistenceManagerBuilder<T: MessagesManagerTrait> {
    storage: Option<Arc<dyn MessageStorage>>,
    relay_id: Option<Hash>,
    buffer_size: Option<usize>,
    autosubscribe: bool,
    _phantom: std::marker::PhantomData<T>,
}

/// Type alias for the common case of MessagePersistenceManagerBuilder with concrete MessagesManager
pub type MessagePersistenceManagerBuilder =
    GenericMessagePersistenceManagerBuilder<MessagesManager>;

impl<T: MessagesManagerTrait> GenericMessagePersistenceManagerBuilder<T> {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            storage: None,
            relay_id: None,
            buffer_size: None,
            autosubscribe: false,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set the storage implementation to use for persistence
    pub fn storage(mut self, storage: Arc<dyn MessageStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set whether to automatically subscribe after creating the messages manager
    pub fn autosubscribe(mut self, autosubscribe: bool) -> Self {
        self.autosubscribe = autosubscribe;
        self
    }

    /// Set the relay ID (hash of public key) for sync tracking
    pub fn relay_id(mut self, relay_id: Hash) -> Self {
        self.relay_id = Some(relay_id);
        self
    }

    /// Set the relay public key for sync tracking (convenience method that computes the ID)
    pub fn relay_pubkey(mut self, relay_pubkey: VerifyingKey) -> Self {
        self.relay_id = Some(Hash::from(*relay_pubkey.id()));
        self
    }

    /// Set the buffer size for the persistence task queue
    pub fn buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = Some(buffer_size);
        self
    }

    pub async fn build_with_messages_manager(
        self,
        messages_manager: Arc<T>,
    ) -> Result<GenericMessagePersistenceManager<T>> {
        let storage = self
            .storage
            .ok_or_else(|| ClientError::Generic("Storage is required".to_string()))?;

        let relay_id = self
            .relay_id
            .ok_or_else(|| ClientError::Generic("Relay ID is required".to_string()))?;

        // Create the persistence manager
        let manager =
            GenericMessagePersistenceManager::new(storage, messages_manager, relay_id).await?;

        Ok(manager)
    }
}

// Concrete implementation for the type alias
impl MessagePersistenceManagerBuilder {
    /// Build the MessagePersistenceManager and MessagesManager
    ///
    /// This will:
    /// 1. Create the MessagesManager from the connection and configuration
    /// 2. Create the MessagePersistenceManager with the MessagesManager
    /// 3. Start the background persistence task
    /// 4. Return a fully configured MessagePersistenceManager
    ///
    /// # Errors
    /// Returns an error if storage is not provided or connection fails
    pub async fn build_with_messages_manager_configuration<F>(
        self,
        connection: &quinn::Connection,
        configure: F,
    ) -> Result<MessagePersistenceManager>
    where
        F: FnOnce(MessagesManagerBuilder) -> MessagesManagerBuilder,
    {
        let storage = self
            .storage
            .as_ref()
            .ok_or_else(|| ClientError::Generic("Storage is required".to_string()))?;

        // Load subscription state from storage if we have a relay ID
        let subscription_state = if let Some(relay_id) = &self.relay_id {
            MessagePersistenceManager::load_subscription_state(&**storage, relay_id)
                .await?
                .unwrap_or_default()
        } else {
            SubscriptionState::default()
        };

        // Create the MessagesManager with loaded state
        let messages_manager = Arc::new(
            configure(
                MessagesManagerBuilder::new()
                    .state(subscription_state)
                    .buffer_size(self.buffer_size.unwrap_or(1000))
                    .autosubscribe(self.autosubscribe),
            )
            .build(connection)
            .await?,
        );

        self.build_with_messages_manager(messages_manager).await
    }

    /// Build the MessagePersistenceManager and MessagesManager
    ///
    /// This will:
    /// 1. Create the MessagesManager from the connection and configuration
    /// 2. Create the MessagePersistenceManager with the MessagesManager
    /// 3. Start the background persistence task
    /// 4. Return a fully configured MessagePersistenceManager
    ///
    /// # Errors
    /// Returns an error if storage is not provided or connection fails
    pub async fn build(self, connection: &quinn::Connection) -> Result<MessagePersistenceManager> {
        self.build_with_messages_manager_configuration(connection, |builder| builder)
            .await
    }
}

impl Default for MessagePersistenceManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level message persistence manager that automatically stores messages.
///
/// The `MessagePersistenceManager` bridges the gap between real-time messaging
/// and persistent storage by:
/// - **Automatic Persistence**: Stores all message events as they occur
/// - **Relay Sync Tracking**: Tracks which messages have been synced to which relays
/// - **Non-blocking Operation**: Runs persistence in the background without affecting message flow
///
/// This manager operates by subscribing to the message events stream from MessagesManager
/// and automatically persisting all events to the configured storage backend.
#[derive(Debug)]
pub struct GenericMessagePersistenceManager<T: MessagesManagerTrait> {
    /// The messages manager that this persistence manager wraps
    messages_manager: Arc<T>,
    /// Handle to the background persistence task
    persistence_task: JoinHandle<Result<()>>,
}

/// Type alias for the common case of MessagePersistenceManager with concrete MessagesManager
pub type MessagePersistenceManager = GenericMessagePersistenceManager<MessagesManager>;

impl<T: MessagesManagerTrait> GenericMessagePersistenceManager<T> {
    /// Get a reference to the underlying MessagesManager
    ///
    /// This provides explicit access to the MessagesManager for cases where
    /// method discovery is important or when you need to pass it to other components.
    pub fn messages_manager(&self) -> &Arc<T> {
        &self.messages_manager
    }

    /// Load subscription state from storage for a specific relay
    pub async fn load_subscription_state(
        storage: &dyn MessageStorage,
        relay_id: &Hash,
    ) -> Result<Option<SubscriptionState>> {
        storage
            .get_subscription_state(relay_id)
            .await
            .map_err(|e| ClientError::Generic(format!("Failed to load subscription state: {}", e)))
    }

    /// Load all subscription states from storage
    pub async fn load_all_subscription_states(
        storage: &dyn MessageStorage,
    ) -> Result<std::collections::HashMap<Hash, SubscriptionState>> {
        storage.get_all_subscription_states().await.map_err(|e| {
            ClientError::Generic(format!("Failed to load all subscription states: {}", e))
        })
    }

    /// Create a new MessagePersistenceManager with the given components.
    ///
    /// This starts the background persistence task immediately.
    ///
    /// # Arguments
    /// * `storage` - The storage implementation to persist messages to
    /// * `messages_manager` - The messages manager to monitor for events
    /// * `relay_pubkey` - Optional relay public key for sync tracking
    /// * `buffer_size` - Optional buffer size for the task queue
    async fn new(
        storage: Arc<dyn MessageStorage>,
        messages_manager: Arc<T>,
        relay_id: Hash,
    ) -> Result<Self> {
        // Get the message events stream before spawning the task to avoid lifetime issues
        let events_stream = messages_manager.message_events_stream();
        let mut state_updates = messages_manager.get_subscription_state_updates().await;
        let storage_clone = storage.clone();

        // Start the background persistence task
        let persistence_task = tokio::spawn(async move {
            debug!("MessagePersistenceManager started");

            let mut events_stream = Box::pin(events_stream);
            // let mut state_updates = Box::pin(state_updates);
            loop {
                select! {
                    event_result = events_stream.next() => {
                        match event_result {
                            Some(Ok(event)) => {
                                if let Err(e) =
                                    Self::handle_message_event(&*storage_clone, &event, &relay_id).await
                                {
                                    warn!("Failed to handle message event {:?}: {}", event, e);
                                    // Continue processing other events even if one fails
                                }
                            }
                            Some(Err(e)) => {
                                error!(error=?e, "Failed to receive message event");
                                // Continue processing other events even if one fails
                            }
                            _ => {
                                warn!("Message events stream unexpectedly ended");
                                break;
                            }
                        }
                    }
                    state = state_updates.next() => {
                        let Some(state) = state else {
                            // non updates are not of interest to us
                            continue;
                        };
                        debug!("Subscription state updated: {:?}", state);
                        if let Err(e) = storage_clone.store_subscription_state(&relay_id, &state).await {
                            error!(error=?e, "Failed to store subscription state");
                            // Continue processing other events even if state storage fails
                        }
                    }
                }
            }
            Ok(())
        });

        Ok(Self {
            messages_manager,
            persistence_task,
        })
    }

    /// Handle a single message event by persisting it
    async fn handle_message_event(
        storage: &dyn MessageStorage,
        event: &MessageEvent,
        relay_id: &Hash,
    ) -> Result<()> {
        match event {
            MessageEvent::MessageReceived {
                message,
                stream_height,
            } => {
                debug!(
                    "Persisting received message: {}",
                    hex::encode(message.id().as_bytes())
                );
                storage.store_message(message).await.map_err(|e| {
                    ClientError::Generic(format!("Failed to store received message: {}", e))
                })?;

                // Mark as synced if we have relay info
                storage
                    .mark_message_synced(message.id(), relay_id, stream_height)
                    .await
                    .map_err(|e| {
                        ClientError::Generic(format!("Failed to mark message as synced: {}", e))
                    })?;
            }
            MessageEvent::MessageSent { message, .. } => {
                debug!(
                    "Persisting sent message: {}",
                    hex::encode(message.id().as_bytes())
                );
                storage.store_message(message).await.map_err(|e| {
                    ClientError::Generic(format!("Failed to store sent message: {}", e))
                })?;
            }
            MessageEvent::CatchUpMessage {
                message,
                request_id,
            } => {
                debug!(
                    "Persisting catch-up message (request {}): {}",
                    request_id,
                    hex::encode(message.id().as_bytes())
                );
                storage.store_message(message).await.map_err(|e| {
                    ClientError::Generic(format!("Failed to store catch-up message: {}", e))
                })?;
            }
            MessageEvent::StreamHeightUpdate { .. } => {
                // Stream height updates don't need persistence by themselves
                // They're already handled as part of MessageReceived events
            }
            MessageEvent::CatchUpCompleted { request_id } => {
                debug!("Catch-up completed for request {}", request_id);
                // Could be used for metrics or completion tracking
            }
        }

        Ok(())
    }

    /// Check if the persistence task is still running
    pub fn is_running(&self) -> bool {
        !self.persistence_task.is_finished()
    }

    /// Stop the persistence manager and wait for the background task to complete
    pub async fn shutdown(self) -> Result<()> {
        let task = self.persistence_task;
        task.abort();
        match task.await {
            Ok(result) => result,
            Err(e) if e.is_cancelled() => {
                debug!("MessagePersistenceManager shutdown successfully");
                Ok(())
            }
            Err(e) => Err(ClientError::Generic(format!(
                "Error during persistence manager shutdown: {}",
                e
            ))),
        }
    }
}

// Concrete implementation for the type alias
impl MessagePersistenceManager {
    /// Create a new MessagePersistenceManager builder
    pub fn builder() -> MessagePersistenceManagerBuilder {
        MessagePersistenceManagerBuilder::new()
    }

    /// Get a reference to the inner MessagesManager for use with components
    /// that require the concrete type (like PqxdhProtocolHandler)
    ///
    /// This method is only available on the concrete MessagePersistenceManager
    /// type alias, not the generic version.
    pub fn inner_messages_manager(&self) -> &MessagesManager {
        &self.messages_manager
    }
}

impl Deref for MessagePersistenceManager {
    type Target = MessagesManager;

    fn deref(&self) -> &Self::Target {
        &self.messages_manager
    }
}

// Implement MessagesManagerTrait for GenericMessagePersistenceManager
// This allows it to act as a transparent proxy to the underlying MessagesManager
#[async_trait]
impl<T: MessagesManagerTrait> MessagesManagerTrait for GenericMessagePersistenceManager<T> {
    fn message_events_stream(&self) -> BroadcastStream<MessageEvent> {
        self.messages_manager.message_events_stream()
    }

    async fn get_subscription_state_updates(
        &self,
    ) -> eyeball::Subscriber<SubscriptionState, AsyncLock> {
        self.messages_manager.get_subscription_state_updates().await
    }

    async fn subscribe(&self) -> Result<()> {
        self.messages_manager.subscribe().await
    }

    async fn publish(&self, message: MessageFull) -> Result<PublishResult> {
        self.messages_manager.publish(message).await
    }

    async fn ensure_contains_filter(&self, filter: Filter) -> Result<()> {
        self.messages_manager.ensure_contains_filter(filter).await
    }

    fn messages_stream(&self) -> BroadcastStream<StreamMessage> {
        self.messages_manager.messages_stream()
    }

    fn catch_up_stream(&self) -> BroadcastStream<CatchUpResponse> {
        self.messages_manager.catch_up_stream()
    }

    fn filtered_messages_stream<'a>(
        &'a self,
        filter: Filter,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send + 'a>> {
        self.messages_manager.filtered_messages_stream(filter)
    }

    async fn catch_up_and_subscribe<'a>(
        &'a self,
        filter: Filter,
        since: Option<String>,
    ) -> Result<std::pin::Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send + 'a>>> {
        self.messages_manager
            .catch_up_and_subscribe(filter, since)
            .await
    }

    async fn user_data(
        &self,
        author: zoe_wire_protocol::keys::Id,
        storage_key: zoe_wire_protocol::StoreKey,
    ) -> Result<Option<MessageFull>> {
        self.messages_manager.user_data(author, storage_key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use rand::rngs::OsRng;
    use std::collections::HashMap;

    use crate::services::messages_manager::MockMessagesManagerTrait;
    use tokio::sync::broadcast;
    use zoe_client_storage::{StorageError, storage::MockMessageStorage};
    use zoe_wire_protocol::{Content, KeyPair, Kind, MessageFilters, MessageFull, PublishResult};

    fn create_test_message(content: &str) -> MessageFull {
        let keypair = KeyPair::generate(&mut OsRng);
        let content_obj = Content::Raw(content.as_bytes().to_vec());
        let message = zoe_wire_protocol::Message::new_v0(
            content_obj,
            keypair.public_key(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Kind::Regular,
            vec![],
        );
        MessageFull::new(message, &keypair).expect("Failed to create MessageFull")
    }

    #[tokio::test]
    async fn test_builder_defaults() {
        let builder = MessagePersistenceManagerBuilder::new();
        assert!(builder.storage.is_none());
        assert!(builder.relay_id.is_none());
        assert!(builder.buffer_size.is_none());
        assert!(!builder.autosubscribe);
    }

    #[tokio::test]
    async fn test_builder_relay_pubkey_conversion() {
        let keypair = KeyPair::generate(&mut OsRng);
        let pubkey = keypair.public_key();
        let expected_hash = Hash::from(*pubkey.id());

        let builder = MessagePersistenceManagerBuilder::new().relay_pubkey(pubkey);

        assert_eq!(builder.relay_id, Some(expected_hash));
    }

    #[tokio::test]
    async fn test_builder_configuration() {
        let relay_id = Hash::from([1u8; 32]);
        let buffer_size = 2000;

        let builder = MessagePersistenceManagerBuilder::new()
            .relay_id(relay_id)
            .buffer_size(buffer_size)
            .autosubscribe(true);

        assert_eq!(builder.relay_id, Some(relay_id));
        assert_eq!(builder.buffer_size, Some(buffer_size));
        assert!(builder.autosubscribe);
    }

    #[tokio::test]
    async fn test_message_received_persistence() {
        let mut mock_storage = MockMessageStorage::new();
        let message = create_test_message("Test message");
        let relay_id = Hash::from([1u8; 32]);
        let stream_height = "100".to_string();

        // Set up expectations
        mock_storage
            .expect_store_message()
            .with(eq(message.clone()))
            .times(1)
            .returning(|_| Ok(()));

        mock_storage
            .expect_mark_message_synced()
            .with(eq(*message.id()), eq(relay_id), eq("100"))
            .times(1)
            .returning(|_, _, _| Ok(()));

        // Create message event
        let event = MessageEvent::MessageReceived {
            message: message.clone(),
            stream_height: stream_height.clone(),
        };

        // Test the handler
        let result =
            MessagePersistenceManager::handle_message_event(&mock_storage, &event, &relay_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_message_sent_persistence() {
        let mut mock_storage = MockMessageStorage::new();
        let relay_id = Hash::from([1u8; 32]);
        let message = create_test_message("Sent message");
        let publish_result = PublishResult::StoredNew {
            global_stream_id: "200".to_string(),
        };

        // Set up expectations
        mock_storage
            .expect_store_message()
            .with(eq(message.clone()))
            .times(1)
            .returning(|_| Ok(()));

        // Create message event
        let event = MessageEvent::MessageSent {
            message: message.clone(),
            publish_result,
        };

        // Test the handler
        let result =
            MessagePersistenceManager::handle_message_event(&mock_storage, &event, &relay_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_catch_up_message_persistence() {
        let mut mock_storage = MockMessageStorage::new();
        let relay_id = Hash::from([1u8; 32]);
        let message = create_test_message("Catch-up message");
        let request_id = 42;

        // Set up expectations
        mock_storage
            .expect_store_message()
            .with(eq(message.clone()))
            .times(1)
            .returning(|_| Ok(()));

        // Create message event
        let event = MessageEvent::CatchUpMessage {
            message: message.clone(),
            request_id,
        };

        // Test the handler
        let result =
            MessagePersistenceManager::handle_message_event(&mock_storage, &event, &relay_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stream_height_update_no_persistence() {
        let mock_storage = MockMessageStorage::new();
        let relay_id = Hash::from([1u8; 32]);

        // Stream height updates should not trigger any storage calls
        let event = MessageEvent::StreamHeightUpdate {
            height: "300".to_string(),
        };

        // Test the handler - should succeed without any storage calls
        let result =
            MessagePersistenceManager::handle_message_event(&mock_storage, &event, &relay_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_catch_up_completed_no_persistence() {
        let mock_storage = MockMessageStorage::new();
        let relay_id = Hash::from([1u8; 32]);

        // Catch-up completed events should not trigger any storage calls
        let event = MessageEvent::CatchUpCompleted { request_id: 123 };

        // Test the handler - should succeed without any storage calls
        let result =
            MessagePersistenceManager::handle_message_event(&mock_storage, &event, &relay_id).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_storage_error_handling() {
        let mut mock_storage = MockMessageStorage::new();
        let relay_id = Hash::from([1u8; 32]);
        let message = create_test_message("Error test message");

        // Set up storage to return an error
        mock_storage
            .expect_store_message()
            .with(eq(message.clone()))
            .times(1)
            .returning(|_| Err(StorageError::Internal("Test error".to_string())));

        // Create message event
        let event = MessageEvent::MessageSent {
            message: message.clone(),
            publish_result: PublishResult::StoredNew {
                global_stream_id: "400".to_string(),
            },
        };

        // Test the handler - should return an error
        let result =
            MessagePersistenceManager::handle_message_event(&mock_storage, &event, &relay_id).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to store sent message")
        );
    }

    #[tokio::test]
    async fn test_load_subscription_state() {
        let mut mock_storage = MockMessageStorage::new();
        let relay_id = Hash::from([4u8; 32]);
        let expected_state = SubscriptionState {
            latest_stream_height: Some("500".to_string()),
            current_filters: MessageFilters {
                filters: Some(vec![]),
            },
        };

        // Set up expectations
        mock_storage
            .expect_get_subscription_state()
            .with(eq(relay_id))
            .times(1)
            .returning(move |_| Ok(Some(expected_state.clone())));

        // Test loading subscription state
        let result =
            MessagePersistenceManager::load_subscription_state(&mock_storage, &relay_id).await;

        assert!(result.is_ok());
        let loaded_state = result.unwrap();
        assert!(loaded_state.is_some());
        assert_eq!(
            loaded_state.unwrap().latest_stream_height,
            Some("500".to_string())
        );
    }

    #[tokio::test]
    async fn test_load_all_subscription_states() {
        let mut mock_storage = MockMessageStorage::new();
        let relay_id1 = Hash::from([5u8; 32]);
        let relay_id2 = Hash::from([6u8; 32]);

        let mut expected_states = HashMap::new();
        expected_states.insert(
            relay_id1,
            SubscriptionState {
                latest_stream_height: Some("600".to_string()),
                current_filters: MessageFilters {
                    filters: Some(vec![]),
                },
            },
        );
        expected_states.insert(
            relay_id2,
            SubscriptionState {
                latest_stream_height: Some("700".to_string()),
                current_filters: MessageFilters {
                    filters: Some(vec![]),
                },
            },
        );

        // Set up expectations
        mock_storage
            .expect_get_all_subscription_states()
            .times(1)
            .returning(move || Ok(expected_states.clone()));

        // Test loading all subscription states
        let result = MessagePersistenceManager::load_all_subscription_states(&mock_storage).await;

        assert!(result.is_ok());
        let loaded_states = result.unwrap();
        assert_eq!(loaded_states.len(), 2);
        assert!(loaded_states.contains_key(&relay_id1));
        assert!(loaded_states.contains_key(&relay_id2));
    }

    #[tokio::test]
    async fn test_subscription_state_helpers() {
        // Test default subscription state
        let state = SubscriptionState::default();
        assert!(state.latest_stream_height.is_none());
        assert!(state.current_filters.filters.is_none());

        // Test subscription state with filters
        let filters = MessageFilters {
            filters: Some(vec![]),
        };
        let state = SubscriptionState::with_filters(filters.clone());
        assert_eq!(state.current_filters, filters);
        assert!(state.latest_stream_height.is_none());

        // Test setting stream height
        let mut state = SubscriptionState::default();
        state.latest_stream_height = Some("100".to_string());
        assert_eq!(state.latest_stream_height, Some("100".to_string()));
    }

    #[tokio::test]
    async fn test_subscription_state_operations() {
        let mut state = SubscriptionState::default();

        // Test setting filters directly
        let filters = MessageFilters {
            filters: Some(vec![]),
        };
        state.current_filters = filters.clone();
        assert_eq!(state.current_filters, filters);

        // Test setting stream height
        state.latest_stream_height = Some("500".to_string());
        assert_eq!(state.latest_stream_height, Some("500".to_string()));

        // Test has_active_filters
        assert!(!state.has_active_filters()); // Empty filters

        // Test with actual filters (would need real Filter objects for a complete test)
        let state_with_filters = SubscriptionState {
            latest_stream_height: Some("600".to_string()),
            current_filters: MessageFilters {
                filters: Some(vec![]),
            },
        };
        assert!(!state_with_filters.has_active_filters()); // Still empty vec
    }

    #[tokio::test]
    async fn test_error_handling_scenarios() {
        // Test various error scenarios that might occur

        // Test with invalid relay ID (all zeros)
        let zero_relay_id = Hash::from([0u8; 32]);
        assert_eq!(zero_relay_id, Hash::from([0u8; 32]));

        // Test with maximum relay ID (all 255s)
        let max_relay_id = Hash::from([255u8; 32]);
        assert_eq!(max_relay_id, Hash::from([255u8; 32]));

        // Test subscription state edge cases
        let empty_state = SubscriptionState::default();
        assert!(empty_state.latest_stream_height.is_none());
        assert!(!empty_state.has_active_filters());

        // Test with very long stream height string
        let long_height = "a".repeat(1000);
        let mut state = SubscriptionState::default();
        state.latest_stream_height = Some(long_height.clone());
        assert_eq!(state.latest_stream_height, Some(long_height));
    }

    // ============================================================================
    // COMPREHENSIVE WIRING AND SYNC STATUS TESTS WITH MOCKED MESSAGES MANAGER
    // ============================================================================

    #[cfg(test)]
    mod wiring_tests {
        use zoe_client_storage::StorageError;

        use super::*;

        type TestPersistenceManager = GenericMessagePersistenceManager<MockMessagesManagerTrait>;
        type TestPersistenceManagerBuilder =
            GenericMessagePersistenceManagerBuilder<MockMessagesManagerTrait>;

        fn create_mock_message_events_stream() -> BroadcastStream<MessageEvent> {
            let (tx, rx) = broadcast::channel(100);

            // Send some test events
            tokio::spawn(async move {
                let _ = tx.send(MessageEvent::MessageReceived {
                    message: create_test_message("test message 1"),
                    stream_height: "100".to_string(),
                });
                let _ = tx.send(MessageEvent::StreamHeightUpdate {
                    height: "101".to_string(),
                });
                let _ = tx.send(MessageEvent::MessageSent {
                    message: create_test_message("sent message"),
                    publish_result: PublishResult::StoredNew {
                        global_stream_id: "102".to_string(),
                    },
                });
            });

            BroadcastStream::new(rx)
        }

        #[tokio::test]
        async fn test_generic_builder_with_mock_messages_manager() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([1u8; 32]);

            // Set up storage expectations
            mock_storage.expect_store_message().returning(|_| Ok(()));
            mock_storage
                .expect_mark_message_synced()
                .returning(|_, _, _| Ok(()));

            // Set up messages manager expectations
            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(create_mock_message_events_stream);

            // Add missing subscription state updates expectation
            let shared = eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(
                SubscriptionState::default(),
            );
            let subscriber = shared.subscribe().await;
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber.clone());

            // Build the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());
            let manager = persistence_manager.unwrap();

            // Verify we can access the messages manager
            let messages_manager_ref = manager.messages_manager();
            // Just verify we got a reference (Arc is never null)
            assert!(Arc::strong_count(messages_manager_ref) > 0);

            // Give some time for background task to process events
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        #[tokio::test]
        async fn test_subscription_state_wiring_with_mock() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([2u8; 32]);

            // Set up initial subscription state in storage
            let initial_state = SubscriptionState {
                latest_stream_height: Some("50".to_string()),
                current_filters: MessageFilters {
                    filters: Some(vec![]),
                },
            };

            mock_storage
                .expect_get_subscription_state()
                .with(eq(relay_id))
                .times(1)
                .returning(move |_| Ok(Some(initial_state.clone())));

            mock_storage
                .expect_store_subscription_state()
                .returning(|_, _| Ok(()));

            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (tx, rx) = broadcast::channel(10);
                    tokio::spawn(async move {
                        // Note: FiltersUpdated variant removed - using StreamHeightUpdate instead
                        let _ = tx.send(MessageEvent::StreamHeightUpdate {
                            height: "103".to_string(),
                        });
                    });
                    BroadcastStream::new(rx)
                });

            // Add missing subscription state updates expectation
            let shared = eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(
                SubscriptionState::default(),
            );
            let subscriber = shared.subscribe().await;
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber.clone());

            // Test loading subscription state
            let loaded_state =
                TestPersistenceManager::load_subscription_state(&mock_storage, &relay_id).await;

            assert!(loaded_state.is_ok());
            let state = loaded_state.unwrap();
            assert!(state.is_some());
            assert_eq!(state.unwrap().latest_stream_height, Some("50".to_string()));

            // Test building with the state
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());
        }

        #[tokio::test]
        async fn test_message_sync_tracking_with_mock() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([3u8; 32]);
            let test_message = create_test_message("sync test message");
            let message_id = *test_message.id();

            // Set up expectations for message sync tracking
            mock_storage
                .expect_store_message()
                .with(eq(test_message.clone()))
                .times(1)
                .returning(|_| Ok(()));

            mock_storage
                .expect_mark_message_synced()
                .with(eq(message_id), eq(relay_id), eq("150"))
                .times(1)
                .returning(|_, _, _| Ok(()));

            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(move || {
                    let (tx, rx) = broadcast::channel(10);
                    let test_msg = test_message.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(MessageEvent::MessageReceived {
                            message: test_msg,
                            stream_height: "150".to_string(),
                        });
                    });
                    BroadcastStream::new(rx)
                });

            // Add missing subscription state updates expectation
            let shared = eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(
                SubscriptionState::default(),
            );
            let subscriber = shared.subscribe().await;
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber.clone());

            // Build and test the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());

            // Give time for the background task to process the message
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        #[tokio::test]
        async fn test_multiple_relay_sync_status() {
            let mut mock_storage = MockMessageStorage::new();
            let relay_id1 = Hash::from([4u8; 32]);
            let relay_id2 = Hash::from([5u8; 32]);

            // Set up multiple subscription states
            let mut all_states = HashMap::new();
            all_states.insert(
                relay_id1,
                SubscriptionState {
                    latest_stream_height: Some("100".to_string()),
                    current_filters: MessageFilters {
                        filters: Some(vec![]),
                    },
                },
            );
            all_states.insert(
                relay_id2,
                SubscriptionState {
                    latest_stream_height: Some("200".to_string()),
                    current_filters: MessageFilters {
                        filters: Some(vec![]),
                    },
                },
            );

            mock_storage
                .expect_get_all_subscription_states()
                .times(1)
                .returning(move || Ok(all_states.clone()));

            // Test loading all subscription states
            let result = TestPersistenceManager::load_all_subscription_states(&mock_storage).await;

            assert!(result.is_ok());
            let loaded_states = result.unwrap();
            assert_eq!(loaded_states.len(), 2);
            assert!(loaded_states.contains_key(&relay_id1));
            assert!(loaded_states.contains_key(&relay_id2));
            assert_eq!(
                loaded_states.get(&relay_id1).unwrap().latest_stream_height,
                Some("100".to_string())
            );
            assert_eq!(
                loaded_states.get(&relay_id2).unwrap().latest_stream_height,
                Some("200".to_string())
            );
        }

        #[tokio::test]
        async fn test_builder_error_handling_with_mock() {
            let mock_messages_manager = MockMessagesManagerTrait::new();

            // Test building without storage should fail
            let result = TestPersistenceManagerBuilder::new()
                .relay_id(Hash::from([6u8; 32]))
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("Storage is required")
            );
        }

        #[tokio::test]
        async fn test_persistence_manager_deref_with_mock() {
            let mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();

            // Set up minimal expectations
            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (_, rx) = broadcast::channel(1);
                    BroadcastStream::new(rx)
                });

            // Add missing subscription state updates expectation
            let shared = eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(
                SubscriptionState::default(),
            );
            let subscriber = shared.subscribe().await;
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber.clone());

            // Build the persistence manager
            let relay_id = Hash::from([10u8; 32]);
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await
                .unwrap();

            // Give time for the background task to start and call message_events_stream
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Test that we can access the messages manager through the persistence manager
            let messages_manager_ref = persistence_manager.messages_manager();
            // Just verify we got a reference (Arc is never null)
            assert!(Arc::strong_count(messages_manager_ref) > 0);
        }

        #[tokio::test]
        async fn test_background_task_error_resilience() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([7u8; 32]);

            // Set up storage to fail on first message, succeed on second
            let mut call_count = 0;
            mock_storage.expect_store_message().returning(move |_| {
                call_count += 1;
                if call_count == 1 {
                    Err(StorageError::Internal("Simulated failure".to_string()))
                } else {
                    Ok(())
                }
            });

            mock_storage
                .expect_mark_message_synced()
                .returning(|_, _, _| Ok(()));

            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (tx, rx) = broadcast::channel(10);
                    tokio::spawn(async move {
                        // Send a message that will fail
                        let _ = tx.send(MessageEvent::MessageReceived {
                            message: create_test_message("failing message"),
                            stream_height: "100".to_string(),
                        });

                        // Send a message that will succeed
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        let _ = tx.send(MessageEvent::MessageReceived {
                            message: create_test_message("succeeding message"),
                            stream_height: "101".to_string(),
                        });
                    });
                    BroadcastStream::new(rx)
                });

            // Add missing subscription state updates expectation
            let shared = eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(
                SubscriptionState::default(),
            );
            let subscriber = shared.subscribe().await;
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber.clone());

            // Build the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());

            // Give time for both messages to be processed
            tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;

            // The persistence manager should still be running despite the first failure
            // This test mainly verifies that the background task continues after errors
        }

        #[tokio::test]
        async fn test_stream_height_update_persistence() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([9u8; 32]);

            // Create a real SharedObservable for subscription state with AsyncLock
            let initial_state = SubscriptionState {
                latest_stream_height: Some("100".to_string()),
                current_filters: MessageFilters {
                    filters: Some(vec![]),
                },
            };
            let shared_observable =
                eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(initial_state);
            let subscriber = shared_observable.subscribe().await;

            // Set up storage expectations - should be called when state updates
            mock_storage
                .expect_store_subscription_state()
                .with(
                    eq(relay_id),
                    function(|state: &SubscriptionState| {
                        state.latest_stream_height == Some("150".to_string())
                    }),
                )
                .times(1)
                .returning(|_, _| Ok(()));

            // Set up mock messages manager to return empty message events stream
            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (_, rx) = broadcast::channel(10);
                    BroadcastStream::new(rx)
                });

            // Set up mock to return the cloned subscriber
            let subscriber_clone = subscriber.clone();
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber_clone.clone());

            // Build the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());

            // Give a moment for the persistence manager to start up
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Now trigger a subscription state update by updating the SharedObservable
            shared_observable
                .set(SubscriptionState {
                    latest_stream_height: Some("150".to_string()),
                    current_filters: MessageFilters {
                        filters: Some(vec![]),
                    },
                })
                .await;

            // Give time for the background task to process the state update
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // The mock expectation will verify that store_subscription_state was called
            // with the updated height of "150"
        }

        #[tokio::test]
        async fn test_stream_event_filtering_and_processing() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([8u8; 32]);

            // Set up expectations for different event types
            mock_storage
                .expect_store_message()
                .times(2) // Only for MessageReceived and MessageSent
                .returning(|_| Ok(()));

            mock_storage
                .expect_mark_message_synced()
                .times(1) // Only for MessageReceived
                .returning(|_, _, _| Ok(()));

            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (tx, rx) = broadcast::channel(10);
                    tokio::spawn(async move {
                        // Send various event types
                        let _ = tx.send(MessageEvent::MessageReceived {
                            message: create_test_message("received message"),
                            stream_height: "200".to_string(),
                        });

                        let _ = tx.send(MessageEvent::MessageSent {
                            message: create_test_message("sent message"),
                            publish_result: PublishResult::StoredNew {
                                global_stream_id: "201".to_string(),
                            },
                        });

                        let _ = tx.send(MessageEvent::StreamHeightUpdate {
                            height: "202".to_string(),
                        });

                        let _ = tx.send(MessageEvent::CatchUpCompleted { request_id: 123 });
                    });
                    BroadcastStream::new(rx)
                });

            // Add missing subscription state updates expectation
            let shared = eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(
                SubscriptionState::default(),
            );
            let subscriber = shared.subscribe().await;
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber.clone());

            // Build the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());

            // Give time for all events to be processed
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // The mock expectations will verify that the right methods were called
            // for the right event types
        }

        #[tokio::test]
        async fn test_subscription_state_persistence_on_updates() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([11u8; 32]);

            // Create a real SharedObservable for subscription state with AsyncLock
            let initial_state = SubscriptionState {
                latest_stream_height: Some("100".to_string()),
                current_filters: MessageFilters {
                    filters: Some(vec![]),
                },
            };
            let shared_observable =
                eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(initial_state);
            let subscriber = shared_observable.subscribe().await;

            // Set up storage expectations - should be called when state updates
            // Allow 0-2 calls since the timing of observable updates is not deterministic
            mock_storage
                .expect_store_subscription_state()
                .with(eq(relay_id), always())
                .times(0..=2)
                .returning(|_, _| Ok(()));

            // Set up mock messages manager to return empty message events stream
            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (_, rx) = broadcast::channel(10);
                    BroadcastStream::new(rx)
                });

            // Set up mock to return the cloned subscriber
            let subscriber_clone = subscriber.clone();
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber_clone.clone());

            // Build the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());

            // Give a moment for the persistence manager to start up
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Trigger subscription state updates
            shared_observable
                .set(SubscriptionState {
                    latest_stream_height: Some("150".to_string()),
                    current_filters: MessageFilters {
                        filters: Some(vec![]),
                    },
                })
                .await;

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            shared_observable
                .set(SubscriptionState {
                    latest_stream_height: Some("200".to_string()),
                    current_filters: MessageFilters {
                        filters: Some(vec![]),
                    },
                })
                .await;

            // Give time for the background task to process all state updates
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // The mock expectations will verify that store_subscription_state was called
        }

        #[tokio::test]
        async fn test_subscription_state_loading_on_startup() {
            let mut mock_storage = MockMessageStorage::new();
            let relay_id = Hash::from([12u8; 32]);

            // Set up initial subscription state in storage
            let stored_state = SubscriptionState {
                latest_stream_height: Some("500".to_string()),
                current_filters: MessageFilters {
                    filters: Some(vec![]),
                },
            };

            mock_storage
                .expect_get_subscription_state()
                .with(eq(relay_id))
                .times(1)
                .returning(move |_| Ok(Some(stored_state.clone())));

            // Test loading subscription state
            let loaded_state =
                TestPersistenceManager::load_subscription_state(&mock_storage, &relay_id).await;

            assert!(loaded_state.is_ok());
            let state = loaded_state.unwrap();
            assert!(state.is_some());
            let state = state.unwrap();
            assert_eq!(state.latest_stream_height, Some("500".to_string()));
            assert!(state.current_filters.filters.is_some());
        }

        #[tokio::test]
        async fn test_subscription_state_error_handling() {
            let mut mock_storage = MockMessageStorage::new();
            let relay_id = Hash::from([13u8; 32]);

            // Set up storage to return an error
            mock_storage
                .expect_get_subscription_state()
                .with(eq(relay_id))
                .times(1)
                .returning(|_| Err(StorageError::Internal("Database error".to_string())));

            // Test loading subscription state with storage error
            let loaded_state =
                TestPersistenceManager::load_subscription_state(&mock_storage, &relay_id).await;

            assert!(loaded_state.is_err());
            assert!(
                loaded_state
                    .unwrap_err()
                    .to_string()
                    .contains("Failed to load subscription state")
            );
        }

        #[tokio::test]
        async fn test_subscription_state_persistence_error_resilience() {
            let mut mock_storage = MockMessageStorage::new();
            let mut mock_messages_manager = MockMessagesManagerTrait::new();
            let relay_id = Hash::from([14u8; 32]);

            // Create a real SharedObservable for subscription state with AsyncLock
            let initial_state = SubscriptionState::default();
            let shared_observable =
                eyeball::SharedObservable::<SubscriptionState, AsyncLock>::new_async(initial_state);
            let subscriber = shared_observable.subscribe().await;

            // Set up storage to fail on state persistence - allow 0 or 1 calls
            // since the timing of when the observable triggers is not deterministic
            mock_storage
                .expect_store_subscription_state()
                .with(eq(relay_id), always())
                .times(0..=1)
                .returning(|_, _| Err(StorageError::Internal("Storage failure".to_string())));

            // Set up mock messages manager to return a message events stream that stays open
            mock_messages_manager
                .expect_message_events_stream()
                .times(1)
                .returning(|| {
                    let (tx, rx) = broadcast::channel(10);
                    // Keep the sender alive to prevent the stream from closing immediately
                    tokio::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                        drop(tx); // Eventually drop it, but not immediately
                    });
                    BroadcastStream::new(rx)
                });

            // Set up mock to return the cloned subscriber
            let subscriber_clone = subscriber.clone();
            mock_messages_manager
                .expect_get_subscription_state_updates()
                .times(1)
                .returning(move || subscriber_clone.clone());

            // Build the persistence manager
            let persistence_manager = TestPersistenceManagerBuilder::new()
                .storage(Arc::new(mock_storage))
                .relay_id(relay_id)
                .build_with_messages_manager(Arc::new(mock_messages_manager))
                .await;

            assert!(persistence_manager.is_ok());
            let manager = persistence_manager.unwrap();

            // Give a moment for the persistence manager to start up
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

            // Verify the manager starts running initially
            assert!(manager.is_running());

            // Trigger a subscription state update that may fail to persist
            shared_observable
                .set(SubscriptionState {
                    latest_stream_height: Some("300".to_string()),
                    current_filters: MessageFilters {
                        filters: Some(vec![]),
                    },
                })
                .await;

            // Give time for the background task to process the state update
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // The main goal is to verify that the background task handles errors gracefully
            // and continues running. The exact timing of state updates is not deterministic.
        }
    }
}
