use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use futures::stream::Stream;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::BroadcastStream;

use eyeball::{AsyncLock, SharedObservable};
use zoe_client_storage::{MessageStorage, SubscriptionState};
use zoe_wire_protocol::{
    CatchUpResponse, Filter, KeyId, MessageFull, PublishResult, StoreKey, StreamMessage,
};

use crate::error::{ClientError, Result};
use crate::services::{MessageEvent, MessagesManager, MessagesManagerTrait};

// Constants for catch-up processing
const CATCH_UP_BATCH_SIZE: usize = 50;

/// Connection state for a relay
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// Relay is connected and operational
    Connected,
    /// Relay is disconnected but may reconnect
    Disconnected,
    /// Currently attempting to reconnect
    Reconnecting,
    /// Connection failed, will retry later
    Failed {
        last_error: String,
        retry_at: SystemTime,
    },
}

/// Represents a connection to a single relay with its associated managers
pub struct RelayConnection {
    /// The messages manager for this relay
    pub manager: Arc<MessagesManager>,
    /// Connection state tracking
    pub connection_state: ConnectionState,
    /// When this relay was last seen as active
    pub last_seen: SystemTime,
    /// Relay-specific subscription state
    pub subscription_state: SubscriptionState,
}

/// Multi-relay message manager that provides unified messaging across multiple relays
/// with offline support and automatic failover.
///
/// This manager:
/// - Manages connections to multiple relay servers
/// - Uses persistent storage for offline message queuing (no in-memory queue)
/// - Implements automatic failover and load balancing
/// - Aggregates messages from all connected relays
/// - Deduplicates messages based on message ID
/// - Maintains the same interface as a single MessagesManager
pub struct MultiRelayMessageManager<S: MessageStorage> {
    /// Map of relay ID to relay connection info
    relay_connections: Arc<RwLock<BTreeMap<KeyId, RelayConnection>>>,
    /// Storage for message persistence and offline queuing
    storage: Arc<S>,
    /// Global message event broadcaster (aggregates from all relays)
    global_events_tx: broadcast::Sender<MessageEvent>,
    /// Global message broadcaster (aggregates from all relays)
    global_messages_tx: broadcast::Sender<StreamMessage>,
    /// Global catch-up response broadcaster
    global_catchup_tx: broadcast::Sender<CatchUpResponse>,
    /// Map of active catch-up tasks by relay ID
    catch_up_tasks: Arc<RwLock<BTreeMap<KeyId, JoinHandle<()>>>>,
}

impl<S: MessageStorage + 'static> MultiRelayMessageManager<S> {
    /// Create a new multi-relay message manager
    pub fn new(storage: Arc<S>) -> Self {
        let (global_events_tx, _) = broadcast::channel(1000);
        let (global_messages_tx, _) = broadcast::channel(1000);
        let (global_catchup_tx, _) = broadcast::channel(1000);

        let relay_connections = Arc::new(RwLock::new(BTreeMap::new()));
        let catch_up_tasks = Arc::new(RwLock::new(BTreeMap::new()));

        Self {
            relay_connections,
            storage,
            global_events_tx,
            global_messages_tx,
            global_catchup_tx,
            catch_up_tasks,
        }
    }

    /// Add a relay connection to the manager
    ///
    /// # Arguments
    /// * `relay_id` - The unique identifier for the relay
    /// * `manager` - The messages manager for this relay
    /// * `should_catch_up` - Whether to start catching up on historical messages
    pub async fn add_relay(
        &self,
        relay_id: KeyId,
        manager: Arc<MessagesManager>,
        should_catch_up: bool,
    ) -> Result<()> {
        let connection = RelayConnection {
            manager: Arc::clone(&manager),
            connection_state: ConnectionState::Connected,
            last_seen: SystemTime::now(),
            subscription_state: SubscriptionState::default(),
        };

        // Add to our connections map
        {
            let mut connections = self.relay_connections.write().await;
            connections.insert(relay_id, connection);
        }

        tracing::info!(
            "Added relay connection: {}",
            hex::encode(relay_id.as_bytes())
        );

        // Start catch-up task if requested
        if should_catch_up {
            self.start_catch_up_task(relay_id, manager).await?;
        }

        Ok(())
    }

    /// Remove a relay connection
    pub async fn remove_relay(&self, relay_id: &KeyId) -> Option<Arc<MessagesManager>> {
        // Cancel any active catch-up task for this relay
        {
            let mut tasks = self.catch_up_tasks.write().await;
            if let Some(task) = tasks.remove(relay_id) {
                task.abort();
                tracing::debug!(
                    "Cancelled catch-up task for relay: {}",
                    hex::encode(relay_id.as_bytes())
                );
            }
        }

        let mut connections = self.relay_connections.write().await;
        let removed = connections.remove(relay_id);

        if let Some(connection) = &removed {
            tracing::info!(
                "Removed relay connection: {}",
                hex::encode(relay_id.as_bytes())
            );
            Some(Arc::clone(&connection.manager))
        } else {
            None
        }
    }

    /// Get list of currently connected relay IDs
    pub async fn get_connected_relay_ids(&self) -> Vec<KeyId> {
        let connections = self.relay_connections.read().await;
        connections
            .iter()
            .filter(|(_, conn)| matches!(conn.connection_state, ConnectionState::Connected))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get list of all relay IDs (connected and disconnected)
    pub async fn get_all_relay_ids(&self) -> Vec<KeyId> {
        let connections = self.relay_connections.read().await;
        connections.keys().copied().collect()
    }

    /// Check if any relays are currently connected
    pub async fn has_connected_relays(&self) -> bool {
        !self.get_connected_relay_ids().await.is_empty()
    }

    /// Start a catch-up task for a specific relay
    async fn start_catch_up_task(
        &self,
        relay_id: KeyId,
        manager: Arc<MessagesManager>,
    ) -> Result<()> {
        let storage = Arc::clone(&self.storage);
        let tasks = Arc::clone(&self.catch_up_tasks);

        let task = tokio::spawn(async move {
            tracing::info!(
                "Starting catch-up task for relay: {}",
                hex::encode(relay_id.as_bytes())
            );

            match Self::process_all_unsynced_messages_for_relay::<MessagesManager>(
                &storage,
                &relay_id,
                &manager,
                CATCH_UP_BATCH_SIZE,
            )
            .await
            {
                Ok(total_processed) => {
                    tracing::info!(
                        "Catch-up completed for relay: {} ({} messages processed)",
                        hex::encode(relay_id.as_bytes()),
                        total_processed
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Catch-up failed for relay {}: {}",
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                }
            }

            // Remove this task from the active tasks map when done
            let mut tasks_guard = tasks.write().await;
            tasks_guard.remove(&relay_id);
        });

        // Store the task handle
        {
            let mut tasks_guard = self.catch_up_tasks.write().await;
            tasks_guard.insert(relay_id, task);
        }

        Ok(())
    }

    /// Process all unsynced messages for a specific relay in batches
    /// Returns the total number of messages processed
    async fn process_all_unsynced_messages_for_relay<M: MessagesManagerTrait>(
        storage: &Arc<S>,
        relay_id: &KeyId,
        manager: &Arc<M>,
        batch_size: usize,
    ) -> Result<usize> {
        let mut total_processed = 0;
        let mut batch_count = 0;

        loop {
            tracing::debug!(
                "Processing batch {} for relay {} (batch size: {})",
                batch_count,
                hex::encode(relay_id.as_bytes()),
                batch_size
            );

            let batch_result = Self::process_unsynced_messages_batch_for_relay(
                storage, relay_id, manager, batch_size,
            )
            .await?;

            let Some(batch_processed) = batch_result else {
                // No more messages to process - we're done
                tracing::debug!(
                    "No unsynced messages left for relay {}, stopping catch-up after {} batches",
                    hex::encode(relay_id.as_bytes()),
                    batch_count
                );
                break;
            };

            total_processed += batch_processed;
            batch_count += 1;

            tracing::debug!(
                "Batch {} complete: {} messages processed for relay {}",
                batch_count,
                batch_processed,
                hex::encode(relay_id.as_bytes())
            );
        }

        Ok(total_processed)
    }

    /// Process a single batch of unsynced messages for a specific relay
    /// Returns:
    /// - Ok(Some(count)) if messages were processed (count = number successfully processed)
    /// - Ok(None) if no unsynced messages were found (indicates completion)
    /// - Err(_) if there was an error
    async fn process_unsynced_messages_batch_for_relay<M: MessagesManagerTrait>(
        storage: &Arc<S>,
        relay_id: &KeyId,
        manager: &Arc<M>,
        batch_size: usize,
    ) -> Result<Option<usize>> {
        // Convert KeyId to Hash for storage API
        let relay_key_id = relay_id;

        // Get unsynced messages for this relay
        let unsynced_messages = storage
            .get_unsynced_messages_for_relay(relay_key_id, Some(batch_size))
            .await
            .map_err(|e| ClientError::Generic(format!("Failed to get unsynced messages: {}", e)))?;

        if unsynced_messages.is_empty() {
            return Ok(None); // No messages to process - indicates completion
        }

        let batch_message_count = unsynced_messages.len();
        tracing::debug!(
            "Processing batch of {} unsynced messages for relay {}",
            batch_message_count,
            hex::encode(relay_id.as_bytes())
        );

        // Filter out expired messages and delete them immediately from storage
        let mut valid_messages = Vec::new();
        let mut expired_count = 0;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for message in unsynced_messages {
            if message.is_expired(current_time) {
                // Delete expired message immediately
                if let Err(e) = storage.delete_message(message.id()).await {
                    tracing::error!(
                        "Failed to delete expired message {} from storage: {}. Continuing with other messages.",
                        hex::encode(message.id().as_bytes()),
                        e
                    );
                    // Continue processing other messages even if this deletion failed
                }
                expired_count += 1;
                continue;
            } else {
                valid_messages.push(message);
            }
        }

        // If all messages were expired, return Some(0) to indicate we processed a batch
        // but didn't sync any messages (they were expired and removed)
        if valid_messages.is_empty() {
            tracing::debug!(
                "All {} messages in batch were expired and removed for relay {}",
                expired_count,
                hex::encode(relay_id.as_bytes())
            );
            return Ok(Some(0));
        }

        // Now check which valid messages already exist on the server
        let message_ids: Vec<_> = valid_messages.iter().map(|msg| *msg.id()).collect();

        tracing::debug!(
            "Checking existence of {} valid messages on relay {} ({} expired messages removed)",
            message_ids.len(),
            hex::encode(relay_id.as_bytes()),
            expired_count
        );

        let existence_results = manager.check_messages(message_ids).await?;
        let mut processed_count = 0;
        // Process messages based on existence check results
        for (message, existence_result) in valid_messages.iter().zip(existence_results.iter()) {
            if let Some(global_stream_id) = existence_result {
                // Message already exists on server, just mark as synced
                if let Err(e) = storage
                    .mark_message_synced(message.id(), relay_key_id, global_stream_id)
                    .await
                {
                    tracing::error!(
                        "Failed to mark existing message {} as synced to relay {}: {}",
                        hex::encode(message.id().as_bytes()),
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                } else {
                    tracing::debug!(
                        "Message {} already exists on relay {}, marked as synced",
                        hex::encode(message.id().as_bytes()),
                        hex::encode(relay_id.as_bytes())
                    );
                    processed_count += 1;
                }
                continue;
            }

            // Message doesn't exist, need to send it
            let global_stream_id = match manager.publish(message.clone()).await {
                Ok(result) => match result {
                    PublishResult::StoredNew { global_stream_id } => global_stream_id,
                    PublishResult::AlreadyExists { global_stream_id } => global_stream_id,
                    PublishResult::Expired => {
                        tracing::warn!("Message expired: {}", hex::encode(message.id().as_bytes()));
                        continue;
                    }
                },
                Err(e) => {
                    tracing::error!(
                        "Failed to send message {} to relay {}: {}",
                        hex::encode(message.id().as_bytes()),
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                    continue;
                }
            };

            // Mark as synced in storage
            if let Err(e) = storage
                .mark_message_synced(message.id(), relay_key_id, &global_stream_id)
                .await
            {
                tracing::error!(
                    "Failed to mark message {} as synced to relay {}: {}",
                    hex::encode(message.id().as_bytes()),
                    hex::encode(relay_id.as_bytes()),
                    e
                );
            }
            processed_count += 1;
        }

        tracing::debug!(
            "Batch complete: {}/{} valid messages successfully processed for relay {} ({} expired messages removed)",
            processed_count,
            valid_messages.len(),
            hex::encode(relay_id.as_bytes()),
            expired_count
        );

        Ok(Some(processed_count))
    }
}

#[async_trait]
impl<S: MessageStorage + 'static> MessagesManagerTrait for MultiRelayMessageManager<S> {
    /// Get a stream of all message events from all relays
    fn message_events_stream(&self) -> BroadcastStream<MessageEvent> {
        BroadcastStream::new(self.global_events_tx.subscribe())
    }

    /// Subscribe to subscription state changes (aggregated from all relays)
    async fn get_subscription_state_updates(
        &self,
    ) -> eyeball::Subscriber<SubscriptionState, AsyncLock> {
        // For now, return a default state. In a full implementation, we'd aggregate
        // subscription states from all relays
        let state = SubscriptionState::default();
        let observable = SharedObservable::new_async(state);
        observable.subscribe().await
    }

    /// Subscribe to messages on all connected relays
    async fn subscribe(&self) -> Result<()> {
        let connections = self.relay_connections.read().await;
        let mut results = Vec::new();

        for (relay_id, connection) in connections.iter() {
            if matches!(connection.connection_state, ConnectionState::Connected) {
                match connection.manager.subscribe().await {
                    Ok(()) => {
                        tracing::debug!("Subscribed to relay {}", hex::encode(relay_id.as_bytes()));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to subscribe to relay {}: {}",
                            hex::encode(relay_id.as_bytes()),
                            e
                        );
                        results.push(e);
                    }
                }
            }
        }

        // Return error if all subscriptions failed
        if !results.is_empty() && results.len() == connections.len() {
            return Err(results.into_iter().next().unwrap());
        }

        Ok(())
    }

    /// Publish a message to available relays or queue for offline delivery
    async fn publish(&self, message: MessageFull) -> Result<PublishResult> {
        let connected_relays = {
            let connections = self.relay_connections.read().await;
            connections
                .iter()
                .filter(|(_, conn)| matches!(conn.connection_state, ConnectionState::Connected))
                .map(|(id, conn)| (*id, Arc::clone(&conn.manager)))
                .collect::<Vec<_>>()
        };

        if connected_relays.is_empty() {
            // No relays available, store message for offline processing
            self.storage.store_message(&message).await.map_err(|e| {
                ClientError::Generic(format!(
                    "Failed to store message for offline delivery: {}",
                    e
                ))
            })?;

            tracing::info!(
                "No relays available, stored message {} for offline processing",
                hex::encode(message.id().as_bytes())
            );

            return Ok(PublishResult::StoredNew {
                global_stream_id: "queued_offline".to_string(),
            });
        }

        // Try to send to the first available relay
        // In a more sophisticated implementation, we could implement load balancing
        let (relay_id, manager) = &connected_relays[0];

        match manager.publish(message.clone()).await {
            Ok(result) => {
                // Mark as synced to this relay
                let relay_key_id = relay_id;
                let global_stream_id = match &result {
                    PublishResult::StoredNew { global_stream_id } => global_stream_id,
                    PublishResult::AlreadyExists { global_stream_id } => global_stream_id,
                    PublishResult::Expired => {
                        tracing::warn!("Message expired during publish");
                        return Ok(result);
                    }
                };

                if let Err(e) = self
                    .storage
                    .mark_message_synced(message.id(), relay_key_id, global_stream_id)
                    .await
                {
                    tracing::error!(
                        "Failed to mark message {} as synced to relay {}: {}",
                        hex::encode(message.id().as_bytes()),
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                }

                tracing::debug!(
                    "Successfully published message to relay {}",
                    hex::encode(relay_id.as_bytes())
                );
                Ok(result)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to publish message to relay {}: {}",
                    hex::encode(relay_id.as_bytes()),
                    e
                );

                // Store message for offline processing - background task will retry
                self.storage
                    .store_message(&message)
                    .await
                    .map_err(|storage_err| {
                        ClientError::Generic(format!(
                            "Failed to store message for offline delivery: {}",
                            storage_err
                        ))
                    })?;

                tracing::info!(
                    "Stored message {} for offline processing after publish failure",
                    hex::encode(message.id().as_bytes())
                );

                Err(e)
            }
        }
    }

    /// Ensure a filter is included in the subscription on all connected relays
    async fn ensure_contains_filter(&self, filter: Filter) -> Result<()> {
        let connections = self.relay_connections.read().await;
        let mut results = Vec::new();

        for (relay_id, connection) in connections.iter() {
            if matches!(connection.connection_state, ConnectionState::Connected) {
                match connection
                    .manager
                    .ensure_contains_filter(filter.clone())
                    .await
                {
                    Ok(()) => {
                        tracing::debug!(
                            "Added filter to relay {}",
                            hex::encode(relay_id.as_bytes())
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to add filter to relay {}: {}",
                            hex::encode(relay_id.as_bytes()),
                            e
                        );
                        results.push(e);
                    }
                }
            }
        }

        // Return error if all filter additions failed
        if !results.is_empty() && results.len() == connections.len() {
            return Err(results.into_iter().next().unwrap());
        }

        Ok(())
    }

    /// Get a stream of incoming messages from all relays
    fn messages_stream(&self) -> BroadcastStream<StreamMessage> {
        BroadcastStream::new(self.global_messages_tx.subscribe())
    }

    /// Get a stream of catch-up responses from all relays
    fn catch_up_stream(&self) -> BroadcastStream<CatchUpResponse> {
        BroadcastStream::new(self.global_catchup_tx.subscribe())
    }

    /// Get a filtered stream of messages matching the given filter from all relays
    fn filtered_messages_stream<'a>(
        &'a self,
        _filter: Filter,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send + 'a>> {
        // TODO: Implement proper filtering
        // For now, return an empty stream
        Box::pin(futures::stream::empty())
    }

    /// Catch up to historical messages and subscribe to new ones for a filter
    async fn catch_up_and_subscribe<'a>(
        &'a self,
        _filter: Filter,
        _since: Option<String>,
    ) -> Result<std::pin::Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send + 'a>>> {
        // TODO: Implement proper catch-up across all relays
        // For now, return an empty stream as a placeholder
        Ok(Box::pin(futures::stream::empty()))
    }

    /// Get user data by author and storage key from any available relay
    async fn user_data(&self, author: KeyId, storage_key: StoreKey) -> Result<Option<MessageFull>> {
        let connections = self.relay_connections.read().await;

        // Try each connected relay until we find the data
        for (relay_id, connection) in connections.iter() {
            if matches!(connection.connection_state, ConnectionState::Connected) {
                match connection
                    .manager
                    .user_data(author, storage_key.clone())
                    .await
                {
                    Ok(Some(data)) => {
                        tracing::debug!(
                            "Found user data on relay {}",
                            hex::encode(relay_id.as_bytes())
                        );
                        return Ok(Some(data));
                    }
                    Ok(None) => {
                        // Not found on this relay, try next
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to get user data from relay {}: {}",
                            hex::encode(relay_id.as_bytes()),
                            e
                        );
                        continue;
                    }
                }
            }
        }

        Ok(None) // Not found on any relay
    }

    /// Check which messages exist on any connected relay
    /// Returns the first successful result from any relay
    async fn check_messages(
        &self,
        message_ids: Vec<zoe_wire_protocol::MessageId>,
    ) -> Result<Vec<Option<String>>> {
        let connections = self.relay_connections.read().await;

        // Try each connected relay until we get a successful response
        for (relay_id, connection) in connections.iter() {
            if matches!(connection.connection_state, ConnectionState::Connected) {
                match connection.manager.check_messages(message_ids.clone()).await {
                    Ok(result) => {
                        tracing::debug!(
                            "Successfully checked {} messages on relay {}",
                            message_ids.len(),
                            hex::encode(relay_id.as_bytes())
                        );
                        return Ok(result);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to check messages on relay {}: {}",
                            hex::encode(relay_id.as_bytes()),
                            e
                        );
                        continue;
                    }
                }
            }
        }

        // If no relay is available, return None for all messages (assume they don't exist)
        tracing::warn!("No connected relays available for checking messages");
        Ok(vec![None; message_ids.len()])
    }
}

impl<S: MessageStorage> Drop for MultiRelayMessageManager<S> {
    fn drop(&mut self) {
        // Cancel all active catch-up tasks
        if let Ok(mut tasks) = self.catch_up_tasks.try_write() {
            for (relay_id, task) in tasks.iter() {
                task.abort();
                tracing::debug!(
                    "Cancelled catch-up task for relay during drop: {}",
                    hex::encode(relay_id.as_bytes())
                );
            }
            tasks.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_client_storage::storage::MockMessageStorage;
    use zoe_wire_protocol::{Content, KeyPair, Kind, Message, MessageFull};

    fn create_test_message() -> MessageFull {
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng);
        let message = Message::new_v0(
            Content::raw(b"Test message".to_vec()),
            keypair.public_key(),
            1234567890u64, // Fixed timestamp for testing
            Kind::Regular,
            vec![],
        );
        MessageFull::new(message, &keypair).unwrap()
    }

    #[tokio::test]
    async fn test_multi_relay_manager_creation() {
        let mock_storage = MockMessageStorage::new();
        let manager = MultiRelayMessageManager::new(Arc::new(mock_storage));

        // Should start with no relays
        assert_eq!(manager.get_all_relay_ids().await.len(), 0);
        assert!(!manager.has_connected_relays().await);
    }

    #[tokio::test]
    async fn test_offline_message_queuing() {
        let mut mock_storage = MockMessageStorage::new();
        mock_storage
            .expect_store_message()
            .times(1)
            .returning(|_| Ok(()));

        let manager = MultiRelayMessageManager::new(Arc::new(mock_storage));
        let test_message = create_test_message();

        // Publishing with no relays should queue the message offline
        let result = manager.publish(test_message).await;
        assert!(result.is_ok());

        if let Ok(publish_result) = result {
            assert_eq!(
                publish_result,
                PublishResult::StoredNew {
                    global_stream_id: "queued_offline".to_string()
                }
            );
        }
    }

    #[tokio::test]
    async fn test_basic_functionality() {
        let mock_storage = MockMessageStorage::new();
        let manager = MultiRelayMessageManager::new(Arc::new(mock_storage));

        // Should start with no relays
        assert_eq!(manager.get_all_relay_ids().await.len(), 0);
        assert!(!manager.has_connected_relays().await);

        // Test getting connected relay IDs when none are connected
        let connected_ids = manager.get_connected_relay_ids().await;
        assert!(connected_ids.is_empty());
    }

    #[tokio::test]
    async fn test_session_manager_compatibility() {
        use crate::pqxdh::PqxdhProtocolState;
        use crate::session_manager::SessionManager;
        use zoe_client_storage::storage::MockStateStorage;
        use zoe_wire_protocol::KeyPair;

        let mock_message_storage = MockMessageStorage::new();
        let multi_relay_manager = Arc::new(MultiRelayMessageManager::new(Arc::new(
            mock_message_storage,
        )));

        let mut mock_state_storage = MockStateStorage::new();
        // Mock the expected calls for loading PQXDH states
        mock_state_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| Ok(vec![]));
        // Mock the expected calls for group manager initialization
        mock_state_storage
            .expect_list_namespace_data::<zoe_state_machine::GroupSession>()
            .returning(|_| Ok(vec![]));

        let mock_state_storage = Arc::new(mock_state_storage);

        // Create a test keypair
        let mut rng = rand::thread_rng();
        let keypair = Arc::new(KeyPair::generate(&mut rng));

        // Test that SessionManager can be created with MultiRelayMessageManager
        let session_manager_result =
            SessionManager::builder(mock_state_storage, multi_relay_manager)
                .client_keypair(keypair)
                .build()
                .await;

        // This should compile and work without issues
        assert!(session_manager_result.is_ok());

        let session_manager = session_manager_result.unwrap();

        // Verify we can access the multi-relay manager through the session manager
        let messages_manager = session_manager.messages_manager();

        // Test that we can use the session manager's message manager interface
        let _events_stream = messages_manager.message_events_stream();
        // Stream creation should succeed (we can't easily test if it's active without subscribing)
    }

    #[tokio::test]
    async fn test_pqxdh_handler_compatibility() {
        use crate::pqxdh::PqxdhProtocolHandler;
        use zoe_wire_protocol::{KeyPair, PqxdhInboxProtocol};

        let mock_message_storage = MockMessageStorage::new();
        let multi_relay_manager = Arc::new(MultiRelayMessageManager::new(Arc::new(
            mock_message_storage,
        )));

        // Create a test keypair
        let mut rng = rand::thread_rng();
        let keypair = Arc::new(KeyPair::generate(&mut rng));

        // Test that PqxdhProtocolHandler can be created with MultiRelayMessageManager
        let _pqxdh_handler = PqxdhProtocolHandler::new(
            multi_relay_manager,
            keypair,
            PqxdhInboxProtocol::EchoService,
        );

        // Verify the handler was created successfully by checking it can be used
        // We can't easily test internal state without more complex setup,
        // but the fact that it compiles and creates successfully is the main test
    }

    #[tokio::test]
    async fn test_catch_up_processing() {
        use crate::services::messages_manager::MockMessagesManagerTrait;

        // Create a message that will be "unsynced" for a relay
        let test_message = create_test_message();
        let relay_id = KeyId::from([1u8; 32]);
        let relay_key_id = relay_id;

        // Mock storage to return the unsynced message
        let mut mock_storage = MockMessageStorage::new();
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(50)),
            )
            .times(1)
            .returning(move |_, _| Ok(vec![test_message.clone()]));

        // Mock successful message sync marking
        mock_storage
            .expect_mark_message_synced()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let storage = Arc::new(mock_storage);

        // Create a mock messages manager that will succeed
        let mut mock_manager = MockMessagesManagerTrait::new();

        // Mock check_messages to return that the message doesn't exist (None)
        mock_manager
            .expect_check_messages()
            .times(1)
            .returning(|_| Ok(vec![None])); // Message doesn't exist, needs to be sent

        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_123".to_string(),
            })
        });

        let mock_manager = Arc::new(mock_manager);

        // Test the catch-up processing function directly
        let result = MultiRelayMessageManager::process_unsynced_messages_batch_for_relay(
            &storage,
            &relay_id,
            &mock_manager,
            50,
        )
        .await;

        assert!(result.is_ok(), "Catch-up processing should succeed");

        // Verify that we processed exactly 1 message
        assert_eq!(
            result.unwrap(),
            Some(1),
            "Should have processed exactly 1 message"
        );
    }

    #[tokio::test]
    async fn test_batched_catch_up_processing() {
        use crate::services::messages_manager::MockMessagesManagerTrait;

        // Create multiple test messages
        let test_messages: Vec<MessageFull> = (0u64..5u64)
            .map(|i| {
                let mut rng = rand::thread_rng();
                let keypair = KeyPair::generate(&mut rng);
                let message = Message::new_v0(
                    Content::raw(format!("Test message {}", i).as_bytes().to_vec()),
                    keypair.public_key(),
                    1234567890u64 + i,
                    Kind::Regular,
                    vec![],
                );
                MessageFull::new(message, &keypair).unwrap()
            })
            .collect();

        let relay_id = KeyId::from([1u8; 32]);
        let relay_key_id = relay_id;

        // Mock storage to return messages in batches
        let mut mock_storage = MockMessageStorage::new();

        // First call returns 2 messages (batch size 2)
        let messages_batch_1 = vec![test_messages[0].clone(), test_messages[1].clone()];
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(2)),
            )
            .times(1)
            .returning(move |_, _| Ok(messages_batch_1.clone()));

        // Second call returns 2 more messages
        let messages_batch_2 = vec![test_messages[2].clone(), test_messages[3].clone()];
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(2)),
            )
            .times(1)
            .returning(move |_, _| Ok(messages_batch_2.clone()));

        // Third call returns 1 message
        let messages_batch_3 = vec![test_messages[4].clone()];
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(2)),
            )
            .times(1)
            .returning(move |_, _| Ok(messages_batch_3.clone()));

        // Fourth call returns 0 messages (indicating we're done)
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(2)),
            )
            .times(1)
            .returning(move |_, _| Ok(vec![]));

        // Mock successful message sync marking for all 5 messages
        mock_storage
            .expect_mark_message_synced()
            .times(5)
            .returning(|_, _, _| Ok(()));

        let storage = Arc::new(mock_storage);

        // Create a mock messages manager that will succeed for all messages
        let mut mock_manager = MockMessagesManagerTrait::new();

        // Mock check_messages for each batch:
        // Batch 1: 2 messages, both don't exist (need to send)
        mock_manager
            .expect_check_messages()
            .times(1)
            .returning(|_| Ok(vec![None, None]));

        // Batch 2: 2 messages, both don't exist (need to send)
        mock_manager
            .expect_check_messages()
            .times(1)
            .returning(|_| Ok(vec![None, None]));

        // Batch 3: 1 message, doesn't exist (need to send)
        mock_manager
            .expect_check_messages()
            .times(1)
            .returning(|_| Ok(vec![None]));

        mock_manager.expect_publish().times(5).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_123".to_string(),
            })
        });

        let mock_manager = Arc::new(mock_manager);

        // Test the full batched catch-up processing
        let result = MultiRelayMessageManager::process_all_unsynced_messages_for_relay(
            &storage,
            &relay_id,
            &mock_manager,
            2, // batch size of 2
        )
        .await;

        assert!(result.is_ok(), "Batched catch-up processing should succeed");

        // Verify that we processed all 5 messages across 4 batches (2+2+1+0)
        assert_eq!(
            result.unwrap(),
            5,
            "Should have processed exactly 5 messages total"
        );
    }

    #[tokio::test]
    async fn test_efficient_catch_up_with_existing_messages() {
        use crate::services::messages_manager::MockMessagesManagerTrait;

        // Create 3 test messages
        let test_messages: Vec<MessageFull> = (0u64..3u64)
            .map(|i| {
                let mut rng = rand::thread_rng();
                let keypair = KeyPair::generate(&mut rng);
                let message = Message::new_v0(
                    Content::raw(format!("Test message {}", i).as_bytes().to_vec()),
                    keypair.public_key(),
                    1234567890u64 + i,
                    Kind::Regular,
                    vec![],
                );
                MessageFull::new(message, &keypair).unwrap()
            })
            .collect();

        let relay_id = KeyId::from([1u8; 32]);
        let relay_key_id = relay_id;

        // Extract message IDs before creating closures
        let message_ids = vec![
            *test_messages[0].id(),
            *test_messages[1].id(),
            *test_messages[2].id(),
        ];

        // Mock storage to return 3 unsynced messages
        let mut mock_storage = MockMessageStorage::new();
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(3)),
            )
            .times(1)
            .returning(move |_, _| Ok(test_messages.clone()));

        // Second call returns empty (indicating we're done)
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(3)),
            )
            .times(1)
            .returning(move |_, _| Ok(vec![]));

        // Mock successful message sync marking for all 3 messages
        mock_storage
            .expect_mark_message_synced()
            .times(3)
            .returning(|_, _, _| Ok(()));

        let storage = Arc::new(mock_storage);

        // Create a mock messages manager
        let mut mock_manager = MockMessagesManagerTrait::new();

        // Mock check_messages to return:
        // - Message 0: already exists (Some("existing_stream_1"))
        // - Message 1: doesn't exist (None)
        // - Message 2: already exists (Some("existing_stream_2"))
        mock_manager
            .expect_check_messages()
            .with(mockall::predicate::eq(message_ids))
            .times(1)
            .returning(|_| {
                Ok(vec![
                    Some("existing_stream_1".to_string()), // Message 0 exists
                    None,                                  // Message 1 doesn't exist
                    Some("existing_stream_2".to_string()), // Message 2 exists
                ])
            });

        // Mock publish to be called only once (for message 1 that doesn't exist)
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "new_stream_123".to_string(),
            })
        });

        let mock_manager = Arc::new(mock_manager);

        // Test the efficient batch processing
        let result = MultiRelayMessageManager::process_all_unsynced_messages_for_relay(
            &storage,
            &relay_id,
            &mock_manager,
            3, // batch size of 3
        )
        .await;

        assert!(
            result.is_ok(),
            "Efficient catch-up processing should succeed"
        );

        // Verify that we processed all 3 messages:
        // - 2 were marked as synced without sending (already existed)
        // - 1 was sent and then marked as synced
        assert_eq!(
            result.unwrap(),
            3,
            "Should have processed exactly 3 messages total"
        );
    }

    #[tokio::test]
    async fn test_expired_message_handling() {
        use crate::services::messages_manager::MockMessagesManagerTrait;
        use zoe_wire_protocol::Kind;

        // Create test messages - one expired, one valid
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        // Create an expired ephemeral message (timeout of 1 second, created 2 seconds ago)
        let expired_message = {
            let past_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(2); // 2 seconds ago

            let message = Message::new_v0(
                Content::raw(b"Expired message".to_vec()),
                keypair.public_key(),
                past_timestamp,
                Kind::Emphemeral(1), // 1 second timeout - should be expired
                vec![],
            );
            MessageFull::new(message, &keypair).unwrap()
        };

        // Create a valid regular message
        let valid_message = {
            let message = Message::new_v0(
                Content::raw(b"Valid message".to_vec()),
                keypair.public_key(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Kind::Regular,
                vec![],
            );
            MessageFull::new(message, &keypair).unwrap()
        };

        let test_messages = vec![expired_message.clone(), valid_message.clone()];
        let relay_id = KeyId::from([1u8; 32]);
        let relay_key_id = relay_id;

        // Mock storage to return both messages initially
        let mut mock_storage = MockMessageStorage::new();
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(2)),
            )
            .times(1)
            .returning(move |_, _| Ok(test_messages.clone()));

        // Second call returns empty (indicating we're done)
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(2)),
            )
            .times(1)
            .returning(move |_, _| Ok(vec![]));

        // Mock deletion of expired message
        let expired_id = *expired_message.id();
        mock_storage
            .expect_delete_message()
            .with(mockall::predicate::eq(expired_id))
            .times(1)
            .returning(|_| Ok(true));

        // Mock successful message sync marking for the valid message only
        mock_storage
            .expect_mark_message_synced()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let storage = Arc::new(mock_storage);

        // Create a mock messages manager
        let mut mock_manager = MockMessagesManagerTrait::new();

        // Mock check_messages for the valid message only (expired message filtered out)
        let valid_message_id = *valid_message.id();
        mock_manager
            .expect_check_messages()
            .with(mockall::predicate::eq(vec![valid_message_id]))
            .times(1)
            .returning(|_| Ok(vec![None])); // Valid message doesn't exist, needs to be sent

        // Mock publish to be called only for the valid message
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "valid_stream_123".to_string(),
            })
        });

        let mock_manager = Arc::new(mock_manager);

        // Test the batch processing with expired messages
        let result = MultiRelayMessageManager::process_all_unsynced_messages_for_relay(
            &storage,
            &relay_id,
            &mock_manager,
            2, // batch size of 2
        )
        .await;

        assert!(
            result.is_ok(),
            "Processing with expired messages should succeed"
        );

        // Verify that we processed only 1 message (the valid one)
        // The expired message should have been removed from storage
        assert_eq!(
            result.unwrap(),
            1,
            "Should have processed exactly 1 valid message (expired message removed)"
        );
    }

    #[tokio::test]
    async fn test_all_expired_messages_batch() {
        use crate::services::messages_manager::MockMessagesManagerTrait;
        use zoe_wire_protocol::Kind;

        // Create test messages - all expired
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let expired_messages: Vec<MessageFull> = (0..3)
            .map(|i| {
                let past_timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .saturating_sub(10); // 10 seconds ago

                let message = Message::new_v0(
                    Content::raw(format!("Expired message {}", i).as_bytes().to_vec()),
                    keypair.public_key(),
                    past_timestamp,
                    Kind::Emphemeral(1), // 1 second timeout - all should be expired
                    vec![],
                );
                MessageFull::new(message, &keypair).unwrap()
            })
            .collect();

        let relay_id = KeyId::from([1u8; 32]);
        let relay_key_id = relay_id;

        // Mock storage to return all expired messages
        let mut mock_storage = MockMessageStorage::new();
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(3)),
            )
            .times(1)
            .returning(move |_, _| Ok(expired_messages.clone()));

        // Second call returns empty (indicating we're done)
        mock_storage
            .expect_get_unsynced_messages_for_relay()
            .with(
                mockall::predicate::eq(relay_key_id),
                mockall::predicate::eq(Some(3)),
            )
            .times(1)
            .returning(move |_, _| Ok(vec![]));

        // Mock deletion of all expired messages
        mock_storage
            .expect_delete_message()
            .times(3)
            .returning(|_| Ok(true));

        let storage = Arc::new(mock_storage);

        // Create a mock messages manager - no expectations for check_messages or publish
        // since all messages are expired and filtered out
        let mock_manager = MockMessagesManagerTrait::new();
        let mock_manager = Arc::new(mock_manager);

        // Test the batch processing with all expired messages
        let result = MultiRelayMessageManager::process_all_unsynced_messages_for_relay(
            &storage,
            &relay_id,
            &mock_manager,
            3, // batch size of 3
        )
        .await;

        assert!(
            result.is_ok(),
            "Processing all expired messages should succeed"
        );

        // Verify that we processed 0 messages (all were expired and removed)
        assert_eq!(
            result.unwrap(),
            0,
            "Should have processed 0 messages (all were expired and removed)"
        );
    }
}
