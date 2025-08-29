use crate::error::{ClientError, Result};
use futures::StreamExt;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};
use zoe_client_storage::{MessageStorage, StorageError};
use zoe_wire_protocol::VerifyingKey;

use super::messages_manager::{MessageEvent, MessagesManager};

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
/// #     storage: Arc<dyn MessageStorage<Error = StorageError>>,
/// #     messages_manager: Arc<zoe_client::services::MessagesManager>,
/// #     relay_key: VerifyingKey,
/// # ) -> zoe_client::error::Result<()> {
/// let persistence_manager = MessagePersistenceManagerBuilder::new()
///     .storage(storage)
///     .messages_manager(messages_manager)
///     .relay_pubkey(relay_key)

///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct MessagePersistenceManagerBuilder {
    storage: Option<Arc<dyn MessageStorage<Error = StorageError>>>,
    messages_manager: Option<Arc<MessagesManager>>,
    relay_pubkey: Option<VerifyingKey>,
    buffer_size: Option<usize>,
}

impl MessagePersistenceManagerBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            storage: None,
            messages_manager: None,
            relay_pubkey: None,
            buffer_size: None,
        }
    }

    /// Set the storage implementation to use for persistence
    pub fn storage(mut self, storage: Arc<dyn MessageStorage<Error = StorageError>>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Set the messages manager to monitor for message events
    pub fn messages_manager(mut self, messages_manager: Arc<MessagesManager>) -> Self {
        self.messages_manager = Some(messages_manager);
        self
    }

    /// Set the relay public key for sync tracking
    pub fn relay_pubkey(mut self, relay_pubkey: VerifyingKey) -> Self {
        self.relay_pubkey = Some(relay_pubkey);
        self
    }

    /// Set the buffer size for the persistence task queue
    pub fn buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = Some(buffer_size);
        self
    }

    /// Build the MessagePersistenceManager and start persistence
    ///
    /// This will:
    /// 1. Validate that all required components are provided
    /// 2. Start the background persistence task
    /// 3. Return a fully configured MessagePersistenceManager
    ///
    /// # Errors
    /// Returns an error if storage or messages_manager are not provided
    pub async fn build(self) -> Result<MessagePersistenceManager> {
        let storage = self
            .storage
            .ok_or_else(|| ClientError::Generic("Storage is required".to_string()))?;
        let messages_manager = self
            .messages_manager
            .ok_or_else(|| ClientError::Generic("MessagesManager is required".to_string()))?;

        let manager = MessagePersistenceManager::new(
            storage.clone(),
            messages_manager.clone(),
            self.relay_pubkey,
            self.buffer_size,
        )
        .await?;

        Ok(manager)
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
pub struct MessagePersistenceManager {
    /// Handle to the background persistence task
    persistence_task: JoinHandle<Result<()>>,
}

impl MessagePersistenceManager {
    /// Create a new MessagePersistenceManager builder
    pub fn builder() -> MessagePersistenceManagerBuilder {
        MessagePersistenceManagerBuilder::new()
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
        storage: Arc<dyn MessageStorage<Error = StorageError>>,
        messages_manager: Arc<MessagesManager>,
        relay_pubkey: Option<VerifyingKey>,
        _buffer_size: Option<usize>,
    ) -> Result<Self> {
        // Get the message events stream before spawning the task to avoid lifetime issues
        let events_stream = messages_manager.message_events_stream();
        let storage_clone = storage.clone();

        // Start the background persistence task
        let persistence_task = tokio::spawn(async move {
            debug!("MessagePersistenceManager started");

            let mut events_stream = Box::pin(events_stream);
            while let Some(event) = events_stream.next().await {
                if let Err(e) =
                    Self::handle_message_event(&*storage_clone, &event, &relay_pubkey).await
                {
                    warn!("Failed to handle message event {:?}: {}", event, e);
                    // Continue processing other events even if one fails
                }
            }

            debug!("MessagePersistenceManager task ended");
            Ok(())
        });

        Ok(Self { persistence_task })
    }

    /// Handle a single message event by persisting it
    async fn handle_message_event(
        storage: &dyn MessageStorage<Error = StorageError>,
        event: &MessageEvent,
        relay_pubkey: &Option<VerifyingKey>,
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
                if let Some(relay_key) = relay_pubkey {
                    storage
                        .mark_message_synced(message.id(), relay_key, stream_height)
                        .await
                        .map_err(|e| {
                            ClientError::Generic(format!("Failed to mark message as synced: {}", e))
                        })?;
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_builder_defaults() {
        let builder = MessagePersistenceManagerBuilder::new();
        assert!(builder.storage.is_none());
        assert!(builder.messages_manager.is_none());
        assert!(builder.relay_pubkey.is_none());
        assert!(builder.buffer_size.is_none());
    }

    #[tokio::test]
    async fn test_builder_validation() {
        // Test builder validation - should fail without required components
        let result = MessagePersistenceManagerBuilder::new().build().await;
        assert!(result.is_err());
    }
}
