use async_broadcast::Receiver;
use async_trait::async_trait;
use eyeball::AsyncLock;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use zoe_wire_protocol::{
    CatchUpResponse, Filter, MessageFilters, MessageFull, PublishResult, StreamMessage,
};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessagesManagerError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("Client error: {0}")]
    Client(String),
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("Message error: {0}")]
    Message(String),
}

pub type Result<T> = std::result::Result<T, MessagesManagerError>;

// Conversion from RpcError to MessagesManagerError
impl From<tarpc::client::RpcError> for MessagesManagerError {
    fn from(err: tarpc::client::RpcError) -> Self {
        MessagesManagerError::Rpc(err.to_string())
    }
}

// Conversion from MessageError to MessagesManagerError
impl From<zoe_wire_protocol::MessageError> for MessagesManagerError {
    fn from(err: zoe_wire_protocol::MessageError) -> Self {
        MessagesManagerError::Message(err.to_string())
    }
}

#[cfg(any(feature = "mock", test))]
use mockall::automock;

/// Trait abstraction for MessagesManager to enable mocking in tests
#[cfg_attr(any(feature = "mock", test), automock())]
#[async_trait]
pub trait MessagesManagerTrait: Send + Sync {
    /// Get a stream of all message events for persistence and monitoring
    fn message_events_stream(&self) -> Receiver<MessageEvent>;

    /// Subscribe to subscription state changes for reactive programming
    ///
    /// This returns an eyeball::Subscriber that can be used to observe changes to the
    /// subscription state reactively. The subscriber will be notified whenever:
    /// - Stream height is updated
    /// - Filters are added or removed
    /// - Any other subscription state changes occur
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::services::MessagesManagerTrait;
    /// # async fn example(manager: &impl MessagesManagerTrait) {
    /// let subscriber = manager.subscribe_to_subscription_state();
    /// let current_state = subscriber.get();
    /// println!("Current stream height: {:?}", current_state.latest_stream_height);
    /// # }
    /// ```
    async fn get_subscription_state_updates(
        &self,
    ) -> eyeball::Subscriber<SubscriptionState, AsyncLock>;

    /// Subscribe to messages with current filters
    async fn subscribe(&self) -> Result<()>;

    /// Publish a message
    async fn publish(&self, message: MessageFull) -> Result<PublishResult>;

    /// Ensure a filter is included in the subscription
    async fn ensure_contains_filter(&self, filter: Filter) -> Result<()>;

    /// Get a stream of incoming messages
    fn messages_stream(&self) -> Receiver<StreamMessage>;

    /// Get a stream of catch-up responses
    fn catch_up_stream(&self) -> Receiver<CatchUpResponse>;

    /// Get a filtered stream of messages matching the given filter
    fn filtered_messages_stream(
        &self,
        filter: Filter,
    ) -> Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send>>;

    /// Catch up to historical messages and subscribe to new ones for a filter
    async fn catch_up_and_subscribe(
        &self,
        filter: Filter,
        since: Option<String>,
    ) -> Result<Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send>>>;

    /// Get user data by author and storage key (for PQXDH inbox fetching)
    async fn user_data(
        &self,
        author: zoe_wire_protocol::KeyId,
        storage_key: zoe_wire_protocol::StoreKey,
    ) -> Result<Option<MessageFull>>;

    /// Check which messages the server already has and return their global stream IDs.
    /// Returns a vec of `Option<String>` in the same order as the input, where:
    /// - `Some(stream_id)` means the server has the message with that global stream ID
    /// - `None` means the server doesn't have this message yet
    async fn check_messages(
        &self,
        message_ids: Vec<zoe_wire_protocol::MessageId>,
    ) -> Result<Vec<Option<String>>>;
}

/// Comprehensive message event that covers all message flows for persistence and monitoring.
///
/// This enum captures every type of message activity in the MessagesManager,
/// enabling complete message persistence and audit trails.
#[derive(Debug, Clone)]
pub enum MessageEvent {
    /// Message received from subscription stream
    MessageReceived {
        message: MessageFull,
        stream_height: String,
    },
    /// Message sent by this client
    MessageSent {
        message: MessageFull,
        publish_result: PublishResult,
    },
    /// Historical message from catch-up
    CatchUpMessage {
        message: MessageFull,
        request_id: u32,
    },
    /// Stream height update
    StreamHeightUpdate { height: String },
    /// Catch-up completed
    CatchUpCompleted { request_id: u32 },
}

/// Serializable subscription state that can be persisted and restored.
///
/// This state contains all the information needed to restore a MessagesManager
/// to its previous subscription state after a connection restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SubscriptionState {
    /// The latest stream height we've received
    /// Used to resume from the correct position after reconnection
    pub latest_stream_height: Option<String>,

    /// Combined subscription filters accumulated over time
    /// This represents the union of all active subscriptions
    pub current_filters: MessageFilters,
}

impl SubscriptionState {
    /// Create a new empty subscription state
    pub fn new() -> Self {
        Self::default()
    }

    /// Create subscription state with initial filters
    pub fn with_filters(filters: MessageFilters) -> Self {
        Self {
            latest_stream_height: None,
            current_filters: filters,
        }
    }

    /// Add filters to the combined state
    pub fn add_filters(&mut self, new_filters: &[zoe_wire_protocol::Filter]) {
        let current_filters = self.current_filters.filters.get_or_insert_with(Vec::new);
        for filter in new_filters {
            if !current_filters.contains(filter) {
                current_filters.push(filter.clone());
            }
        }
    }

    /// Remove filters from the combined state
    pub fn remove_filters(&mut self, filters_to_remove: &[zoe_wire_protocol::Filter]) {
        if let Some(current_filters) = self.current_filters.filters.as_mut() {
            current_filters.retain(|f| !filters_to_remove.contains(f));
            if current_filters.is_empty() {
                self.current_filters.filters = None;
            }
        }
    }

    /// Update the latest stream height
    pub fn set_stream_height(&mut self, height: String) {
        self.latest_stream_height = Some(height);
    }

    /// Check if we have any active filters
    pub fn has_active_filters(&self) -> bool {
        !self.current_filters.is_empty()
    }
}

#[cfg(any(feature = "mock", test))]
impl Clone for MockMessagesManagerTrait {
    fn clone(&self) -> Self {
        // Create a new mock with the same expectations
        // Note: This is a simplified clone that creates a fresh mock
        // In practice, you might want to copy over expectations
        MockMessagesManagerTrait::new()
    }
}
