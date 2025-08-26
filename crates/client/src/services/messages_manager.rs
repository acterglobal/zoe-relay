use crate::error::{ClientError, Result};
use futures::{Stream, StreamExt, pin_mut};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::{
    select,
    sync::{RwLock, broadcast},
    task::JoinHandle,
};
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::warn;
use zoe_wire_protocol::{
    CatchUpRequest, CatchUpResponse, Filter, MessageFilters, MessageFull, PublishResult,
    StreamMessage, SubscriptionConfig,
};

use super::messages::{CatchUpStream, MessagesService, MessagesStream};
use async_stream::stream;
use std::sync::atomic::AtomicU32;

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

/// Configuration for catching up on historical messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CatchUpConfig {
    /// How far back to catch up (in messages or time)
    pub since: Option<u64>,
    /// Maximum number of messages to catch up
    pub limit: Option<u32>,
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
    pub fn add_filters(&mut self, new_filters: &[Filter]) {
        let current_filters = self.current_filters.filters.get_or_insert_with(Vec::new);
        for filter in new_filters {
            if !current_filters.contains(filter) {
                current_filters.push(filter.clone());
            }
        }
    }

    /// Remove filters from the combined state
    pub fn remove_filters(&mut self, filters_to_remove: &[Filter]) {
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

impl From<&SubscriptionState> for SubscriptionConfig {
    fn from(val: &SubscriptionState) -> Self {
        SubscriptionConfig {
            filters: val.current_filters.clone(),
            since: val.latest_stream_height.clone(),
            limit: None,
        }
    }
}

/// Builder for creating MessagesManager instances with persistent state support.
///
/// This builder allows you to configure the MessagesManager with previous state,
/// buffer sizes, and other options before connecting to the message service.
///
/// # Example
///
/// ```rust,no_run
/// # use zoe_client::services::{MessagesManagerBuilder, SubscriptionState};
/// # async fn example(connection: &quinn::Connection) -> zoe_client::error::Result<()> {
/// // Create with previous state
/// let previous_state = SubscriptionState::from_bytes(&saved_bytes)?;
/// let manager = MessagesManagerBuilder::new()
///     .with_state(previous_state)
///     .with_buffer_size(2000)
///     .build(connection)
///     .await?;
///
/// // Or create fresh
/// let manager = MessagesManagerBuilder::new()
///     .build(connection)
///     .await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MessagesManagerBuilder {
    /// Previous subscription state to restore
    state: SubscriptionState,
    /// Buffer size for the broadcast channel
    buffer_size: Option<usize>,
}

impl Default for MessagesManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MessagesManagerBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            state: SubscriptionState::new(),
            buffer_size: None,
        }
    }

    /// Set the subscription state to restore from
    pub fn state(mut self, state: SubscriptionState) -> Self {
        self.state = state;
        self
    }

    pub fn with_filters(mut self, filters: MessageFilters) -> Self {
        self.state.current_filters = filters;
        self
    }

    /// Set the buffer size for the broadcast channel
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = Some(size);
        self
    }

    /// Build the MessagesManager by connecting to the service
    ///
    /// This will:
    /// 1. Connect to the messages service
    /// 2. Restore previous subscription state if any
    /// 3. Start the message broadcasting
    /// 4. Return a fully configured MessagesManager
    pub async fn build(self, connection: &quinn::Connection) -> Result<MessagesManager> {
        // Create the messages service and stream
        let (messages_service, (messages_stream, catch_up_stream)) =
            MessagesService::connect(connection).await?;
        let MessagesManagerBuilder { state, buffer_size } = self;
        messages_service.subscribe((&state).into()).await?;

        // Create the manager
        let manager = MessagesManager::new_with_state(
            messages_service,
            messages_stream,
            catch_up_stream,
            state,
            buffer_size,
        );

        Ok(manager)
    }
}

/// High-level messages manager that provides a unified interface for message operations.
///
/// The `MessagesManager` combines message broadcasting and subscription management:
/// - **Message Broadcasting**: Distributes incoming messages to multiple subscribers
/// - **Subscription Management**: Manages server-side subscriptions with in-flight updates
/// - **Stream Filtering**: Provides client-side filtering and routing capabilities
/// - **Lifecycle Management**: Automatic subscription creation, updates, and cleanup
///
/// This is the primary interface for interacting with the messaging system.
///
/// ```
pub struct MessagesManager {
    /// The underlying messages service for RPC operations
    messages_service: Arc<MessagesService>,
    /// Broadcast sender for distributing messages to subscribers
    broadcast_tx: broadcast::Sender<StreamMessage>,
    /// Broadcast sender for distributing catch-up responses to subscribers
    catch_up_tx: broadcast::Sender<CatchUpResponse>,
    /// Current subscription state (persistent across reconnections)
    state: Arc<RwLock<SubscriptionState>>,
    /// Background task handle for syncing with the server
    sync_handler: JoinHandle<Result<()>>,
    /// Catch-up request ID counter
    catch_up_request_id: AtomicU32,
}

impl MessagesManager {
    pub fn builder() -> MessagesManagerBuilder {
        MessagesManagerBuilder::new()
    }

    /// Create a new MessagesManager with existing subscription state.
    ///
    /// This allows restoring a manager to a previous state after reconnection.
    ///
    /// # Arguments
    /// * `messages_service` - The underlying messages service for RPC operations
    /// * `messages_stream` - The stream of messages from the server
    /// * `state` - Previous subscription state to restore
    /// * `buffer_size` - Optional buffer size for the broadcast channel (default: 1000)
    fn new_with_state(
        messages_service: MessagesService,
        messages_stream: MessagesStream,
        catch_up_stream: CatchUpStream,
        state: SubscriptionState,
        buffer_size: Option<usize>,
    ) -> Self {
        let buffer_size = buffer_size.unwrap_or(1000);
        let (broadcast_tx, _) = broadcast::channel(buffer_size);
        let (catch_up_tx, _) = broadcast::channel(buffer_size);

        // Clone state for the background task
        let state_for_task = Arc::new(RwLock::new(state.clone()));
        let state_clone = state_for_task.clone();

        // Start background task to forward messages from stream to broadcast channel
        let tx_clone = broadcast_tx.clone();
        let catch_up_tx_clone = catch_up_tx.clone();
        let sync_handler = tokio::spawn(async move {
            let mut m_stream = messages_stream;
            let mut c_stream = catch_up_stream;
            loop {
                select! {
                    message = m_stream.recv() => {
                        let Some(message) = message else {
                            break;
                        };
                        // Update stream height in state
                        if let StreamMessage::StreamHeightUpdate(height) = &message {
                            let mut state = state_clone.write().await;
                            state.set_stream_height(height.clone());
                        } else if let StreamMessage::MessageReceived { stream_height, .. } = &message {
                            let mut state = state_clone.write().await;
                            state.set_stream_height(stream_height.clone());
                        }

                        // Forward message to all subscribers
                        // If no subscribers are listening, the message is dropped (which is fine)
                        if let Err(e) = tx_clone.send(message) {
                            warn!("No subscribers listening for messages: {e}");
                            // Don't return error - this is expected when no one is subscribed
                        }
                    }
                    catch_up_response = c_stream.recv() => {
                        let Some(catch_up_response) = catch_up_response else {
                            break;
                        };
                        if let Err(e) = catch_up_tx_clone.send(catch_up_response) {
                            warn!("No subscribers listening for catch-up responses: {e}");
                            // Don't return error - this is expected when no one is subscribed
                        }
                        // Handle catch-up response
                    }
                }
            }

            Ok(())
        });

        Self {
            messages_service: Arc::new(messages_service),
            broadcast_tx,
            catch_up_tx,
            state: state_for_task,
            sync_handler,
            catch_up_request_id: AtomicU32::new(0),
        }
    }

    pub async fn catch_up_and_subscribe<'a>(
        &'a self,
        filter: Filter,
        since: Option<String>,
    ) -> Result<impl Stream<Item = Box<MessageFull>> + 'a> {
        // Enure if the underlying service is still alive
        if self.messages_service.is_closed() {
            return Err(ClientError::Generic(
                "Messages service connection is closed".to_string(),
            ));
        }

        let request_id = self
            .catch_up_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = CatchUpRequest {
            filter: filter.clone(),
            since,
            max_messages: None,
            request_id,
        };

        let regular_messages_stream = self.filtered_messages_stream(filter.clone());

        let catch_up_stream = {
            // we put this into a scope so the broadcaster is dropped when the stream finished

            let catch_up_rcv = BroadcastStream::new(self.catch_up_tx.subscribe()).filter_map(
                move |result| async move {
                    match result {
                        Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                            warn!(
                                "MessagesManager subscriber lagged, skipped {} messages",
                                skipped
                            );
                            None
                        }
                        Ok(CatchUpResponse {
                            request_id,
                            messages,
                            is_complete,
                            ..
                        }) => {
                            if request_id != request.request_id {
                                return None;
                            }
                            Some((messages, is_complete))
                        }
                    }
                },
            );

            stream! {
                pin_mut!(catch_up_rcv);
                while let Some((messages, is_complete)) = catch_up_rcv.next().await {
                    for message in messages {
                        yield Box::new(message);
                    }
                    if is_complete {
                        break;
                    }
                }
            }
        };

        self.messages_service.catch_up(request).await?;
        Ok(catch_up_stream.chain(regular_messages_stream))
    }

    pub fn filtered_messages_stream(&self, filter: Filter) -> impl Stream<Item = Box<MessageFull>> {
        self.filtered_fn(move |msg| {
            let StreamMessage::MessageReceived { message, .. } = msg else {
                return None;
            };
            if filter.matches(&message) {
                Some(message)
            } else {
                None
            }
        })
    }

    /// Get a filtered stream of messages.
    ///
    /// This creates a client-side filtered stream from the internal broadcast channel.
    /// The filter function is applied to all messages received by the manager.
    ///
    /// # Arguments
    /// * `filter` - A function that returns true for messages to include
    ///
    /// # Returns
    /// A stream of messages that match the filter
    pub fn filtered_fn<F, T>(&self, filter: F) -> impl Stream<Item = T>
    where
        F: Fn(StreamMessage) -> Option<T> + Send + Clone + 'static,
    {
        let receiver = self.broadcast_tx.subscribe();

        // Convert broadcast receiver to stream and apply filter
        BroadcastStream::new(receiver).filter_map(move |result| {
            let filter = filter.clone();
            async move {
                match result {
                    Ok(message) => filter(message),
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        warn!(
                            "MessagesManager subscriber lagged, skipped {} messages",
                            skipped
                        );
                        None
                    }
                }
            }
        })
    }

    /// Get a stream of all messages.
    ///
    /// # Returns
    /// A stream of all messages received by the manager
    pub fn all_messages_stream(&self) -> impl Stream<Item = StreamMessage> {
        let receiver = self.broadcast_tx.subscribe();

        BroadcastStream::new(receiver).filter_map(|result| async move {
            match result {
                Ok(message) => Some(message),
                Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                    warn!(
                        "MessagesManager subscriber lagged, skipped {} messages",
                        skipped
                    );
                    None
                }
            }
        })
    }

    pub async fn publish(&self, message: MessageFull) -> Result<PublishResult> {
        Ok(self
            .messages_service
            .publish(tarpc::context::current(), message)
            .await??)
    }

    /// Get access to the underlying messages service for direct RPC operations.
    ///
    /// Most users should prefer the higher-level methods on MessagesManager.
    pub fn messages_service(&self) -> &MessagesService {
        &self.messages_service
    }

    /// Get the current subscription state for persistence.
    ///
    /// This state can be saved and later restored using MessagesManagerBuilder.
    ///
    /// # Returns
    /// A clone of the current subscription state
    pub async fn get_subscription_state(&self) -> SubscriptionState {
        self.state.read().await.clone()
    }
    /// Get the latest stream height received.
    ///
    /// This can be used to determine how up-to-date the client is.
    pub async fn get_latest_stream_height(&self) -> Option<String> {
        self.state.read().await.latest_stream_height.clone()
    }

    /// Get the current combined filters.
    ///
    /// This shows all the filters that are currently active in the subscription.
    pub async fn get_current_filters(&self) -> MessageFilters {
        self.state.read().await.current_filters.clone()
    }
}

impl Drop for MessagesManager {
    fn drop(&mut self) {
        self.sync_handler.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_wire_protocol::Tag;

    #[tokio::test]
    async fn test_filtered_stream_logic() {
        // Test the filtering logic that would be used in get_filtered_stream
        let test_messages = [
            StreamMessage::StreamHeightUpdate("100".to_string()),
            StreamMessage::StreamHeightUpdate("200".to_string()),
            StreamMessage::StreamHeightUpdate("150".to_string()),
        ];

        // Test filter that only allows values > 150
        let filter = |msg: &StreamMessage| -> bool {
            match msg {
                StreamMessage::StreamHeightUpdate(height) => {
                    height.parse::<i32>().unwrap_or(0) > 150
                }
                _ => false,
            }
        };

        let filtered: Vec<_> = test_messages.iter().filter(|msg| filter(msg)).collect();
        assert_eq!(filtered.len(), 1); // Only "200" should pass

        match filtered[0] {
            StreamMessage::StreamHeightUpdate(height) => {
                assert_eq!(height, "200");
            }
            _ => panic!("Expected StreamHeightUpdate"),
        }
    }

    #[tokio::test]
    async fn test_tag_filtering_logic() {
        use rand::rngs::OsRng;
        use zoe_wire_protocol::{
            Content, KeyPair, Kind, Message, MessageFull, MessageV0, MessageV0Header,
        };

        // Create test tags
        let channel_tag = Tag::Channel {
            id: b"test-channel".to_vec(),
            relays: vec![],
        };

        let user_tag = Tag::User {
            id: [0u8; 32],
            relays: vec![],
        };

        // Test the tag filtering logic
        let target_tag = channel_tag.clone();
        let filter = move |msg: &StreamMessage| -> bool {
            match msg {
                StreamMessage::MessageReceived { message, .. } => {
                    message.tags().contains(&target_tag)
                }
                StreamMessage::StreamHeightUpdate(_) => false,
            }
        };

        // Create a keypair for signing
        let keypair = KeyPair::generate(&mut OsRng);

        // Create test message with channel tag
        let message_v0_with_channel = MessageV0 {
            header: MessageV0Header {
                sender: keypair.public_key(),
                when: 1640995200,
                kind: Kind::Emphemeral(3600), // 1 hour TTL
                tags: vec![channel_tag],
            },
            content: Content::Raw(b"test message".to_vec()),
        };

        let message_with_channel = Message::MessageV0(message_v0_with_channel);
        let full_message_with_channel = MessageFull::new(message_with_channel, &keypair).unwrap();

        let stream_msg_with_channel = StreamMessage::MessageReceived {
            message: Box::new(full_message_with_channel),
            stream_height: "100".to_string(),
        };

        // Create test message with user tag
        let message_v0_with_user = MessageV0 {
            header: MessageV0Header {
                sender: keypair.public_key(),
                when: 1640995200,
                kind: Kind::Emphemeral(3600),
                tags: vec![user_tag],
            },
            content: Content::Raw(b"test message".to_vec()),
        };

        let message_with_user = Message::MessageV0(message_v0_with_user);
        let full_message_with_user = MessageFull::new(message_with_user, &keypair).unwrap();

        let stream_msg_with_user = StreamMessage::MessageReceived {
            message: Box::new(full_message_with_user),
            stream_height: "101".to_string(),
        };

        let height_update = StreamMessage::StreamHeightUpdate("100".to_string());

        // Test filtering
        assert!(
            filter(&stream_msg_with_channel),
            "Should pass channel tag filter"
        );
        assert!(
            !filter(&stream_msg_with_user),
            "Should not pass channel tag filter"
        );
        assert!(!filter(&height_update), "Should not pass height update");
    }

    #[tokio::test]
    async fn test_subscription_state_tracking() {
        // Test the new subscription state tracking logic
        let mut state = SubscriptionState::new();

        let tag = Tag::Channel {
            id: b"test".to_vec(),
            relays: vec![],
        };

        let filter: Filter = tag.into();

        // Test adding filters
        state.add_filters(&[filter.clone()]);
        assert!(state.has_active_filters());
        assert_eq!(state.current_filters.filters.as_ref().unwrap().len(), 1);

        // Test updating stream height
        state.set_stream_height("123".to_string());
        assert_eq!(state.latest_stream_height, Some("123".to_string()));

        // Test removing filters
        state.remove_filters(&[filter]);
        assert!(!state.has_active_filters());

        // Test serialization
        let bytes = postcard::to_stdvec(&state).unwrap();
        let restored: SubscriptionState = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(state, restored);
    }
}
