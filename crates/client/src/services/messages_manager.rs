use crate::error::{ClientError, Result};
use async_broadcast::{Receiver, RecvError, Sender};
use async_trait::async_trait;
use eyeball::{AsyncLock, ObservableWriteGuard, SharedObservable};
use futures::{Stream, StreamExt, pin_mut};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use tokio::{select, task::JoinHandle};
use tracing::warn;
use zoe_state_machine::messages::{
    MessageEvent, MessagesManagerTrait, Result as MessagesManagerResult, SubscriptionState,
};
use zoe_wire_protocol::{
    CatchUpRequest, CatchUpResponse, Filter, FilterOperation, FilterUpdateRequest, MessageFilters,
    MessageFull, PublishResult, StreamMessage, SubscriptionConfig,
};

use super::messages::{CatchUpStream, MessagesService, MessagesStream};
use async_stream::stream;
use std::sync::atomic::AtomicU32;

/// Configuration for catching up on historical messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CatchUpConfig {
    /// How far back to catch up (in messages or time)
    pub since: Option<u64>,
    /// Maximum number of messages to catch up
    pub limit: Option<u32>,
}

/// Convert SubscriptionState to SubscriptionConfig for wire protocol
fn subscription_state_to_config(state: &SubscriptionState) -> SubscriptionConfig {
    SubscriptionConfig {
        filters: state.current_filters.clone(),
        since: state.latest_stream_height.clone(),
        limit: None,
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
/// # let saved_bytes: Vec<u8> = vec![];
/// // Create with previous state
/// let previous_state = SubscriptionState::new();
/// let manager = MessagesManagerBuilder::new()
///     .state(previous_state)
///     .buffer_size(2000)
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
    /// whether to automatically issue the subscribe command at start
    autosubscribe: bool,
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
            autosubscribe: false,
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

    pub fn autosubscribe(mut self, autosubscribe: bool) -> Self {
        self.autosubscribe = autosubscribe;
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
        let MessagesManagerBuilder {
            state,
            buffer_size,
            autosubscribe,
        } = self;

        // Create the manager
        let manager = MessagesManager::new_with_state(
            messages_service,
            messages_stream,
            catch_up_stream,
            state,
            buffer_size,
        );

        if autosubscribe {
            manager.subscribe().await?;
        }

        Ok(manager)
    }
}

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
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
#[derive(Clone)]
pub struct MessagesManager {
    /// The underlying messages service for RPC operations
    messages_service: Arc<MessagesService>,
    /// Broadcast sender for distributing messages to subscribers
    broadcast_tx: Arc<Sender<StreamMessage>>,
    /// Broadcast sender for distributing catch-up responses to subscribers
    catch_up_tx: Arc<Sender<CatchUpResponse>>,
    /// Broadcast sender for all message events (for persistence and monitoring)
    message_events_tx: Arc<Sender<MessageEvent>>,
    /// Keeper receiver to prevent broadcast channel closure (not actively used)
    _broadcast_keeper: async_broadcast::InactiveReceiver<StreamMessage>,
    /// Keeper receiver to prevent catch-up channel closure (not actively used)
    _catch_up_keeper: async_broadcast::InactiveReceiver<CatchUpResponse>,
    /// Keeper receiver to prevent message events channel closure (not actively used)
    _message_events_keeper: async_broadcast::InactiveReceiver<MessageEvent>,
    /// Current subscription state (persistent across reconnections)
    state: SharedObservable<SubscriptionState, AsyncLock>,
    /// Background task handle for syncing with the server
    _sync_handler: Arc<AbortOnDrop<Result<()>>>,
    /// Catch-up request ID counter
    catch_up_request_id: Arc<AtomicU32>,
}

impl MessagesManager {
    pub fn builder() -> MessagesManagerBuilder {
        MessagesManagerBuilder::new()
    }

    /// Helper function to safely broadcast messages using try_broadcast
    /// Handles TrySendError cases gracefully without panicking
    fn safe_broadcast<T: Clone>(sender: &Sender<T>, message: T, context: &str) {
        match sender.try_broadcast(message) {
            Ok(_msg) => {
                tracing::trace!("{context}: Successfully broadcast message");
            }
            Err(async_broadcast::TrySendError::Inactive(_msg)) => {
                tracing::debug!("{context}: All receivers inactive, message not sent");
            }
            Err(async_broadcast::TrySendError::Full(_msg)) => {
                tracing::warn!("{context}: Broadcast channel full, message dropped");
            }
            Err(async_broadcast::TrySendError::Closed(_msg)) => {
                tracing::debug!("{context}: Broadcast channel closed");
            }
        }
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
        let (broadcast_tx, broadcast_keeper) = async_broadcast::broadcast(buffer_size);
        let (catch_up_tx, catch_up_keeper) = async_broadcast::broadcast(buffer_size);
        let (message_events_tx, message_events_keeper) = async_broadcast::broadcast(buffer_size);

        // Create observable state
        let state = SharedObservable::new_async(state);

        // Start background task to forward messages from stream to broadcast channel
        let tx_clone = broadcast_tx.clone();
        let catch_up_tx_clone = catch_up_tx.clone();
        let message_events_tx_clone = message_events_tx.clone();
        let state_clone = state.clone();
        let sync_handler = tokio::spawn(async move {
            let mut m_stream = messages_stream;
            let mut c_stream = catch_up_stream;
            loop {
                select! {
                    message = m_stream.recv() => {
                        let Some(message) = message else {
                            tracing::debug!("📪 Subscriptions stream ended");
                            break;
                        };
                        match &message {
                            StreamMessage::StreamHeightUpdate(height) => {
                                // Update both the internal state and the observable
                                {
                                    let mut state = state_clone.write().await;
                                    ObservableWriteGuard::update(&mut state, |state: &mut SubscriptionState| {
                                        state.set_stream_height(height.clone());
                                    });
                                }
                                // Emit height update event
                                let event = MessageEvent::StreamHeightUpdate { height: height.clone() };
                                Self::safe_broadcast(&message_events_tx_clone, event, "StreamHeightUpdate event");
                            },
                            StreamMessage::MessageReceived { message: msg, stream_height } => {
                                // Update both the internal state and the observable
                                {
                                    let mut state = state_clone.write().await;
                                    ObservableWriteGuard::update(&mut state, |state: &mut SubscriptionState| {
                                        state.set_stream_height(stream_height.clone());
                                    });
                                }

                                // Emit message received event
                                let event = MessageEvent::MessageReceived {
                                    message: (**msg).clone(),
                                    stream_height: stream_height.clone()
                                };
                                Self::safe_broadcast(&message_events_tx_clone, event, "MessageReceived event");
                            }
                        }

                        // Forward message to all subscribers
                        // async-broadcast queues messages for receivers even if they're not actively polling
                        tracing::debug!("MessagesManager forwarding message to broadcast channel: {:?}", message);
                        Self::safe_broadcast(&tx_clone, message, "StreamMessage");
                    }
                    catch_up_response = c_stream.recv() => {
                        let Some(catch_up_response) = catch_up_response else {
                            tracing::debug!("📪 Catch-up stream ended");
                            break;
                        };
                        tracing::debug!("📨 MessagesManager received catch-up response: {:?}", catch_up_response);

                        // Emit catch-up message events
                        for message in &catch_up_response.messages {
                            let event = MessageEvent::CatchUpMessage {
                                message: message.clone(),
                                request_id: catch_up_response.request_id
                            };
                            Self::safe_broadcast(&message_events_tx_clone, event, "CatchUpMessage event");
                        }

                        if catch_up_response.is_complete {
                            let event = MessageEvent::CatchUpCompleted {
                                request_id: catch_up_response.request_id
                            };
                            Self::safe_broadcast(&message_events_tx_clone, event, "CatchUpCompleted event");
                        }

                        Self::safe_broadcast(&catch_up_tx_clone, catch_up_response, "CatchUpResponse");
                    }
                }
            }

            Ok(())
        });

        Self {
            messages_service: Arc::new(messages_service),
            broadcast_tx: Arc::new(broadcast_tx),
            catch_up_tx: Arc::new(catch_up_tx),
            message_events_tx: Arc::new(message_events_tx),
            state,
            catch_up_request_id: Arc::new(AtomicU32::new(0)),
            _broadcast_keeper: broadcast_keeper.deactivate(),
            _catch_up_keeper: catch_up_keeper.deactivate(),
            _message_events_keeper: message_events_keeper.deactivate(),
            _sync_handler: Arc::new(AbortOnDrop(sync_handler)),
        }
    }

    pub async fn subscribe(&self) -> Result<()> {
        let state = self.state.read().await.clone();
        self.messages_service
            .subscribe(subscription_state_to_config(&state))
            .await
    }

    pub async fn ensure_contains_filter(&self, filter: Filter) -> Result<()> {
        let new_filters = self
            .messages_service
            .update_filters(FilterUpdateRequest {
                operations: vec![FilterOperation::Add(vec![filter])],
            })
            .await?;

        // Update both the internal state and the observable
        {
            let mut state = self.state.write().await;
            ObservableWriteGuard::update(&mut state, |state: &mut SubscriptionState| {
                state.current_filters = new_filters.filters;
            });
        }

        Ok(())
    }

    pub async fn catch_up_and_subscribe(
        self,
        filter: Filter,
        since: Option<String>,
    ) -> Result<impl Stream<Item = Box<MessageFull>>> {
        // Enure if the underlying service is still alive
        if self.messages_service.is_closed() {
            return Err(ClientError::Generic(
                "Messages service connection is closed".to_string(),
            ));
        }

        // First, ensure the filter is added to the server-side subscription
        // This is crucial so that future messages matching this filter will be delivered
        self.ensure_contains_filter(filter.clone()).await?;

        let request_id = self
            .catch_up_request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let request = CatchUpRequest {
            filter: filter.clone(),
            since,
            max_messages: None,
            request_id,
        };

        // Store request_id before moving the request
        let request_id_filter = request.request_id;

        // Create and start polling the catch-up receiver immediately to make it "active"
        let mut catch_up_receiver = self.catch_up_tx.new_receiver();

        // Send the catch-up request to the server
        self.messages_service.catch_up(request).await?;

        let regular_messages_stream = self.clone().filtered_messages_stream(filter.clone());

        let catch_up_stream = {
            // we put this into a scope so the broadcaster is dropped when the stream finished

            let catch_up_rcv = async_stream::stream! {
                loop {
                    match catch_up_receiver.recv().await {
                        Ok(CatchUpResponse {
                            request_id,
                            messages,
                            is_complete,
                            ..
                        }) => {
                            if request_id == request_id_filter {
                                yield (messages, is_complete);
                            }
                        }
                        Err(RecvError::Closed) => break, // we are done processing
                        Err(RecvError::Overflowed(skipped)) => {
                            warn!(
                                "MessagesManager catch-up subscriber lagged, skipped {} responses",
                                skipped
                            );
                            // Continue receiving after overflow
                        }
                    }
                }
            };

            stream! {
                pin_mut!(catch_up_rcv);
                tracing::debug!("🔄 Catch-up stream starting for request_id: {request_id_filter}");
                while let Some((messages, is_complete)) = catch_up_rcv.next().await {
                    tracing::debug!("📦 Catch-up received {} messages, is_complete: {}", messages.len(), is_complete);
                    for message in messages {
                        yield Box::new(message);
                    }
                    if is_complete {
                        tracing::debug!("✅ Catch-up stream completed for request_id: {request_id_filter}");
                        break;
                    }
                }
                tracing::debug!("🏁 Catch-up stream ended for request_id: {request_id_filter}");
            }
        };

        Ok(Box::pin(catch_up_stream.chain(regular_messages_stream)))
    }

    pub fn filtered_messages_stream(
        self,
        filter: Filter,
    ) -> Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send>> {
        Box::pin(self.filtered_fn(move |msg| {
            let StreamMessage::MessageReceived { message, .. } = msg else {
                return None;
            };
            if filter.matches(&message) {
                tracing::debug!(
                    "✅ Message matched filter: {:?}, message_id: {}",
                    filter,
                    hex::encode(message.id().as_bytes())
                );
                Some(message)
            } else {
                tracing::debug!(
                    "❌ Message did not match filter: {:?}, message_id: {}",
                    filter,
                    hex::encode(message.id().as_bytes())
                );
                None
            }
        }))
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
    pub fn filtered_fn<F, T>(self, filter: F) -> impl Stream<Item = T>
    where
        F: Fn(StreamMessage) -> Option<T> + Send + Clone + 'static,
    {
        let mut receiver = self.broadcast_tx.new_receiver();
        tracing::info!(
            "🔧 Created new broadcast receiver for filtered stream (manager: {:p})",
            self.broadcast_tx.as_ref()
        );

        // Convert async-broadcast receiver to stream and apply filter
        async_stream::stream! {
            tracing::info!("🎯 Filtered stream started, waiting for messages...");
            loop {
                match receiver.recv().await {
                    Ok(message) => {
                        if let Some(filtered) = filter(message) {
                            yield filtered;
                        }
                    }
                    Err(RecvError::Closed) => {
                        break;
                    }
                    Err(RecvError::Overflowed(skipped)) => {
                        warn!(
                            "MessagesManager subscriber lagged, skipped {} messages",
                            skipped
                        );
                        // Continue receiving after overflow
                    }
                }
            }
        }
    }

    /// Get a stream of all messages.
    ///
    /// # Returns
    /// A stream of all messages received by the manager
    pub fn all_messages_stream(&self) -> Receiver<StreamMessage> {
        self.broadcast_tx.new_receiver()
    }

    pub async fn publish(&self, message: MessageFull) -> Result<PublishResult> {
        // Publish to network
        let result = self
            .messages_service
            .publish(tarpc::context::current(), message.clone())
            .await??;

        // Emit the sent message event
        let event = MessageEvent::MessageSent {
            message,
            publish_result: result.clone(),
        };

        Self::safe_broadcast(&self.message_events_tx, event, "MessageSent event");

        Ok(result)
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

    /// Get a stream of all message events for persistence and monitoring.
    ///
    /// This stream captures every message activity including:
    /// - Messages received from subscriptions
    /// - Messages sent by this client
    /// - Historical messages from catch-up requests
    /// - Stream height updates
    /// - Catch-up completion notifications
    ///
    /// This is primarily intended for persistence services and audit logging.
    ///
    /// # Returns
    /// A stream of `MessageEvent` that captures all message activities
    pub fn message_events_stream(&self) -> Receiver<MessageEvent> {
        self.message_events_tx.new_receiver()
    }
}

#[async_trait]
impl MessagesManagerTrait for MessagesManager {
    fn message_events_stream(&self) -> Receiver<MessageEvent> {
        self.message_events_tx.new_receiver()
    }

    async fn get_subscription_state_updates(
        &self,
    ) -> eyeball::Subscriber<SubscriptionState, AsyncLock> {
        self.state.subscribe().await
    }

    async fn subscribe(&self) -> MessagesManagerResult<()> {
        MessagesManager::subscribe(self).await.map_err(|e| e.into())
    }

    async fn publish(&self, message: MessageFull) -> MessagesManagerResult<PublishResult> {
        MessagesManager::publish(self, message)
            .await
            .map_err(|e| e.into())
    }

    async fn ensure_contains_filter(&self, filter: Filter) -> MessagesManagerResult<()> {
        MessagesManager::ensure_contains_filter(self, filter)
            .await
            .map_err(|e| e.into())
    }

    fn messages_stream(&self) -> Receiver<StreamMessage> {
        self.all_messages_stream()
    }

    fn catch_up_stream(&self) -> Receiver<CatchUpResponse> {
        self.catch_up_tx.new_receiver()
    }

    fn filtered_messages_stream(
        &self,
        filter: Filter,
    ) -> std::pin::Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send>> {
        Box::pin(MessagesManager::filtered_messages_stream(
            self.clone(),
            filter,
        ))
    }

    async fn catch_up_and_subscribe(
        &self,
        filter: Filter,
        since: Option<String>,
    ) -> MessagesManagerResult<std::pin::Pin<Box<dyn Stream<Item = Box<MessageFull>> + Send>>> {
        let stream = MessagesManager::catch_up_and_subscribe(self.clone(), filter, since).await?;
        Ok(Box::pin(stream))
    }

    async fn user_data(
        &self,
        author: zoe_wire_protocol::KeyId,
        storage_key: zoe_wire_protocol::StoreKey,
    ) -> MessagesManagerResult<Option<MessageFull>> {
        use tarpc::context;
        let result = self
            .messages_service
            .user_data(context::current(), author, storage_key)
            .await?;
        Ok(result?)
    }

    async fn check_messages(
        &self,
        message_ids: Vec<zoe_wire_protocol::MessageId>,
    ) -> MessagesManagerResult<Vec<Option<String>>> {
        use tarpc::context;
        let result = self
            .messages_service
            .check_messages(context::current(), message_ids)
            .await?;
        Ok(result?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_wire_protocol::{Filter, KeyId, Tag};

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
            id: KeyId::from_bytes([0u8; 32]),
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
                kind: Kind::Ephemeral(3600), // 1 hour TTL
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
                kind: Kind::Ephemeral(3600),
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
        state.add_filters(std::slice::from_ref(&filter));
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

    #[tokio::test]
    async fn test_subscription_state_observable() {
        // Create a test subscription state
        let initial_state = SubscriptionState::new();

        // Create a SharedObservable directly to test the API
        let state_observable = SharedObservable::new(initial_state.clone());

        // Test subscription
        let subscriber = state_observable.subscribe();
        let current_state = subscriber.get();
        assert_eq!(current_state, initial_state);

        // Test state update
        let mut updated_state = initial_state.clone();
        updated_state.set_stream_height("123".to_string());

        state_observable.set_if_not_eq(updated_state.clone());

        // Verify the subscriber sees the update
        let observed_state = subscriber.get();
        assert_eq!(observed_state.latest_stream_height, Some("123".to_string()));
        assert_eq!(observed_state, updated_state);
    }

    #[tokio::test]
    async fn test_filter_matching_logic() {
        use rand::rngs::OsRng;
        use zoe_wire_protocol::{
            Content, KeyPair, Kind, Message, MessageFull, MessageV0, MessageV0Header,
        };

        // Create test keypair
        let keypair = KeyPair::generate(&mut OsRng);

        // Test Channel filter matching
        let channel_id = b"test-channel-123".to_vec();
        let channel_filter = Filter::Channel(channel_id.clone());

        // Create message with matching channel tag
        let message_with_channel = MessageV0 {
            header: MessageV0Header {
                sender: keypair.public_key(),
                when: 1640995200,
                kind: Kind::Regular,
                tags: vec![Tag::Channel {
                    id: channel_id.clone(),
                    relays: vec![],
                }],
            },
            content: Content::Raw(b"test message".to_vec()),
        };
        let message = Message::MessageV0(message_with_channel);
        let full_message = MessageFull::new(message, &keypair).unwrap();

        // Test that channel filter matches
        assert!(
            channel_filter.matches(&full_message),
            "Channel filter should match message with same channel tag"
        );

        // Test with different channel ID
        let different_channel_filter = Filter::Channel(b"different-channel".to_vec());
        assert!(
            !different_channel_filter.matches(&full_message),
            "Channel filter should not match message with different channel tag"
        );

        // Create message with Event tag
        let event_id = *full_message.id();
        let message_with_event = MessageV0 {
            header: MessageV0Header {
                sender: keypair.public_key(),
                when: 1640995200,
                kind: Kind::Regular,
                tags: vec![Tag::Event {
                    id: event_id,
                    relays: vec![],
                }],
            },
            content: Content::Raw(b"test message".to_vec()),
        };
        let message = Message::MessageV0(message_with_event);
        let full_message_with_event = MessageFull::new(message, &keypair).unwrap();

        // Test Event filter matching
        let event_filter = Filter::Event(event_id);
        assert!(
            event_filter.matches(&full_message_with_event),
            "Event filter should match message with same event tag"
        );

        // Test that channel filter doesn't match event message
        assert!(
            !channel_filter.matches(&full_message_with_event),
            "Channel filter should not match message with event tag"
        );

        // Test Author filter matching
        let author_filter = Filter::Author(KeyId::from(*keypair.public_key().id()));
        assert!(
            author_filter.matches(&full_message),
            "Author filter should match message from same author"
        );
        assert!(
            author_filter.matches(&full_message_with_event),
            "Author filter should match any message from same author"
        );

        // Test with different author
        let different_keypair = KeyPair::generate(&mut OsRng);
        let different_author_filter =
            Filter::Author(KeyId::from(*different_keypair.public_key().id()));
        assert!(
            !different_author_filter.matches(&full_message),
            "Author filter should not match message from different author"
        );
    }
}
