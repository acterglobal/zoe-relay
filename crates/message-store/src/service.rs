use crate::RedisMessageStorage;
use futures::StreamExt;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};
use zoe_wire_protocol::{
    CatchUpRequest, CatchUpResponse, FilterUpdateRequest, Hash, MessageError, MessageFilters,
    MessageFull, MessageService as MessageServiceRpc, MessageServiceResponseWrap, PublishResult,
    StoreKey, StreamMessage, SubscriptionConfig, VerifyingKey,
};

/// Subscription state for tracking active subscriptions
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    pub config: SubscriptionConfig,
    pub task_handle: Option<tokio::task::AbortHandle>,
}

#[derive(Clone)]
pub struct MessagesRpcService {
    pub store: Arc<RedisMessageStorage>,
    /// Channel for sending streaming messages back to the relay service
    pub stream_sender: Option<mpsc::UnboundedSender<StreamMessage>>,
    /// Channel for sending catch-up responses back to the relay service  
    pub response_sender: Option<mpsc::UnboundedSender<MessageServiceResponseWrap>>,
    /// Active subscriptions tracked by subscription ID
    pub subscriptions: Arc<RwLock<HashMap<String, SubscriptionState>>>,
}

impl MessagesRpcService {
    pub fn new(store: Arc<RedisMessageStorage>) -> Self {
        Self {
            store,
            stream_sender: None,
            response_sender: None,
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set the communication channels for sending messages back to the relay service
    pub fn with_channels(
        mut self,
        stream_sender: mpsc::UnboundedSender<StreamMessage>,
        response_sender: mpsc::UnboundedSender<MessageServiceResponseWrap>,
    ) -> Self {
        self.stream_sender = Some(stream_sender);
        self.response_sender = Some(response_sender);
        self
    }
}

// Background task functions for handling subscriptions and catch-up requests
async fn subscription_task(
    service: Arc<RedisMessageStorage>,
    filters: MessageFilters,
    since: Option<String>,
    limit: Option<usize>,
    sender: mpsc::UnboundedSender<StreamMessage>,
) -> Result<(), crate::MessageStoreError> {
    info!("Starting subscription task with filters: {:?}", filters);

    let stream = service.listen_for_messages(&filters, since, limit).await?;
    info!("Subscription stream created, starting to listen for messages");

    // Pin the stream so we can use it with .next()
    tokio::pin!(stream);

    while let Some(result) = stream.next().await {
        let to_client = match result {
            Ok((Some(message), height)) => StreamMessage::MessageReceived {
                message,
                stream_height: height,
            },
            Ok((None, height)) => {
                // Empty batch - just a stream height update
                StreamMessage::StreamHeightUpdate(height)
            }
            Err(e) => {
                error!("Error in subscription stream: {}", e);
                break;
            }
        };

        // Send response to relay service
        if sender.send(to_client).is_err() {
            debug!("Relay service closed, stopping subscription");
            break;
        }
    }

    info!("Subscription task ended");
    Ok(())
}

async fn handle_catch_up_request(
    service: Arc<RedisMessageStorage>,
    request: CatchUpRequest,
    sender: mpsc::UnboundedSender<MessageServiceResponseWrap>,
) -> Result<(), crate::MessageStoreError> {
    info!("Handling catch-up request: {:?}", request);

    let stream = service
        .catch_up(request.filter_field, &request.filter_value, request.since)
        .await?;

    tokio::pin!(stream);

    let mut messages = Vec::new();
    let mut count = 0;
    let max_messages = request.max_messages.unwrap_or(100);

    while let Some(result) = stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                messages.push(message);
                count += 1;

                // Send in batches or when we reach the limit
                if count >= max_messages || messages.len() >= 50 {
                    let response = CatchUpResponse {
                        request_id: request.request_id.clone(),
                        filter_field: request.filter_field,
                        filter_value: request.filter_value.clone(),
                        messages: messages.clone(),
                        is_complete: count >= max_messages,
                        next_since: None, // Could be enhanced for pagination
                    };

                    if sender
                        .send(MessageServiceResponseWrap::CatchUpResponse(response))
                        .is_err()
                    {
                        debug!("Relay service closed, stopping catch-up");
                        break;
                    }

                    if count >= max_messages {
                        break;
                    }
                    messages.clear();
                }
            }
            Err(e) => {
                error!("Error in catch-up stream: {}", e);
                break;
            }
        }
    }

    // Send any remaining messages
    if !messages.is_empty() {
        let response = CatchUpResponse {
            request_id: request.request_id.clone(),
            filter_field: request.filter_field,
            filter_value: request.filter_value.clone(),
            messages,
            is_complete: true,
            next_since: None,
        };

        if sender
            .send(MessageServiceResponseWrap::CatchUpResponse(response))
            .is_err()
        {
            debug!("Relay service closed during final catch-up send");
        }
    }

    info!(
        "Catch-up request completed for request_id: {}",
        request.request_id
    );
    Ok(())
}

impl MessageServiceRpc for MessagesRpcService {
    async fn publish(
        self,
        _context: ::tarpc::context::Context,
        message: MessageFull,
    ) -> Result<PublishResult, MessageError> {
        self.store
            .store_message(&message)
            .await
            .map_err(MessageError::from)
    }

    async fn message(
        self,
        _context: ::tarpc::context::Context,
        id: Hash,
    ) -> Result<Option<MessageFull>, MessageError> {
        self.store
            .get_message(id.as_bytes())
            .await
            .map_err(MessageError::from)
    }

    async fn user_data(
        self,
        _context: ::tarpc::context::Context,
        author: VerifyingKey,
        storage_key: StoreKey,
    ) -> Result<Option<MessageFull>, MessageError> {
        self.store
            .get_user_data(author.as_bytes(), storage_key)
            .await
            .map_err(MessageError::from)
    }

    async fn check_messages(
        self,
        _context: ::tarpc::context::Context,
        message_ids: Vec<Hash>,
    ) -> Result<Vec<Option<String>>, MessageError> {
        self.store
            .check_messages(&message_ids)
            .await
            .map_err(MessageError::from)
    }

    async fn subscribe(
        self,
        _context: ::tarpc::context::Context,
        config: SubscriptionConfig,
    ) -> Result<String, MessageError> {
        // Generate a unique subscription ID
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let subscription_id = format!("sub_{timestamp}");

        info!(
            "Creating subscription {} with config: {:?}",
            subscription_id, config
        );

        // Check if we have the stream sender channel
        let stream_sender = self
            .stream_sender
            .as_ref()
            .ok_or_else(|| MessageError::InternalError {
                message: "Stream sender not configured".to_string(),
            })?
            .clone();

        // Spawn the background subscription task
        let store = self.store.clone();
        let filters = config.filters.clone();
        let since = config.since.clone();
        let limit = config.limit;
        let task_subscription_id = subscription_id.clone();

        let task_handle = tokio::spawn(async move {
            if let Err(e) = subscription_task(store, filters, since, limit, stream_sender).await {
                error!("Subscription task {} failed: {}", task_subscription_id, e);
            }
        });

        // Store the subscription state
        let subscription_state = SubscriptionState {
            config,
            task_handle: Some(task_handle.abort_handle()),
        };

        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id.clone(), subscription_state);
        }

        info!("Subscription {} created and task spawned", subscription_id);
        Ok(subscription_id)
    }

    async fn update_filters(
        self,
        _context: ::tarpc::context::Context,
        subscription_id: String,
        request: FilterUpdateRequest,
    ) -> Result<(), MessageError> {
        info!(
            "Updating filters for subscription {}: {:?}",
            subscription_id, request
        );

        let mut subscriptions = self.subscriptions.write().await;
        let subscription_state =
            subscriptions
                .get_mut(&subscription_id)
                .ok_or_else(|| MessageError::NotFound {
                    hash: format!("Subscription not found: {subscription_id}"),
                })?;

        // Apply filter operations to the current config
        let mut updated_filters = subscription_state.config.filters.clone();
        for operation in &request.operations {
            updated_filters.apply_operation(operation);
        }

        // Cancel the existing task
        if let Some(task_handle) = subscription_state.task_handle.take() {
            task_handle.abort();
            info!(
                "Cancelled existing subscription task for {}",
                subscription_id
            );
        }

        // Get the stream sender channel
        let stream_sender = self
            .stream_sender
            .as_ref()
            .ok_or_else(|| MessageError::InternalError {
                message: "Stream sender not configured".to_string(),
            })?
            .clone();

        // Start a new task with updated filters
        let store = self.store.clone();
        let since = subscription_state.config.since.clone();
        let limit = subscription_state.config.limit;
        let task_subscription_id = subscription_id.clone();
        let filters_for_task = updated_filters.clone();

        let task_handle = tokio::spawn(async move {
            if let Err(e) =
                subscription_task(store, filters_for_task, since, limit, stream_sender).await
            {
                error!(
                    "Updated subscription task {} failed: {}",
                    task_subscription_id, e
                );
            }
        });

        // Update the subscription state
        subscription_state.config.filters = updated_filters;
        subscription_state.task_handle = Some(task_handle.abort_handle());

        info!(
            "Filter update completed for subscription {}",
            subscription_id
        );
        Ok(())
    }

    async fn catch_up(
        self,
        _context: ::tarpc::context::Context,
        request: CatchUpRequest,
    ) -> Result<String, MessageError> {
        // Generate a unique catch-up ID for tracking
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let catch_up_id = format!("catchup_{timestamp}");

        info!(
            "Creating catch-up {} for request: {:?}",
            catch_up_id, request
        );

        // Get the response sender channel
        let response_sender = self
            .response_sender
            .as_ref()
            .ok_or_else(|| MessageError::InternalError {
                message: "Response sender not configured".to_string(),
            })?
            .clone();

        // Spawn the background catch-up task
        let store = self.store.clone();
        let task_catch_up_id = catch_up_id.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_catch_up_request(store, request, response_sender).await {
                error!("Catch-up task {} failed: {}", task_catch_up_id, e);
            }
        });

        info!("Catch-up {} task spawned", catch_up_id);
        Ok(catch_up_id)
    }

    async fn unsubscribe(
        self,
        _context: ::tarpc::context::Context,
        subscription_id: String,
    ) -> Result<(), MessageError> {
        info!("Unsubscribing from subscription {}", subscription_id);

        let mut subscriptions = self.subscriptions.write().await;
        let subscription_state =
            subscriptions
                .remove(&subscription_id)
                .ok_or_else(|| MessageError::NotFound {
                    hash: format!("Subscription not found: {subscription_id}"),
                })?;

        // Cancel the background task
        if let Some(task_handle) = subscription_state.task_handle {
            task_handle.abort();
            info!("Cancelled subscription task for {}", subscription_id);
        }

        info!("Subscription {} successfully unsubscribed", subscription_id);
        Ok(())
    }
}
