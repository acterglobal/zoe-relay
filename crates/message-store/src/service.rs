use crate::error::MessageStoreError;
use crate::storage::RedisMessageStorage;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};
use zoe_wire_protocol::{
    CatchUpRequest, CatchUpResponse, FilterOperation, FilterUpdateRequest, KeyId, MessageError,
    MessageFilters, MessageFull, MessageId, MessageService as MessageServiceRpc, PublishResult,
    StoreKey, StreamMessage, SubscriptionConfig,
};

#[derive(Clone)]
pub struct MessagesRpcService {
    pub store: Arc<RedisMessageStorage>,
    /// Channel for sending streaming messages back to the relay service
    pub stream_sender: mpsc::UnboundedSender<StreamMessage>,
    /// Channel for sending catch-up responses back to the relay service  
    pub response_sender: mpsc::UnboundedSender<CatchUpResponse>,
    /// The current subscription config
    pub subscription: Arc<RwLock<SubscriptionConfig>>,
    /// the running task handle for the subscription task
    pub task_handle: Arc<RwLock<Option<tokio::task::AbortHandle>>>,
}

impl MessagesRpcService {
    pub fn new(
        store: Arc<RedisMessageStorage>,
    ) -> (
        mpsc::UnboundedReceiver<StreamMessage>,
        mpsc::UnboundedReceiver<CatchUpResponse>,
        Self,
    ) {
        // Channels for receiving messages from background tasks
        let (sub_sender, sub_receiver) = mpsc::unbounded_channel::<StreamMessage>();
        let (response_sender, response_receiver) = mpsc::unbounded_channel::<CatchUpResponse>();
        (
            sub_receiver,
            response_receiver,
            Self {
                store,
                stream_sender: sub_sender,
                response_sender,
                subscription: Arc::new(RwLock::new(SubscriptionConfig::default())),
                task_handle: Arc::new(RwLock::new(None)),
            },
        )
    }

    async fn start_subscription_task(&self) -> Result<(), MessageStoreError> {
        let config = self.subscription.read().await;

        // Spawn the background subscription task
        let filters = config.filters.clone();
        if filters.is_empty() {
            // if we are empty, we are not starting the task,
            // just clear the current handle.
            self.abort_subscription_task().await?;
            return Ok(());
        }

        // Check if we have the stream sender channel
        let stream_sender = self.stream_sender.clone();

        let since = config.since.clone();
        let store = self.store.clone();
        let limit = config.limit;
        let subscription = self.subscription.clone();

        let task_handle = tokio::spawn(async move {
            if let Err(e) =
                subscription_task(store, filters, since, limit, subscription, stream_sender).await
            {
                error!(error = ?e, "Subscription task failed");
            }
        });
        self.task_handle
            .write()
            .await
            .replace(task_handle.abort_handle());
        Ok(())
    }

    async fn abort_subscription_task(&self) -> Result<(), MessageStoreError> {
        if let Some(task_handle) = self.task_handle.write().await.take() {
            task_handle.abort();
        }
        Ok(())
    }
}

// Background task functions for handling subscriptions and catch-up requests
async fn subscription_task(
    service: Arc<RedisMessageStorage>,
    filters: MessageFilters,
    since: Option<String>,
    limit: Option<usize>,
    subscription: Arc<RwLock<SubscriptionConfig>>,
    sender: mpsc::UnboundedSender<StreamMessage>,
) -> Result<(), MessageStoreError> {
    let task_id = format!("{:p}", &sender);
    info!(
        "🔄 Starting subscription task {} with filters: {:?}",
        task_id, filters
    );

    let stream = service.listen_for_messages(&filters, since, limit).await?;
    info!("Subscription stream created, starting to listen for messages");

    // Pin the stream so we can use it with .next()
    tokio::pin!(stream);

    while let Some(result) = stream.next().await {
        let to_client = match result {
            Ok((Some(message), height)) => {
                tracing::debug!(
                    "📤 Subscription task {} yielding message to client: {}",
                    task_id,
                    hex::encode(message.id().as_bytes())
                );
                StreamMessage::MessageReceived {
                    message: Box::new(message),
                    stream_height: height,
                }
            }
            Ok((None, height)) => {
                // Empty batch - just a stream height update
                StreamMessage::StreamHeightUpdate(height)
            }
            Err(e) => {
                error!("Error in subscription stream: {}", e);
                break;
            }
        };

        let new_height = match &to_client {
            StreamMessage::MessageReceived { stream_height, .. } => stream_height.clone(),
            StreamMessage::StreamHeightUpdate(height) => height.clone(),
        };

        // Send response to relay service
        if let Err(error) = sender.send(to_client) {
            error!(?error, "Relay service closed, stopping subscription");
            break;
        }

        {
            // also update the internal subscription state height for future restarting.
            let mut subscription = subscription.write().await;
            subscription.since = Some(new_height);
        }
    }

    info!("Subscription task ended");
    Ok(())
}

async fn handle_catch_up_request(
    service: Arc<RedisMessageStorage>,
    request: CatchUpRequest,
    sender: mpsc::UnboundedSender<CatchUpResponse>,
) -> Result<(), MessageStoreError> {
    info!("Handling catch-up request: {:?}", request);

    let stream = service.catch_up(&request.filter, request.since).await?;

    tokio::pin!(stream);

    let mut messages = Vec::new();
    // let max_messages = request.max_messages.unwrap_or(100);

    while let Some(result) = stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                messages.push(message);

                // Send in batches
                if messages.len() >= 10 {
                    let response = CatchUpResponse {
                        request_id: request.request_id,
                        filter: request.filter.clone(),
                        messages: messages.clone(),
                        is_complete: false,
                        next_since: None, // Could be enhanced for pagination
                    };

                    if let Err(e) = sender.send(response) {
                        warn!("Relay service closed, stopping catch-up: {}", e);
                        return Err(MessageStoreError::Internal(format!(
                            "Relay service closed, stopping catch-up: {e}",
                        )));
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

    // Always send a completion response, even if there are no messages
    let response = CatchUpResponse {
        request_id: request.request_id,
        filter: request.filter.clone(),
        messages,
        is_complete: true,
        next_since: None,
    };

    if let Err(e) = sender.send(response) {
        warn!("Relay service closed during final catch-up send: {}", e);
        return Err(MessageStoreError::Internal(format!(
            "Relay service closed during final catch-up send: {e}"
        )));
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
        id: MessageId,
    ) -> Result<Option<MessageFull>, MessageError> {
        self.store
            .get_message(id.as_bytes())
            .await
            .map_err(MessageError::from)
    }

    async fn user_data(
        self,
        _context: ::tarpc::context::Context,
        author: KeyId,
        storage_key: StoreKey,
    ) -> Result<Option<MessageFull>, MessageError> {
        self.store
            .get_user_data(author, storage_key)
            .await
            .map_err(MessageError::from)
    }

    async fn check_messages(
        self,
        _context: ::tarpc::context::Context,
        message_ids: Vec<MessageId>,
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
    ) -> Result<(), MessageError> {
        self.abort_subscription_task().await?;
        {
            // also update the internal subscription state height for future restarting.
            let mut subscription = self.subscription.write().await;
            *subscription = config.clone();
        }
        self.start_subscription_task().await?;
        Ok(())
    }

    async fn update_filters(
        self,
        _context: ::tarpc::context::Context,
        request: FilterUpdateRequest,
    ) -> Result<SubscriptionConfig, MessageError> {
        self.abort_subscription_task().await?;
        let new_config = {
            let mut subscription = self.subscription.write().await;

            // Apply filter operations to the current config
            let updated_filters = &mut subscription.filters;
            for operation in &request.operations {
                updated_filters.apply_operation(operation);
            }
            subscription.clone()
        };

        self.start_subscription_task().await?;

        Ok(new_config)
    }

    async fn catch_up(
        self,
        _context: ::tarpc::context::Context,
        request: CatchUpRequest,
    ) -> Result<SubscriptionConfig, MessageError> {
        self.abort_subscription_task().await?;
        let new_config = {
            // we are stopping live subscriptions, so we can just return the current subscription state.
            let mut subscription = self.subscription.write().await; // hold the lock to update the subscription state.
            let filter = request.filter.clone();

            // Get the response sender channel
            let response_sender = self.response_sender.clone();

            handle_catch_up_request(self.store.clone(), request, response_sender).await?;

            // we apply the new filters
            subscription
                .filters
                .apply_operation(&FilterOperation::Add(vec![filter]));
            subscription.clone()
        };
        self.start_subscription_task().await?;
        Ok(new_config)
    }
}
