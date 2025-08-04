use crate::Service;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tarpc::server::{BaseChannel, Channel};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};
use zoe_message_store::{MessageStoreError, MessagesRpcService, RedisMessageStorage};
use zoe_wire_protocol::{
    CatchUpRequest, CatchUpResponse, FilterUpdateRequest, MessageFilters,
    MessageService as MessageServiceRpc, MessageServiceResponseWrap, MessagesServiceRequestWrap,
    StreamMessage, StreamPair,
};

#[derive(Debug, thiserror::Error)]
pub enum MessagesServiceError {
    #[error("Message store error: {0}")]
    MessageStoreError(#[from] MessageStoreError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

pub struct MessagesService {
    streams: StreamPair,
    store: Arc<RedisMessageStorage>,
    service: MessagesRpcService,
    /// Shared filter state for live updates
    current_filters: Arc<RwLock<Option<MessageFilters>>>,
}

impl MessagesService {
    pub fn new(streams: StreamPair, redis: RedisMessageStorage) -> Self {
        let store = Arc::new(redis);
        Self {
            streams,
            store: store.clone(),
            service: MessagesRpcService::new(store),
            current_filters: Arc::new(RwLock::new(None)),
        }
    }
}

// Task to handle a subscription stream with live filter updates
async fn subscription_task(
    service: Arc<RedisMessageStorage>,
    filters: Arc<RwLock<Option<MessageFilters>>>,
    since: Option<String>,
    limit: Option<usize>,
    sender: mpsc::UnboundedSender<StreamMessage>,
) -> Result<(), MessagesServiceError> {
    info!("Starting subscription task");

    // Wait for initial filters to be set
    let initial_filters = loop {
        let filters_guard = filters.read().await;
        if let Some(ref filters) = *filters_guard {
            let filters_clone = filters.clone();
            drop(filters_guard);
            break filters_clone;
        }
        drop(filters_guard);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    };

    info!("Starting subscription with initial filters: {:?}", initial_filters);

    let stream = service.listen_for_messages(&initial_filters, since, limit).await?;
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

        // Send response to main task
        if sender.send(to_client).is_err() {
            debug!("Main task closed, stopping subscription");
            break;
        }
    }

    info!("Subscription task ended");
    Ok(())
}

// Task to handle catch-up requests
async fn handle_catch_up_request(
    service: Arc<RedisMessageStorage>,
    request: CatchUpRequest,
    sender: mpsc::UnboundedSender<MessageServiceResponseWrap>,
) -> Result<(), MessagesServiceError> {
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

                    if sender.send(MessageServiceResponseWrap::CatchUpResponse(response)).is_err() {
                        debug!("Main task closed, stopping catch-up");
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

        if sender.send(MessageServiceResponseWrap::CatchUpResponse(response)).is_err() {
            debug!("Main task closed during final catch-up send");
        }
    }

    info!("Catch-up request completed for request_id: {}", request.request_id);
    Ok(())
}

#[async_trait]
impl Service for MessagesService {
    type Error = MessagesServiceError;

    async fn run(self) -> Result<(), Self::Error> {
        info!("Starting MessagesService");
        let Self {
            mut streams,
            store,
            service,
            current_filters,
        } = self;
        streams.send_ack().await?;
        let (mut incoming, mut sink) =
            streams.unpack_transports::<MessagesServiceRequestWrap, MessageServiceResponseWrap>();

        // Channel for receiving messages from subscription tasks
        let (mut sub_sender, mut sub_receiver) = mpsc::unbounded_channel::<StreamMessage>();
        let mut current_subscription_task: Option<tokio::task::JoinHandle<()>> = None;

        // Channel for receiving responses (including catch-up responses)
        let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<MessageServiceResponseWrap>();

        let (mut client_transport, server_transport) = tarpc::transport::channel::unbounded();

        let server = BaseChannel::with_defaults(server_transport);
        let rpc_spawn = tokio::spawn(
            server
                .execute(service.serve())
                // Handle all requests concurrently.
                .for_each(|response| async move {
                    tokio::spawn(response);
                }),
        );

        loop {
            tokio::select! {
                // Poll for incoming requests from client
                request_result = incoming.next() => {
                    match request_result {
                        Some(Ok(request)) => {
                            debug!("Received request: {:?}", request);
                            match request {
                                MessagesServiceRequestWrap::Subscribe(config) => {
                                    info!("Setting up subscription with filters: {:?}", config.filters);

                                    // Update shared filter state
                                    {
                                        let mut filters_guard = current_filters.write().await;
                                        *filters_guard = Some(config.filters.clone());
                                    }

                                    // Cancel existing subscription task if any
                                    if let Some(task) = current_subscription_task.take() {
                                        task.abort();
                                        // clear the previous receiver and create a fresh one
                                        sub_receiver.close();
                                        (sub_sender, sub_receiver) = mpsc::unbounded_channel::<StreamMessage>();
                                        // Give the old task time to clean up
                                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                                        debug!("Cancelled existing subscription task and reset channels");
                                    }

                                    // Start new subscription task
                                    let store_clone = store.clone();
                                    let task_sender = sub_sender.clone();
                                    let filters_clone = current_filters.clone();
                                    // Always start new subscriptions from the beginning to catch all messages
                                    let since = config.since.or_else(|| Some("0-0".to_string()));
                                    let limit = config.limit;

                                    let task = tokio::spawn(async move {
                                        if let Err(e) = subscription_task(
                                            store_clone,
                                            filters_clone,
                                            since,
                                            limit,
                                            task_sender,
                                        ).await {
                                            error!("Subscription task failed: {}", e);
                                        }
                                    });

                                    current_subscription_task = Some(task);
                                    info!("Started new subscription task");
                                }

                                MessagesServiceRequestWrap::UpdateFilters(filter_update) => {
                                    info!("Updating filters: {:?}", filter_update);

                                    // Update shared filter state
                                    {
                                        let mut filters_guard = current_filters.write().await;
                                        if let Some(ref mut filters) = *filters_guard {
                                            // Apply all operations atomically
                                            for operation in &filter_update.operations {
                                                filters.apply_operation(operation);
                                            }
                                            info!("Applied filter operations, new filters: {:?}", filters);
                                        } else {
                                            warn!("Received filter update but no subscription is active");
                                        }
                                    }

                                    // Send acknowledgment
                                    if let Err(e) = sink.send(MessageServiceResponseWrap::FilterUpdateAck).await {
                                        error!("Failed to send filter update ack: {}", e);
                                    }
                                }

                                MessagesServiceRequestWrap::CatchUp(catch_up_request) => {
                                    info!("Handling catch-up request: {:?}", catch_up_request);

                                    // Spawn catch-up task
                                    let store_clone = store.clone();
                                    let response_sender_clone = response_sender.clone();
                                    
                                    tokio::spawn(async move {
                                        if let Err(e) = handle_catch_up_request(
                                            store_clone,
                                            catch_up_request,
                                            response_sender_clone,
                                        ).await {
                                            error!("Catch-up task failed: {}", e);
                                        }
                                    });
                                }

                                MessagesServiceRequestWrap::RpcRequest(request) => {
                                    if let Err(e) = client_transport.send(request).await {
                                        error!("Failed to send request to server: {}", e);
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error reading request: {} (this may be due to client disconnecting)", e);
                            break;
                        }
                        None => {
                            info!("Request stream closed");
                            break;
                        }
                    }
                }

                // Poll for messages from subscription task
                stream_message = sub_receiver.recv() => {
                    match stream_message {
                        Some(message) => {
                            // Forward message to client
                            if let Err(e) = sink.send(MessageServiceResponseWrap::StreamMessage(message)).await {
                                error!("Failed to send response to client: {}", e);
                                break;
                            }
                        }
                        None => {
                            debug!("Subscription channel closed");
                            // Continue running - this can happen when subscription task ends
                        }
                    }
                }

                // Poll from rpc task
                rpc_message = client_transport.next() => {
                    match rpc_message {
                        Some(Ok(message)) => {
                            // Forward message to client
                            if let Err(e) = sink.send(MessageServiceResponseWrap::RpcResponse(message)).await {
                                error!("Failed to send response to client: {}", e);
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error reading RPC message: {}", e);
                            break;
                        }
                        None => {
                            debug!("RPC channel closed");
                            // Continue running - this can happen when rpc task ends
                        }
                    }
                }

                // Poll for responses from catch-up tasks
                response_message = response_receiver.recv() => {
                    match response_message {
                        Some(response) => {
                            // Forward response to client
                            if let Err(e) = sink.send(response).await {
                                error!("Failed to send response to client: {}", e);
                                break;
                            }
                        }
                        None => {
                            debug!("Response channel closed");
                            // Continue running
                        }
                    }
                }
            }
        }

        info!("MessagesService shutting down");
        rpc_spawn.abort();
        Ok(())
    }
}
