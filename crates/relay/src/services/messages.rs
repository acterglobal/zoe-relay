use crate::Service;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tarpc::server::{BaseChannel, Channel};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use zoe_message_store::{MessageStoreError, MessagesRpcService, RedisMessageStorage};
use zoe_wire_protocol::{
    MessageFilters, MessageService as MessageServiceRpc, MessageServiceResponseWrap,
    MessagesServiceRequestWrap, StreamMessage, StreamPair,
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
}

impl MessagesService {
    pub fn new(streams: StreamPair, redis: RedisMessageStorage) -> Self {
        let store = Arc::new(redis);
        Self {
            streams,
            store: store.clone(),
            service: MessagesRpcService::new(store),
        }
    }
}

// Task to handle a subscription stream
async fn subscription_task(
    service: Arc<RedisMessageStorage>,
    filters: MessageFilters,
    since: Option<String>,
    limit: Option<usize>,
    sender: mpsc::UnboundedSender<StreamMessage>,
) -> Result<(), MessagesServiceError> {
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

        // Send response to main task
        if sender.send(to_client).is_err() {
            debug!("Main task closed, stopping subscription");
            break;
        }
    }

    info!("Subscription task ended");
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
        } = self;
        streams.send_ack().await?;
        let (mut incoming, mut sink) =
            streams.unpack_transports::<MessagesServiceRequestWrap, MessageServiceResponseWrap>();

        // Channel for receiving messages from subscription tasks
        let (mut sub_sender, mut sub_receiver) = mpsc::unbounded_channel::<StreamMessage>();
        let mut current_subscription_task: Option<tokio::task::JoinHandle<()>> = None;

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
                                    let filters = config.filters;
                                    // Always start new subscriptions from the beginning to catch all messages
                                    let since = config.since.or_else(|| Some("0-0".to_string()));
                                    let limit = config.limit;

                                    let task = tokio::spawn(async move {
                                        if let Err(e) = subscription_task(
                                            store_clone,
                                            filters,
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
            }
        }

        info!("MessagesService shutting down");
        rpc_spawn.abort();
        Ok(())
    }
}
