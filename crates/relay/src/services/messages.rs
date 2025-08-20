use crate::Service;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tarpc::server::{BaseChannel, Channel};
use tokio::sync::mpsc;
use tracing::{debug, error, info};
use zoe_message_store::{MessageStoreError, MessagesRpcService, RedisMessageStorage};
use zoe_wire_protocol::{
    MessageService as _, MessageServiceResponseWrap, MessagesServiceRequestWrap, StreamMessage,
    StreamPair,
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

// Background task functions have been moved to the message-store service
// All subscription, filter updates, and catch-up requests are now handled as RPC calls
// that spawn background tasks managed by the RPC service

#[async_trait]
impl Service for MessagesService {
    type Error = MessagesServiceError;

    async fn run(self) -> Result<(), Self::Error> {
        info!("Starting MessagesService");
        let Self {
            mut streams,
            store: _store,
            service,
        } = self;
        streams.send_ack().await?;
        let (mut incoming, mut sink) =
            streams.unpack_transports::<MessagesServiceRequestWrap, MessageServiceResponseWrap>();

        // Channels for receiving messages from background tasks
        let (sub_sender, mut sub_receiver) = mpsc::unbounded_channel::<StreamMessage>();
        let (response_sender, mut response_receiver) =
            mpsc::unbounded_channel::<MessageServiceResponseWrap>();

        let (mut client_transport, server_transport) = tarpc::transport::channel::unbounded();

        // Configure the RPC service with communication channels
        let enhanced_service = service.with_channels(sub_sender, response_sender);

        let server = BaseChannel::with_defaults(server_transport);
        let rpc_spawn = tokio::spawn(
            server
                .execute(enhanced_service.serve())
                // Handle all requests concurrently.
                .for_each(|response| async move {
                    tokio::spawn(response);
                }),
        );

        loop {
            tokio::select! {
                // Poll for incoming RPC requests from client
                request_result = incoming.next() => {
                    match request_result {
                        Some(Ok(request)) => {
                            debug!("Received RPC request: {:?}", request);
                            // All requests are now RPC requests - forward directly to RPC handler
                            if let Err(e) = client_transport.send(request).await {
                                error!("Failed to send request to RPC server: {}", e);
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
                            if let Err(e) = sink.send(MessageServiceResponseWrap::RpcResponse(Box::new(message))).await {
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
