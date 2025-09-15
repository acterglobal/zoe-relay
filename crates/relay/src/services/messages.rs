use crate::router::Service;
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use tarpc::server::{BaseChannel, Channel};
use tracing::{debug, error, info};
use zoe_message_store::{
    error::MessageStoreError, service::MessagesRpcService, storage::RedisMessageStorage,
};
use zoe_wire_protocol::{
    MessageService as _, MessageServiceResponseWrap, MessagesServiceRequestWrap, StreamPair,
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
}

impl MessagesService {
    pub fn new(streams: StreamPair, redis: RedisMessageStorage) -> Self {
        let store = Arc::new(redis);
        Self {
            streams,
            store: store.clone(),
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
        let service_id = format!("{:p}", &self.store);
        info!("🚀 Starting MessagesService {}", service_id);
        let Self { mut streams, store } = self;
        streams.send_ack().await?;
        let (mut incoming, mut sink) =
            streams.unpack_transports::<MessagesServiceRequestWrap, MessageServiceResponseWrap>();

        let (mut client_transport, server_transport) = tarpc::transport::channel::unbounded();
        let (mut msg_recv, mut catchup_recv, rpc) = MessagesRpcService::new(store);

        let server = BaseChannel::with_defaults(server_transport);
        let rpc_spawn = tokio::spawn(
            server
                .execute(rpc.serve())
                // Handle all requests concurrently.
                .for_each(|response| async move {
                    tokio::spawn(response);
                }),
        );

        let mut request_stream_closed = false;

        loop {
            tokio::select! {
                // Poll for incoming RPC requests from client
                request_result = incoming.next(), if !request_stream_closed => {
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
                            // Give a brief moment for potential recovery before breaking
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                            break;
                        }
                        None => {
                            info!("Request stream closed - continuing to process responses");
                            request_stream_closed = true;
                            // Don't break - continue processing responses and background tasks
                        }
                    }
                }

                // Poll from rpc responses
                rpc_message = client_transport.next() => {
                    match rpc_message {
                        Some(Ok(message)) => {
                            // Forward message to client
                            if let Err(e) = sink.send(MessageServiceResponseWrap::RpcResponse(Box::new(message))).await {
                                error!("Failed to send response to client: {}", e);
                                // Allow a brief moment for recovery before breaking
                                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!("Error reading RPC message: {}", e);
                            break;
                        }
                        None => {
                            debug!("RPC channel closed - service shutting down");
                            // RPC channel closed means no more responses can be processed
                            break;
                        }
                    }
                }

                // Poll for messages from subscription task
                stream_message = msg_recv.recv() => {
                    match stream_message {
                        Some(message) => {
                            debug!("🔄 MessagesService {} received stream message from subscription task: {:?}", service_id, message);
                            // Forward message to client
                            if let Err(e) = sink.send(MessageServiceResponseWrap::StreamMessage(message)).await {
                                error!("Failed to send stream message to client: {}", e);
                                // Allow a brief moment for recovery before breaking
                                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                                break;
                            } else {
                                debug!("✅ MessagesService {} successfully sent stream message to client", service_id);
                            }
                        }
                        None => {
                            debug!("Subscription channel closed");
                            // Continue running - this can happen when subscription task ends
                        }
                    }
                }

                // Poll for responses from catch-up tasks
                response_message = catchup_recv.recv() => {
                    match response_message {
                        Some(response) => {
                            // Forward response to client
                            if let Err(e) = sink.send(MessageServiceResponseWrap::CatchUpResponse(response)).await {
                                error!("Failed to send catch-up response to client: {}", e);
                                // Allow a brief moment for recovery before breaking
                                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
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
