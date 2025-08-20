use std::ops::Deref;

use crate::error::{ClientError, Result};
use futures::{SinkExt, StreamExt};
use quinn::Connection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::mpsc::{UnboundedReceiver, unbounded_channel},
    task::JoinHandle,
};
use zoe_wire_protocol::{
    CatchUpRequest, FilterUpdateRequest, MessageServiceClient, MessageServiceResponseWrap,
    MessagesServiceRequestWrap, StreamMessage, SubscriptionConfig, ZoeServices,
    stream_pair::create_postcard_streams,
};

pub type MessagesStream = UnboundedReceiver<StreamMessage>;

pub struct MessagesService {
    rpc_client: MessageServiceClient,
    handle: JoinHandle<Result<()>>,
}

impl Deref for MessagesService {
    type Target = MessageServiceClient;
    fn deref(&self) -> &Self::Target {
        &self.rpc_client
    }
}

impl MessagesService {
    pub async fn connect(connection: &Connection) -> Result<(Self, MessagesStream)> {
        // Open bidirectional stream
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send service ID
        send.write_u8(ZoeServices::Messages as u8).await?;

        let service_ok = recv.read_u8().await?;
        if service_ok != 1 {
            return Err(ClientError::Generic(
                "Service ID not acknowledged".to_string(),
            ));
        }

        let (mut stream, mut sink) = create_postcard_streams::<
            MessageServiceResponseWrap,
            MessagesServiceRequestWrap,
        >(recv, send);
        let (incoming_tx, incoming_rx) = unbounded_channel::<StreamMessage>();

        let (client_transport, mut server_transport) = tarpc::transport::channel::unbounded();
        let rpc_client = MessageServiceClient::new(Default::default(), client_transport).spawn();

        let handle = tokio::spawn(async move {
            loop {
                select! {
                    // Receive messages from server and forward to client
                    message_result = stream.next() => {
                        let Some(incoming_message) = message_result else {
                            tracing::info!("Stream ended");
                            break;
                        };
                        match incoming_message {
                            Ok(MessageServiceResponseWrap::StreamMessage(message)) => {
                                if let Err(e) = incoming_tx.send(message) {
                                    return Err(ClientError::Generic(format!("Send error: {e}")));
                                }
                            }
                                        Ok(MessageServiceResponseWrap::RpcResponse(response)) => {
                if let Err(e) = server_transport.send(*response).await {
                                    return Err(ClientError::Generic(format!("Send error: {e}")));
                                }
                            }
                            Ok(MessageServiceResponseWrap::CatchUpResponse(catch_up_response)) => {
                                // Log catch-up response for now - could be forwarded to a specific handler
                                tracing::info!(
                                    "Received catch-up response: request_id={}, filter_field={:?}, message_count={}",
                                    catch_up_response.request_id,
                                    catch_up_response.filter_field,
                                    catch_up_response.messages.len()
                                );
                                // TODO: Forward to a catch-up response handler if needed
                            }
                            // FilterUpdateAck is now handled as RPC responses, not streaming messages
                            Err(e) => {
                                return Err(ClientError::Generic(format!("Stream error: {e}")));
                            }
                        }
                    }
                    // Poll for messages from rpc client
                    rpc_message = server_transport.next() => {
                        let Some(Ok(rpc_message)) = rpc_message else {
                            tracing::info!("RPC client closed");
                            break;
                        };
                        // Send RPC message directly since MessagesServiceRequestWrap is now just ClientMessage
                        if let Err(e) = sink.send(rpc_message).await {
                            return Err(ClientError::Generic(format!("Send error: {e}")));
                        }
                    }
                }
            }
            Ok(())
        });

        Ok((Self { rpc_client, handle }, incoming_rx))
    }

    pub async fn subscribe(&self, filters: SubscriptionConfig) -> Result<String> {
        // Use RPC client directly for subscription - returns subscription ID
        self.rpc_client
            .subscribe(tarpc::context::current(), filters)
            .await
            .map_err(|e| ClientError::Generic(format!("Subscription failed: {e}")))?
            .map_err(|e| ClientError::Generic(format!("Subscription error: {e}")))
    }

    pub async fn update_filters(
        &self,
        subscription_id: String,
        request: FilterUpdateRequest,
    ) -> Result<()> {
        self.rpc_client
            .update_filters(tarpc::context::current(), subscription_id, request)
            .await
            .map_err(|e| ClientError::Generic(format!("Update filters failed: {e}")))?
            .map_err(|e| ClientError::Generic(format!("Update filters error: {e}")))
    }

    pub async fn catch_up(&self, request: CatchUpRequest) -> Result<String> {
        self.rpc_client
            .catch_up(tarpc::context::current(), request)
            .await
            .map_err(|e| ClientError::Generic(format!("Catch up failed: {e}")))?
            .map_err(|e| ClientError::Generic(format!("Catch up error: {e}")))
    }

    /// Check if the service is closed
    pub fn is_closed(&self) -> bool {
        self.handle.is_finished()
    }
}
