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
    CatchUpRequest, CatchUpResponse, FilterUpdateRequest, MessageServiceClient,
    MessageServiceResponseWrap, MessagesServiceRequestWrap, StreamMessage, SubscriptionConfig,
    ZoeServices, stream_pair::create_postcard_streams,
};

pub type MessagesStream = UnboundedReceiver<StreamMessage>;
pub type CatchUpStream = UnboundedReceiver<CatchUpResponse>;

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
    pub async fn connect(
        connection: &Connection,
    ) -> Result<(Self, (MessagesStream, CatchUpStream))> {
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
        let (catch_up_tx, catch_up_rx) = unbounded_channel::<CatchUpResponse>();

        let (client_transport, mut server_transport) = tarpc::transport::channel::unbounded();
        let rpc_client = MessageServiceClient::new(Default::default(), client_transport).spawn();

        let handle = tokio::spawn(async move {
            loop {
                select! {
                    // Receive messages from server and forward to client
                    message_result = stream.next() => {
                        let Some(incoming_message) = message_result else {
                            tracing::info!("Stream ended - server closed connection");
                            break;
                        };
                        let inner = match incoming_message {
                            Ok(msg) => msg,
                            Err(e) => {
                                tracing::warn!("Stream error (connection may be closing): {e}");
                                // Don't return error immediately - let the loop continue to handle graceful shutdown
                                continue;
                            }
                        };
                        match inner {
                            MessageServiceResponseWrap::StreamMessage(message) => {
                                if let Err(e) = incoming_tx.send(message) {
                                    return Err(ClientError::Generic(format!("Stream Message Send error: {e}")));
                                }
                            }
                            MessageServiceResponseWrap::RpcResponse(response) => {
                                if let Err(e) = server_transport.send(*response).await {
                                    return Err(ClientError::Generic(format!("RPC Response Send error: {e}")));
                                }
                            }
                            MessageServiceResponseWrap::CatchUpResponse(catch_up_response) => {
                                if let Err(e) = catch_up_tx.send(catch_up_response) {
                                    return Err(ClientError::Generic(format!("Catch Up Response Send error: {e}")));
                                }
                            }
                        }
                    }
                    // Poll for messages from rpc client
                    rpc_message = server_transport.next() => {
                        let Some(rpc_message) = rpc_message else {
                            tracing::trace!("RPC client closed");
                            break;
                        };
                        let rpc_message = match rpc_message {
                            Ok(msg) => msg,
                            Err(e) => {
                                tracing::warn!("RPC client error: {e}");
                                continue;
                            }
                        };
                        // Send RPC message directly since MessagesServiceRequestWrap is now just ClientMessage
                        if let Err(e) = sink.send(rpc_message).await {
                            tracing::warn!("Failed to send RPC message (connection may be closing): {e}");
                            break;
                        }
                    }
                }
            }
            Ok(())
        });

        Ok((Self { rpc_client, handle }, (incoming_rx, catch_up_rx)))
    }

    pub async fn subscribe(&self, filters: SubscriptionConfig) -> Result<()> {
        // Use RPC client directly for subscription - returns subscription ID
        self.rpc_client
            .subscribe(tarpc::context::current(), filters)
            .await
            .map_err(|e| ClientError::Generic(format!("Subscription failed: {e}")))?
            .map_err(|e| ClientError::Generic(format!("Subscription error: {e}")))
    }

    pub async fn update_filters(&self, request: FilterUpdateRequest) -> Result<SubscriptionConfig> {
        self.rpc_client
            .update_filters(tarpc::context::current(), request)
            .await
            .map_err(|e| ClientError::Generic(format!("Update filters failed: {e}")))?
            .map_err(|e| ClientError::Generic(format!("Update filters error: {e}")))
    }

    pub async fn catch_up(&self, request: CatchUpRequest) -> Result<SubscriptionConfig> {
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
