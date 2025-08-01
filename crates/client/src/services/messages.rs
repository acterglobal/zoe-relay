use std::ops::Deref;

use crate::error::{ClientError, Result};
use futures::{SinkExt, StreamExt};
use quinn::Connection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinHandle,
};
use zoe_wire_protocol::{
    MessageServiceClient, MessageServiceResponseWrap, MessagesServiceRequestWrap, StreamMessage,
    SubscriptionConfig, ZoeServices, stream_pair::create_postcard_streams,
};

pub type MessagesStream = UnboundedReceiver<StreamMessage>;

pub struct MessagesService {
    outgoing_tx: UnboundedSender<MessagesServiceRequestWrap>,
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
        let (outgoing_tx, mut outgoing_rx) = unbounded_channel::<MessagesServiceRequestWrap>();
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
                                if let Err(e) = server_transport.send(response).await {
                                    return Err(ClientError::Generic(format!("Send error: {e}")));
                                }
                            }
                            Err(e) => {
                                return Err(ClientError::Generic(format!("Stream error: {e}")));
                            }
                        }
                    }
                    // Send messages from client to server
                    msg = outgoing_rx.recv() => {
                        let Some(request) =  msg else {
                            tracing::info!("Outgoing channel closed");
                            break;
                        };
                        if let Err(e) = sink.send(request).await {
                            return Err(ClientError::Generic(format!("Send error: {e}")));
                        }
                    }
                    // Poll for messages from rpc client
                    rpc_message = server_transport.next() => {
                        let Some(Ok(rpc_message)) = rpc_message else {
                            tracing::info!("RPC client closed");
                            break;
                        };
                        if let Err(e) = sink.send(MessagesServiceRequestWrap::RpcRequest(rpc_message)).await {
                            return Err(ClientError::Generic(format!("Send error: {e}")));
                        }
                    }
                }
            }
            Ok(())
        });

        Ok((
            Self {
                outgoing_tx,
                rpc_client,
                handle,
            },
            incoming_rx,
        ))
    }

    pub async fn subscribe(&self, filters: SubscriptionConfig) -> Result<()> {
        self.outgoing_tx
            .send(MessagesServiceRequestWrap::Subscribe(filters))
            .map_err(|e| ClientError::Generic(format!("Service is closed: {e}")))
    }

    /// Check if the service is closed
    pub fn is_closed(&self) -> bool {
        self.handle.is_finished()
    }
}
