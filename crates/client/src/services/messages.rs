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
    MessageFull, MessagesServiceRequest, StreamMessage, ZoeServices,
    stream_pair::create_postcard_streams,
};

pub type MessagesStream = UnboundedReceiver<StreamMessage>;

pub struct MessagesService {
    outgoing_tx: UnboundedSender<MessagesServiceRequest>,
    handle: JoinHandle<Result<()>>,
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

        let (mut stream, mut sink) =
            create_postcard_streams::<StreamMessage, MessagesServiceRequest>(recv, send);
        let (outgoing_tx, mut outgoing_rx) = unbounded_channel::<MessagesServiceRequest>();
        let (incoming_tx, incoming_rx) = unbounded_channel::<StreamMessage>();

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
                            Ok(message) => {
                                if let Err(e) = incoming_tx.send(message) {
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
                }
            }
            Ok(())
        });

        Ok((
            Self {
                outgoing_tx,
                handle,
            },
            incoming_rx,
        ))
    }

    pub async fn publish(&self, message: MessageFull) -> Result<()> {
        self.send_raw(MessagesServiceRequest::Publish(message))
            .await
    }

    /// Send a message service request to the server
    pub async fn send_raw(&self, request: MessagesServiceRequest) -> Result<()> {
        self.outgoing_tx
            .send(request)
            .map_err(|_| ClientError::Generic("Service is closed".to_string()))
    }

    /// Check if the service is closed
    pub fn is_closed(&self) -> bool {
        self.handle.is_finished()
    }
}
