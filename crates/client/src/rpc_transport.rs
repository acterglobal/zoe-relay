//! Simple RPC Message Listener over X25519 Encrypted Messages
//!
//! This module provides a simple listener that detects ephemeral RPC messages
//! targeted at this client and decrypts their content, deserializing via postcard.

use crate::error::{ClientError, Result};
use crate::services::messages::{MessagesService, MessagesStream};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::{SinkExt, Stream, StreamExt};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
// use std::time::{SystemTime, UNIX_EPOCH}; // Temporarily disabled
use tarpc::transport::channel::UnboundedChannel;
use tarpc::{ClientMessage, Response};
use tokio::select;
use tokio::task::JoinHandle;
use tracing::{debug, error};
use zoe_wire_protocol::{Kind, Message, MessageFull, MessageV0Header, StreamMessage, Tag};

/// RPC message containing both header metadata and deserialized content
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcMessage<T> {
    /// Message header with sender, timestamp, kind, and tags
    pub header: MessageV0Header,
    /// Deserialized message content
    pub content: T,
}

/// Simple RPC message listener that detects and decrypts RPC messages
/// Now specifically for tarpc wrapper types
pub struct RpcMessageListener<TarpcMsg> {
    signing_key: SigningKey,
    messages_stream: MessagesStream,
    _phantom: PhantomData<TarpcMsg>,
}

impl<TarpcMsg> RpcMessageListener<TarpcMsg> {
    pub fn new(signing_key: SigningKey, messages_stream: MessagesStream) -> Self {
        Self {
            signing_key,
            messages_stream,
            _phantom: PhantomData,
        }
    }

    /// Check if this message is an ephemeral RPC message targeted at us
    fn is_rpc_message_for_us(&self, message: &MessageFull) -> bool {
        // Check if it's an ephemeral message
        if !matches!(message.kind(), Kind::Emphemeral(_)) {
            tracing::debug!("Message is not ephemeral: {:?}", message.kind());
            return false;
        }

        // Check if it's targeted at our public key
        let our_public_key = *self.signing_key.verifying_key().as_bytes();
        tracing::debug!("Our public key: {}", hex::encode(our_public_key));

        let is_targeted = message.tags().iter().any(|tag| {
            if let Tag::User { id, .. } = tag {
                tracing::debug!("Checking tag user ID: {}", hex::encode(id));
                id == &our_public_key
            } else {
                false
            }
        });

        tracing::debug!("Message is targeted at us: {}", is_targeted);
        is_targeted
    }

    /// Try to decrypt ephemeral ECDH encrypted content and deserialize as `RpcMessage<TarpcMsg>`
    fn try_decrypt_and_deserialize_message(
        &self,
        message: &MessageFull,
    ) -> Option<RpcMessage<TarpcMsg>>
    where
        TarpcMsg: serde::de::DeserializeOwned,
    {
        // Try to decrypt ephemeral ECDH encrypted content
        let ecdh_content = message.content().as_ephemeral_ecdh()?;
        tracing::debug!(
            "Got ephemeral ECDH encrypted content with {} bytes ciphertext",
            ecdh_content.ciphertext.len()
        );

        // Decrypt using our private key (ephemeral X25519 public key is stored in the content)
        tracing::debug!(
            "Sender ML-DSA public key: {}",
            hex::encode(message.author().encode())
        );
        let decrypted_data = match ecdh_content.decrypt(&self.signing_key) {
            Ok(data) => {
                tracing::debug!("Successfully decrypted {} bytes", data.len());
                data
            }
            Err(e) => {
                tracing::debug!("Failed to decrypt X25519 content: {}", e);
                return None;
            }
        };

        // Try to deserialize the decrypted data using postcard
        let content = match postcard::from_bytes::<TarpcMsg>(&decrypted_data) {
            Ok(content) => {
                tracing::debug!("Successfully deserialized RPC content");
                content
            }
            Err(e) => {
                tracing::debug!("Failed to deserialize content: {}", e);
                return None;
            }
        };

        // Extract header information from the message
        let header = match message.message() {
            Message::MessageV0(msg) => msg.header.clone(),
        };

        Some(RpcMessage { header, content })
    }
}

impl<TarpcMsg> Stream for RpcMessageListener<TarpcMsg>
where
    TarpcMsg: serde::de::DeserializeOwned + Unpin,
{
    type Item = RpcMessage<TarpcMsg>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // Poll the underlying messages stream
            let this = self.as_mut().get_mut();
            match this.messages_stream.poll_recv(cx) {
                Poll::Ready(Some(stream_message)) => {
                    match stream_message {
                        StreamMessage::MessageReceived { message, .. } => {
                            tracing::debug!(
                                "RpcMessageListener received message from {}, kind: {:?}, tags: {:?}",
                                hex::encode(message.author().encode()),
                                message.kind(),
                                message.tags()
                            );

                            // Check if this is an ephemeral message targeted at us
                            if this.is_rpc_message_for_us(&message) {
                                tracing::debug!(
                                    "Message is targeted at us, attempting to decrypt..."
                                );
                                // Try to decrypt and deserialize the content
                                if let Some(deserialized_message) =
                                    this.try_decrypt_and_deserialize_message(&message)
                                {
                                    tracing::debug!(
                                        "Successfully decrypted and deserialized RPC message"
                                    );
                                    return Poll::Ready(Some(deserialized_message));
                                } else {
                                    tracing::debug!("Failed to decrypt or deserialize message");
                                }
                            } else {
                                tracing::debug!("Message is not for us or not ephemeral");
                            }
                        }
                        other => {
                            tracing::debug!(
                                "RpcMessageListener received non-message stream event: {:?}",
                                other
                            );
                        }
                    }
                    // Continue polling if this wasn't a valid RPC message for us
                    continue;
                }
                Poll::Ready(None) => {
                    // Stream ended
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    // No messages available right now
                    return Poll::Pending;
                }
            }
        }
    }
}

type ServiceMaker<Req, Resp> =
    fn(UnboundedChannel<ClientMessage<Req>, Response<Resp>>) -> JoinHandle<Result<()>>;

pub struct TarpcOverMessagesServer {
    // Bridge task handle
    handle: JoinHandle<Result<()>>,
    rpc_spawn: JoinHandle<Result<()>>,
}

impl TarpcOverMessagesServer {
    pub fn new<S, Req, Resp>(
        mut request_listener: S,
        _signing_key: SigningKey,
        _messages_service: MessagesService,
        service_maker: ServiceMaker<Req, Resp>,
    ) -> Self
    where
        Req: serde::de::DeserializeOwned + Unpin + Send + Sync + 'static,
        Resp: serde::Serialize + Unpin + Send + Sync + 'static,
        S: Stream<Item = RpcMessage<ClientMessage<Req>>> + Unpin + Send + Sync + 'static,
    {
        // Create tarpc transport channel - just like messages.rs
        let (mut client_transport, server_transport) = tarpc::transport::channel::unbounded();
        let rpc_spawn = service_maker(server_transport);

        let mut target_public_keys = HashMap::new();

        // Bridge task: bidirectional bridge like messages.rs select! loop
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Incoming: RpcMessageListener -> tarpc server
                    rpc_request = request_listener.next() => {
                        match rpc_request {
                            Some(RpcMessage { header, content }) => {
                                debug!("📨 Bridge forwarding request to tarpc server from {}",
                                       hex::encode(header.sender.encode()));
                                match &content {
                                    ClientMessage::Request(request) => {
                                        target_public_keys.insert(request.id, header.sender);
                                    }
                                    ClientMessage::Cancel { request_id, .. } => {
                                        target_public_keys.remove(request_id);
                                    }
                                    _ => {
                                        error!("Unexpected request type");
                                    }
                                }

                                if let Err(e) = client_transport.send(content).await {
                                    error!("Failed to forward request to tarpc server: {e}");
                                    break;
                                }
                            }
                            None => {
                                debug!("Request listener stream ended");
                                break;
                            }
                        }
                    }

                    // Outgoing: tarpc server -> send_rpc_response
                    tarpc_response = client_transport.next() => {
                        match tarpc_response {
                            Some(Ok(response)) => {
                                debug!("📤 Bridge sending tarpc response via RPC message");
                                let Some(_target_public_key) = target_public_keys.remove(&response.request_id) else {
                                    // This should never happen, but just in case
                                    error!("Target public key not found for response ID: {}", response.request_id);
                                    continue;
                                };
                                // TODO: Temporarily disabled due to Ed25519/ML-DSA key type mismatch
                                error!("RPC-over-messages temporarily disabled during ML-DSA migration");
                                break;
                            }
                            Some(Err(e)) => {
                                error!("tarpc transport error: {e}");
                                break;
                            }
                            None => {
                                debug!("tarpc server transport closed");
                                break;
                            }
                        }
                    }
                }
            }
            debug!("RPC bridge server task ending");
            Ok(())
        });

        Self { handle, rpc_spawn }
    }

    /// Check if the bridge is still running
    pub fn is_running(&self) -> bool {
        !self.handle.is_finished()
    }

    pub fn abort(&self) {
        self.handle.abort();
        self.rpc_spawn.abort();
    }
}

type ClientMaker<C, Req, Resp> = fn(UnboundedChannel<Response<Resp>, ClientMessage<Req>>) -> C;

pub struct TarpcOverMessagesClient<C> {
    // Bridge task handle
    handle: JoinHandle<Result<()>>,
    client: C,
}

impl<C> Deref for TarpcOverMessagesClient<C> {
    type Target = C;
    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl<C> TarpcOverMessagesClient<C> {
    pub fn new<S, Req, Resp>(
        request_listener: S,
        signing_key: SigningKey,
        messages_service: MessagesService,
        target_public_key: VerifyingKey,
        client_maker: ClientMaker<C, Req, Resp>,
    ) -> Self
    where
        S: Stream<Item = RpcMessage<Response<Resp>>> + Unpin + Send + Sync + 'static,
        Req: serde::Serialize + Unpin + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Unpin + Send + Sync + 'static,
    {
        Self::new_with_mapper(
            request_listener,
            signing_key,
            messages_service,
            target_public_key,
            client_maker,
            |rpc_message| rpc_message,
        )
    }

    pub fn new_with_mapper<S, Req, Resp, M, T>(
        mut request_listener: S,
        signing_key: SigningKey,
        messages_service: MessagesService,
        target_public_key: VerifyingKey,
        client_maker: ClientMaker<C, Req, Resp>,
        mapper: M,
    ) -> Self
    where
        S: Stream<Item = RpcMessage<Response<Resp>>> + Unpin + Send + Sync + 'static,
        T: serde::Serialize + Unpin + Send + Sync + 'static,
        Req: serde::Serialize + Unpin + Send + Sync + 'static,
        Resp: serde::de::DeserializeOwned + Unpin + Send + Sync + 'static,
        M: Fn(ClientMessage<Req>) -> T + Send + Sync + 'static,
    {
        let (client_transport, mut server_transport) = tarpc::transport::channel::unbounded();
        let client = client_maker(client_transport);

        let handle = tokio::spawn(async move {
            loop {
                select! {
                    // Incoming: RpcMessageListener coming from the tarpc server
                    rpc_request = request_listener.next() => {
                        match rpc_request {
                            Some(RpcMessage { header, content }) => {
                                debug!("📨 Bridge forwarding request to tarpc server from {}",
                                    hex::encode(header.sender.encode()));

                                if let Err(e) = server_transport.send(content).await {
                                    error!("Failed to forward request to tarpc server: {e}");
                                    break;
                                }
                            }
                            None => {
                                debug!("Request listener stream ended");
                                break;
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

                        if let Err(e) = send_tarpc_message(&signing_key, target_public_key, &messages_service, &mapper(rpc_message)).await {
                            return Err(ClientError::Generic(format!("Send error: {e}")));
                        }
                    }
                }
            }
            Ok(())
        });

        Self { client, handle }
    }

    /// Check if the bridge is still running
    pub fn is_running(&self) -> bool {
        !self.handle.is_finished()
    }

    pub fn abort(&self) {
        self.handle.abort();
    }
}

/// Internal helper function to send tarpc messages  
/// Serializes the message using postcard before encryption
async fn send_tarpc_message<TarpcMsg>(
    _signing_key: &SigningKey,
    _target_public_key: VerifyingKey,
    _messages_service: &MessagesService,
    _message: &TarpcMsg,
) -> Result<()>
where
    TarpcMsg: serde::Serialize,
{
    // TODO: Temporarily disabled due to Ed25519/ML-DSA key type mismatch
    // The message system now uses ML-DSA keys but RPC transport uses Ed25519 keys
    // This needs to be redesigned to work with the hybrid architecture
    Err(ClientError::Generic(
        "RPC-over-messages temporarily disabled during ML-DSA migration".to_string(),
    ))
}
