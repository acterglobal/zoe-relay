use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tarpc::{client, serde_transport};
use tracing::{error, info};
// Removed unused compat imports

use crate::RelayClient;
use zoeyr_wire_protocol::{
    generate_ed25519_keypair, load_ed25519_key_from_hex, load_ed25519_public_key_from_hex,
    RelayServiceClient, StreamRequest,
};

/// Generic QUIC + tarpc client that can connect to any tarpc service
pub struct QuicTarpcClient {
    relay_client: RelayClient,
}

impl QuicTarpcClient {
    pub async fn connect(
        server_addr: SocketAddr,
        expected_server_ed25519_key: ed25519_dalek::VerifyingKey,
        client_key: SigningKey,
    ) -> Result<Self> {
        let relay_client =
            RelayClient::connect(server_addr, expected_server_ed25519_key, client_key).await?;

        Ok(Self { relay_client })
    }

    pub fn client_public_key(&self) -> [u8; 32] {
        self.relay_client.client_key.verifying_key().to_bytes()
    }

    pub fn client_signing_key(&self) -> &SigningKey {
        &self.relay_client.client_key
    }

    /// Create a tarpc client for the RelayService
    pub async fn relay_service(&self) -> Result<RelayServiceClient> {
        // Get QUIC connection
        let connection = &self.relay_client.connection;

        // Open bidirectional stream
        let (send, recv) = connection.open_bi().await?;

        // Create tarpc transport from QUIC streams
        use crate::server::{PostcardSerializer, QuicDuplexStream};
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let codec = LengthDelimitedCodec::new();
        let combined = QuicDuplexStream::new(recv, send);
        let framed = Framed::new(combined, codec);
        let transport = serde_transport::new(framed, PostcardSerializer::default());

        // Create tarpc client
        let client = RelayServiceClient::new(client::Config::default(), transport).spawn();

        Ok(client)
    }

    /// Start a message stream using the streaming protocol over QUIC
    pub async fn start_message_stream(&self, stream_request: StreamRequest) -> Result<()> {
        info!("🎧 Starting message stream with streaming protocol");

        // Get QUIC connection
        let connection = &self.relay_client.connection;

        // Open a bidirectional stream for streaming
        let (send, recv) = connection.open_bi().await?;

        // Create framed stream for the streaming protocol
        use crate::server::QuicDuplexStream;
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let codec = LengthDelimitedCodec::new();
        let combined = QuicDuplexStream::new(recv, send);
        let mut framed = Framed::new(combined, codec);

        // Send the initial stream request
        use zoeyr_wire_protocol::StreamProtocolMessage;
        let request_msg = StreamProtocolMessage::Request(stream_request);
        let request_bytes = postcard::to_allocvec(&request_msg)
            .map_err(|e| anyhow::anyhow!("Failed to serialize stream request: {}", e))?;

        use futures_util::SinkExt;
        framed
            .send(request_bytes.into())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send stream request: {}", e))?;

        info!("📤 Sent stream request to server");

        // Wait for response
        use futures_util::StreamExt;
        if let Some(response_frame) = framed.next().await {
            let response_frame = response_frame
                .map_err(|e| anyhow::anyhow!("Failed to receive response frame: {}", e))?;

            let response_msg: StreamProtocolMessage = postcard::from_bytes(&response_frame)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize response: {}", e))?;

            use zoeyr_wire_protocol::{StreamResponse, StreamingMessage};
            match response_msg {
                StreamProtocolMessage::Response(StreamResponse::StreamStarted) => {
                    info!("✅ Stream started successfully, listening for messages...");
                }
                StreamProtocolMessage::Response(StreamResponse::StreamRejected(reason)) => {
                    return Err(anyhow::anyhow!("Stream rejected: {}", reason));
                }
                _ => {
                    return Err(anyhow::anyhow!("Unexpected response to stream request"));
                }
            }
        } else {
            return Err(anyhow::anyhow!("No response to stream request"));
        }

        // Now listen for streaming messages
        let mut message_count = 0;
        while let Some(message_frame) = framed.next().await {
            let message_frame = message_frame
                .map_err(|e| anyhow::anyhow!("Failed to receive message frame: {}", e))?;

            let message: StreamProtocolMessage = postcard::from_bytes(&message_frame)
                .map_err(|e| anyhow::anyhow!("Failed to deserialize message: {}", e))?;

            use zoeyr_wire_protocol::StreamingMessage;
            match message {
                StreamProtocolMessage::Message(StreamingMessage::MessageReceived {
                    message_id,
                    stream_position,
                    message_data,
                }) => {
                    message_count += 1;
                    info!("📨 Received message {}: {}", message_count, message_id);
                    info!("   Stream position: {}", stream_position);
                    info!("   Data size: {} bytes", message_data.len());

                    // Try to decode the message data as a string for display
                    if let Ok(content) = String::from_utf8(message_data) {
                        info!("   Content: {}", content);
                        println!("📨 Message {}: {}", message_count, content);
                    }
                }
                StreamProtocolMessage::Message(StreamingMessage::Heartbeat) => {
                    info!("💓 Received heartbeat from server");
                }
                StreamProtocolMessage::Message(StreamingMessage::BatchEnd) => {
                    info!("📦 Batch end received");
                }
                StreamProtocolMessage::Message(StreamingMessage::StreamEnd) => {
                    info!("🔚 Stream ended by server");
                    break;
                }
                StreamProtocolMessage::Message(StreamingMessage::StreamError(error)) => {
                    error!("❌ Stream error: {}", error);
                    return Err(anyhow::anyhow!("Stream error: {}", error));
                }
                _ => {
                    error!("❌ Unexpected message type in stream");
                }
            }
        }

        info!(
            "✅ Streaming completed, received {} messages",
            message_count
        );
        Ok(())
    }
}

/// Client builder for common relay client setup
pub struct RelayClientBuilder {
    server_addr: SocketAddr,
    server_public_key: String,
    private_key: Option<String>,
}

impl RelayClientBuilder {
    pub fn new(server_addr: SocketAddr, server_public_key: String) -> Self {
        Self {
            server_addr,
            server_public_key,
            private_key: None,
        }
    }

    pub fn with_private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub async fn build(self) -> Result<QuicTarpcClient> {
        // Load or generate client key
        let client_key = match self.private_key {
            Some(key_hex) => load_ed25519_key_from_hex(&key_hex)
                .context("Failed to load private key from hex")?,
            None => {
                let key = generate_ed25519_keypair();
                info!(
                    "🔑 Generated new client key: {}",
                    hex::encode(key.verifying_key().to_bytes())
                );
                key
            }
        };

        let expected_server_key = load_ed25519_public_key_from_hex(&self.server_public_key)
            .map_err(|e| anyhow::anyhow!("Failed to parse server public key: {}", e))?;

        let client =
            QuicTarpcClient::connect(self.server_addr, expected_server_key, client_key).await?;

        Ok(client)
    }
}
