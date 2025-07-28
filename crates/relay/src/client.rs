use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use std::net::SocketAddr;
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, info};

use crate::{QuicDuplexStream, RelayClient};
use zoeyr_wire_protocol::{
    generate_ed25519_keypair, load_ed25519_key_from_hex, load_ed25519_public_key_from_hex,
    ServerWireMessage, StreamMessage,
};

/// Generic QUIC client with separated RPC and streaming capabilities
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

    /// Create a QUIC stream that can be used for tarpc RPC
    pub async fn create_rpc_stream(&self) -> Result<QuicDuplexStream> {
        info!("🔗 Creating RPC stream");

        // Get QUIC connection
        let connection = &self.relay_client.connection;

        // Open bidirectional stream for RPC
        let (send, recv) = connection.open_bi().await?;

        // Create duplex stream
        let stream = QuicDuplexStream::new(recv, send);

        info!("✅ RPC stream established");
        Ok(stream)
    }

    /// Create a streaming receiver for server messages
    pub async fn create_stream_receiver<T>(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<StreamMessage>> {
        info!("🔗 Creating stream receiver connection");

        // Get QUIC connection
        let connection = &self.relay_client.connection;

        // Open bidirectional stream for streaming
        let (send, recv) = connection.open_bi().await?;

        // Create transport stack for streaming
        let codec = LengthDelimitedCodec::new();
        let combined = QuicDuplexStream::new(recv, send);
        let mut framed = Framed::new(combined, codec);

        // Create channel for stream messages
        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn task to handle incoming stream messages
        tokio::spawn(async move {
            while let Some(item) = framed.next().await {
                match item {
                    Ok(bytes) => {
                        // Deserialize the message
                        match postcard::from_bytes::<ServerWireMessage<()>>(&bytes) {
                            Ok(ServerWireMessage::Stream(stream_msg)) => {
                                if let Err(e) = tx.send(stream_msg) {
                                    error!("Failed to send stream message: {}", e);
                                    break;
                                }
                            }
                            Ok(ServerWireMessage::Rpc(_)) => {
                                // Ignore RPC messages on stream channel
                            }
                            Err(e) => {
                                error!("Failed to deserialize message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Stream error: {}", e);
                        break;
                    }
                }
            }
        });

        info!("✅ Stream receiver connection established");
        Ok(rx)
    }

    /// Send a raw ServerWireMessage directly (for lower-level usage)
    pub async fn send_wire_message<R>(&self, message: ServerWireMessage<R>) -> Result<()>
    where
        R: serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + Clone
            + PartialEq
            + Send
            + Sync
            + Unpin
            + std::fmt::Debug,
    {
        info!("📤 Sending wire message directly");

        // Get QUIC connection
        let connection = &self.relay_client.connection;

        // Open bidirectional stream
        let (mut send, _recv) = connection.open_bi().await?;

        // Serialize and send the message
        let bytes = postcard::to_allocvec(&message)
            .map_err(|e| anyhow::anyhow!("Failed to serialize wire message: {}", e))?;

        send.write_all(&bytes).await?;
        send.finish()?;

        info!("✅ Wire message sent successfully");
        Ok(())
    }

    /// Send a stream message directly (wraps in ServerWireMessage::Stream)
    pub async fn send_stream_message(&self, message: StreamMessage) -> Result<()> {
        let wire_message: ServerWireMessage<()> = ServerWireMessage::Stream(message);
        self.send_wire_message(wire_message).await
    }

    /// Send an RPC message directly (wraps in ServerWireMessage::Rpc)
    pub async fn send_rpc_message<R>(&self, message: R) -> Result<()>
    where
        R: serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + Clone
            + PartialEq
            + Send
            + Sync
            + Unpin
            + std::fmt::Debug,
    {
        let wire_message: ServerWireMessage<R> = ServerWireMessage::Rpc(message);
        self.send_wire_message(wire_message).await
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
