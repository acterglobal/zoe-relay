use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use tracing::info;

use crate::RelayClient;
use zoeyr_wire_protocol::{
    generate_ed25519_keypair, load_ed25519_key_from_hex, load_ed25519_public_key_from_hex,
    ServerWireMessage, StreamMessage,
};

/// Generic QUIC client with persistent bi-directional connection
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

    /// Create a persistent bi-directional connection with RPC client and stream message receiver
    /// Note: Temporarily disabled due to tarpc integration complexity
    /*
    pub async fn create_persistent_connection<R, T>(&self) -> Result<(
        client::NewClient<R, RoutingTransport<R, T, tarpc::serde_transport::Transport<tokio_util::codec::Framed<crate::QuicDuplexStream, tokio_util::codec::LengthDelimitedCodec>, ServerWireMessage<R, T>, ServerWireMessage<R, T>, PostcardCodec>>>,
        mpsc::UnboundedReceiver<StreamMessage<T>>,
    )>
    where
        R: serde::Serialize + for<'a> serde::Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin + std::fmt::Debug + 'static,
        T: serde::Serialize + for<'a> serde::Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin + std::fmt::Debug + 'static,
    {
        info!("🔗 Creating persistent bi-directional connection");

        // Get QUIC connection
        let connection = &self.relay_client.connection;

        // Open persistent bidirectional stream
        let (send, recv) = connection.open_bi().await?;

        // Create layered transport: QUIC -> framed -> postcard -> routing
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        let codec = LengthDelimitedCodec::new();
        let combined = crate::QuicDuplexStream::new(recv, send);
        let framed = Framed::new(combined, codec);
        let postcard_transport = tarpc::serde_transport::new(framed, PostcardCodec);

        // Create routing transport with channels
        let (routing_transport, stream_rx) = RoutingTransport::with_channels(postcard_transport);

        // Create tarpc client that works with the RPC type R
        let rpc_client = client::new(client::Config::default(), routing_transport);

        info!("✅ Persistent connection established");
        Ok((rpc_client, stream_rx))
    }

    /// Convenience method to create a connection and spawn a stream message handler
    pub async fn create_connection_with_stream_handler<R, T, F>(&self, mut stream_handler: F) -> Result<client::NewClient<R, RoutingTransport<R, T, tarpc::serde_transport::Transport<tokio_util::codec::Framed<crate::QuicDuplexStream, tokio_util::codec::LengthDelimitedCodec>, ServerWireMessage<R, T>, ServerWireMessage<R, T>, PostcardCodec>>>>
    where
        R: serde::Serialize + for<'a> serde::Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin + std::fmt::Debug + 'static,
        T: serde::Serialize + for<'a> serde::Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin + std::fmt::Debug + 'static,
        F: FnMut(StreamMessage<T>) -> Result<()> + Send + 'static,
    {
        let (rpc_client, mut stream_rx) = self.create_persistent_connection().await?;

        // Spawn task to handle incoming stream messages
        tokio::spawn(async move {
            info!("📨 Stream message handler started");
            while let Some(stream_msg) = stream_rx.recv().await {
                info!("📨 Received stream message: {:?}", stream_msg);
                if let Err(e) = stream_handler(stream_msg) {
                    error!("❌ Stream handler error: {}", e);
                }
            }
            info!("📨 Stream message handler ended");
        });

        Ok(rpc_client)
    }
    */

    /// Send a raw ServerWireMessage directly (for lower-level usage)
    pub async fn send_wire_message<R, T>(&self, message: ServerWireMessage<R, T>) -> Result<()>
    where
        R: serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + Clone
            + PartialEq
            + Send
            + Sync
            + Unpin
            + std::fmt::Debug,
        T: serde::Serialize
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
    pub async fn send_stream_message<T>(&self, message: StreamMessage<T>) -> Result<()>
    where
        T: serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + Clone
            + PartialEq
            + Send
            + Sync
            + Unpin
            + std::fmt::Debug,
    {
        let wire_message: ServerWireMessage<(), T> = ServerWireMessage::Stream(message);
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
        let wire_message: ServerWireMessage<R, ()> = ServerWireMessage::Rpc(message);
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
