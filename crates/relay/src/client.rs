use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use tarpc::{client, serde_transport};
use tracing::info;
// Removed unused compat imports

use crate::RelayClient;
use zoeyr_wire_protocol::{
    generate_ed25519_keypair, load_ed25519_key_from_hex, load_ed25519_public_key_from_hex,
    RelayServiceClient,
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
