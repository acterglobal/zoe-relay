// Remove unused clap imports since they're not needed in this file
use crate::challenge::perform_client_challenge_handshake;
use crate::error::{ClientError, Result};
use crate::{BlobService, MessagesService, MessagesStream};
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use zoe_wire_protocol::{KeyPair, VerifyingKey, connection::client::create_client_endpoint};

struct RelayClientInner {
    client_keypair_tls: KeyPair, // For TLS certificates (Ed25519 or ML-DSA-44)
    client_keypair_inner: KeyPair, // For inner protocol
    connection: Connection,
}

/// A Zoe Relay Client
pub struct RelayClient {
    inner: Arc<RelayClientInner>,
}

impl RelayClient {
    pub async fn new_with_random_key(
        server_public_key: VerifyingKey,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let inner_keypair = KeyPair::generate(&mut rand::thread_rng()); // ML-DSA-65 for inner protocol
        Self::new(inner_keypair, server_public_key, server_addr).await
    }

    pub async fn new(
        client_keypair_inner: KeyPair,   // For inner protocol
        server_public_key: VerifyingKey, // TLS server key (Ed25519 or ML-DSA-44)
        server_addr: SocketAddr,
    ) -> Result<Self> {
        // Generate TLS keypair for certificates (default to Ed25519)
        let client_keypair_tls = KeyPair::generate_ed25519(&mut rand::thread_rng()); // Ed25519 by default
        let connection = Self::connect_with_transport_keys(
            &client_keypair_tls,
            &client_keypair_inner,
            server_addr,
            &server_public_key,
        )
        .await?;
        Ok(Self {
            inner: Arc::new(RelayClientInner {
                client_keypair_tls,
                client_keypair_inner,
                connection,
            }),
        })
    }

    /// Create a new relay client with ML-DSA key support (deprecated - use new() instead)
    #[cfg(feature = "tls-ml-dsa-44")]
    pub async fn new_with_ml_dsa_keys(
        client_keypair_inner: ml_dsa::KeyPair<ml_dsa::MlDsa65>,
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let server_key = VerifyingKey::from(server_public_key);
        Self::new(client_keypair_inner, server_key, server_addr).await
    }

    /// Connect to relay server with transport keys and return the connection
    pub async fn connect_with_transport_keys(
        client_keypair_tls: &KeyPair, // For TLS certificates (Ed25519 or ML-DSA-44)
        client_keypair_inner: &KeyPair, // For inner protocol
        server_addr: SocketAddr,
        server_public_key: &VerifyingKey,
    ) -> Result<Connection> {
        info!("🚀 Starting relay client with transport keys");
        info!(
            "🔑 Client TLS key: {} ({})",
            client_keypair_tls.public_key(),
            client_keypair_tls.algorithm()
        );
        info!(
            "🔑 Client inner public key: {}",
            hex::encode(client_keypair_inner.public_key().encode())
        );
        info!("🌐 Connecting to server: {}", server_addr);
        info!(
            "🔐 Server public key: {} ({})",
            server_public_key,
            server_public_key.algorithm()
        );

        // Create client endpoint and establish QUIC connection
        let client_endpoint = create_client_endpoint(server_public_key)?;
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;

        // Validate that the server supports our protocol
        let client_protocol_config = zoe_wire_protocol::version::ClientProtocolConfig::default();
        match zoe_wire_protocol::version::validate_server_protocol_support(
            &connection,
            &client_protocol_config,
        ) {
            Ok(negotiated_version) => {
                info!(
                    "✅ Connected to relay server with protocol: {}",
                    negotiated_version
                );
            }
            Err(e) => {
                return Err(ClientError::ProtocolError(format!(
                    "Server protocol validation failed: {}",
                    e
                )));
            }
        }

        // No conversion needed - server_public_key is already a VerifyingKey

        // Perform ML-DSA challenge-response handshake
        let (send, recv) = connection.accept_bi().await?;
        let Ok((verified_count, _)) = perform_client_challenge_handshake(
            send,
            recv,
            server_public_key,
            &[client_keypair_inner],
        )
        .await
        else {
            connection.close(0u32.into(), b"ML-DSA handshake failed");
            return Err(anyhow::anyhow!("ML-DSA handshake failed").into());
        };

        info!(
            "🔐 ML-DSA handshake completed: {} out of {} keys verified",
            verified_count, 1
        );

        Ok(connection)
    }

    pub async fn connect_message_service(&self) -> Result<(MessagesService, MessagesStream)> {
        MessagesService::connect(&self.inner.connection).await
    }

    pub async fn connect_blob_service(&self) -> Result<BlobService> {
        BlobService::connect(&self.inner.connection).await
    }

    /// Get the client's inner protocol public key
    pub fn public_key(&self) -> VerifyingKey {
        self.inner.client_keypair_inner.public_key()
    }

    /// Get the client's inner protocol keypair
    pub fn keypair(&self) -> &KeyPair {
        &self.inner.client_keypair_inner
    }

    /// Get the client's TLS public key (Ed25519 or ML-DSA-44)
    pub fn tls_public_key(&self) -> VerifyingKey {
        self.inner.client_keypair_tls.public_key()
    }
}
