// Remove unused clap imports since they're not needed in this file
use crate::challenge::perform_client_challenge_handshake;
use crate::error::{ClientError, Result};
use crate::{BlobService, MessagesService, MessagesStream};
use ml_dsa;
use quinn::Connection;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use zoe_wire_protocol::{
    KeyPair, TransportPrivateKey, TransportPublicKey, VerifyingKey,
    connection::client::create_client_endpoint, generate_keypair,
};

struct RelayClientInner {
    client_keypair_tls: TransportPrivateKey, // For TLS certificates (Ed25519 or ML-DSA-44)
    client_keypair_inner: KeyPair,           // For inner protocol
    connection: Connection,
}

/// A Zoe Relay Client
pub struct RelayClient {
    inner: Arc<RelayClientInner>,
}

impl RelayClient {
    pub async fn new_with_random_key(
        server_public_key: TransportPublicKey,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let inner_keypair = generate_keypair(&mut rand::thread_rng()); // ML-DSA-65 for inner protocol
        Self::new(inner_keypair, server_public_key, server_addr).await
    }

    pub async fn new(
        client_keypair_inner: KeyPair,         // For inner protocol
        server_public_key: TransportPublicKey, // TLS server key (Ed25519 or ML-DSA-44)
        server_addr: SocketAddr,
    ) -> Result<Self> {
        // Generate TLS keypair for certificates (default to Ed25519)
        let client_keypair_tls = TransportPrivateKey::default(); // Ed25519 by default
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
        let server_key = TransportPublicKey::from_ml_dsa_44(&server_public_key);
        Self::new(client_keypair_inner, server_key, server_addr).await
    }

    /// Connect to relay server with transport keys and return the connection
    pub async fn connect_with_transport_keys(
        client_keypair_tls: &TransportPrivateKey, // For TLS certificates (Ed25519 or ML-DSA-44)
        client_keypair_inner: &KeyPair,           // For inner protocol
        server_addr: SocketAddr,
        server_public_key: &TransportPublicKey,
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

        // Convert TransportPublicKey to VerifyingKey for challenge
        // TODO: move this to the wire protocol as an into impl
        let server_verifying_key = match server_public_key {
            TransportPublicKey::Ed25519 { verifying_key } => {
                VerifyingKey::Ed25519(Box::new(*verifying_key))
            }
            TransportPublicKey::MlDsa44 {
                verifying_key_bytes,
            } => {
                let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(
                    verifying_key_bytes.as_slice(),
                )
                .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 public key"))?;
                VerifyingKey::MlDsa44(Box::new(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(
                    &encoded,
                )))
            }
        };

        // Perform ML-DSA challenge-response handshake
        let (send, recv) = connection.accept_bi().await?;
        let Ok((verified_count, _)) = perform_client_challenge_handshake(
            send,
            recv,
            &server_verifying_key,
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
    pub fn tls_public_key(&self) -> TransportPublicKey {
        self.inner.client_keypair_tls.public_key()
    }
}
