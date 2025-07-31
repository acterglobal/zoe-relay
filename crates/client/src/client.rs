// Remove unused clap imports since they're not needed in this file
use crate::error::{ClientError, Result};
use crate::{MessagesService, MessagesStream, BlobService};
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::Connection;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rand::rngs::OsRng;
use rustls::ClientConfig as RustlsClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use zoe_wire_protocol::{
    AcceptSpecificServerCertVerifier, generate_deterministic_cert_from_ed25519,
};

struct RelayClientInner {
    client_key: SigningKey,
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
        Self::new(
            SigningKey::generate(&mut OsRng),
            server_public_key,
            server_addr,
        )
        .await
    }

    pub async fn new(
        key: SigningKey,
        server_public_key: VerifyingKey,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let connection = Self::connect(&key, server_addr, server_public_key).await?;
        Ok(Self {
            inner: Arc::new(RelayClientInner {
                client_key: key,
                connection,
            }),
        })
    }

    /// Connect to relay server and return the connection
    pub async fn connect(
        client_key: &SigningKey,
        server_addr: SocketAddr,
        server_public_key: VerifyingKey,
    ) -> Result<Connection> {
        info!("🚀 Starting message client");
        info!(
            "🔑 Client public key: {}",
            hex::encode(client_key.verifying_key().to_bytes())
        );
        info!("🌐 Connecting to server: {}", server_addr);
        info!(
            "🔐 Server public key: {}",
            hex::encode(server_public_key.to_bytes())
        );

        // Create client endpoint
        let client_endpoint = Self::create_client_endpoint(client_key, &server_public_key)?;

        // Connect to server
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        info!("✅ Connected to relay server");
        Ok(connection)
    }

    fn create_client_endpoint(
        client_key: &SigningKey,
        server_public_key: &VerifyingKey,
    ) -> Result<Endpoint> {
        // Generate client certificate for mutual TLS
        let (client_certs, client_key) =
            generate_deterministic_cert_from_ed25519(client_key, "client")
                .map_err(|e| ClientError::Crypto(e.to_string()))?;

        // Create custom certificate verifier that accepts our server
        let verifier = AcceptSpecificServerCertVerifier::new(*server_public_key);

        // Create client config with client certificate for mutual TLS
        let crypto = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(client_certs, client_key)?;

        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).map_err(|e| ClientError::Generic(e.to_string()))?,
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(endpoint)
    }

    pub async fn connect_message_service(&self) -> Result<(MessagesService, MessagesStream)> {
        MessagesService::connect(&self.inner.connection).await
    }

    pub async fn connect_blob_service(&self) -> Result<BlobService> {
        BlobService::connect(&self.inner.connection).await
    }

    /// Get the client's public key
    pub fn public_key(&self) -> VerifyingKey {
        self.inner.client_key.verifying_key()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.inner.client_key
    }
}
