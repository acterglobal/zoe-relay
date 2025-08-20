// Remove unused clap imports since they're not needed in this file
use crate::challenge::perform_client_ml_dsa_handshake;
use crate::error::{ClientError, Result};
use crate::{BlobService, MessagesService, MessagesStream};
use quinn::Connection;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use rustls::SignatureAlgorithm;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use zoe_wire_protocol::{
    AcceptSpecificServerCertVerifier, generate_deterministic_cert_from_ml_dsa_44_for_tls,
    generate_ml_dsa_44_keypair_for_tls, prelude::*,
};

struct RelayClientInner {
    client_keypair_tls: ml_dsa::KeyPair<ml_dsa::MlDsa44>, // For TLS certificates
    client_keypair_inner: ml_dsa::KeyPair<ml_dsa::MlDsa65>, // For inner protocol
    connection: Connection,
}

/// Custom certificate resolver that provides ML-DSA-44 certificates for client authentication
#[derive(Debug)]
struct MlDsaCertResolver {
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa44>,
}

impl MlDsaCertResolver {
    fn new(
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa44>,
    ) -> Self {
        Self {
            cert_chain,
            signing_key,
        }
    }
}

impl rustls::client::ResolvesClientCert for MlDsaCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        // Check if ML-DSA-44 is supported
        if sigschemes.contains(&rustls::SignatureScheme::ML_DSA_44) {
            // Create a signing key wrapper for ML-DSA-44
            let signer = Arc::new(MlDsaSigner::new(self.signing_key.clone()));

            Some(Arc::new(rustls::sign::CertifiedKey::new(
                self.cert_chain.clone(),
                signer,
            )))
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        !self.cert_chain.is_empty()
    }
}

/// Custom signer that implements rustls::sign::Signer for ML-DSA-44
#[derive(Debug)]
struct MlDsaSigner {
    signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa44>,
}

impl MlDsaSigner {
    fn new(signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa44>) -> Self {
        Self { signing_key }
    }
}

impl rustls::sign::Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
        use signature::Signer;

        let signature = self.signing_key.sign(message);
        Ok(signature.encode().to_vec())
    }

    fn scheme(&self) -> rustls::SignatureScheme {
        rustls::SignatureScheme::ML_DSA_44
    }
}

impl rustls::sign::SigningKey for MlDsaSigner {
    fn choose_scheme(
        &self,
        offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&rustls::SignatureScheme::ML_DSA_44) {
            Some(Box::new(MlDsaSigner::new(self.signing_key.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0x09) // ML-DSA-44 algorithm ID (truncated to fit u8)
    }
}
/// A Zoe Relay Client
pub struct RelayClient {
    inner: Arc<RelayClientInner>,
}

impl RelayClient {
    pub async fn new_with_random_key(
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        let inner_keypair = generate_keypair(&mut rand::thread_rng()); // ML-DSA-65 for inner protocol
        Self::new(inner_keypair, server_public_key, server_addr).await
    }

    pub async fn new(
        client_keypair_inner: ml_dsa::KeyPair<ml_dsa::MlDsa65>, // For inner protocol
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>, // TLS server key
        server_addr: SocketAddr,
    ) -> Result<Self> {
        // Generate TLS keypair for certificates
        let client_keypair_tls = generate_ml_dsa_44_keypair_for_tls();
        let connection = Self::connect_with_ml_dsa_keys(
            &client_keypair_tls,
            &client_keypair_inner,
            server_addr,
            server_public_key,
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
    pub async fn new_with_ml_dsa_keys(
        client_keypair_inner: ml_dsa::KeyPair<ml_dsa::MlDsa65>,
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        server_addr: SocketAddr,
    ) -> Result<Self> {
        Self::new(client_keypair_inner, server_public_key, server_addr).await
    }

    /// Connect to relay server with ML-DSA handshake and return the connection
    pub async fn connect_with_ml_dsa_keys(
        client_keypair_tls: &ml_dsa::KeyPair<ml_dsa::MlDsa44>, // For TLS certificates
        client_keypair_inner: &ml_dsa::KeyPair<ml_dsa::MlDsa65>, // For inner protocol
        server_addr: SocketAddr,
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
    ) -> Result<Connection> {
        info!("🚀 Starting relay client with ML-DSA-44 keys");
        info!(
            "🔑 Client TLS public key: {}",
            hex::encode(client_keypair_tls.verifying_key().encode())
        );
        info!(
            "🔑 Client inner public key: {}",
            hex::encode(client_keypair_inner.verifying_key().encode())
        );
        info!("🌐 Connecting to server: {}", server_addr);
        info!(
            "🔐 Server public key: {}",
            hex::encode(server_public_key.encode())
        );

        // Create client endpoint and establish QUIC connection
        let client_endpoint = Self::create_client_endpoint(client_keypair_tls, &server_public_key)?;
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        info!("✅ Connected to relay server");

        // Perform ML-DSA challenge-response handshake
        let (send, recv) = connection.open_bi().await?;
        let verified_count =
            perform_client_ml_dsa_handshake(send, recv, &[client_keypair_inner]).await?;

        info!(
            "🔐 ML-DSA handshake completed: {} out of {} keys verified",
            verified_count, 1
        );

        Ok(connection)
    }

    fn create_client_endpoint(
        client_key_pair: &ml_dsa::KeyPair<ml_dsa::MlDsa44>,
        server_public_key: &ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
    ) -> Result<Endpoint> {
        // Generate ML-DSA-44 keypair and certificate for client authentication
        let client_certs =
            generate_deterministic_cert_from_ml_dsa_44_for_tls(client_key_pair, "client")
                .map_err(|e| ClientError::Crypto(e.to_string()))?;

        // Create a custom cert resolver that provides our ML-DSA-44 certificate
        let cert_resolver = Arc::new(MlDsaCertResolver::new(
            client_certs,
            client_key_pair.signing_key().clone(),
        ));

        // Create custom certificate verifier that accepts our server
        let verifier = AcceptSpecificServerCertVerifier::new(server_public_key.clone());

        // Create client config with ML-DSA-44 certificate resolver
        let crypto = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_cert_resolver(cert_resolver);

        // we need to set the keep alive interval to 25 seconds, below the 30s timeout default so we keep the connection alive
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.keep_alive_interval(Some(Duration::from_secs(25)));

        let mut client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).map_err(|e| ClientError::Generic(e.to_string()))?,
        ));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())?;
        endpoint.set_default_client_config(client_config);

        Ok(endpoint)
    }

    pub async fn connect_message_service(&self) -> Result<(MessagesService, MessagesStream)> {
        MessagesService::connect(&self.inner.connection).await
    }

    pub async fn connect_blob_service(&self) -> Result<BlobService> {
        BlobService::connect(&self.inner.connection).await
    }

    /// Get the client's inner protocol public key (ML-DSA-65)
    pub fn public_key(&self) -> ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
        self.inner.client_keypair_inner.verifying_key().clone()
    }

    /// Get the client's inner protocol signing key (ML-DSA-65)
    pub fn signing_key(&self) -> &ml_dsa::SigningKey<ml_dsa::MlDsa65> {
        self.inner.client_keypair_inner.signing_key()
    }

    /// Get the client's TLS public key (ML-DSA-44)
    pub fn tls_public_key(&self) -> ml_dsa::VerifyingKey<ml_dsa::MlDsa44> {
        self.inner.client_keypair_tls.verifying_key().clone()
    }
}
