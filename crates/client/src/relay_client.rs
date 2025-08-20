// Remove unused clap imports since they're not needed in this file
use crate::challenge::perform_client_ml_dsa_handshake;
use crate::error::{ClientError, Result};
use crate::{BlobService, MessagesService, MessagesStream};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ml_dsa;
use quinn::Connection;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rustls::ClientConfig as RustlsClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use zoe_wire_protocol::{
    AcceptSpecificEd25519ServerCertVerifier, KeyPair, TransportPrivateKey, TransportPublicKey,
    VerifyingKey, generate_ed25519_cert_for_tls, generate_keypair,
};

// ML-DSA-44 imports (only available with tls-ml-dsa-44 feature)
#[cfg(feature = "tls-ml-dsa-44")]
use rustls::SignatureAlgorithm;
#[cfg(feature = "tls-ml-dsa-44")]
use zoe_wire_protocol::{
    AcceptSpecificServerCertVerifier, generate_deterministic_cert_from_ml_dsa_44_for_tls,
    generate_ml_dsa_44_keypair_for_tls, ml_dsa_44_crypto_provider,
};

struct RelayClientInner {
    client_keypair_tls: TransportPrivateKey, // For TLS certificates (Ed25519 or ML-DSA-44)
    client_keypair_inner: KeyPair,           // For inner protocol
    connection: Connection,
}

/// Custom certificate resolver that provides transport certificates for client authentication
#[derive(Debug)]
struct TransportCertResolver {
    cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    transport_key: TransportPrivateKey,
}

impl TransportCertResolver {
    fn new(
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        transport_key: TransportPrivateKey,
    ) -> Self {
        Self {
            cert_chain,
            transport_key,
        }
    }
}

impl rustls::client::ResolvesClientCert for TransportCertResolver {
    fn resolve(
        &self,
        _acceptable_issuers: &[&[u8]],
        sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        match &self.transport_key {
            TransportPrivateKey::Ed25519 { signing_key } => {
                // Check if Ed25519 is supported
                if sigschemes.contains(&rustls::SignatureScheme::ED25519) {
                    // Use rustls built-in Ed25519 support
                    if let Ok(private_key_der) = signing_key.to_pkcs8_der() {
                        let private_key = rustls::pki_types::PrivateKeyDer::from(
                            rustls::pki_types::PrivatePkcs8KeyDer::from(
                                private_key_der.as_bytes().to_vec(),
                            ),
                        );

                        if let Ok(signer) =
                            rustls::crypto::aws_lc_rs::sign::any_supported_type(&private_key)
                        {
                            return Some(Arc::new(rustls::sign::CertifiedKey::new(
                                self.cert_chain.clone(),
                                signer,
                            )));
                        }
                    }
                }
                None
            }

            #[cfg(feature = "tls-ml-dsa-44")]
            TransportPrivateKey::MlDsa44 { keypair } => {
                // Check if ML-DSA-44 is supported
                if sigschemes.contains(&rustls::SignatureScheme::ML_DSA_44) {
                    // Create a signing key wrapper for ML-DSA-44
                    let signer = Arc::new(MlDsaSigner::new(keypair.signing_key().clone()));

                    Some(Arc::new(rustls::sign::CertifiedKey::new(
                        self.cert_chain.clone(),
                        signer,
                    )))
                } else {
                    None
                }
            }
        }
    }

    fn has_certs(&self) -> bool {
        !self.cert_chain.is_empty()
    }
}

/// Custom ML-DSA-44 signer for rustls (only available with tls-ml-dsa-44 feature)
#[cfg(feature = "tls-ml-dsa-44")]
#[derive(Debug)]
struct MlDsaSigner {
    signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa44>,
}

#[cfg(feature = "tls-ml-dsa-44")]
impl MlDsaSigner {
    fn new(signing_key: ml_dsa::SigningKey<ml_dsa::MlDsa44>) -> Self {
        Self { signing_key }
    }
}

#[cfg(feature = "tls-ml-dsa-44")]
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

#[cfg(feature = "tls-ml-dsa-44")]
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
        let client_endpoint = Self::create_client_endpoint(client_keypair_tls, server_public_key)?;
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;

        info!("✅ Connected to relay server");

        // Convert TransportPublicKey to VerifyingKey for challenge
        let server_verifying_key = match server_public_key {
            TransportPublicKey::Ed25519 { verifying_key } => VerifyingKey::Ed25519(*verifying_key),
            TransportPublicKey::MlDsa44 {
                verifying_key_bytes,
            } => {
                let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(
                    verifying_key_bytes.as_slice(),
                )
                .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 public key"))?;
                VerifyingKey::MlDsa44(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded))
            }
        };

        // Perform ML-DSA challenge-response handshake
        let (send, recv) = connection.open_bi().await?;
        let Ok(verified_count) = perform_client_ml_dsa_handshake(
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

    fn create_client_endpoint(
        client_key_pair: &TransportPrivateKey,
        server_public_key: &TransportPublicKey,
    ) -> Result<Endpoint> {
        let (_client_certs, cert_resolver, verifier, crypto_provider) =
            match (client_key_pair, server_public_key) {
                (
                    TransportPrivateKey::Ed25519 { signing_key },
                    TransportPublicKey::Ed25519 { verifying_key },
                ) => {
                    // Generate Ed25519 certificate for client authentication
                    let client_certs = generate_ed25519_cert_for_tls(signing_key, "client")
                        .map_err(|e| ClientError::Crypto(e.to_string()))?;

                    // Create a custom cert resolver that provides our Ed25519 certificate
                    let cert_resolver = Arc::new(TransportCertResolver::new(
                        client_certs.clone(),
                        client_key_pair.clone(),
                    ));

                    // Create custom certificate verifier that accepts our server
                    let verifier = AcceptSpecificEd25519ServerCertVerifier::new(*verifying_key);

                    // Use default crypto provider (supports Ed25519)
                    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

                    (
                        client_certs,
                        cert_resolver,
                        Arc::new(verifier) as Arc<dyn rustls::client::danger::ServerCertVerifier>,
                        crypto_provider,
                    )
                }

                #[cfg(feature = "tls-ml-dsa-44")]
                (
                    TransportPrivateKey::MlDsa44 { keypair },
                    TransportPublicKey::MlDsa44 {
                        verifying_key_bytes,
                    },
                ) => {
                    // Generate ML-DSA-44 certificate for client authentication
                    let client_certs =
                        generate_deterministic_cert_from_ml_dsa_44_for_tls(keypair, "client")
                            .map_err(|e| ClientError::Crypto(e.to_string()))?;

                    // Create a custom cert resolver that provides our ML-DSA-44 certificate
                    let cert_resolver = Arc::new(TransportCertResolver::new(
                        client_certs.clone(),
                        client_key_pair.clone(),
                    ));

                    // Reconstruct ML-DSA-44 verifying key for verifier
                    let encoded_key: &ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa44> =
                        verifying_key_bytes.as_slice().try_into().map_err(|_| {
                            ClientError::Crypto("Invalid ML-DSA-44 server key".to_string())
                        })?;
                    let ml_dsa_verifying_key =
                        ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(encoded_key);

                    // Create custom certificate verifier that accepts our server
                    let verifier = AcceptSpecificServerCertVerifier::new(ml_dsa_verifying_key);

                    // Use ML-DSA-44 crypto provider
                    let crypto_provider = Arc::new(ml_dsa_44_crypto_provider());

                    (
                        client_certs,
                        cert_resolver,
                        Arc::new(verifier) as Arc<dyn rustls::client::danger::ServerCertVerifier>,
                        crypto_provider,
                    )
                }

                _ => {
                    return Err(ClientError::Crypto(
                        "Mismatched client and server key types".to_string(),
                    ));
                }
            };

        // Create client config with certificate resolver using the appropriate crypto provider
        let crypto = RustlsClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| ClientError::Generic(format!("Failed to set TLS version: {}", e)))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
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
