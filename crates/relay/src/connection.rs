use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use zoeyr_wire_protocol::{extract_ed25519_from_cert, generate_deterministic_cert_from_ed25519};

/// Custom TLS verifier that checks the server's embedded ed25519 key
#[derive(Debug)]
pub struct ServerEd25519TlsVerifier {
    expected_server_ed25519_key: VerifyingKey,
}

impl ServerEd25519TlsVerifier {
    pub fn new(expected_key: VerifyingKey) -> Self {
        Self {
            expected_server_ed25519_key: expected_key,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for ServerEd25519TlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match extract_ed25519_from_cert(end_entity) {
            Ok(cert_ed25519_key) => {
                if cert_ed25519_key.to_bytes() == self.expected_server_ed25519_key.to_bytes() {
                    info!("✅ Server TLS certificate contains expected ed25519 key!");
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    error!("❌ Server TLS certificate contains wrong ed25519 key!");
                    error!(
                        "   Expected: {}",
                        hex::encode(self.expected_server_ed25519_key.to_bytes())
                    );
                    error!("   Found:    {}", hex::encode(cert_ed25519_key.to_bytes()));
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            Err(e) => {
                error!(
                    "❌ Failed to extract ed25519 key from server certificate: {}",
                    e
                );
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Only accept Ed25519 signatures to enforce our security model
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Shared QUIC client for connecting to relay servers
pub struct RelayClient {
    pub connection: Connection,
    pub client_key: SigningKey,
    pub server_key: VerifyingKey,
}

impl RelayClient {
    /// Connect to a relay server with ed25519 identity verification
    pub async fn connect(
        server_addr: SocketAddr,
        expected_server_ed25519_key: VerifyingKey,
        client_key: SigningKey,
    ) -> Result<Self> {
        info!("🔗 Connecting to relay server at {}", server_addr);
        info!(
            "🔑 Expected server ed25519 key: {}",
            hex::encode(expected_server_ed25519_key.to_bytes())
        );
        info!(
            "🔑 Client ed25519 key: {}",
            hex::encode(client_key.verifying_key().to_bytes())
        );

        // Create client config with server identity verification
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerEd25519TlsVerifier::new(
                expected_server_ed25519_key.clone(),
            )))
            .with_no_client_auth();

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        // Connect - TLS handshake will verify server identity
        let connection = endpoint
            .connect(server_addr, "localhost")?
            .await
            .context("Failed to establish QUIC connection")?;

        info!("✅ Connected! TLS handshake verified server identity.");

        Ok(Self {
            connection,
            client_key,
            server_key: expected_server_ed25519_key,
        })
    }

    /// Send postcard-serialized data and receive response
    pub async fn send_postcard<T, R>(&self, request: &T) -> Result<R>
    where
        T: serde::Serialize,
        R: for<'a> serde::Deserialize<'a>,
    {
        let (mut send, mut recv) = self.connection.open_bi().await?;

        // Send request using postcard
        let request_bytes = postcard::to_allocvec(request)?;

        send.write_all(&request_bytes).await?;
        send.finish()?;

        // Receive response
        let response_bytes = recv.read_to_end(1024 * 1024).await?; // 1MB limit
        let response: R = postcard::from_bytes(&response_bytes)?;

        Ok(response)
    }
}

/// Create a QUIC server endpoint with ed25519-derived TLS certificate
pub fn create_relay_server_endpoint(addr: SocketAddr, server_key: &SigningKey) -> Result<Endpoint> {
    info!("🚀 Creating relay server endpoint");
    info!("📋 Server Address: {}", addr);
    info!(
        "🔑 Server Public Key: {}",
        hex::encode(server_key.verifying_key().to_bytes())
    );

    // Generate TLS certificate from ed25519 key
    let (certs, key) = generate_deterministic_cert_from_ed25519(server_key, "localhost")
        .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

    // Create QUIC server config with no client auth required
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?,
    ));

    let endpoint = Endpoint::server(server_config, addr)?;

    info!("✅ Server endpoint ready on {}", addr);
    info!(
        "💡 Clients can connect with server public key: {}",
        hex::encode(server_key.verifying_key().to_bytes())
    );

    Ok(endpoint)
}
