use crate::crypto::{CryptoError, Result};
use crate::version::ClientProtocolConfig;
use crate::TransportPublicKey;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
use rustls::ClientConfig as RustlsClientConfig;
use std::sync::Arc;
use std::time::Duration;

mod ed25519 {
    use rustls::pki_types::CertificateDer;
    #[derive(Debug)]
    pub(super) struct AcceptSpecificEd25519ServerCertVerifier {
        expected_server_key_ed25519: ed25519_dalek::VerifyingKey,
    }

    impl AcceptSpecificEd25519ServerCertVerifier {
        pub(super) fn new(expected_server_key_ed25519: ed25519_dalek::VerifyingKey) -> Self {
            Self {
                expected_server_key_ed25519,
            }
        }
    }

    impl rustls::client::danger::ServerCertVerifier for AcceptSpecificEd25519ServerCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer,
            _intermediates: &[CertificateDer],
            _server_name: &rustls::pki_types::ServerName,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            // Extract Ed25519 key from certificate
            match super::super::ed25519::extract_ed25519_public_key_from_cert(end_entity) {
                Ok(server_ed25519_key) => {
                    let extracted_key_hex = hex::encode(server_ed25519_key.to_bytes());
                    let expected_key_hex = hex::encode(self.expected_server_key_ed25519.to_bytes());

                    tracing::debug!("🔍 Extracted server key: {}", extracted_key_hex);
                    tracing::debug!("🔍 Expected server key:  {}", expected_key_hex);

                    // Verify it matches our expected key
                    if server_ed25519_key.to_bytes() == self.expected_server_key_ed25519.to_bytes()
                    {
                        tracing::info!("✅ Server Ed25519 identity verified via certificate");
                        Ok(rustls::client::danger::ServerCertVerified::assertion())
                    } else {
                        tracing::error!("❌ Server Ed25519 key mismatch");
                        tracing::error!("   Extracted: {}", extracted_key_hex);
                        tracing::error!("   Expected:  {}", expected_key_hex);
                        Err(rustls::Error::InvalidCertificate(
                            rustls::CertificateError::ApplicationVerificationFailure,
                        ))
                    }
                }
                Err(e) => {
                    tracing::error!("❌ Failed to extract Ed25519 key from certificate: {}", e);
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
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            // We only support TLS 1.3
            Err(rustls::Error::UnsupportedNameType)
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            // Accept any TLS 1.3 signature - we verify identity via the embedded Ed25519 key
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![rustls::SignatureScheme::ED25519]
        }
    }
}

pub fn create_client_endpoint(server_public_key: &TransportPublicKey) -> Result<Endpoint> {
    create_client_endpoint_with_protocols(server_public_key, &ClientProtocolConfig::default())
}

pub fn create_client_endpoint_with_protocols(
    server_public_key: &TransportPublicKey,
    protocol_versions: &ClientProtocolConfig,
) -> Result<Endpoint> {
    let cert_verifier = match server_public_key {
        TransportPublicKey::Ed25519 { verifying_key } => {
            ed25519::AcceptSpecificEd25519ServerCertVerifier::new(*verifying_key)
        }
        #[cfg(feature = "tls-ml-dsa-44")]
        TransportPublicKey::MlDsa44 {
            verifying_key_bytes,
        } => AcceptSpecificServerCertVerifier::new(
            ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(verifying_key_bytes),
        ),
        _ => {
            return Err(CryptoError::TlsError(
                "Server cerficiate type not supported".to_string(),
            ));
        }
    };

    // Create client config with certificate resolver using the appropriate crypto provider
    let mut crypto = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(cert_verifier))
        .with_no_client_auth();

    // Set ALPN protocols for version negotiation
    let alpn_protocols = protocol_versions.alpn_protocols();
    crypto.alpn_protocols = alpn_protocols;

    // we need to set the keep alive interval to 25 seconds, below the 30s timeout default so we keep the connection alive
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(Duration::from_secs(25)));

    let mut client_config = ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)
            .map_err(|e| CryptoError::TlsError(format!("Failed to create client config: {e}")))?,
    ));
    client_config.transport_config(Arc::new(transport_config));

    let mut endpoint = Endpoint::client((std::net::Ipv6Addr::UNSPECIFIED, 0).into())
        .map_err(|e| CryptoError::TlsError(format!("Failed to create endpoint: {e}")))?;
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}
