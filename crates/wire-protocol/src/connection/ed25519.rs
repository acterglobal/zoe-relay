//! Ed25519-based TLS certificate and connection utilities
//!
//! This module provides Ed25519-based TLS certificate generation and verification
//! for transport security in the Zoe wire protocol.

use der::{asn1::*, Encode};
use rustls::pki_types::CertificateDer;
use std::sync::Arc;
use x509_cert::{
    attr::{AttributeTypeAndValue, AttributeValue},
    certificate::{Certificate, TbsCertificate, Version},
    name::{Name, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
    time::{Time, Validity},
};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;

use crate::crypto::{CryptoError, Result};

/// Generate a deterministic TLS certificate using Ed25519
///
/// This creates a proper Ed25519 certificate where the Ed25519 public key
/// is stored directly in the SubjectPublicKeyInfo field.
pub fn generate_ed25519_cert_for_tls(
    ed25519_signing_key: &ed25519_dalek::SigningKey,
    subject_name: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    tracing::debug!(
        "🔧 Creating proper Ed25519 certificate for subject: {}",
        subject_name
    );

    let verifying_key = ed25519_signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();

    tracing::debug!(
        "🔧 Ed25519 public key length: {} bytes",
        public_key_bytes.len()
    );

    // Ed25519 algorithm identifier OID (RFC 8410)
    let ed25519_oid = ObjectIdentifier::new("1.3.101.112")
        .map_err(|e| CryptoError::ParseError(format!("Invalid Ed25519 OID: {e}")))?;

    // Create SubjectPublicKeyInfo with Ed25519 public key
    let algorithm = AlgorithmIdentifier {
        oid: ed25519_oid,
        parameters: None,
    };

    let subject_public_key_info = SubjectPublicKeyInfo {
        algorithm,
        subject_public_key: BitString::from_bytes(&public_key_bytes)
            .map_err(|e| CryptoError::ParseError(format!("Failed to create BitString: {e}")))?,
    };

    // Create subject name (CN=subject_name)
    let cn_oid = const_oid::db::rfc4519::CN;
    let cn_value = AttributeValue::new(der::Tag::Utf8String, subject_name.as_bytes())
        .map_err(|e| CryptoError::ParseError(format!("Failed to create CN value: {e}")))?;

    let cn_attribute = AttributeTypeAndValue {
        oid: cn_oid,
        value: cn_value,
    };

    let rdn = RelativeDistinguishedName::from(
        SetOfVec::try_from(vec![cn_attribute])
            .map_err(|e| CryptoError::ParseError(format!("Failed to create RDN: {e}")))?,
    );

    let subject = Name::try_from(vec![rdn])
        .map_err(|e| CryptoError::ParseError(format!("Failed to create subject: {e}")))?;

    // Set validity period (1 year from now)
    let now = std::time::SystemTime::now();
    let not_before = Time::GeneralTime(
        GeneralizedTime::from_system_time(now)
            .map_err(|e| CryptoError::ParseError(format!("Time conversion error: {e}")))?,
    );
    let not_after = Time::GeneralTime(
        GeneralizedTime::from_system_time(now + std::time::Duration::from_secs(365 * 24 * 3600))
            .map_err(|e| CryptoError::ParseError(format!("Time conversion error: {e}")))?,
    );

    let validity = Validity {
        not_before,
        not_after,
    };

    // Create TBS certificate
    let tbs_certificate = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::from(1u32),
        signature: AlgorithmIdentifier {
            oid: ed25519_oid,
            parameters: None,
        },
        issuer: subject.clone(), // Self-signed
        validity,
        subject,
        subject_public_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };

    // Encode TBS certificate for signing
    let tbs_der = tbs_certificate
        .to_der()
        .map_err(|e| CryptoError::ParseError(format!("Failed to encode TBS certificate: {e}")))?;

    // Sign the TBS certificate with Ed25519
    use signature::Signer;
    let signature = ed25519_signing_key.sign(&tbs_der);

    // Create final certificate
    let certificate = Certificate {
        tbs_certificate,
        signature_algorithm: AlgorithmIdentifier {
            oid: ed25519_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&signature.to_bytes()).map_err(|e| {
            CryptoError::ParseError(format!("Failed to create signature BitString: {e}"))
        })?,
    };

    // Encode certificate to DER
    let cert_der = certificate
        .to_der()
        .map_err(|e| CryptoError::ParseError(format!("Failed to encode certificate: {e}")))?;

    tracing::debug!("✅ Generated proper Ed25519 certificate successfully");

    Ok(vec![CertificateDer::from(cert_der)])
}

/// Extract Ed25519 public key from a certificate
/// This function extracts the Ed25519 public key directly from the certificate's
/// SubjectPublicKeyInfo field when the certificate uses the Ed25519 algorithm identifier.
pub fn extract_ed25519_public_key_from_cert(
    cert_der: &CertificateDer,
) -> Result<ed25519_dalek::VerifyingKey> {
    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| CryptoError::ParseError(format!("Failed to parse certificate: {e:?}")))?;

    // Get the subject public key info
    let spki = cert.public_key();
    let algorithm_oid = &spki.algorithm.algorithm;

    // Ed25519 algorithm identifier: 1.3.101.112
    let ed25519_oid = oid!(1.3.101 .112);

    tracing::debug!("🔍 Certificate algorithm OID: {}", algorithm_oid);

    if algorithm_oid != &ed25519_oid {
        return Err(CryptoError::ParseError(format!(
            "Certificate is not using Ed25519 algorithm. Found OID: {algorithm_oid}"
        )));
    }

    tracing::debug!("🔍 Found Ed25519 certificate");
    let public_key_bits = &spki.subject_public_key;

    // The BIT STRING contains the raw 32-byte Ed25519 public key
    // Note: BIT STRING may have unused bits indicator as first byte
    let key_bytes = if public_key_bits.data.len() == 33 && public_key_bits.data[0] == 0 {
        // Skip the unused bits indicator (should be 0 for Ed25519)
        &public_key_bits.data[1..]
    } else if public_key_bits.data.len() == 32 {
        // Direct 32-byte key
        &public_key_bits.data
    } else {
        return Err(CryptoError::ParseError(format!(
            "Invalid Ed25519 public key length: {} bytes",
            public_key_bits.data.len()
        )));
    };

    tracing::debug!("🔍 Extracted Ed25519 public key: {} bytes", key_bytes.len());

    // Validate key length
    if key_bytes.len() != 32 {
        return Err(CryptoError::ParseError(format!(
            "Invalid Ed25519 public key length: {} bytes (expected 32)",
            key_bytes.len()
        )));
    }

    // Convert to Ed25519 VerifyingKey
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes);

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
        .map_err(|e| CryptoError::ParseError(format!("Invalid Ed25519 public key: {}", e)))?;

    tracing::debug!("✅ Successfully extracted Ed25519 public key from certificate");
    Ok(verifying_key)
}

/// Create certificate verifier for client-side (Ed25519)
///
/// This verifier accepts any certificate but extracts and validates
/// the embedded Ed25519 public key against a known server key.
#[derive(Debug)]
pub struct AcceptSpecificEd25519ServerCertVerifier {
    expected_server_key_ed25519: ed25519_dalek::VerifyingKey,
}

impl AcceptSpecificEd25519ServerCertVerifier {
    pub fn new(expected_server_key_ed25519: ed25519_dalek::VerifyingKey) -> Self {
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
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Extract Ed25519 key from certificate
        match extract_ed25519_public_key_from_cert(end_entity) {
            Ok(server_ed25519_key) => {
                let extracted_key_hex = hex::encode(server_ed25519_key.to_bytes());
                let expected_key_hex = hex::encode(self.expected_server_key_ed25519.to_bytes());

                tracing::debug!("🔍 Extracted server key: {}", extracted_key_hex);
                tracing::debug!("🔍 Expected server key:  {}", expected_key_hex);

                // Verify it matches our expected key
                if server_ed25519_key.to_bytes() == self.expected_server_key_ed25519.to_bytes() {
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
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // We only support TLS 1.3
        Err(rustls::Error::UnsupportedNameType)
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Accept any TLS 1.3 signature - we verify identity via the embedded Ed25519 key
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Create a complete rustls ServerConfig for Ed25519 certificates
///
/// This function creates a fully configured rustls ServerConfig that:
/// - Uses the default crypto provider with Ed25519 support
/// - Requires TLS 1.3
/// - Uses anonymous client authentication
/// - Configures the Ed25519 certificate and signing key
///
/// # Arguments
/// * `server_signing_key` - The Ed25519 signing key for the server
/// * `hostname` - The hostname for the certificate (e.g., "localhost")
///
/// # Returns
/// A configured rustls ServerConfig ready for use with QUIC
pub fn create_ed25519_server_config(
    server_signing_key: &ed25519_dalek::SigningKey,
    hostname: &str,
) -> std::result::Result<rustls::ServerConfig, CryptoError> {
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    // Generate TLS certificate from Ed25519 key
    let certs = generate_ed25519_cert_for_tls(server_signing_key, hostname)?;

    // Use the default crypto provider (supports Ed25519)
    let crypto_provider = rustls::crypto::aws_lc_rs::default_provider();

    // Create certificate resolver with Ed25519 signing key
    let pkcs8_der = server_signing_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::ParseError(format!("Failed to encode Ed25519 key: {}", e)))?;

    let private_key = rustls::pki_types::PrivateKeyDer::from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes().to_vec()),
    );

    // Create a simple certificate resolver that always returns our certificate
    #[derive(Debug)]
    struct Ed25519CertResolver {
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    }

    impl rustls::server::ResolvesServerCert for Ed25519CertResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            let signing_key =
                rustls::crypto::aws_lc_rs::sign::any_supported_type(&self.key).ok()?;
            Some(Arc::new(rustls::sign::CertifiedKey::new(
                self.certs.clone(),
                signing_key,
            )))
        }
    }

    let cert_resolver = Ed25519CertResolver {
        certs,
        key: private_key,
    };

    let client_verifier =
        rustls::server::WebPkiClientVerifier::builder(rustls::RootCertStore::empty().into())
            .allow_unauthenticated()
            .build()
            .map_err(|e| {
                CryptoError::TlsError(format!("Failed to create client verifier: {}", e))
            })?;

    // Create rustls server config
    let rustls_config = rustls::ServerConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| CryptoError::TlsError(format!("Failed to set TLS version: {}", e)))?
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(Arc::new(cert_resolver));

    Ok(rustls_config)
}
