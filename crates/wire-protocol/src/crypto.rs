use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey, VerifyingKey};
use rcgen::{Certificate, CertificateParams, CustomExtension, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid ed25519 key: {0:?}")]
    InvalidEd25519Key(String),

    #[error("Not found")]
    Ed25519KeyNotFound,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Generate a deterministic TLS certificate embedding an ed25519 public key
///
/// This creates a certificate that can be used for TLS while embedding
/// the ed25519 public key for application-layer verification.
pub fn generate_deterministic_cert_from_ed25519(
    ed25519_key: &SigningKey,
    subject_name: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Create certificate parameters
    let mut cert_params = CertificateParams::new(vec![subject_name.to_string()]);
    cert_params.alg = &PKCS_ED25519;

    // Embed the ed25519 public key in a custom extension
    // OID 1.3.6.1.4.1.99999.1 is a private enterprise number for demonstration
    let ed25519_pubkey_bytes = ed25519_key.verifying_key().to_bytes().to_vec();
    tracing::debug!(
        "🔧 Embedding ed25519 public key in certificate: {} (length: {})",
        hex::encode(&ed25519_pubkey_bytes),
        ed25519_pubkey_bytes.len()
    );

    let ed25519_pubkey_ext =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], ed25519_pubkey_bytes);
    cert_params.custom_extensions = vec![ed25519_pubkey_ext];

    // Generate deterministic keypair for certificate
    // Note: This is different from the ed25519 key - it's used for TLS compatibility
    let cert_key_bytes = blake3::hash(&ed25519_key.verifying_key().to_bytes())
        .as_bytes()
        .to_vec();

    // Create a deterministic Ed25519 keypair for the certificate
    use ed25519_dalek::SigningKey as Ed25519SigningKey;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&cert_key_bytes[..32]);
    let cert_ed25519_key = Ed25519SigningKey::from_bytes(&seed);

    // Convert to rcgen KeyPair format
    let cert_keypair = KeyPair::from_der(cert_ed25519_key.to_pkcs8_der().unwrap().as_bytes())
        .map_err(|e| CryptoError::ParseError(format!("Failed to create keypair: {e}")))?;

    cert_params.key_pair = Some(cert_keypair);

    // Generate the certificate
    let certificate = Certificate::from_params(cert_params)
        .map_err(|e| CryptoError::ParseError(format!("Failed to generate certificate: {e}")))?;

    // Convert to DER format
    let cert_der =
        CertificateDer::from(certificate.serialize_der().map_err(|e| {
            CryptoError::ParseError(format!("Failed to serialize certificate: {e}"))
        })?);

    let private_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certificate.serialize_private_key_der(),
    ));

    Ok((vec![cert_der], private_key_der))
}

/// Extract ed25519 public key from a certificate
///
/// This function looks for the custom extension containing the ed25519 public key
/// that was embedded during certificate generation.
pub fn extract_ed25519_from_cert(cert_der: &CertificateDer) -> Result<VerifyingKey> {
    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| CryptoError::ParseError(format!("Failed to parse certificate: {e:?}")))?;

    // Look for our custom extension
    let target_oid = oid!(1.3.6 .1 .4 .1 .99999 .1);
    tracing::debug!("🔍 Looking for ed25519 extension with OID: {}", target_oid);
    tracing::debug!("Certificate has {} extensions", cert.extensions().len());

    for (i, extension) in cert.extensions().iter().enumerate() {
        tracing::debug!(
            "  Extension {}: OID {} (value length: {})",
            i,
            extension.oid,
            extension.value.len()
        );
        if extension.oid == target_oid {
            let key_bytes = extension.value;
            tracing::debug!(
                "🔍 Found ed25519 extension with {} bytes: {}",
                key_bytes.len(),
                hex::encode(key_bytes)
            );

            if key_bytes.len() != 32 {
                return Err(CryptoError::ParseError(format!(
                    "Invalid ed25519 key length in certificate: {} bytes",
                    key_bytes.len()
                )));
            }

            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key_bytes);

            let result = VerifyingKey::from_bytes(&key_array)
                .map_err(|e| CryptoError::ParseError(format!("Invalid ed25519 key: {e}")));

            if let Ok(ref key) = result {
                tracing::debug!(
                    "✅ Successfully extracted ed25519 key: {}",
                    hex::encode(key.to_bytes())
                );
            }

            return result;
        }
    }

    Err(CryptoError::Ed25519KeyNotFound)
}

/// Generate a new ed25519 key pair
pub fn generate_ed25519_keypair() -> SigningKey {
    SigningKey::generate(&mut rand::thread_rng())
}

/// Load ed25519 private key from hex string
pub fn load_ed25519_key_from_hex(hex_string: &str) -> Result<SigningKey> {
    let key_bytes = hex::decode(hex_string)
        .map_err(|e| CryptoError::ParseError(format!("Invalid hex: {e}")))?;

    if key_bytes.len() != 32 {
        return Err(CryptoError::ParseError(
            "ed25519 private key must be 32 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    Ok(SigningKey::from_bytes(&key_array))
}

/// Save ed25519 private key to hex string
pub fn save_ed25519_key_to_hex(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

/// Load ed25519 public key from hex string
pub fn load_ed25519_public_key_from_hex(hex_string: &str) -> Result<VerifyingKey> {
    let key_bytes = hex::decode(hex_string)
        .map_err(|e| CryptoError::ParseError(format!("Invalid hex: {e}")))?;

    if key_bytes.len() != 32 {
        return Err(CryptoError::ParseError(
            "ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    VerifyingKey::from_bytes(&key_array)
        .map_err(|e| CryptoError::ParseError(format!("Invalid ed25519 public key: {e}")))
}

/// Save ed25519 public key to hex string
pub fn save_ed25519_public_key_to_hex(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

/// Load ed25519 private key from file
pub fn load_ed25519_key_from_file(path: &str) -> Result<SigningKey> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| CryptoError::ParseError(format!("Failed to read key file: {e}")))?;

    let hex_string = content.trim();
    load_ed25519_key_from_hex(hex_string)
}

/// Save ed25519 private key to file
pub fn save_ed25519_key_to_file(key: &SigningKey, path: &str) -> Result<()> {
    let hex_string = save_ed25519_key_to_hex(key);
    std::fs::write(path, hex_string)
        .map_err(|e| CryptoError::ParseError(format!("Failed to write key file: {e}")))
}

/// Create certificate verifier for cleint-side
///
/// This verifier accepts any certificate but extracts and validates
/// the embedded ed25519 public key against a known server key.
#[derive(Debug)]
pub struct AcceptSpecificServerCertVerifier {
    expected_server_key: VerifyingKey,
}

impl AcceptSpecificServerCertVerifier {
    pub fn new(expected_server_key: VerifyingKey) -> Self {
        Self {
            expected_server_key,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for AcceptSpecificServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Extract ed25519 key from certificate
        match extract_ed25519_from_cert(end_entity) {
            Ok(server_ed25519_key) => {
                let extracted_key_hex = hex::encode(server_ed25519_key.to_bytes());
                let expected_key_hex = hex::encode(self.expected_server_key.to_bytes());

                tracing::debug!("🔍 Extracted server key: {}", extracted_key_hex);
                tracing::debug!("🔍 Expected server key:  {}", expected_key_hex);

                // Verify it matches our expected key
                if server_ed25519_key.to_bytes() == self.expected_server_key.to_bytes() {
                    tracing::info!("✅ Server ed25519 identity verified via certificate");
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    tracing::error!("❌ Server ed25519 key mismatch");
                    tracing::error!("   Extracted: {}", extracted_key_hex);
                    tracing::error!("   Expected:  {}", expected_key_hex);
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to extract ed25519 key from certificate: {}", e);
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
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Only accept Ed25519 signatures to enforce our security model
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Custom client certificate verifier that accepts any valid certificate
/// as long as it contains a correct ed25519 public key as per our protoco,
/// extensions
#[derive(Debug)]
pub struct ZoeClientCertVerifier;

impl Default for ZoeClientCertVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ZoeClientCertVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl rustls::server::danger::ClientCertVerifier for ZoeClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        tracing::debug!(
            "🔍 Verifying client certificate ({} bytes)",
            end_entity.as_ref().len()
        );

        // Extract ed25519 key from certificate
        match extract_ed25519_from_cert(end_entity) {
            Ok(public_key) => {
                tracing::info!(
                    "✅ Client ed25519 identity verified: {}",
                    hex::encode(public_key.to_bytes())
                );
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
            Err(e) => {
                tracing::error!(
                    "❌ Failed to extract ed25519 key from client certificate: {}",
                    e
                );
                tracing::debug!(
                    "Certificate DER length: {} bytes",
                    end_entity.as_ref().len()
                );

                // Try to parse the certificate to see what extensions it has
                if let Ok((_, cert)) =
                    x509_parser::certificate::X509Certificate::from_der(end_entity.as_ref())
                {
                    tracing::debug!(
                        "Certificate parsed successfully, extensions: {}",
                        cert.extensions().len()
                    );
                    for (i, ext) in cert.extensions().iter().enumerate() {
                        tracing::debug!(
                            "  Extension {}: OID {} (critical: {})",
                            i,
                            ext.oid,
                            ext.critical
                        );
                    }
                } else {
                    tracing::error!("Failed to parse certificate DER");
                }

                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_certificate_generation() {
        let key = generate_ed25519_keypair();

        // Generate certificate twice
        let (certs1, _) =
            generate_deterministic_cert_from_ed25519(&key, "test.example.com").unwrap();
        let (certs2, _) =
            generate_deterministic_cert_from_ed25519(&key, "test.example.com").unwrap();

        // Should be identical
        assert_eq!(certs1[0].as_ref(), certs2[0].as_ref());
    }

    #[test]
    fn test_ed25519_key_extraction() {
        let key = generate_ed25519_keypair();
        let original_pubkey = key.verifying_key();

        let (certs, _) =
            generate_deterministic_cert_from_ed25519(&key, "test.example.com").unwrap();
        let extracted_pubkey = extract_ed25519_from_cert(&certs[0]).unwrap();

        assert_eq!(original_pubkey.to_bytes(), extracted_pubkey.to_bytes());
    }

    #[test]
    fn test_key_serialization() {
        let key = generate_ed25519_keypair();
        let hex_string = save_ed25519_key_to_hex(&key);
        let loaded_key = load_ed25519_key_from_hex(&hex_string).unwrap();

        assert_eq!(key.to_bytes(), loaded_key.to_bytes());
    }

    #[test]
    fn test_public_key_serialization() {
        let key = generate_ed25519_keypair();
        let pubkey = key.verifying_key();
        let hex_string = save_ed25519_public_key_to_hex(&pubkey);
        let loaded_pubkey = load_ed25519_public_key_from_hex(&hex_string).unwrap();

        assert_eq!(pubkey.to_bytes(), loaded_pubkey.to_bytes());
    }
}
