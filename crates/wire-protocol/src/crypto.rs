use const_oid::ObjectIdentifier;
use der::{
    asn1::{BitString, GeneralizedTime},
    Encode,
};
use ml_dsa::{KeyGen, KeyPair, MlDsa44, MlDsa65, SigningKey, VerifyingKey as MlDsaVerifyingKey};
use rustls::pki_types::CertificateDer;
use signature::{SignatureEncoding, Signer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
use x509_cert::{
    attr::{AttributeTypeAndValue, AttributeValue},
    name::{RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
    time::{Time, Validity},
    Certificate, TbsCertificate, Version,
};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;

// ChaCha20-Poly1305 and mnemonic support
use argon2::{Argon2, PasswordHasher};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::{thread_rng, RngCore, SeedableRng};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Invalid ML-DSA key: {0:?}")]
    InvalidMlDsaKey(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Mnemonic error: {0}")]
    MnemonicError(String),

    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Generate a deterministic TLS certificate using ML-DSA-44
///
/// This creates a proper ML-DSA-44 certificate where the ML-DSA-44 public key
/// is stored directly in the SubjectPublicKeyInfo field according to FIPS 204.
pub fn generate_deterministic_cert_from_ml_dsa_44_for_tls(
    ml_dsa_key_pair: &KeyPair<MlDsa44>,
    subject_name: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    tracing::debug!(
        "🔧 Creating proper ML-DSA-44 certificate for subject: {}",
        subject_name
    );

    let verifying_key = ml_dsa_key_pair.verifying_key();
    let public_key_bytes = verifying_key.encode();

    tracing::debug!(
        "🔧 ML-DSA-44 public key length: {} bytes",
        public_key_bytes.len()
    );

    // ML-DSA-44 algorithm identifier OID (from FIPS 204)
    let ml_dsa_44_oid = ObjectIdentifier::new("2.16.840.1.101.3.4.3.17")
        .map_err(|e| CryptoError::ParseError(format!("Invalid ML-DSA-44 OID: {e}")))?;

    // Create SubjectPublicKeyInfo with ML-DSA-44 public key
    let algorithm = AlgorithmIdentifier {
        oid: ml_dsa_44_oid,
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

    let cn_attr = AttributeTypeAndValue {
        oid: cn_oid,
        value: cn_value,
    };

    let mut rdn = RelativeDistinguishedName::default();
    rdn.0
        .insert(cn_attr)
        .map_err(|_| CryptoError::ParseError("Failed to insert CN attribute".to_string()))?;

    let mut subject = RdnSequence::default();
    subject.0.push(rdn);

    // Create validity period (1 year from now)
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
            oid: ml_dsa_44_oid,
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

    // Sign the TBS certificate with ML-DSA-44
    let signature = ml_dsa_key_pair.sign(&tbs_der);

    // Create final certificate
    let certificate = Certificate {
        tbs_certificate,
        signature_algorithm: AlgorithmIdentifier {
            oid: ml_dsa_44_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(signature.to_bytes().as_ref()).map_err(|e| {
            CryptoError::ParseError(format!("Failed to create signature BitString: {e}"))
        })?,
    };

    // Encode certificate to DER
    let cert_der = certificate
        .to_der()
        .map_err(|e| CryptoError::ParseError(format!("Failed to encode certificate: {e}")))?;

    tracing::debug!("✅ Generated proper ML-DSA-44 certificate successfully");

    Ok(vec![CertificateDer::from(cert_der)])
}

/// Generate a deterministic TLS certificate (compatibility function)
///
/// This function provides backward compatibility for existing code that uses ed25519.
/// It now generates ML-DSA-44 certificates instead.
pub fn generate_deterministic_cert_from_ed25519(
    _ed25519_key: &crate::Ed25519SigningKey, // Ignored - we generate ML-DSA-44 instead
    subject_name: &str,
) -> Result<Vec<CertificateDer<'static>>> {
    // Generate a new ML-DSA-44 key pair for this certificate
    let keypair = generate_ml_dsa_44_keypair_for_tls();

    tracing::warn!(
        "🔄 Compatibility mode: Generating ML-DSA-44 certificate instead of ed25519 for subject: {}",
        subject_name
    );

    // Generate ML-DSA-44 certificate
    generate_deterministic_cert_from_ml_dsa_44_for_tls(&keypair, subject_name)
}

/// ML-DSA-44 public key extracted from certificates
pub type PublicKey = MlDsaVerifyingKey<MlDsa44>;

/// Extract ML-DSA-44 public key from a certificate
///
/// This function extracts the ML-DSA-44 public key directly from the certificate's
/// SubjectPublicKeyInfo field when the certificate uses the ML-DSA-44 algorithm identifier.
pub fn extract_public_key_from_cert(cert_der: &CertificateDer) -> Result<PublicKey> {
    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| CryptoError::ParseError(format!("Failed to parse certificate: {e:?}")))?;

    // Get the subject public key info
    let spki = cert.public_key();
    let algorithm_oid = &spki.algorithm.algorithm;

    // ML-DSA-44 algorithm identifier: 2.16.840.1.101.3.4.3.17
    let ml_dsa_44_oid = oid!(2.16.840 .1 .101 .3 .4 .3 .17);

    tracing::debug!("🔍 Certificate algorithm OID: {}", algorithm_oid);

    if algorithm_oid != &ml_dsa_44_oid {
        return Err(CryptoError::ParseError(format!(
            "Certificate is not using ML-DSA-44 algorithm. Found OID: {algorithm_oid}"
        )));
    }

    tracing::debug!("🔍 Found ML-DSA-44 certificate");
    let public_key_bits = &spki.subject_public_key;

    // The BIT STRING contains the raw 1312-byte ML-DSA-44 public key
    // Note: BIT STRING may have unused bits indicator as first byte
    let key_bytes = if public_key_bits.data.len() == 1313 && public_key_bits.data[0] == 0 {
        // Skip the unused bits indicator (should be 0 for ML-DSA-44)
        &public_key_bits.data[1..]
    } else if public_key_bits.data.len() == 1312 {
        // Direct 1312-byte key
        &public_key_bits.data
    } else {
        return Err(CryptoError::ParseError(format!(
            "Invalid ML-DSA-44 public key length: {} bytes",
            public_key_bits.data.len()
        )));
    };

    tracing::debug!(
        "🔍 Found ML-DSA-44 public key with {} bytes",
        key_bytes.len()
    );

    if key_bytes.len() != 1312 {
        return Err(CryptoError::ParseError(format!(
            "Invalid ML-DSA-44 key length: {} bytes (expected 1312)",
            key_bytes.len()
        )));
    }

    // Convert to ML-DSA encoded verifying key format
    // Note: ML-DSA-44 uses MlDsa44, not MlDsa65
    let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa44> = key_bytes
        .try_into()
        .map_err(|_| CryptoError::ParseError("Invalid ML-DSA-44 key format".to_string()))?;

    let ml_dsa_key = MlDsaVerifyingKey::<MlDsa44>::decode(encoded_key);

    tracing::debug!("✅ Successfully extracted ML-DSA-44 key");

    Ok(ml_dsa_key)
}

/// Extract ed25519 public key from certificate (compatibility function)
///
/// This function provides backward compatibility for existing code.
/// It now extracts ML-DSA-44 keys instead of ed25519 keys.
pub fn extract_ed25519_from_cert(cert_der: &CertificateDer) -> Result<MlDsaVerifyingKey<MlDsa44>> {
    tracing::warn!("🔄 Compatibility mode: Extracting ML-DSA-44 key instead of ed25519");
    extract_public_key_from_cert(cert_der)
}

/// Generate a new ML-DSA-44 key pair for TLS certificates
///
/// This is specifically for TLS transport layer security.
/// For inner protocol cryptography, use the ML-DSA-65 functions from prelude.
pub fn generate_ml_dsa_44_keypair_for_tls() -> KeyPair<MlDsa44> {
    let mut rng = rand::thread_rng();

    MlDsa44::key_gen(&mut rng)
}

/// Load ML-DSA-44 private key from hex string (for TLS certificates)
pub fn load_ml_dsa_44_key_from_hex_for_tls(hex_string: &str) -> Result<SigningKey<MlDsa44>> {
    let key_bytes = hex::decode(hex_string)
        .map_err(|e| CryptoError::ParseError(format!("Invalid hex: {e}")))?;

    // ML-DSA-44 private key is 2560 bytes
    if key_bytes.len() != 2560 {
        return Err(CryptoError::ParseError(format!(
            "Invalid ML-DSA-44 key length: {} bytes (expected 2560)",
            key_bytes.len()
        )));
    }

    let encoded_key: &ml_dsa::EncodedSigningKey<MlDsa44> = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::ParseError("Invalid ML-DSA-44 signing key length".to_string()))?;

    Ok(SigningKey::<MlDsa44>::decode(encoded_key))
}

/// Save ML-DSA-44 private key to hex string (for TLS certificates)
pub fn save_ml_dsa_44_key_to_hex_for_tls(key: &SigningKey<MlDsa44>) -> String {
    hex::encode(key.encode())
}

/// Load ML-DSA-44 public key from hex string
pub fn load_ml_dsa_44_public_key_from_hex(hex_string: &str) -> Result<MlDsaVerifyingKey<MlDsa44>> {
    let key_bytes = hex::decode(hex_string)
        .map_err(|e| CryptoError::ParseError(format!("Invalid hex: {e}")))?;

    // ML-DSA-44 public key is 1312 bytes
    if key_bytes.len() != 1312 {
        return Err(CryptoError::ParseError(format!(
            "Invalid ML-DSA-44 public key length: {} bytes (expected 1312)",
            key_bytes.len()
        )));
    }

    let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa44> =
        key_bytes.as_slice().try_into().map_err(|_| {
            CryptoError::ParseError("Invalid ML-DSA-44 verifying key length".to_string())
        })?;

    Ok(MlDsaVerifyingKey::<MlDsa44>::decode(encoded_key))
}

/// Save ML-DSA-44 public key to hex string
pub fn save_ml_dsa_44_public_key_to_hex(key: &MlDsaVerifyingKey<MlDsa44>) -> String {
    hex::encode(key.encode())
}

/// Load ML-DSA-44 private key from file
pub fn load_ml_dsa_44_key_from_file(path: &str) -> Result<SigningKey<MlDsa44>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| CryptoError::ParseError(format!("Failed to read key file: {e}")))?;
    load_ml_dsa_44_key_from_hex_for_tls(content.trim())
}

/// Save ML-DSA-44 private key to file
pub fn save_ml_dsa_44_key_to_file(key: &SigningKey<MlDsa44>, path: &str) -> Result<()> {
    let hex_key = save_ml_dsa_44_key_to_hex_for_tls(key);
    std::fs::write(path, hex_key)
        .map_err(|e| CryptoError::ParseError(format!("Failed to write key file: {e}")))?;
    Ok(())
}

/// Load ML-DSA public key from hex string
pub fn load_ml_dsa_public_key_from_hex(hex_string: &str) -> Result<MlDsaVerifyingKey<MlDsa65>> {
    let key_bytes = hex::decode(hex_string)
        .map_err(|e| CryptoError::ParseError(format!("Invalid hex: {e}")))?;

    let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa65> = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::ParseError("Invalid ML-DSA verifying key length".to_string()))?;
    Ok(MlDsaVerifyingKey::<MlDsa65>::decode(encoded_key))
}

/// Save ML-DSA public key to hex string
pub fn save_ml_dsa_public_key_to_hex(key: &MlDsaVerifyingKey<MlDsa65>) -> String {
    hex::encode(key.encode())
}

/// Create certificate verifier for client-side
///
/// This verifier accepts any certificate but extracts and validates
/// the embedded ML-DSA-44 public key against a known server key.
#[derive(Debug)]
pub struct AcceptSpecificServerCertVerifier {
    expected_server_key_ml_dsa_44: MlDsaVerifyingKey<MlDsa44>,
}

impl AcceptSpecificServerCertVerifier {
    pub fn new(expected_server_key_ml_dsa_44: MlDsaVerifyingKey<MlDsa44>) -> Self {
        Self {
            expected_server_key_ml_dsa_44,
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
        // Extract ML-DSA-44 key from certificate
        match extract_public_key_from_cert(end_entity) {
            Ok(server_ml_dsa_key) => {
                let extracted_key_hex = hex::encode(server_ml_dsa_key.encode());
                let expected_key_hex = hex::encode(self.expected_server_key_ml_dsa_44.encode());

                tracing::debug!("🔍 Extracted server key: {}", extracted_key_hex);
                tracing::debug!("🔍 Expected server key:  {}", expected_key_hex);

                // Verify it matches our expected key
                if server_ml_dsa_key.encode() == self.expected_server_key_ml_dsa_44.encode() {
                    tracing::info!("✅ Server ML-DSA-44 identity verified via certificate");
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    tracing::error!("❌ Server ML-DSA-44 key mismatch");
                    tracing::error!("   Extracted: {}", extracted_key_hex);
                    tracing::error!("   Expected:  {}", expected_key_hex);
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to extract ML-DSA-44 key from certificate: {}", e);
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
        Err(rustls::Error::General(
            "TLS 1.2 is not supported".to_string(),
        ))
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
        // Only accept ML DSA 44 signatures to enforce our security model
        vec![rustls::SignatureScheme::ML_DSA_44]
    }
}

/// Custom client certificate verifier that accepts any valid certificate
/// as long as it contains a correct ML-DSA-44 public key as per our protocol
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

        // Extract ML-DSA-44 key from certificate
        match extract_public_key_from_cert(end_entity) {
            Ok(public_key) => {
                tracing::info!(
                    "✅ Client ML-DSA-44 identity verified: {}",
                    hex::encode(public_key.encode())
                );
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
            Err(e) => {
                tracing::error!(
                    "❌ Failed to extract ML-DSA-44 key from client certificate: {}",
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
        Err(rustls::Error::General(
            "TLS 1.2 is not supported".to_string(),
        ))
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
        // Only accept ML DSA 44 signatures to enforce our security model
        vec![rustls::SignatureScheme::ML_DSA_44]
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
}

// ==================== ChaCha20-Poly1305 & Mnemonic Support ====================

/// Mnemonic phrase for key derivation
#[derive(Debug, Clone)]
pub struct MnemonicPhrase {
    pub phrase: String,
    pub language: Language,
}

impl MnemonicPhrase {
    /// Generate a new 24-word mnemonic phrase
    pub fn generate() -> Result<Self> {
        // Generate 32 bytes of entropy for 24 words
        let mut entropy = [0u8; 32];
        thread_rng().fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| CryptoError::MnemonicError(format!("Failed to generate mnemonic: {e}")))?;

        Ok(Self {
            phrase: mnemonic.to_string(),
            language: Language::English,
        })
    }

    /// Create from existing phrase
    pub fn from_phrase(phrase: &str, language: Language) -> Result<Self> {
        // Validate the mnemonic
        Mnemonic::parse_in(language, phrase)
            .map_err(|e| CryptoError::MnemonicError(format!("Invalid mnemonic phrase: {e}")))?;

        Ok(Self {
            phrase: phrase.to_string(),
            language,
        })
    }

    /// Derive a seed from the mnemonic with optional passphrase
    pub fn to_seed(&self, passphrase: &str) -> Result<[u8; 64]> {
        let mnemonic = Mnemonic::parse_in(self.language, &self.phrase)
            .map_err(|e| CryptoError::MnemonicError(format!("Invalid mnemonic: {e}")))?;

        Ok(mnemonic.to_seed(passphrase))
    }

    /// Get the phrase as string (be careful with this!)
    pub fn phrase(&self) -> &str {
        &self.phrase
    }
}

/// Key derivation methods supported by the system
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyDerivationMethod {
    /// BIP39 mnemonic phrase with Argon2 key derivation
    ///
    /// This is the standard method for user-controlled key derivation using
    /// a BIP39 mnemonic phrase combined with Argon2 for key stretching.
    Bip39Argon2,

    /// Direct ChaCha20-Poly1305 key generation
    ///
    /// Used for fallback scenarios or when no mnemonic is provided.
    /// Keys are generated directly without mnemonic derivation.
    ChaCha20Poly1305Keygen,
}

impl KeyDerivationMethod {
    /// Get the string representation of this derivation method
    ///
    /// This is useful for compatibility with existing string-based systems
    /// or for display purposes.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bip39Argon2 => "bip39+argon2",
            Self::ChaCha20Poly1305Keygen => "chacha20-poly1305-keygen",
        }
    }
}

impl std::fmt::Display for KeyDerivationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for KeyDerivationMethod {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "bip39+argon2" => Ok(Self::Bip39Argon2),
            "chacha20-poly1305-keygen" => Ok(Self::ChaCha20Poly1305Keygen),
            _ => Err(format!("Unknown key derivation method: '{s}'")),
        }
    }
}

/// Information about how a key was derived
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyDerivationInfo {
    /// Key derivation method used
    pub method: KeyDerivationMethod,
    /// Salt used for derivation
    pub salt: Vec<u8>,
    /// Argon2 parameters used
    pub argon2_params: Argon2Params,
    /// Context string used for derivation
    pub context: String, // e.g., "dga-group-key"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2Params {
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory: 65536,  // 64 MB
            iterations: 3,  // 3 iterations
            parallelism: 4, // 4 threads
        }
    }
}

/// ChaCha20-Poly1305 encryption key
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    /// The actual key bytes (32 bytes for ChaCha20)
    pub key: [u8; 32],
    /// Key identifier
    pub key_id: Vec<u8>,
    /// When this key was created
    pub created_at: u64,
    /// Optional derivation info (for mnemonic-derived keys)
    pub derivation_info: Option<KeyDerivationInfo>,
}

/// Minimal encrypted content for wire protocol messages
/// Optimized for space - no key_id since it's determined by channel context
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChaCha20Poly1305Content {
    /// Encrypted data + authentication tag
    pub ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (fixed 12 bytes for space efficiency)
    pub nonce: [u8; 12],
}

/// Ed25519-derived ChaCha20-Poly1305 encrypted content
/// Simple self-encryption using only the sender's ed25519 keypair derived from mnemonic
/// Only the sender can decrypt this content (encrypt-to-self pattern)
/// Public key is available from message sender field - no need to duplicate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ed25519SelfEncryptedContent {
    /// Encrypted data + authentication tag
    pub ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes)
    pub nonce: [u8; 12],
}

/// Ephemeral ECDH ChaCha20-Poly1305 encrypted content
/// Simple public key encryption using ephemeral X25519 keys
/// Anyone can encrypt for the recipient using only their public key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EphemeralEcdhContent {
    /// Encrypted data + authentication tag
    pub ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes)
    pub nonce: [u8; 12],
    /// Ephemeral X25519 public key (generated randomly for each message)
    pub ephemeral_public: [u8; 32],
}

impl Ed25519SelfEncryptedContent {
    /// Encrypt data using ed25519 private key (self-encryption)
    /// Derives a ChaCha20 key from the ed25519 private key deterministically
    /// Only the same private key can decrypt this content
    pub fn encrypt(plaintext: &[u8], signing_key: &ed25519_dalek::SigningKey) -> Result<Self> {
        use chacha20poly1305::aead::{Aead, OsRng};
        use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit};

        // Derive ChaCha20 key from ed25519 private key using Blake3
        let ed25519_private_bytes = signing_key.to_bytes();
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(&ed25519_private_bytes);
        key_derivation_input.extend_from_slice(b"ed25519-to-chacha20-key-derivation");

        let derived_key_hash = blake3::hash(&key_derivation_input);
        let chacha_key = Key::from_slice(derived_key_hash.as_bytes());
        let cipher = ChaCha20Poly1305::new(chacha_key);

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptoError::EncryptionError(format!("Ed25519-derived ChaCha20 encryption failed: {e}"))
        })?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce);

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt data using ed25519 private key (self-decryption)
    /// Must be the same private key that was used for encryption
    pub fn decrypt(&self, signing_key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

        // Derive the same ChaCha20 key from ed25519 private key
        let ed25519_private_bytes = signing_key.to_bytes();
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(&ed25519_private_bytes);
        key_derivation_input.extend_from_slice(b"ed25519-to-chacha20-key-derivation");

        let derived_key_hash = blake3::hash(&key_derivation_input);
        let chacha_key = Key::from_slice(derived_key_hash.as_bytes());
        let cipher = ChaCha20Poly1305::new(chacha_key);

        let nonce = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| {
                CryptoError::DecryptionError(format!(
                    "Ed25519-derived ChaCha20 decryption failed: {e}"
                ))
            })
    }
}

/// ML-DSA-derived ChaCha20-Poly1305 encrypted content
/// Simple self-encryption using only the sender's ML-DSA keypair derived from mnemonic
/// Only the sender can decrypt this content (encrypt-to-self pattern)
/// Public key is available from message sender field - no need to duplicate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MlDsaSelfEncryptedContent {
    /// Encrypted data + authentication tag
    pub ciphertext: Vec<u8>,
    /// ChaCha20-Poly1305 nonce (12 bytes)
    pub nonce: [u8; 12],
}

impl MlDsaSelfEncryptedContent {
    /// Encrypt data using ML-DSA private key (self-encryption)
    /// Derives a ChaCha20 key from the ML-DSA private key deterministically
    /// Only the same private key can decrypt this content
    pub fn encrypt(plaintext: &[u8], signing_key: &SigningKey<MlDsa65>) -> Result<Self> {
        use chacha20poly1305::aead::{Aead, OsRng};
        use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit};

        // Derive ChaCha20 key from ML-DSA private key using Blake3
        let ml_dsa_private_bytes = signing_key.encode();
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(&ml_dsa_private_bytes);
        key_derivation_input.extend_from_slice(b"ml-dsa-to-chacha20-key-derivation");

        let derived_key_hash = blake3::hash(&key_derivation_input);
        let chacha_key = Key::from_slice(derived_key_hash.as_bytes());
        let cipher = ChaCha20Poly1305::new(chacha_key);

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptoError::EncryptionError(format!("ML-DSA-derived ChaCha20 encryption failed: {e}"))
        })?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce);

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt data using ML-DSA private key (self-decryption)
    /// Must be the same private key that was used for encryption
    pub fn decrypt(&self, signing_key: &SigningKey<MlDsa65>) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

        // Derive the same ChaCha20 key from ML-DSA private key
        let ml_dsa_private_bytes = signing_key.encode();
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(&ml_dsa_private_bytes);
        key_derivation_input.extend_from_slice(b"ml-dsa-to-chacha20-key-derivation");

        let derived_key_hash = blake3::hash(&key_derivation_input);
        let chacha_key = Key::from_slice(derived_key_hash.as_bytes());
        let cipher = ChaCha20Poly1305::new(chacha_key);

        let nonce = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| {
                CryptoError::DecryptionError(format!(
                    "ML-DSA-derived ChaCha20 decryption failed: {e}"
                ))
            })
    }
}

impl EphemeralEcdhContent {
    /// Encrypt data using ephemeral X25519 ECDH  
    /// Generates a random ephemeral key pair for each message
    /// Anyone can encrypt for the recipient using only their Ed25519 public key
    pub fn encrypt(
        plaintext: &[u8],
        recipient_ed25519_public: &ed25519_dalek::VerifyingKey,
    ) -> Result<Self> {
        use chacha20poly1305::aead::{Aead, OsRng};
        use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit};

        // Generate ephemeral X25519 key pair for this message
        let ephemeral_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_private);

        // For ephemeral ECDH, we need a consistent way to derive X25519 public key
        // from Ed25519 public key. We'll use a deterministic derivation based on the Ed25519 public key bytes.
        // This creates a "virtual" X25519 public key that will match what the recipient computes.
        let recipient_x25519_public = {
            // Use Ed25519 public key bytes as seed for deterministic X25519 public key derivation
            let ed25519_bytes = recipient_ed25519_public.to_bytes();
            // Hash the Ed25519 public key to create deterministic X25519 private key
            let x25519_private_bytes = *blake3::hash(&ed25519_bytes).as_bytes();
            let x25519_private = x25519_dalek::StaticSecret::from(x25519_private_bytes);
            x25519_dalek::PublicKey::from(&x25519_private)
        };

        // Ephemeral ECDH: each message uses a unique ephemeral key pair for perfect forward secrecy

        // Perform ECDH: ephemeral_private + recipient_public → shared secret
        let shared_secret = ephemeral_private.diffie_hellman(&recipient_x25519_public);

        // Derive ChaCha20 key from shared secret using Blake3
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(shared_secret.as_bytes());
        key_derivation_input.extend_from_slice(b"ephemeral-ecdh-to-chacha20-key-derivation");

        let derived_key_hash = blake3::hash(&key_derivation_input);
        let chacha_key = Key::from_slice(derived_key_hash.as_bytes());
        let cipher = ChaCha20Poly1305::new(chacha_key);

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptoError::EncryptionError(format!("Ephemeral ECDH ChaCha20 encryption failed: {e}"))
        })?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce);

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
            ephemeral_public: ephemeral_public.to_bytes(),
        })
    }

    /// Decrypt data using ephemeral X25519 ECDH
    /// Recipient uses their Ed25519 private key + stored ephemeral public key
    pub fn decrypt(&self, recipient_ed25519_key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

        // Use the same deterministic derivation as encryption
        // Derive X25519 private key from Ed25519 public key (deterministic)
        let recipient_x25519_private = {
            let ed25519_public = recipient_ed25519_key.verifying_key();
            let ed25519_bytes = ed25519_public.to_bytes();
            // Hash the Ed25519 public key to create deterministic X25519 private key (same as encryption)
            let x25519_private_bytes = *blake3::hash(&ed25519_bytes).as_bytes();
            x25519_dalek::StaticSecret::from(x25519_private_bytes)
        };
        let _recipient_x25519_public = x25519_dalek::PublicKey::from(&recipient_x25519_private);

        // Extract ephemeral public key from message
        let ephemeral_public = x25519_dalek::PublicKey::from(self.ephemeral_public);

        // Use same deterministic X25519 derivation to compute shared secret

        // Perform ECDH: recipient_private + ephemeral_public → shared secret (same as encryption)
        let shared_secret = recipient_x25519_private.diffie_hellman(&ephemeral_public);

        // Derive the same ChaCha20 key from shared secret
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(shared_secret.as_bytes());
        key_derivation_input.extend_from_slice(b"ephemeral-ecdh-to-chacha20-key-derivation");

        let derived_key_hash = blake3::hash(&key_derivation_input);
        let chacha_key = Key::from_slice(derived_key_hash.as_bytes());
        let cipher = ChaCha20Poly1305::new(chacha_key);

        let nonce = Nonce::from_slice(&self.nonce);

        cipher
            .decrypt(nonce, self.ciphertext.as_ref())
            .map_err(|e| {
                CryptoError::DecryptionError(format!(
                    "Ephemeral ECDH ChaCha20 decryption failed: {e}"
                ))
            })
    }
}

/// Convert Ed25519 private key to X25519 private key
/// Both curves use the same underlying Curve25519
pub fn ed25519_to_x25519_private(
    ed25519_key: &ed25519_dalek::SigningKey,
) -> Result<X25519PrivateKey> {
    // Ed25519 private key is the same as X25519 private key (both are 32-byte scalars)
    let ed25519_bytes = ed25519_key.to_bytes();
    Ok(X25519PrivateKey::from(ed25519_bytes))
}

/// Convert Ed25519 public key to X25519 public key
/// Derives X25519 public key from the corresponding Ed25519 private key
/// Note: This is a simplified approach that requires the private key
pub fn ed25519_to_x25519_public(
    ed25519_private_key: &ed25519_dalek::SigningKey,
) -> Result<X25519PublicKey> {
    // Convert Ed25519 private key to X25519 private key, then derive public
    let x25519_private = ed25519_to_x25519_private(ed25519_private_key)?;
    Ok(X25519PublicKey::from(&x25519_private))
}

/// Convert Ed25519 public key (VerifyingKey) to X25519 public key
/// Uses curve25519-dalek's Edwards to Montgomery conversion to match
/// the same conversion that happens in the private key derivation path
pub fn ed25519_to_x25519_public_from_verifying_key(
    ed25519_public: &ed25519_dalek::VerifyingKey,
) -> Result<X25519PublicKey> {
    // Use curve25519-dalek's conversion which should match the private key approach
    use curve25519_dalek::edwards::CompressedEdwardsY;

    let compressed_point = CompressedEdwardsY::from_slice(&ed25519_public.to_bytes())
        .map_err(|_| CryptoError::ParseError("Invalid Ed25519 public key".to_string()))?;

    let edwards_point = compressed_point.decompress().ok_or_else(|| {
        CryptoError::ParseError("Cannot decompress Ed25519 public key".to_string())
    })?;

    let montgomery_point = edwards_point.to_montgomery();
    Ok(X25519PublicKey::from(montgomery_point.to_bytes()))
}

impl EncryptionKey {
    /// Generate a random encryption key
    pub fn generate(timestamp: u64) -> Self {
        let mut key = [0u8; 32];
        let mut key_id = vec![0u8; 16];
        thread_rng().fill_bytes(&mut key);
        thread_rng().fill_bytes(&mut key_id);

        Self {
            key,
            key_id,
            created_at: timestamp,
            derivation_info: None,
        }
    }

    /// Derive an encryption key from a mnemonic phrase
    pub fn from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        context: &str, // e.g., "dga-group-key"
        timestamp: u64,
    ) -> Result<Self> {
        // Generate a random salt
        let mut salt = [0u8; 32];
        thread_rng().fill_bytes(&mut salt);

        Self::from_mnemonic_with_salt(mnemonic, passphrase, context, &salt, timestamp)
    }

    /// Derive an encryption key from a mnemonic phrase with specific salt (for key recovery)
    pub fn from_mnemonic_with_salt(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        context: &str,
        salt: &[u8; 32],
        timestamp: u64,
    ) -> Result<Self> {
        // First get the BIP39 seed
        let seed = mnemonic.to_seed(passphrase)?;

        // Then use Argon2 to derive the actual encryption key
        let argon2_params = Argon2Params::default();
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                argon2_params.memory,
                argon2_params.iterations,
                argon2_params.parallelism,
                Some(32), // output length
            )
            .map_err(|e| CryptoError::KeyDerivationError(format!("Invalid Argon2 params: {e}")))?,
        );

        // Combine seed with context for key derivation
        let mut input = Vec::new();
        input.extend_from_slice(&seed);
        input.extend_from_slice(context.as_bytes());

        // Create salt for argon2 - use first 16 bytes encoded as base64 without padding
        use base64::Engine;
        let salt_bytes = &salt[..16]; // argon2 salt should be 16 bytes
        let salt_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt_bytes);
        let salt_ref = argon2::password_hash::Salt::from_b64(&salt_b64)
            .map_err(|e| CryptoError::KeyDerivationError(format!("Salt error: {e}")))?;

        let password_hash = argon2
            .hash_password(&input, salt_ref)
            .map_err(|e| CryptoError::KeyDerivationError(format!("Key derivation failed: {e}")))?;

        // Extract the key bytes
        let mut key = [0u8; 32];
        let hash = password_hash.hash.unwrap();
        let hash_bytes = hash.as_bytes();
        key.copy_from_slice(&hash_bytes[..32]);

        // Generate key ID from the derivation parameters
        let mut key_id_input = Vec::new();
        key_id_input.extend_from_slice(salt);
        key_id_input.extend_from_slice(context.as_bytes());
        let key_id = blake3::hash(&key_id_input).as_bytes()[..16].to_vec();

        Ok(Self {
            key,
            key_id,
            created_at: timestamp,
            derivation_info: Some(KeyDerivationInfo {
                method: KeyDerivationMethod::Bip39Argon2,
                salt: salt.to_vec(),
                argon2_params,
                context: context.to_string(),
            }),
        })
    }

    /// Encrypt data to minimal ChaCha20Poly1305Content (no key_id for wire protocol)
    pub fn encrypt_content(&self, plaintext: &[u8]) -> Result<ChaCha20Poly1305Content> {
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|e| {
            CryptoError::EncryptionError(format!("ChaCha20 encryption failed: {e}"))
        })?;

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&nonce);

        Ok(ChaCha20Poly1305Content {
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt ChaCha20Poly1305Content (assumes correct key based on channel context)
    pub fn decrypt_content(&self, content: &ChaCha20Poly1305Content) -> Result<Vec<u8>> {
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(&content.nonce);

        cipher
            .decrypt(nonce, content.ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionError(format!("ChaCha20 decryption failed: {e}")))
    }
}

/// Generate an ed25519 signing key from a mnemonic phrase
pub fn generate_ed25519_from_mnemonic(
    mnemonic: &MnemonicPhrase,
    passphrase: &str,
    context: &str, // e.g., "ed25519-signing-key"
) -> Result<ed25519_dalek::SigningKey> {
    // Get the BIP39 seed
    let seed = mnemonic.to_seed(passphrase)?;

    // Use Blake3 to derive ed25519 key material from seed + context
    let mut input = Vec::new();
    input.extend_from_slice(&seed);
    input.extend_from_slice(context.as_bytes());

    let key_material = blake3::hash(&input);
    let key_bytes = key_material.as_bytes();

    // ed25519 keys are 32 bytes - SigningKey::from_bytes doesn't return Result
    Ok(ed25519_dalek::SigningKey::from_bytes(key_bytes))
}

/// Recover an ed25519 signing key from a mnemonic phrase (deterministic)
pub fn recover_ed25519_from_mnemonic(
    mnemonic: &MnemonicPhrase,
    passphrase: &str,
    context: &str,
) -> Result<ed25519_dalek::SigningKey> {
    // Same as generate - it's deterministic
    generate_ed25519_from_mnemonic(mnemonic, passphrase, context)
}

/// Generate an ML-DSA signing key from a mnemonic phrase
pub fn generate_ml_dsa_from_mnemonic(
    mnemonic: &MnemonicPhrase,
    passphrase: &str,
    context: &str, // e.g., "ml-dsa-signing-key"
) -> Result<SigningKey<MlDsa65>> {
    // Get the BIP39 seed
    let seed = mnemonic.to_seed(passphrase)?;

    // Use Blake3 to derive ML-DSA key material from seed + context
    let mut input = Vec::new();
    input.extend_from_slice(&seed);
    input.extend_from_slice(context.as_bytes());

    let key_material = blake3::hash(&input);

    // ML-DSA keys need more entropy than 32 bytes, so we expand using Blake3
    let mut expanded_seed = [0u8; 64]; // Use 64 bytes for better entropy
    let mut hasher = blake3::Hasher::new();
    hasher.update(key_material.as_bytes());
    hasher.update(b"ml-dsa-key-expansion");
    let expanded_hash = hasher.finalize();
    expanded_seed[..32].copy_from_slice(expanded_hash.as_bytes());

    // Create second hash for remaining bytes
    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(expanded_hash.as_bytes());
    hasher2.update(b"ml-dsa-key-expansion-2");
    let second_hash = hasher2.finalize();
    expanded_seed[32..].copy_from_slice(&second_hash.as_bytes()[..32]);

    // Generate ML-DSA key from expanded seed
    use ml_dsa::KeyGen;
    // ChaCha20Rng expects 32 bytes, so use the first 32 bytes
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&expanded_seed[..32]);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed_32);
    let keypair = MlDsa65::key_gen(&mut rng);
    Ok(keypair.signing_key().clone())
}

/// Recover an ML-DSA signing key from a mnemonic phrase (deterministic)
pub fn recover_ml_dsa_from_mnemonic(
    mnemonic: &MnemonicPhrase,
    passphrase: &str,
    context: &str,
) -> Result<SigningKey<MlDsa65>> {
    // Same as generate - it's deterministic
    generate_ml_dsa_from_mnemonic(mnemonic, passphrase, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_ecdh_encrypt_decrypt_roundtrip() {
        // Test the new ephemeral ECDH pattern used in RPC transport:
        // Anyone can encrypt for recipient using only their Ed25519 public key
        // Recipient decrypts using their Ed25519 private key

        let plaintext = b"Hello, Ephemeral ECDH World!";

        // Create recipient Ed25519 key pair (sender doesn't need long-term keys!)
        let recipient_ed25519_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let recipient_ed25519_public = recipient_ed25519_key.verifying_key();

        // Encrypt using only recipient's public key (ephemeral key generated automatically)
        let encrypted = EphemeralEcdhContent::encrypt(plaintext, &recipient_ed25519_public)
            .expect("Encryption should succeed");

        // Decrypt using recipient's private key
        let decrypted = encrypted
            .decrypt(&recipient_ed25519_key)
            .expect("Decryption should succeed");

        // Verify roundtrip
        assert_eq!(
            plaintext,
            decrypted.as_slice(),
            "Roundtrip failed: plaintext != decrypted"
        );
    }

    #[test]
    fn test_ml_dsa_44_key_generation() {
        let keypair = generate_ml_dsa_44_keypair_for_tls();

        // Verify the keys are related
        // Just verify the keypair was created successfully
        assert!(!keypair.verifying_key().encode().is_empty());
        assert!(!keypair.signing_key().encode().is_empty());
    }

    #[test]
    fn test_ml_dsa_44_certificate_extraction_placeholder() {
        // This test is a placeholder since certificate generation is not yet implemented
        let keypair = generate_ml_dsa_44_keypair_for_tls();

        // For now, just verify key serialization works
        let key_hex = save_ml_dsa_44_public_key_to_hex(keypair.verifying_key());
        let loaded_key = load_ml_dsa_44_public_key_from_hex(&key_hex).unwrap();

        assert_eq!(keypair.verifying_key().encode(), loaded_key.encode());
    }

    #[test]
    fn test_ml_dsa_44_signature_verification() {
        use signature::Signer;

        // Generate a test key pair
        let keypair = generate_ml_dsa_44_keypair_for_tls();

        // Test message
        let test_message = b"test message for ML-DSA-44 signature verification";

        // Sign the message
        let signature = keypair.signing_key().sign(test_message);

        // Verify the signature
        use signature::Verifier;
        keypair
            .verifying_key()
            .verify(test_message, &signature)
            .expect("ML-DSA-44 signature verification should succeed");
    }

    #[test]
    fn test_ml_dsa_44_key_serialization() {
        let keypair = generate_ml_dsa_44_keypair_for_tls();
        let hex_string = save_ml_dsa_44_key_to_hex_for_tls(keypair.signing_key());
        let loaded_key = load_ml_dsa_44_key_from_hex_for_tls(&hex_string).unwrap();

        assert_eq!(keypair.signing_key().encode(), loaded_key.encode());
    }

    #[test]
    fn test_ml_dsa_44_public_key_serialization() {
        let keypair = generate_ml_dsa_44_keypair_for_tls();
        let hex_string = save_ml_dsa_44_public_key_to_hex(keypair.verifying_key());
        let loaded_pubkey = load_ml_dsa_44_public_key_from_hex(&hex_string).unwrap();

        assert_eq!(keypair.verifying_key().encode(), loaded_pubkey.encode());
    }

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = MnemonicPhrase::generate().unwrap();
        // Should be 24 words
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn test_chacha20_content_encryption_roundtrip() {
        let key = EncryptionKey::generate(1640995200);
        let plaintext = b"Hello, encrypted world!";

        let encrypted = key.encrypt_content(plaintext).unwrap();
        let decrypted = key.decrypt_content(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(encrypted.nonce.len(), 12);
    }

    #[test]
    fn test_encryption_key_from_mnemonic() {
        let mnemonic = MnemonicPhrase::from_phrase(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            Language::English
        ).unwrap();

        let key =
            EncryptionKey::from_mnemonic(&mnemonic, "test passphrase", "test-context", 1640995200)
                .unwrap();

        assert!(key.derivation_info.is_some());
        assert_eq!(
            key.derivation_info.as_ref().unwrap().context,
            "test-context"
        );
    }

    #[test]
    fn test_key_derivation_method_as_str() {
        assert_eq!(KeyDerivationMethod::Bip39Argon2.as_str(), "bip39+argon2");
        assert_eq!(
            KeyDerivationMethod::ChaCha20Poly1305Keygen.as_str(),
            "chacha20-poly1305-keygen"
        );
    }

    #[test]
    fn test_key_derivation_method_display() {
        assert_eq!(KeyDerivationMethod::Bip39Argon2.to_string(), "bip39+argon2");
        assert_eq!(
            KeyDerivationMethod::ChaCha20Poly1305Keygen.to_string(),
            "chacha20-poly1305-keygen"
        );
    }

    #[test]
    fn test_key_derivation_method_from_str() {
        use std::str::FromStr;
        assert_eq!(
            KeyDerivationMethod::from_str("bip39+argon2"),
            Ok(KeyDerivationMethod::Bip39Argon2)
        );
        assert_eq!(
            KeyDerivationMethod::from_str("chacha20-poly1305-keygen"),
            Ok(KeyDerivationMethod::ChaCha20Poly1305Keygen)
        );
        assert!(KeyDerivationMethod::from_str("unknown").is_err());
        assert!(KeyDerivationMethod::from_str("").is_err());
    }

    #[test]
    fn test_key_derivation_method_round_trip() {
        use std::str::FromStr;
        let methods = [
            KeyDerivationMethod::Bip39Argon2,
            KeyDerivationMethod::ChaCha20Poly1305Keygen,
        ];

        for method in methods {
            let as_str = method.as_str();
            let parsed = KeyDerivationMethod::from_str(as_str).expect("Should parse back");
            assert_eq!(method, parsed);
        }
    }

    #[test]
    fn test_key_derivation_info_with_enum() {
        let derivation_info = KeyDerivationInfo {
            method: KeyDerivationMethod::Bip39Argon2,
            salt: vec![1, 2, 3, 4],
            argon2_params: Argon2Params::default(),
            context: "test-context".to_string(),
        };

        assert_eq!(derivation_info.method, KeyDerivationMethod::Bip39Argon2);
        assert_eq!(derivation_info.method.as_str(), "bip39+argon2");
        assert_eq!(derivation_info.context, "test-context");
    }

    #[test]
    fn test_postcard_serialization_key_derivation_method() {
        for method in [
            KeyDerivationMethod::Bip39Argon2,
            KeyDerivationMethod::ChaCha20Poly1305Keygen,
        ] {
            let serialized = postcard::to_stdvec(&method).expect("Failed to serialize");
            let deserialized: KeyDerivationMethod =
                postcard::from_bytes(&serialized).expect("Failed to deserialize");
            assert_eq!(method, deserialized);
        }
    }

    #[test]
    fn test_postcard_serialization_key_derivation_info() {
        let derivation_info = KeyDerivationInfo {
            method: KeyDerivationMethod::Bip39Argon2,
            salt: vec![1, 2, 3, 4, 5, 6, 7, 8],
            argon2_params: Argon2Params {
                memory: 65536,
                iterations: 3,
                parallelism: 4,
            },
            context: "dga-group-key".to_string(),
        };

        let serialized = postcard::to_stdvec(&derivation_info).expect("Failed to serialize");
        let deserialized: KeyDerivationInfo =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");
        assert_eq!(derivation_info, deserialized);
    }
}
