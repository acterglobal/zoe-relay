//! Message-level cryptography for the Zoe protocol
//!
//! This module provides cryptographic primitives for message encryption, key derivation,
//! and mnemonic-based key management used in the Zoe messaging protocol.
//!
//! # Key Features
//!
//! - ChaCha20-Poly1305 encryption for message content
//! - BIP39 mnemonic phrase support for key derivation
//! - Ed25519 and ML-DSA key generation from mnemonics
//! - Self-encryption and ephemeral ECDH patterns
//! - Argon2 key derivation with configurable parameters

use libcrux_ml_dsa::ml_dsa_65::MLDSA65SigningKey;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

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

    #[error("TLS configuration error: {0}")]
    TlsError(String),
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
    pub fn generate() -> std::result::Result<Self, CryptoError> {
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
    pub fn from_phrase(phrase: &str, language: Language) -> std::result::Result<Self, CryptoError> {
        // Validate the mnemonic
        Mnemonic::parse_in(language, phrase)
            .map_err(|e| CryptoError::MnemonicError(format!("Invalid mnemonic phrase: {e}")))?;

        Ok(Self {
            phrase: phrase.to_string(),
            language,
        })
    }

    /// Derive a seed from the mnemonic with optional passphrase
    pub fn to_seed(&self, passphrase: &str) -> std::result::Result<[u8; 64], CryptoError> {
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
#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptionKey {
    /// The actual key bytes (32 bytes for ChaCha20)
    pub key: [u8; 32],
    /// blake3 of the key
    pub key_id: crate::Hash,
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

/// PQXDH encrypted content for asynchronous secure communication
///
/// This supports both initial handshake messages (Phase 2) and ongoing
/// session messages (Phase 3) of the PQXDH protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PqxdhEncryptedContent {
    /// Initial PQXDH handshake message that establishes the session
    /// and delivers the first encrypted payload
    Initial(crate::inbox::pqxdh::PqxdhInitialMessage),

    /// Follow-up session message using established shared secret
    /// for efficient ongoing communication
    Session(crate::inbox::pqxdh::PqxdhSessionMessage),
}

impl Ed25519SelfEncryptedContent {
    /// Encrypt data using ed25519 private key (self-encryption)
    /// Derives a ChaCha20 key from the ed25519 private key deterministically
    /// Only the same private key can decrypt this content
    pub fn encrypt(
        plaintext: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
    ) -> std::result::Result<Self, CryptoError> {
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
    pub fn decrypt(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> std::result::Result<Vec<u8>, CryptoError> {
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
    pub fn encrypt(
        plaintext: &[u8],
        signing_key: &MLDSA65SigningKey,
    ) -> std::result::Result<Self, CryptoError> {
        use chacha20poly1305::aead::{Aead, OsRng};
        use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit};

        // Derive ChaCha20 key from ML-DSA private key using Blake3
        let ml_dsa_private_bytes = signing_key.as_slice();
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(ml_dsa_private_bytes);
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
    pub fn decrypt(
        &self,
        signing_key: &MLDSA65SigningKey,
    ) -> std::result::Result<Vec<u8>, CryptoError> {
        use chacha20poly1305::aead::Aead;
        use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};

        // Derive the same ChaCha20 key from ML-DSA private key
        let ml_dsa_private_bytes = signing_key.as_slice();
        let mut key_derivation_input = Vec::new();
        key_derivation_input.extend_from_slice(ml_dsa_private_bytes);
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
    ) -> std::result::Result<Self, CryptoError> {
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
    pub fn decrypt(
        &self,
        recipient_ed25519_key: &ed25519_dalek::SigningKey,
    ) -> std::result::Result<Vec<u8>, CryptoError> {
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
) -> std::result::Result<X25519PrivateKey, CryptoError> {
    // Ed25519 private key is the same as X25519 private key (both are 32-byte scalars)
    let ed25519_bytes = ed25519_key.to_bytes();
    Ok(X25519PrivateKey::from(ed25519_bytes))
}

/// Convert Ed25519 public key to X25519 public key
/// Derives X25519 public key from the corresponding Ed25519 private key
/// Note: This is a simplified approach that requires the private key
pub fn ed25519_to_x25519_public(
    ed25519_private_key: &ed25519_dalek::SigningKey,
) -> std::result::Result<X25519PublicKey, CryptoError> {
    // Convert Ed25519 private key to X25519 private key, then derive public
    let x25519_private = ed25519_to_x25519_private(ed25519_private_key)?;
    Ok(X25519PublicKey::from(&x25519_private))
}

/// Convert Ed25519 public key (VerifyingKey) to X25519 public key
/// Uses curve25519-dalek's Edwards to Montgomery conversion to match
/// the same conversion that happens in the private key derivation path
pub fn ed25519_to_x25519_public_from_verifying_key(
    ed25519_public: &ed25519_dalek::VerifyingKey,
) -> std::result::Result<X25519PublicKey, CryptoError> {
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
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        thread_rng().fill_bytes(&mut key);
        let key_id = blake3::hash(&key);

        Self {
            key,
            key_id,
            derivation_info: None,
        }
    }

    /// Derive an encryption key from a mnemonic phrase
    pub fn from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        context: &str, // e.g., "dga-group-key"
    ) -> std::result::Result<Self, CryptoError> {
        // Generate a random salt
        let mut salt = [0u8; 32];
        thread_rng().fill_bytes(&mut salt);

        Self::from_mnemonic_with_salt(mnemonic, passphrase, context, &salt)
    }

    /// Derive an encryption key from a mnemonic phrase with specific salt (for key recovery)
    pub fn from_mnemonic_with_salt(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        context: &str,
        salt: &[u8; 32],
    ) -> std::result::Result<Self, CryptoError> {
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
        let key_id = blake3::hash(&key_id_input);

        Ok(Self {
            key,
            key_id,
            derivation_info: Some(KeyDerivationInfo {
                method: KeyDerivationMethod::Bip39Argon2,
                salt: salt.to_vec(),
                argon2_params,
                context: context.to_string(),
            }),
        })
    }

    /// Encrypt data to minimal ChaCha20Poly1305Content (no key_id for wire protocol)
    pub fn encrypt_content(
        &self,
        plaintext: &[u8],
    ) -> std::result::Result<ChaCha20Poly1305Content, CryptoError> {
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
    pub fn decrypt_content(
        &self,
        content: &ChaCha20Poly1305Content,
    ) -> std::result::Result<Vec<u8>, CryptoError> {
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
) -> std::result::Result<ed25519_dalek::SigningKey, CryptoError> {
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
) -> std::result::Result<ed25519_dalek::SigningKey, CryptoError> {
    // Same as generate - it's deterministic
    generate_ed25519_from_mnemonic(mnemonic, passphrase, context)
}

/// Generate an ML-DSA signing key from a mnemonic phrase
pub fn generate_ml_dsa_from_mnemonic(
    mnemonic: &MnemonicPhrase,
    passphrase: &str,
    context: &str, // e.g., "ml-dsa-signing-key"
) -> std::result::Result<MLDSA65SigningKey, CryptoError> {
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
    use libcrux_ml_dsa::{ml_dsa_65, KEY_GENERATION_RANDOMNESS_SIZE};
    use rand::RngCore;
    // ChaCha20Rng expects 32 bytes, so use the first 32 bytes
    let mut seed_32 = [0u8; 32];
    seed_32.copy_from_slice(&expanded_seed[..32]);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed_32);
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    rng.fill_bytes(&mut randomness);
    let keypair = ml_dsa_65::portable::generate_key_pair(randomness);
    Ok(keypair.signing_key)
}

/// Recover an ML-DSA signing key from a mnemonic phrase (deterministic)
pub fn recover_ml_dsa_from_mnemonic(
    mnemonic: &MnemonicPhrase,
    passphrase: &str,
    context: &str,
) -> std::result::Result<MLDSA65SigningKey, CryptoError> {
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
    fn test_mnemonic_generation() {
        let mnemonic = MnemonicPhrase::generate().unwrap();
        // Should be 24 words
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn test_chacha20_content_encryption_roundtrip() {
        let key = EncryptionKey::generate();
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
            EncryptionKey::from_mnemonic(&mnemonic, "test passphrase", "test-context").unwrap();

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
