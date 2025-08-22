//! Hybrid cryptographic key system supporting multiple signature algorithms.
//!
//! This module provides a unified interface for working with different signature algorithms,
//! supporting both legacy Ed25519 and post-quantum ML-DSA signatures. The hybrid approach
//! allows for gradual migration from classical to post-quantum cryptography.
//!
//! ## Supported Algorithms
//!
//! - **Ed25519**: Legacy elliptic curve signatures (32-byte keys, 64-byte signatures)
//! - **ML-DSA-44**: Post-quantum signatures for TLS certificates (~128-bit security)
//! - **ML-DSA-65**: Post-quantum signatures for messages (~192-bit security)
//! - **ML-DSA-87**: Post-quantum signatures for high security (~256-bit security)
//!
//! ## Key Generation
//!
//! ```rust
//! use zoe_wire_protocol::{KeyPair, VerifyingKey, SigningKey, generate_keypair, generate_ed25519_relay_keypair};
//! use rand::rngs::OsRng;
//!
//! // Generate different key types
//! let ed25519_keypair = generate_ed25519_relay_keypair(&mut OsRng);
//! let ml_dsa_65_keypair = generate_keypair(&mut OsRng); // Default: ML-DSA-65
//!
//! // Access keys
//! let verifying_key = ed25519_keypair.public_key();
//! let signature = ed25519_keypair.sign(b"message");
//! ```
//!
//! ## Signing and Verification
//!
//! ```rust
//! use zoe_wire_protocol::{KeyPair, VerifyingKey, SigningKey, generate_keypair};
//! use rand::rngs::OsRng;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let keypair = generate_keypair(&mut OsRng);
//! let message = b"Hello, world!";
//!
//! // Sign message
//! let signature = keypair.sign(message);
//!
//! // Verify signature
//! let verifying_key = keypair.public_key();
//! let is_valid = verifying_key.verify(message, &signature)?;
//! assert!(is_valid);
//! # Ok(())
//! # }
//! ```
//!
//! ## Serialization
//!
//! All key types support postcard serialization for storage and transmission:
//!
//! ```rust
//! use zoe_wire_protocol::{VerifyingKey, Signature};
//!
//! # fn example(verifying_key: VerifyingKey, signature: Signature) -> Result<(), postcard::Error> {
//! // Serialize keys and signatures
//! let key_bytes = verifying_key.encode();
//! let sig_bytes = signature.encode();
//!
//! // Keys can be deserialized using postcard
//! let key_restored: VerifyingKey = postcard::from_bytes(&key_bytes)?;
//! let sig_restored: Signature = postcard::from_bytes(&sig_bytes)?;
//! # Ok(())
//! # }
//! ```
use ml_dsa::KeyGen;
use serde::{Deserialize, Serialize};
use signature::{SignatureEncoding, Signer, Verifier};

/// Public key for signature verification supporting multiple algorithms.
///
/// This enum provides a unified interface for verifying signatures across different
/// cryptographic algorithms, supporting both classical and post-quantum schemes.
///
/// ## Algorithm Selection
///
/// - **Ed25519**: Use for legacy compatibility and smaller key sizes
/// - **ML-DSA-44**: Use for TLS certificates requiring post-quantum security
/// - **ML-DSA-65**: Use for message signatures with strong post-quantum security
/// - **ML-DSA-87**: Use for high-security applications requiring maximum protection
///
/// ## Examples
///
/// ```rust
/// use zoe_wire_protocol::{VerifyingKey, SigningKey, KeyPair, generate_keypair};
/// use rand::rngs::OsRng;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair
/// let keypair = generate_keypair(&mut OsRng);
/// let verifying_key = keypair.public_key();
///
/// // Sign and verify a message
/// let message = b"Hello, world!";
/// let signature = keypair.sign(message);
/// let is_valid = verifying_key.verify(message, &signature)?;
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerifyingKey {
    /// Ed25519 public key (32 bytes)
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
    /// ML-DSA-44 public key (1,312 bytes) - for TLS certificates
    #[serde(with = "crate::serde::VerifyingKeyDef44")]
    MlDsa44(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>),
    /// ML-DSA-65 public key (1,952 bytes) - for message signatures
    #[serde(with = "crate::serde::VerifyingKeyDef65")]
    MlDsa65(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>),
    /// ML-DSA-87 public key (2,592 bytes) - for high security
    #[serde(with = "crate::serde::VerifyingKeyDef87")]
    MlDsa87(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>),
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (VerifyingKey::Ed25519(a), VerifyingKey::Ed25519(b)) => a == b,
            (VerifyingKey::MlDsa44(a), VerifyingKey::MlDsa44(b)) => a == b,
            (VerifyingKey::MlDsa65(a), VerifyingKey::MlDsa65(b)) => a == b,
            (VerifyingKey::MlDsa87(a), VerifyingKey::MlDsa87(b)) => a == b,
            _ => false,
        }
    }
}

impl std::hash::Hash for VerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            VerifyingKey::Ed25519(key) => {
                key.hash(state);
            }
            VerifyingKey::MlDsa44(key) => {
                key.encode().hash(state);
            }
            VerifyingKey::MlDsa65(key) => {
                key.encode().hash(state);
            }
            VerifyingKey::MlDsa87(key) => {
                key.encode().hash(state);
            }
        }
    }
}

impl VerifyingKey {
    /// Verify a signature against a message using the appropriate algorithm.
    ///
    /// This method automatically matches the signature type with the key type
    /// and returns `Ok(false)` if they don't match (rather than an error).
    ///
    /// # Arguments
    ///
    /// * `message` - The message bytes that were signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Signature is valid for this key and message
    /// * `Ok(false)` - Signature is invalid or key/signature types don't match
    /// * `Err(_)` - Verification error (malformed signature, etc.)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use zoe_wire_protocol::{KeyPair, VerifyingKey, SigningKey, generate_ed25519_relay_keypair};
    /// use rand::rngs::OsRng;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let keypair = generate_ed25519_relay_keypair(&mut OsRng);
    /// let message = b"Hello, world!";
    /// let signature = keypair.sign(message);
    /// let verifying_key = keypair.public_key();
    ///
    /// let is_valid = verifying_key.verify(message, &signature)?;
    /// assert!(is_valid);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match (self, signature) {
            (VerifyingKey::Ed25519(key), Signature::Ed25519(sig)) => {
                Ok(key.verify(message, sig).is_ok())
            }
            (VerifyingKey::MlDsa44(key), Signature::MlDsa44(sig)) => {
                Ok(key.verify(message, sig).is_ok())
            }
            (VerifyingKey::MlDsa65(key), Signature::MlDsa65(sig)) => {
                Ok(key.verify(message, sig).is_ok())
            }
            (VerifyingKey::MlDsa87(key), Signature::MlDsa87(sig)) => {
                Ok(key.verify(message, sig).is_ok())
            }
            _ => Ok(false), // Mismatched key and signature types
        }
    }

    /// Encode the VerifyingKey to bytes for serialization.
    ///
    /// This method serializes the key using postcard format for efficient storage
    /// and transmission. The resulting bytes can be deserialized back to a
    /// `VerifyingKey` using `postcard::from_bytes()`.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the serialized key data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use zoe_wire_protocol::{KeyPair, VerifyingKey, generate_ed25519_relay_keypair};
    /// use rand::rngs::OsRng;
    ///
    /// let keypair = generate_ed25519_relay_keypair(&mut OsRng);
    /// let verifying_key = keypair.public_key();
    ///
    /// // Serialize the key
    /// let key_bytes = verifying_key.encode();
    ///
    /// // Deserialize it back
    /// let restored_key: VerifyingKey = postcard::from_bytes(&key_bytes).unwrap();
    /// assert_eq!(&verifying_key, &restored_key);
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("Failed to serialize VerifyingKey")
    }
}

/// Private key for creating digital signatures supporting multiple algorithms.
///
/// This enum provides a unified interface for signing messages across different
/// cryptographic algorithms, supporting both classical and post-quantum schemes.
///
/// ## Security Considerations
///
/// - **Keep private keys secure**: Never transmit or store signing keys in plaintext
/// - **Use appropriate key sizes**: ML-DSA keys are larger but provide post-quantum security
/// - **Match key types**: Ensure the signing key matches the expected verifying key type
///
/// ## Examples
///
/// ```rust
/// use zoe_wire_protocol::{KeyPair, SigningKey, VerifyingKey, generate_keypair};
/// use rand::rngs::OsRng;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Generate a keypair
/// let keypair = generate_keypair(&mut OsRng);
///
/// // Sign a message
/// let message = b"Important message";
/// let signature = keypair.sign(message);
///
/// // Verify with corresponding public key
/// let verifying_key = keypair.public_key();
/// let is_valid = verifying_key.verify(message, &signature)?;
/// assert!(is_valid);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningKey {
    /// Ed25519 private key (32 bytes)
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// ML-DSA-44 private key - for TLS certificates
    #[serde(with = "crate::serde::SigningKeyDef44")]
    MlDsa44(Box<ml_dsa::SigningKey<ml_dsa::MlDsa44>>),
    /// ML-DSA-65 private key - for message signatures
    #[serde(with = "crate::serde::SigningKeyDef65")]
    MlDsa65(Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>),
    /// ML-DSA-87 private key - for high security
    #[serde(with = "crate::serde::SigningKeyDef87")]
    MlDsa87(Box<ml_dsa::SigningKey<ml_dsa::MlDsa87>>),
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SigningKey::Ed25519(a), SigningKey::Ed25519(b)) => a == b,
            (SigningKey::MlDsa44(a), SigningKey::MlDsa44(b)) => a == b,
            (SigningKey::MlDsa65(a), SigningKey::MlDsa65(b)) => a == b,
            (SigningKey::MlDsa87(a), SigningKey::MlDsa87(b)) => a == b,
            _ => false,
        }
    }
}

impl SigningKey {
    /// Sign a message with this signing key
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            SigningKey::Ed25519(key) => Signature::Ed25519(Box::new(key.sign(message))),
            SigningKey::MlDsa44(key) => Signature::MlDsa44(Box::new(key.sign(message))),
            SigningKey::MlDsa65(key) => Signature::MlDsa65(Box::new(key.sign(message))),
            SigningKey::MlDsa87(key) => Signature::MlDsa87(Box::new(key.sign(message))),
        }
    }
}

impl Signature {
    /// Encode the Signature to bytes for serialization
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("Failed to serialize Signature")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Signature {
    Ed25519(Box<ed25519_dalek::Signature>),
    #[serde(with = "crate::serde::SignatureDef44")]
    MlDsa44(Box<ml_dsa::Signature<ml_dsa::MlDsa44>>),
    #[serde(with = "crate::serde::SignatureDef65")]
    MlDsa65(Box<ml_dsa::Signature<ml_dsa::MlDsa65>>),
    #[serde(with = "crate::serde::SignatureDef87")]
    MlDsa87(Box<ml_dsa::Signature<ml_dsa::MlDsa87>>),
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(std::cmp::Ordering::Equal)
    }
}

/// Signature "ordering" is used as tie-breaker for messages with the same timestamp,
///
/// The order is determined by the signature index (the higher the index in the enum, the higher the signature)
/// and if they are the same by comparing the signature bytes directly with each other.
impl PartialOrd for Signature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        // we first compare the signature index,
        let my_key = match self {
            Signature::Ed25519(_) => 0,
            Signature::MlDsa44(_) => 1,
            Signature::MlDsa65(_) => 2,
            Signature::MlDsa87(_) => 3,
        };
        let other_key_idx = match other {
            Signature::Ed25519(_) => 0,
            Signature::MlDsa44(_) => 1,
            Signature::MlDsa65(_) => 2,
            Signature::MlDsa87(_) => 3,
        };
        if my_key < other_key_idx {
            Some(std::cmp::Ordering::Less)
        } else if my_key > other_key_idx {
            Some(std::cmp::Ordering::Greater)
        } else {
            //  only compare the content if the signature index is the same
            match (self, other) {
                (Signature::Ed25519(a), Signature::Ed25519(b)) => {
                    a.to_bytes().partial_cmp(&b.to_bytes())
                }
                (Signature::MlDsa44(a), Signature::MlDsa44(b)) => {
                    a.to_bytes().partial_cmp(&b.to_bytes())
                }
                (Signature::MlDsa65(a), Signature::MlDsa65(b)) => {
                    a.to_bytes().partial_cmp(&b.to_bytes())
                }
                (Signature::MlDsa87(a), Signature::MlDsa87(b)) => {
                    a.to_bytes().partial_cmp(&b.to_bytes())
                }
                _ => None,
            }
        }
    }
}

pub enum KeyPair {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    MlDsa44(Box<ml_dsa::KeyPair<ml_dsa::MlDsa44>>),
    MlDsa65(Box<ml_dsa::KeyPair<ml_dsa::MlDsa65>>),
    MlDsa87(Box<ml_dsa::KeyPair<ml_dsa::MlDsa87>>),
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (KeyPair::Ed25519(a), KeyPair::Ed25519(b)) => a.to_bytes() == b.to_bytes(),
            (KeyPair::MlDsa44(a), KeyPair::MlDsa44(b)) => {
                a.signing_key().encode() == b.signing_key().encode()
            }
            (KeyPair::MlDsa65(a), KeyPair::MlDsa65(b)) => {
                a.signing_key().encode() == b.signing_key().encode()
            }
            (KeyPair::MlDsa87(a), KeyPair::MlDsa87(b)) => {
                a.signing_key().encode() == b.signing_key().encode()
            }
            _ => false,
        }
    }
}

impl KeyPair {
    pub fn public_key(&self) -> VerifyingKey {
        match self {
            KeyPair::Ed25519(a) => VerifyingKey::Ed25519(Box::new(a.verifying_key())),
            KeyPair::MlDsa44(a) => VerifyingKey::MlDsa44(Box::new(a.verifying_key().clone())),
            KeyPair::MlDsa65(a) => VerifyingKey::MlDsa65(Box::new(a.verifying_key().clone())),
            KeyPair::MlDsa87(a) => VerifyingKey::MlDsa87(Box::new(a.verifying_key().clone())),
        }
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            KeyPair::Ed25519(a) => Signature::Ed25519(Box::new(a.sign(message))),
            KeyPair::MlDsa44(a) => Signature::MlDsa44(Box::new(a.sign(message))),
            KeyPair::MlDsa65(a) => Signature::MlDsa65(Box::new(a.sign(message))),
            KeyPair::MlDsa87(a) => Signature::MlDsa87(Box::new(a.sign(message))),
        }
    }
}

/// Generate a new ML-DSA keypair using the default parameters (MlDsa65)
pub fn generate_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    KeyPair::MlDsa65(Box::new(<ml_dsa::MlDsa65 as KeyGen>::key_gen(rng)))
}

/// Generate a new Ed25519 keypair for relay operations
pub fn generate_ed25519_relay_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    KeyPair::Ed25519(Box::new(ed25519_dalek::SigningKey::generate(rng)))
}

/// Convert VerifyingKey to bytes for compatibility with existing serialization
pub fn verifying_key_to_bytes(key: &VerifyingKey) -> Vec<u8> {
    postcard::to_stdvec(key).expect("Failed to serialize VerifyingKey")
}

/// Create VerifyingKey from bytes
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, ml_dsa::Error> {
    let key: VerifyingKey = postcard::from_bytes(bytes).map_err(|_| ml_dsa::Error::new())?;
    Ok(key)
}

/// Convert SigningKey to bytes for compatibility with existing serialization
pub fn signing_key_to_bytes(key: &SigningKey) -> Vec<u8> {
    postcard::to_stdvec(key).expect("Failed to serialize SigningKey")
}

/// Create SigningKey from bytes
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, ml_dsa::Error> {
    let key: SigningKey = postcard::from_bytes(bytes).map_err(|_| ml_dsa::Error::new())?;
    Ok(key)
}
