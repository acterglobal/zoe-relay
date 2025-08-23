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
use crate::Hash;
use ml_dsa::KeyGen;
use serde::{Deserialize, Serialize};
use signature::{Signer, Verifier};

// A short hand hash or content of the inner signature or key
pub type Id = [u8; 32];

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
    #[serde(with = "serde_helpers::VerifyingKeyDef44")]
    MlDsa44((Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>, Hash)),
    /// ML-DSA-65 public key (1,952 bytes) - for message signatures
    #[serde(with = "serde_helpers::VerifyingKeyDef65")]
    MlDsa65((Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>, Hash)),
    /// ML-DSA-87 public key (2,592 bytes) - for high security
    #[serde(with = "serde_helpers::VerifyingKeyDef87")]
    MlDsa87((Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>, Hash)),
}

impl From<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>> for VerifyingKey {
    fn from(key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>) -> Self {
        let hash = blake3::hash(key.encode().as_slice());
        VerifyingKey::MlDsa44((Box::new(key), hash))
    }
}

impl From<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> for VerifyingKey {
    fn from(key: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>) -> Self {
        let hash = blake3::hash(key.encode().as_slice());
        VerifyingKey::MlDsa65((Box::new(key), hash))
    }
}

impl From<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>> for VerifyingKey {
    fn from(key: ml_dsa::VerifyingKey<ml_dsa::MlDsa87>) -> Self {
        let hash = blake3::hash(key.encode().as_slice());
        VerifyingKey::MlDsa87((Box::new(key), hash))
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}

impl Eq for VerifyingKey {}

impl PartialOrd for VerifyingKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerifyingKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // we order by index first
        let my_key = match self {
            VerifyingKey::Ed25519(_) => 0,
            VerifyingKey::MlDsa44(..) => 1,
            VerifyingKey::MlDsa65(..) => 2,
            VerifyingKey::MlDsa87(..) => 3,
        };
        let other_key_idx = match other {
            VerifyingKey::Ed25519(_) => 0,
            VerifyingKey::MlDsa44(..) => 1,
            VerifyingKey::MlDsa65(..) => 2,
            VerifyingKey::MlDsa87(..) => 3,
        };
        if my_key < other_key_idx {
            return std::cmp::Ordering::Less;
        } else if my_key > other_key_idx {
            return std::cmp::Ordering::Greater;
        }
        // we only check the bytes if we are of the same type
        self.id().cmp(other.id())
    }
}

impl std::hash::Hash for VerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id().hash(state);
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = ml_dsa::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let key: VerifyingKey = postcard::from_bytes(value).map_err(|_| ml_dsa::Error::new())?;
        Ok(key)
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
            (VerifyingKey::MlDsa44((key, _hash)), Signature::MlDsa44((sig, _hash2))) => {
                Ok(key.verify(message, sig).is_ok())
            }
            (VerifyingKey::MlDsa65((key, _hash)), Signature::MlDsa65((sig, _hash2))) => {
                Ok(key.verify(message, sig).is_ok())
            }
            (VerifyingKey::MlDsa87((key, _hash)), Signature::MlDsa87((sig, _hash2))) => {
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

    pub fn id(&self) -> &Id {
        match self {
            VerifyingKey::Ed25519(key) => key.as_bytes(),
            VerifyingKey::MlDsa44((_key, hash)) => hash.as_bytes(),
            VerifyingKey::MlDsa65((_key, hash)) => hash.as_bytes(),
            VerifyingKey::MlDsa87((_key, hash)) => hash.as_bytes(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
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
#[derive(Debug, Clone)]
pub enum SigningKey {
    /// Ed25519 private key (32 bytes)
    Ed25519(Box<ed25519_dalek::SigningKey>),
    /// ML-DSA-44 private key - for TLS certificates
    MlDsa44((Box<ml_dsa::SigningKey<ml_dsa::MlDsa44>>, Hash)),
    /// ML-DSA-65 private key - for message signatures
    MlDsa65((Box<ml_dsa::SigningKey<ml_dsa::MlDsa65>>, Hash)),
    /// ML-DSA-87 private key - for high security
    MlDsa87((Box<ml_dsa::SigningKey<ml_dsa::MlDsa87>>, Hash)),
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SigningKey::Ed25519(a), SigningKey::Ed25519(b)) => a == b,
            (SigningKey::MlDsa44((a, _)), SigningKey::MlDsa44((b, _))) => a == b,
            (SigningKey::MlDsa65((a, _)), SigningKey::MlDsa65((b, _))) => a == b,
            (SigningKey::MlDsa87((a, _)), SigningKey::MlDsa87((b, _))) => a == b,
            _ => false,
        }
    }
}

impl SigningKey {
    /// Sign a message with this signing key
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            SigningKey::Ed25519(key) => Signature::Ed25519(Box::new(key.sign(message))),
            SigningKey::MlDsa44((key, _)) => key.sign(message).into(),
            SigningKey::MlDsa65((key, _)) => key.sign(message).into(),
            SigningKey::MlDsa87((key, _)) => key.sign(message).into(),
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
    #[serde(with = "serde_helpers::SignatureDef44")]
    MlDsa44((Box<ml_dsa::Signature<ml_dsa::MlDsa44>>, Hash)),
    #[serde(with = "serde_helpers::SignatureDef65")]
    MlDsa65((Box<ml_dsa::Signature<ml_dsa::MlDsa65>>, Hash)),
    #[serde(with = "serde_helpers::SignatureDef87")]
    MlDsa87((Box<ml_dsa::Signature<ml_dsa::MlDsa87>>, Hash)),
}

impl From<ml_dsa::Signature<ml_dsa::MlDsa44>> for Signature {
    fn from(sig: ml_dsa::Signature<ml_dsa::MlDsa44>) -> Self {
        let hash = blake3::hash(sig.encode().as_slice());
        Signature::MlDsa44((Box::new(sig), hash))
    }
}

impl From<ml_dsa::Signature<ml_dsa::MlDsa65>> for Signature {
    fn from(sig: ml_dsa::Signature<ml_dsa::MlDsa65>) -> Self {
        let hash = blake3::hash(sig.encode().as_slice());
        Signature::MlDsa65((Box::new(sig), hash))
    }
}

impl From<ml_dsa::Signature<ml_dsa::MlDsa87>> for Signature {
    fn from(sig: ml_dsa::Signature<ml_dsa::MlDsa87>) -> Self {
        let hash = blake3::hash(sig.encode().as_slice());
        Signature::MlDsa87((Box::new(sig), hash))
    }
}

impl Signature {
    pub fn id(&self) -> &Id {
        match self {
            Signature::Ed25519(sig) => sig.s_bytes(),
            Signature::MlDsa44((_sig, hash)) => hash.as_bytes(),
            Signature::MlDsa65((_sig, hash)) => hash.as_bytes(),
            Signature::MlDsa87((_sig, hash)) => hash.as_bytes(),
        }
    }
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
            Signature::MlDsa44(..) => 1,
            Signature::MlDsa65(..) => 2,
            Signature::MlDsa87(..) => 3,
        };
        let other_key_idx = match other {
            Signature::Ed25519(_) => 0,
            Signature::MlDsa44(..) => 1,
            Signature::MlDsa65(..) => 2,
            Signature::MlDsa87(..) => 3,
        };
        if my_key < other_key_idx {
            return Some(std::cmp::Ordering::Less);
        } else if my_key > other_key_idx {
            return Some(std::cmp::Ordering::Greater);
        }
        self.id().partial_cmp(other.id())
    }
}

#[derive(Debug)]
pub enum KeyPair {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    MlDsa44(Box<ml_dsa::KeyPair<ml_dsa::MlDsa44>>, Hash),
    MlDsa65(Box<ml_dsa::KeyPair<ml_dsa::MlDsa65>>, Hash),
    MlDsa87(Box<ml_dsa::KeyPair<ml_dsa::MlDsa87>>, Hash),
}

impl KeyPair {
    pub fn id(&self) -> &Id {
        match self {
            KeyPair::Ed25519(key) => key.as_bytes(),
            KeyPair::MlDsa44(_key, hash) => hash.as_bytes(),
            KeyPair::MlDsa65(_key, hash) => hash.as_bytes(),
            KeyPair::MlDsa87(_key, hash) => hash.as_bytes(),
        }
    }
    pub fn public_key(&self) -> VerifyingKey {
        self.into()
    }
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (KeyPair::Ed25519(a), KeyPair::Ed25519(b)) => a.to_bytes() == b.to_bytes(),
            (KeyPair::MlDsa44(_, hash), KeyPair::MlDsa44(_, hash_other)) => hash == hash_other,
            (KeyPair::MlDsa65(_, hash), KeyPair::MlDsa65(_, hash_other)) => hash == hash_other,
            (KeyPair::MlDsa87(_, hash), KeyPair::MlDsa87(_, hash_other)) => hash == hash_other,
            _ => false,
        }
    }
}

impl From<&KeyPair> for VerifyingKey {
    fn from(val: &KeyPair) -> Self {
        match val {
            KeyPair::Ed25519(a) => VerifyingKey::Ed25519(Box::new(a.verifying_key())),
            KeyPair::MlDsa44(a, hash) => {
                // the keypair hash is over the verifying key, so we can just use the hash
                let key = a.verifying_key().clone();
                VerifyingKey::MlDsa44((Box::new(key), *hash))
            }
            KeyPair::MlDsa65(a, hash) => {
                let key = a.verifying_key().clone();
                VerifyingKey::MlDsa65((Box::new(key), *hash))
            }
            KeyPair::MlDsa87(a, hash) => {
                let key = a.verifying_key().clone();
                VerifyingKey::MlDsa87((Box::new(key), *hash))
            }
        }
    }
}

impl KeyPair {
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            KeyPair::Ed25519(a) => Signature::Ed25519(Box::new(a.sign(message))),
            KeyPair::MlDsa44(a, _) => {
                let signature = a.sign(message);
                let hash = blake3::hash(signature.encode().as_slice());
                Signature::MlDsa44((Box::new(signature), hash))
            }
            KeyPair::MlDsa65(a, _) => {
                let signature = a.sign(message);
                let hash = blake3::hash(signature.encode().as_slice());
                Signature::MlDsa65((Box::new(signature), hash))
            }
            KeyPair::MlDsa87(a, _) => {
                let signature = a.sign(message);
                let hash = blake3::hash(signature.encode().as_slice());
                Signature::MlDsa87((Box::new(signature), hash))
            }
        }
    }

    pub fn generate_ml_dsa44<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
        let key = ml_dsa::MlDsa44::key_gen(rng);
        let hash = blake3::hash(key.verifying_key().encode().as_slice());
        KeyPair::MlDsa44(Box::new(key), hash)
    }

    pub fn generate_ml_dsa65<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
        let key = ml_dsa::MlDsa65::key_gen(rng);
        let hash = blake3::hash(key.verifying_key().encode().as_slice());
        KeyPair::MlDsa65(Box::new(key), hash)
    }

    pub fn generate_ml_dsa87<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
        let key = ml_dsa::MlDsa87::key_gen(rng);
        let hash = blake3::hash(key.verifying_key().encode().as_slice());
        KeyPair::MlDsa87(Box::new(key), hash)
    }

    pub fn generate<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
        KeyPair::generate_ml_dsa65(rng)
    }

    pub fn generate_ed25519<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
        KeyPair::Ed25519(Box::new(ed25519_dalek::SigningKey::generate(rng)))
    }
}

/// Generate a keypair using the default parameters
#[deprecated(note = "Use KeyPair::generate instead")]
pub fn generate_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    KeyPair::generate_ml_dsa65(rng)
}

/// Generate a new Ed25519 keypair for relay operations
#[deprecated(note = "Use KeyPair::generate_ed25519 instead")]
pub fn generate_ed25519_relay_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    KeyPair::Ed25519(Box::new(ed25519_dalek::SigningKey::generate(rng)))
}

/// Convert VerifyingKey to bytes for compatibility with existing serialization
#[deprecated(note = "Use VerifyingKey.to_bytes instead")]
pub fn verifying_key_to_bytes(key: &VerifyingKey) -> Vec<u8> {
    postcard::to_stdvec(key).expect("Failed to serialize VerifyingKey")
}

/// Create VerifyingKey from bytes
#[deprecated(note = "Use VerifyingKey::try_from instead")]
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, ml_dsa::Error> {
    let key: VerifyingKey = postcard::from_bytes(bytes).map_err(|_| ml_dsa::Error::new())?;
    Ok(key)
}

mod serde_helpers {
    #![allow(clippy::borrowed_box)]

    use crate::Hash;
    use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
    use ml_dsa;

    /// Remote serde definition for ML-DSA-44 VerifyingKey
    /// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef44")]
    pub struct VerifyingKeyDef44;

    impl VerifyingKeyDef44 {
        pub fn serialize<S>(
            key: &(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>, Hash),
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = key.0.encode().as_slice().to_vec();
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>, Hash), D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let encoded =
                ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(bytes.as_slice())
                    .map_err(::serde::de::Error::custom)?;
            let hash = blake3::hash(bytes.as_slice());
            let key = Box::new(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded));
            Ok((key, hash))
        }
    }

    /// Remote serde definition for ML-DSA-65 VerifyingKey
    /// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef65")]
    pub struct VerifyingKeyDef65;

    impl VerifyingKeyDef65 {
        pub fn serialize<S>(
            key: &(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>, Hash),
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = key.0.encode().as_slice().to_vec();
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>>, Hash), D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let encoded =
                ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(bytes.as_slice())
                    .map_err(::serde::de::Error::custom)?;
            let hash = blake3::hash(bytes.as_slice());
            let key = Box::new(ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded));
            Ok((key, hash))
        }
    }

    /// Remote serde definition for ML-DSA-87 VerifyingKey
    /// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef87")]
    pub struct VerifyingKeyDef87;

    impl VerifyingKeyDef87 {
        pub fn serialize<S>(
            key: &(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>, Hash),
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = key.0.encode().as_slice().to_vec();
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<(Box<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>>, Hash), D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let encoded =
                ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(bytes.as_slice())
                    .map_err(::serde::de::Error::custom)?;
            let hash = blake3::hash(bytes.as_slice());
            let key = Box::new(ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&encoded));
            Ok((key, hash))
        }
    }
    /// Remote serde definition for ML-DSA-44 Signature
    /// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef44")]
    pub struct SignatureDef44;
    impl SignatureDef44 {
        pub fn serialize<S>(
            sig: &(Box<ml_dsa::Signature<ml_dsa::MlDsa44>>, Hash),
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = sig.0.encode().as_slice().to_vec();
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<(Box<ml_dsa::Signature<ml_dsa::MlDsa44>>, Hash), D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let encoded = ml_dsa::EncodedSignature::<ml_dsa::MlDsa44>::try_from(bytes.as_slice())
                .map_err(::serde::de::Error::custom)?;
            let sig = Box::new(
                ml_dsa::Signature::<ml_dsa::MlDsa44>::decode(&encoded).ok_or_else(|| {
                    ::serde::de::Error::custom("Failed to deserialize ML-DSA-44 encoded signature")
                })?,
            );
            let hash = blake3::hash(bytes.as_slice());
            Ok((sig, hash))
        }
    }

    /// Remote serde definition for ML-DSA-65 Signature
    /// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef65")]
    pub struct SignatureDef65;

    impl SignatureDef65 {
        pub fn serialize<S>(
            sig: &(Box<ml_dsa::Signature<ml_dsa::MlDsa65>>, Hash),
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = sig.0.encode().as_slice().to_vec();
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<(Box<ml_dsa::Signature<ml_dsa::MlDsa65>>, Hash), D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let encoded = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(bytes.as_slice())
                .map_err(::serde::de::Error::custom)?;
            let sig = Box::new(
                ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&encoded).ok_or_else(|| {
                    ::serde::de::Error::custom("Failed to deserialize ML-DSA-65 encoded signature")
                })?,
            );
            let hash = blake3::hash(bytes.as_slice());
            Ok((sig, hash))
        }
    }

    /// Remote serde definition for ML-DSA-87 Signature
    /// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef87")]
    pub struct SignatureDef87;

    impl SignatureDef87 {
        pub fn serialize<S>(
            sig: &(Box<ml_dsa::Signature<ml_dsa::MlDsa87>>, Hash),
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let bytes = sig.0.encode().as_slice().to_vec();
            bytes.serialize(serializer)
        }

        pub fn deserialize<'de, D>(
            deserializer: D,
        ) -> Result<(Box<ml_dsa::Signature<ml_dsa::MlDsa87>>, Hash), D::Error>
        where
            D: Deserializer<'de>,
        {
            let bytes = Vec::<u8>::deserialize(deserializer)?;
            let encoded = ml_dsa::EncodedSignature::<ml_dsa::MlDsa87>::try_from(bytes.as_slice())
                .map_err(::serde::de::Error::custom)?;
            let sig = Box::new(
                ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(&encoded).ok_or_else(|| {
                    ::serde::de::Error::custom("Failed to deserialize ML-DSA-87 encoded signature")
                })?,
            );
            let hash = blake3::hash(bytes.as_slice());
            Ok((sig, hash))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::collections::{BTreeSet, HashSet};

    /// Test helper to create test keypairs of all types
    fn create_test_keypairs() -> Vec<KeyPair> {
        let mut rng = OsRng;
        vec![
            generate_ed25519_relay_keypair(&mut rng),
            KeyPair::generate_ml_dsa44(&mut rng),
            KeyPair::generate_ml_dsa65(&mut rng),
            KeyPair::generate_ml_dsa87(&mut rng),
        ]
    }

    /// Test helper to create verifying keys of all types
    fn create_test_verifying_keys() -> Vec<VerifyingKey> {
        create_test_keypairs()
            .iter()
            .map(|kp| kp.public_key())
            .collect()
    }

    #[test]
    fn test_verifying_key_equality_and_id_consistency() {
        let keypairs = create_test_keypairs();

        for keypair in &keypairs {
            let key1 = keypair.public_key();
            let key2 = keypair.public_key();

            // Same keypair should produce equal verifying keys
            assert_eq!(
                key1, key2,
                "VerifyingKeys from same KeyPair should be equal"
            );

            // IDs should be identical
            assert_eq!(
                key1.id(),
                key2.id(),
                "IDs should be identical for equal keys"
            );

            // Keys should be equal to themselves
            assert_eq!(key1, key1, "VerifyingKey should equal itself");
        }

        // Different keypairs should produce different verifying keys
        let keys = create_test_verifying_keys();
        for (i, key1) in keys.iter().enumerate() {
            for (j, key2) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        key1, key2,
                        "Different keypairs should produce different VerifyingKeys"
                    );
                    assert_ne!(
                        key1.id(),
                        key2.id(),
                        "Different keys should have different IDs"
                    );
                }
            }
        }
    }

    #[test]
    fn test_verifying_key_ordering() {
        let keys = create_test_verifying_keys();

        // Test ordering is consistent
        for key1 in &keys {
            for key2 in &keys {
                let cmp1 = key1.cmp(key2);
                let cmp2 = key2.cmp(key1);

                // Ordering should be antisymmetric
                match cmp1 {
                    std::cmp::Ordering::Less => assert_eq!(cmp2, std::cmp::Ordering::Greater),
                    std::cmp::Ordering::Greater => assert_eq!(cmp2, std::cmp::Ordering::Less),
                    std::cmp::Ordering::Equal => assert_eq!(cmp2, std::cmp::Ordering::Equal),
                }

                // PartialOrd should be consistent with Ord
                assert_eq!(key1.partial_cmp(key2), Some(cmp1));
            }
        }

        // Test transitivity with multiple keys
        let mut sorted_keys = keys.clone();
        sorted_keys.sort();

        // Verify the sort order follows our algorithm-index-first rule
        for i in 0..sorted_keys.len() {
            for j in i + 1..sorted_keys.len() {
                assert!(
                    sorted_keys[i] <= sorted_keys[j],
                    "Sort order should be maintained"
                );
            }
        }
    }

    #[test]
    fn test_verifying_key_hash_consistency() {
        let keys = create_test_verifying_keys();

        for key in &keys {
            let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
            let mut hasher2 = std::collections::hash_map::DefaultHasher::new();

            std::hash::Hash::hash(key, &mut hasher1);
            std::hash::Hash::hash(key, &mut hasher2);

            let hash1 = std::hash::Hasher::finish(&hasher1);
            let hash2 = std::hash::Hasher::finish(&hasher2);

            assert_eq!(hash1, hash2, "Hash should be consistent for same key");
        }

        // Test that equal keys have equal hashes
        let keypair = &create_test_keypairs()[0];
        let key1 = keypair.public_key();
        let key2 = keypair.public_key();

        let mut hasher1 = std::collections::hash_map::DefaultHasher::new();
        let mut hasher2 = std::collections::hash_map::DefaultHasher::new();

        std::hash::Hash::hash(&key1, &mut hasher1);
        std::hash::Hash::hash(&key2, &mut hasher2);

        assert_eq!(
            std::hash::Hasher::finish(&hasher1),
            std::hash::Hasher::finish(&hasher2)
        );

        // Test keys can be used in HashSet and BTreeSet
        let mut hash_set = HashSet::new();
        let mut btree_set = BTreeSet::new();

        for key in &keys {
            hash_set.insert(key.clone());
            btree_set.insert(key.clone());
        }

        assert_eq!(
            hash_set.len(),
            keys.len(),
            "All keys should be unique in HashSet"
        );
        assert_eq!(
            btree_set.len(),
            keys.len(),
            "All keys should be unique in BTreeSet"
        );
    }

    #[test]
    fn test_verifying_key_serialization_round_trip() {
        let keys = create_test_verifying_keys();

        for original_key in &keys {
            // Test postcard serialization round trip
            let encoded = original_key.encode();
            let decoded: VerifyingKey = postcard::from_bytes(&encoded)
                .expect("Should successfully deserialize VerifyingKey");

            assert_eq!(
                *original_key, decoded,
                "Round-trip serialization should preserve equality"
            );
            assert_eq!(
                original_key.id(),
                decoded.id(),
                "Round-trip should preserve ID"
            );

            // Test that encoding is deterministic
            let encoded2 = decoded.encode();
            assert_eq!(encoded, encoded2, "Encoding should be deterministic");

            // Test alternative serialization method
            let bytes = verifying_key_to_bytes(original_key);
            let restored =
                verifying_key_from_bytes(&bytes).expect("Should successfully restore from bytes");

            assert_eq!(
                *original_key, restored,
                "Alternative serialization should work"
            );
            assert_eq!(
                original_key.id(),
                restored.id(),
                "Alternative serialization should preserve ID"
            );
        }
    }

    #[test]
    fn test_signing_key_equality() {
        let mut rng = OsRng;

        // Test Ed25519 SigningKey equality
        let ed25519_bytes = [42u8; 32]; // Fixed seed for reproducible keys
        let ed25519_key1 = ed25519_dalek::SigningKey::from_bytes(&ed25519_bytes);
        let ed25519_key2 = ed25519_dalek::SigningKey::from_bytes(&ed25519_bytes);

        let signing_key1 = SigningKey::Ed25519(Box::new(ed25519_key1));
        let signing_key2 = SigningKey::Ed25519(Box::new(ed25519_key2));

        assert_eq!(
            signing_key1, signing_key2,
            "SigningKeys from same bytes should be equal"
        );

        // Test that different keys are not equal
        let different_ed25519 = generate_ed25519_relay_keypair(&mut rng);
        let different_ml_dsa = KeyPair::generate_ml_dsa65(&mut rng);

        let ed25519_signing = match different_ed25519 {
            KeyPair::Ed25519(ref key) => SigningKey::Ed25519(key.clone()),
            _ => panic!("Expected Ed25519 keypair"),
        };

        let ml_dsa_signing = match different_ml_dsa {
            KeyPair::MlDsa65(ref keypair, hash) => {
                SigningKey::MlDsa65((Box::new(keypair.signing_key().clone()), hash))
            }
            _ => panic!("Expected ML-DSA-65 keypair"),
        };

        assert_ne!(
            ed25519_signing, ml_dsa_signing,
            "Different key types should not be equal"
        );
    }

    #[test]
    fn test_signing_key_functionality() {
        let keypairs = create_test_keypairs();
        let message = b"test message for signing";

        for keypair in &keypairs {
            let signature = keypair.sign(message);
            let verifying_key = keypair.public_key();

            // Test that signature can be verified
            let is_valid = verifying_key
                .verify(message, &signature)
                .expect("Verification should not error");
            assert!(
                is_valid,
                "Signature should be valid for correct key and message"
            );

            // Test with wrong message
            let wrong_message = b"different message";
            let is_invalid = verifying_key
                .verify(wrong_message, &signature)
                .expect("Verification should not error");
            assert!(!is_invalid, "Signature should be invalid for wrong message");
        }
    }

    #[test]
    fn test_signature_equality_and_ordering() {
        let keypairs = create_test_keypairs();
        let message = b"test message";

        let mut signatures = Vec::new();
        for keypair in &keypairs {
            signatures.push(keypair.sign(message));
        }

        // Test equality
        for (i, sig1) in signatures.iter().enumerate() {
            for (j, sig2) in signatures.iter().enumerate() {
                if i == j {
                    assert_eq!(sig1, sig2, "Signature should equal itself");
                } else {
                    // Different signatures should not be equal (very high probability)
                    assert_ne!(sig1, sig2, "Different signatures should not be equal");
                }
            }
        }

        // Test ordering consistency
        for sig1 in &signatures {
            for sig2 in &signatures {
                let cmp = sig1.partial_cmp(sig2);
                assert!(cmp.is_some(), "Signatures should always be comparable");

                // Test antisymmetry
                let reverse_cmp = sig2.partial_cmp(sig1);
                match cmp.unwrap() {
                    std::cmp::Ordering::Less => {
                        assert_eq!(reverse_cmp, Some(std::cmp::Ordering::Greater))
                    }
                    std::cmp::Ordering::Greater => {
                        assert_eq!(reverse_cmp, Some(std::cmp::Ordering::Less))
                    }
                    std::cmp::Ordering::Equal => {
                        assert_eq!(reverse_cmp, Some(std::cmp::Ordering::Equal))
                    }
                }
            }
        }

        // Test that sorting works
        let mut sorted_signatures = signatures.clone();
        sorted_signatures.sort_by(|a, b| a.partial_cmp(b).unwrap());

        // Verify sort order maintains our algorithm-first ordering
        for i in 0..sorted_signatures.len() {
            for j in i + 1..sorted_signatures.len() {
                assert!(
                    sorted_signatures[i].partial_cmp(&sorted_signatures[j])
                        != Some(std::cmp::Ordering::Greater)
                );
            }
        }
    }

    #[test]
    fn test_signature_id_consistency() {
        let keypairs = create_test_keypairs();
        let message = b"test message";

        for keypair in &keypairs {
            let sig1 = keypair.sign(message);
            let sig2 = keypair.sign(message);

            // IDs might be different for same message (signatures can be non-deterministic)
            // but the same signature object should have consistent ID
            assert_eq!(sig1.id(), sig1.id(), "Signature ID should be consistent");
            assert_eq!(sig2.id(), sig2.id(), "Signature ID should be consistent");
        }
    }

    #[test]
    fn test_signature_serialization_round_trip() {
        let keypairs = create_test_keypairs();
        let message = b"test message";

        for keypair in &keypairs {
            let original_signature = keypair.sign(message);

            // Test postcard serialization round trip
            let encoded = original_signature.encode();
            let decoded: Signature =
                postcard::from_bytes(&encoded).expect("Should successfully deserialize Signature");

            assert_eq!(
                original_signature, decoded,
                "Round-trip serialization should preserve equality"
            );
            assert_eq!(
                original_signature.id(),
                decoded.id(),
                "Round-trip should preserve ID"
            );

            // Test that encoding is deterministic
            let encoded2 = decoded.encode();
            assert_eq!(encoded, encoded2, "Encoding should be deterministic");
        }
    }

    #[test]
    fn test_keypair_equality_and_id_consistency() {
        let _rng = OsRng;

        // Test that same-seed keypairs are equal (for deterministic algorithms)
        let ed25519_bytes = [42u8; 32];
        let ed25519_key1 = ed25519_dalek::SigningKey::from_bytes(&ed25519_bytes);
        let ed25519_key2 = ed25519_dalek::SigningKey::from_bytes(&ed25519_bytes);

        let keypair1 = KeyPair::Ed25519(Box::new(ed25519_key1));
        let keypair2 = KeyPair::Ed25519(Box::new(ed25519_key2));

        assert_eq!(
            keypair1, keypair2,
            "KeyPairs from same bytes should be equal"
        );
        assert_eq!(
            keypair1.id(),
            keypair2.id(),
            "Equal KeyPairs should have same ID"
        );

        // Test different keypairs are not equal
        let different_keypairs = create_test_keypairs();
        for (i, kp1) in different_keypairs.iter().enumerate() {
            for (j, kp2) in different_keypairs.iter().enumerate() {
                if i != j {
                    assert_ne!(kp1, kp2, "Different KeyPairs should not be equal");
                    assert_ne!(
                        kp1.id(),
                        kp2.id(),
                        "Different KeyPairs should have different IDs"
                    );
                }
            }
        }
    }

    #[test]
    fn test_cross_algorithm_verification_rejection() {
        let keypairs = create_test_keypairs();
        let message = b"test message";

        // Create signatures from each keypair
        let mut signatures = Vec::new();
        let mut verifying_keys = Vec::new();

        for keypair in &keypairs {
            signatures.push(keypair.sign(message));
            verifying_keys.push(keypair.public_key());
        }

        // Test that matching key/signature pairs work
        for (key, sig) in verifying_keys.iter().zip(signatures.iter()) {
            let is_valid = key
                .verify(message, sig)
                .expect("Verification should not error");
            assert!(
                is_valid,
                "Matching key and signature should verify successfully"
            );
        }

        // Test that mismatched key/signature pairs fail
        for (i, key) in verifying_keys.iter().enumerate() {
            for (j, sig) in signatures.iter().enumerate() {
                if i != j {
                    let is_valid = key
                        .verify(message, sig)
                        .expect("Verification should not error");
                    assert!(
                        !is_valid,
                        "Mismatched key and signature should fail verification"
                    );
                }
            }
        }
    }

    #[test]
    fn test_algorithm_ordering_consistency() {
        let mut rng = OsRng;

        // Create one key of each type
        let ed25519_key = generate_ed25519_relay_keypair(&mut rng).public_key();
        let ml_dsa44_key = KeyPair::generate_ml_dsa44(&mut rng).public_key();
        let ml_dsa65_key = KeyPair::generate_ml_dsa65(&mut rng).public_key();
        let ml_dsa87_key = KeyPair::generate_ml_dsa87(&mut rng).public_key();

        // Test that algorithm order is: Ed25519 < ML-DSA-44 < ML-DSA-65 < ML-DSA-87
        assert!(
            ed25519_key < ml_dsa44_key,
            "Ed25519 should be less than ML-DSA-44"
        );
        assert!(
            ml_dsa44_key < ml_dsa65_key,
            "ML-DSA-44 should be less than ML-DSA-65"
        );
        assert!(
            ml_dsa65_key < ml_dsa87_key,
            "ML-DSA-65 should be less than ML-DSA-87"
        );

        // Test same for signatures
        let message = b"test message";
        let ed25519_sig = generate_ed25519_relay_keypair(&mut rng).sign(message);
        let ml_dsa44_sig = KeyPair::generate_ml_dsa44(&mut rng).sign(message);
        let ml_dsa65_sig = KeyPair::generate_ml_dsa65(&mut rng).sign(message);
        let ml_dsa87_sig = KeyPair::generate_ml_dsa87(&mut rng).sign(message);

        assert!(
            ed25519_sig < ml_dsa44_sig,
            "Ed25519 sig should be less than ML-DSA-44 sig"
        );
        assert!(
            ml_dsa44_sig < ml_dsa65_sig,
            "ML-DSA-44 sig should be less than ML-DSA-65 sig"
        );
        assert!(
            ml_dsa65_sig < ml_dsa87_sig,
            "ML-DSA-65 sig should be less than ML-DSA-87 sig"
        );
    }

    #[test]
    fn test_id_across_operations() {
        let keypairs = create_test_keypairs();

        for keypair in &keypairs {
            let public_key = keypair.public_key();
            let public_key_id = public_key.id();
            assert_eq!(
                public_key_id,
                keypair.public_key().id(),
                "Multiple public key extractions should have same ID"
            );

            // ID should be stable across serialization
            let encoded = postcard::to_stdvec(&public_key).expect("Should serialize");
            let decoded: VerifyingKey = postcard::from_bytes(&encoded).expect("Should deserialize");

            assert_eq!(
                public_key_id,
                decoded.id(), // this is the ID of the public key
                "ID should be stable across serialization"
            );

            let signed = keypair.sign(b"test message");
            let signature_id = signed.id();

            // ID should be stable across serialization
            let encoded = postcard::to_stdvec(&signed).expect("Should serialize");
            let decoded: Signature = postcard::from_bytes(&encoded).expect("Should deserialize");

            assert_eq!(
                signature_id,
                decoded.id(), // this is the ID of the signature
                "signature ID should be stable across serialization"
            );
        }
    }

    #[test]
    fn test_hash_based_ids_for_ml_dsa() {
        let mut rng = OsRng;

        // Test that ML-DSA keys use blake3 hash of encoded key as ID
        let ml_dsa65_keypair = KeyPair::generate_ml_dsa65(&mut rng);
        let verifying_key = ml_dsa65_keypair.public_key();

        match verifying_key {
            VerifyingKey::MlDsa65((ref key, ref stored_hash)) => {
                let computed_hash = blake3::hash(key.encode().as_slice());
                assert_eq!(
                    stored_hash.as_bytes(),
                    computed_hash.as_bytes(),
                    "Stored hash should match computed hash of encoded key"
                );
                assert_eq!(
                    verifying_key.id(),
                    computed_hash.as_bytes(),
                    "ID should be the blake3 hash of encoded key"
                );
            }
            _ => panic!("Expected ML-DSA-65 key"),
        }
    }

    #[test]
    fn test_ed25519_id_is_key_bytes() {
        let mut rng = OsRng;
        let ed25519_keypair = generate_ed25519_relay_keypair(&mut rng);
        let verifying_key = ed25519_keypair.public_key();

        match verifying_key {
            VerifyingKey::Ed25519(ref key) => {
                assert_eq!(
                    verifying_key.id(),
                    key.as_bytes(),
                    "Ed25519 ID should be the raw key bytes"
                );
            }
            _ => panic!("Expected Ed25519 key"),
        }
    }

    #[test]
    fn test_generate_keypair_defaults_to_ml_dsa65() {
        let mut rng = OsRng;
        let default_keypair = generate_keypair(&mut rng);

        match default_keypair {
            KeyPair::MlDsa65(..) => {
                // This is expected
            }
            _ => panic!("generate_keypair should default to ML-DSA-65"),
        }
    }

    #[test]
    fn test_signature_id_implementation() {
        let mut rng = OsRng;
        let message = b"test message";

        // Test Ed25519 signature ID uses s_bytes
        let ed25519_keypair = generate_ed25519_relay_keypair(&mut rng);
        let ed25519_sig = ed25519_keypair.sign(message);

        match ed25519_sig {
            Signature::Ed25519(ref sig) => {
                assert_eq!(
                    ed25519_sig.id(),
                    sig.s_bytes(),
                    "Ed25519 signature ID should be s_bytes"
                );
            }
            _ => panic!("Expected Ed25519 signature"),
        }

        // Test ML-DSA signature ID uses hash
        let ml_dsa_keypair = KeyPair::generate_ml_dsa65(&mut rng);
        let ml_dsa_sig = ml_dsa_keypair.sign(message);

        match ml_dsa_sig {
            Signature::MlDsa65((ref sig, ref stored_hash)) => {
                let computed_hash = blake3::hash(sig.encode().as_slice());
                assert_eq!(
                    stored_hash.as_bytes(),
                    computed_hash.as_bytes(),
                    "Stored hash should match computed hash"
                );
                assert_eq!(
                    ml_dsa_sig.id(),
                    computed_hash.as_bytes(),
                    "ML-DSA signature ID should be blake3 hash"
                );
            }
            _ => panic!("Expected ML-DSA-65 signature"),
        }
    }

    #[test]
    fn test_deterministic_encoding() {
        let keypairs = create_test_keypairs();

        for keypair in &keypairs {
            let key = keypair.public_key();

            // Encode multiple times and ensure consistency
            let encoded1 = key.encode();
            let encoded2 = key.encode();
            let encoded3 = postcard::to_stdvec(&key).expect("Should serialize");

            assert_eq!(encoded1, encoded2, "Multiple encodings should be identical");
            assert_eq!(
                encoded2, encoded3,
                "Different encoding methods should produce same result"
            );
        }
    }
}
