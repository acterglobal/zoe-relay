//! Prelude module providing generic type aliases for cryptographic primitives
//!
//! This module allows other crates to use generic types like `crate::SigningKey`
//! without needing to know the specific ML-DSA implementation details.
use ml_dsa::KeyGen;
use serde::{Deserialize, Serialize};
use signature::{SignatureEncoding, Signer, Verifier};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    #[serde(with = "crate::serde::VerifyingKeyDef44")]
    MlDsa44(ml_dsa::VerifyingKey<ml_dsa::MlDsa44>),
    #[serde(with = "crate::serde::VerifyingKeyDef65")]
    MlDsa65(ml_dsa::VerifyingKey<ml_dsa::MlDsa65>),
    #[serde(with = "crate::serde::VerifyingKeyDef87")]
    MlDsa87(ml_dsa::VerifyingKey<ml_dsa::MlDsa87>),
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

impl VerifyingKey {
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

    /// Encode the VerifyingKey to bytes for serialization
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("Failed to serialize VerifyingKey")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    #[serde(with = "crate::serde::SigningKeyDef44")]
    MlDsa44(ml_dsa::SigningKey<ml_dsa::MlDsa44>),
    #[serde(with = "crate::serde::SigningKeyDef65")]
    MlDsa65(ml_dsa::SigningKey<ml_dsa::MlDsa65>),
    #[serde(with = "crate::serde::SigningKeyDef87")]
    MlDsa87(ml_dsa::SigningKey<ml_dsa::MlDsa87>),
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
            SigningKey::Ed25519(key) => Signature::Ed25519(key.sign(message)),
            SigningKey::MlDsa44(key) => Signature::MlDsa44(key.sign(message)),
            SigningKey::MlDsa65(key) => Signature::MlDsa65(key.sign(message)),
            SigningKey::MlDsa87(key) => Signature::MlDsa87(key.sign(message)),
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
    Ed25519(ed25519_dalek::Signature),
    #[serde(with = "crate::serde::SignatureDef44")]
    MlDsa44(ml_dsa::Signature<ml_dsa::MlDsa44>),
    #[serde(with = "crate::serde::SignatureDef65")]
    MlDsa65(ml_dsa::Signature<ml_dsa::MlDsa65>),
    #[serde(with = "crate::serde::SignatureDef87")]
    MlDsa87(ml_dsa::Signature<ml_dsa::MlDsa87>),
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
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa44(ml_dsa::KeyPair<ml_dsa::MlDsa44>),
    MlDsa65(ml_dsa::KeyPair<ml_dsa::MlDsa65>),
    MlDsa87(ml_dsa::KeyPair<ml_dsa::MlDsa87>),
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
            KeyPair::Ed25519(a) => VerifyingKey::Ed25519(a.verifying_key()),
            KeyPair::MlDsa44(a) => VerifyingKey::MlDsa44(a.verifying_key().clone()),
            KeyPair::MlDsa65(a) => VerifyingKey::MlDsa65(a.verifying_key().clone()),
            KeyPair::MlDsa87(a) => VerifyingKey::MlDsa87(a.verifying_key().clone()),
        }
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            KeyPair::Ed25519(a) => Signature::Ed25519(a.sign(message)),
            KeyPair::MlDsa44(a) => Signature::MlDsa44(a.sign(message)),
            KeyPair::MlDsa65(a) => Signature::MlDsa65(a.sign(message)),
            KeyPair::MlDsa87(a) => Signature::MlDsa87(a.sign(message)),
        }
    }
}

/// Generate a new ML-DSA keypair using the default parameters (MlDsa65)
pub fn generate_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    KeyPair::MlDsa65(<ml_dsa::MlDsa65 as KeyGen>::key_gen(rng))
}

/// Generate a new Ed25519 keypair for relay operations
pub fn generate_ed25519_relay_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    KeyPair::Ed25519(ed25519_dalek::SigningKey::generate(rng))
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
