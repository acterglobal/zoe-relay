//! Transport Security Key Management
//!
//! This module provides key types that support multiple cryptographic algorithms
//! for transport security, including both public keys (identity) and private keys (signing).

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use ml_dsa::{MlDsa44, VerifyingKey as MlDsaVerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::crypto::CryptoError;

/// Serde support for Ed25519 SigningKey
mod serde_ed25519_pkcs8 {
    use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    use ed25519_dalek::SigningKey;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(signing_key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the signing key using PKCS#8 DER format
        let pkcs8_der = signing_key
            .to_pkcs8_der()
            .map_err(|e| serde::ser::Error::custom(format!("PKCS#8 encoding failed: {e}")))?;
        serializer.serialize_bytes(pkcs8_der.as_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key_bytes = Vec::<u8>::deserialize(deserializer)?;

        // Deserialize the signing key from PKCS#8 DER format
        let signing_key = SigningKey::from_pkcs8_der(&key_bytes)
            .map_err(|e| D::Error::custom(format!("PKCS#8 decoding failed: {e}")))?;

        Ok(signing_key)
    }
}

/// Serde support for ML-DSA-44 KeyPair (only available with tls-ml-dsa-44 feature)
#[cfg(feature = "tls-ml-dsa-44")]
mod serde_ml_dsa_44_pkcs8 {
    use ml_dsa::{KeyPair, MlDsa44};
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(keypair: &KeyPair<MlDsa44>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the keypair as bytes
        let signing_key_bytes = keypair.signing_key().encode();
        serializer.serialize_bytes(signing_key_bytes.as_slice())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyPair<MlDsa44>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key_bytes = Vec::<u8>::deserialize(deserializer)?;

        // Deserialize the signing key from bytes
        let encoded_key: &ml_dsa::EncodedSigningKey<MlDsa44> = key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| D::Error::custom("Invalid ML-DSA-44 signing key length"))?;

        let signing_key = ml_dsa::SigningKey::<MlDsa44>::decode(encoded_key);
        let verifying_key = signing_key.verifying_key().clone();

        Ok(KeyPair::from_parts(signing_key, verifying_key))
    }
}

/// Transport security public key
///
/// This enum represents public keys for different cryptographic algorithms
/// used in transport security. It can represent both client and server identities.
///
/// Currently supports:
/// - Ed25519: Fast, proven elliptic curve cryptography (default for transport)
/// - ML-DSA-44: Post-quantum signature algorithm (future transport option)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportPublicKey {
    /// Ed25519 verifying key for transport security
    /// Fast, proven, and widely supported
    Ed25519 { verifying_key: Ed25519VerifyingKey },

    /// ML-DSA-44 verifying key for post-quantum transport security
    /// Larger keys but quantum-resistant
    MlDsa44 {
        verifying_key_bytes: Vec<u8>, // Store as bytes since MlDsaVerifyingKey doesn't implement Serialize
    },
}

/// Transport security private key (signing key)
///
/// This enum represents private keys for different cryptographic algorithms
/// used in transport security. Used for server keypairs and client authentication.
///
/// Currently supports:
/// - Ed25519: Fast, proven elliptic curve cryptography (default for transport)
/// - ML-DSA-44: Post-quantum signature algorithm (future transport option)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportPrivateKey {
    /// Ed25519 signing key for transport security (default)
    /// Fast, proven, and widely supported
    Ed25519 {
        #[serde(with = "serde_ed25519_pkcs8")]
        signing_key: Ed25519SigningKey,
    },

    /// ML-DSA-44 keypair for post-quantum transport security
    /// Only available when tls-ml-dsa-44 feature is enabled
    #[cfg(feature = "tls-ml-dsa-44")]
    MlDsa44 {
        #[serde(with = "serde_ml_dsa_44_pkcs8")]
        keypair: ml_dsa::KeyPair<MlDsa44>,
    },
}

impl TransportPublicKey {
    /// Create from Ed25519 verifying key
    pub fn from_ed25519(verifying_key: Ed25519VerifyingKey) -> Self {
        Self::Ed25519 { verifying_key }
    }

    /// Create from ML-DSA-44 verifying key
    pub fn from_ml_dsa_44(verifying_key: &MlDsaVerifyingKey<MlDsa44>) -> Self {
        Self::MlDsa44 {
            verifying_key_bytes: verifying_key.encode().to_vec(),
        }
    }

    /// Get the algorithm name for this key type
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "Ed25519",
            Self::MlDsa44 { .. } => "ML-DSA-44",
        }
    }

    /// Check if this is an Ed25519 key
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519 { .. })
    }

    /// Check if this is an ML-DSA-44 key
    pub fn is_ml_dsa_44(&self) -> bool {
        matches!(self, Self::MlDsa44 { .. })
    }

    /// Get Ed25519 verifying key if this is an Ed25519 identity
    pub fn as_ed25519(&self) -> Option<&Ed25519VerifyingKey> {
        match self {
            Self::Ed25519 { verifying_key } => Some(verifying_key),
            _ => None,
        }
    }

    /// Get ML-DSA-44 verifying key if this is an ML-DSA-44 identity
    pub fn as_ml_dsa_44(&self) -> Option<Result<MlDsaVerifyingKey<MlDsa44>, CryptoError>> {
        match self {
            Self::MlDsa44 {
                verifying_key_bytes,
            } => {
                if verifying_key_bytes.len() != 1312 {
                    return Some(Err(CryptoError::ParseError(format!(
                        "Invalid ML-DSA-44 key length: {} bytes (expected 1312)",
                        verifying_key_bytes.len()
                    ))));
                }

                let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa44> =
                    match verifying_key_bytes.as_slice().try_into() {
                        Ok(key) => key,
                        Err(_) => {
                            return Some(Err(CryptoError::ParseError(
                                "Invalid ML-DSA-44 verifying key length".to_string(),
                            )))
                        }
                    };

                Some(Ok(MlDsaVerifyingKey::<MlDsa44>::decode(encoded_key)))
            }
            _ => None,
        }
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519 { verifying_key } => verifying_key.to_bytes().to_vec(),
            Self::MlDsa44 {
                verifying_key_bytes,
            } => verifying_key_bytes.clone(),
        }
    }

    /// Encode the public key (alias for to_bytes for backward compatibility)
    pub fn encode(&self) -> Vec<u8> {
        self.to_bytes()
    }

    /// Create Ed25519 key from bytes
    pub fn from_ed25519_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::ParseError(format!(
                "Invalid Ed25519 key length: {} bytes (expected 32)",
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(bytes);

        let verifying_key = Ed25519VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| CryptoError::ParseError(format!("Invalid Ed25519 key: {}", e)))?;

        Ok(Self::Ed25519 { verifying_key })
    }

    /// Create ML-DSA-44 key from bytes
    pub fn from_ml_dsa_44_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 1312 {
            return Err(CryptoError::ParseError(format!(
                "Invalid ML-DSA-44 key length: {} bytes (expected 1312)",
                bytes.len()
            )));
        }

        Ok(Self::MlDsa44 {
            verifying_key_bytes: bytes.to_vec(),
        })
    }
}

impl TransportPrivateKey {
    /// Get the public key for this private key
    pub fn public_key(&self) -> TransportPublicKey {
        match self {
            Self::Ed25519 { signing_key } => {
                TransportPublicKey::from_ed25519(signing_key.verifying_key())
            }
            #[cfg(feature = "tls-ml-dsa-44")]
            Self::MlDsa44 { keypair } => {
                TransportPublicKey::from_ml_dsa_44(keypair.verifying_key())
            }
        }
    }

    /// Check if this is an Ed25519 keypair
    pub fn is_ed25519(&self) -> bool {
        matches!(self, Self::Ed25519 { .. })
    }

    /// Check if this is an ML-DSA-44 keypair
    #[cfg(feature = "tls-ml-dsa-44")]
    pub fn is_ml_dsa_44(&self) -> bool {
        matches!(self, Self::MlDsa44 { .. })
    }

    /// Get Ed25519 signing key if this is an Ed25519 keypair
    pub fn as_ed25519(&self) -> Option<&Ed25519SigningKey> {
        match self {
            Self::Ed25519 { signing_key } => Some(signing_key),
            #[cfg(feature = "tls-ml-dsa-44")]
            _ => None,
        }
    }

    /// Get ML-DSA-44 keypair if this is an ML-DSA-44 keypair
    #[cfg(feature = "tls-ml-dsa-44")]
    pub fn as_ml_dsa_44(&self) -> Option<&ml_dsa::KeyPair<MlDsa44>> {
        match self {
            Self::MlDsa44 { keypair } => Some(keypair),
            _ => None,
        }
    }

    /// Get the algorithm name for this key type
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::Ed25519 { .. } => "Ed25519",
            #[cfg(feature = "tls-ml-dsa-44")]
            Self::MlDsa44 { .. } => "ML-DSA-44",
        }
    }
}

impl Default for TransportPrivateKey {
    /// Default to Ed25519 for transport security (fast and proven)
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = Ed25519SigningKey::generate(&mut rng);
        Self::Ed25519 { signing_key }
    }
}

impl Default for TransportPublicKey {
    /// Default to Ed25519 for transport security (fast and proven)
    fn default() -> Self {
        // Generate a dummy Ed25519 key for default
        let mut rng = rand::thread_rng();
        let signing_key = Ed25519SigningKey::generate(&mut rng);
        Self::Ed25519 {
            verifying_key: signing_key.verifying_key(),
        }
    }
}

impl fmt::Display for TransportPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 { verifying_key } => {
                write!(f, "Ed25519({})", hex::encode(verifying_key.to_bytes()))
            }
            Self::MlDsa44 {
                verifying_key_bytes,
            } => {
                write!(f, "ML-DSA-44({})", hex::encode(verifying_key_bytes))
            }
        }
    }
}

impl fmt::Display for TransportPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 { signing_key } => {
                write!(
                    f,
                    "Ed25519({})",
                    hex::encode(signing_key.verifying_key().to_bytes())
                )
            }
            #[cfg(feature = "tls-ml-dsa-44")]
            Self::MlDsa44 { keypair } => {
                write!(
                    f,
                    "ML-DSA-44({})",
                    hex::encode(keypair.verifying_key().encode())
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::KeyGen;

    #[test]
    fn test_ed25519_transport_public_key() {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let public_key = TransportPublicKey::from_ed25519(signing_key.verifying_key());

        assert!(public_key.is_ed25519());
        assert!(!public_key.is_ml_dsa_44());
        assert_eq!(public_key.algorithm(), "Ed25519");

        assert!(public_key.as_ed25519().is_some());
        assert!(public_key.as_ml_dsa_44().is_none());
    }

    #[test]
    fn test_ml_dsa_44_transport_public_key() {
        let mut rng = rand::thread_rng();
        let keypair = ml_dsa::MlDsa44::key_gen(&mut rng);
        let public_key = TransportPublicKey::from_ml_dsa_44(keypair.verifying_key());

        assert!(public_key.is_ml_dsa_44());
        assert!(!public_key.is_ed25519());
        assert_eq!(public_key.algorithm(), "ML-DSA-44");

        assert!(public_key.as_ed25519().is_none());
        assert!(public_key.as_ml_dsa_44().is_some());
    }

    #[test]
    fn test_transport_private_key() {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let private_key = TransportPrivateKey::Ed25519 { signing_key };

        assert!(private_key.is_ed25519());
        assert_eq!(private_key.algorithm(), "Ed25519");

        let public_key = private_key.public_key();
        assert!(public_key.is_ed25519());
        assert_eq!(public_key.algorithm(), "Ed25519");
    }

    #[test]
    fn test_serialization() {
        let mut rng = rand::thread_rng();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let public_key = TransportPublicKey::from_ed25519(signing_key.verifying_key());

        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), 32); // Ed25519 public key is 32 bytes

        let recovered = TransportPublicKey::from_ed25519_bytes(&bytes).unwrap();
        assert_eq!(public_key, recovered);
    }
}
