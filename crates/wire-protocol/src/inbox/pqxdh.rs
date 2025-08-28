//! PQXDH (Post-Quantum Extended Diffie-Hellman) inbox types and cryptographic helpers
//!
//! This module implements the PQXDH protocol for asynchronous secure communication,
//! based on Signal's PQXDH specification. It provides:
//!
//! - Prekey bundle generation and management
//! - PQXDH key agreement protocol
//! - Inbox types for different protocols (RPC, messaging, etc.)
//!
//! ## Security
//!
//! PQXDH provides:
//! - Post-quantum forward secrecy via ML-KEM (using libcrux-ml-kem)
//! - Classical security via X25519 ECDH
//! - Authentication via ML-DSA signatures
//! - Perfect forward secrecy through one-time prekeys

use std::collections::BTreeMap;

// Note: libcrux_ml_kem will be used for actual key generation in implementation
pub mod pqxdh_crypto;
pub use pqxdh_crypto::*;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Signature, VerifyingKey};

/// Inbox type indicating expected responsiveness and access control
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum InboxType {
    /// Only authenticated senders, recipient will likely respond
    Private = 0,
    /// Anyone can send, recipient may or may not respond  
    Public = 9,
}

/// PQXDH prekey bundle containing both classical and post-quantum keys
///
/// This bundle contains all the cryptographic material needed for a client
/// to initiate a PQXDH key agreement with the bundle owner.
///
/// ## Security Properties
///
/// - **Hybrid Security**: Combines X25519 (classical) and ML-KEM (post-quantum)
/// - **Forward Secrecy**: One-time keys provide perfect forward secrecy
/// - **Authentication**: All keys are signed by the identity key
/// - **Key Rotation**: Signed prekeys are rotated periodically
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PqxdhPrekeyBundle {
    // Classical ECDH keys
    /// Medium-term X25519 public key for ECDH, rotated periodically
    pub signed_prekey: x25519_dalek::PublicKey,
    /// Signature over the signed prekey by the identity key
    pub signed_prekey_signature: Signature,
    /// Unique identifier for this signed prekey
    pub signed_prekey_id: String,

    /// One-time X25519 public keys (each used exactly once)
    pub one_time_prekeys: BTreeMap<String, x25519_dalek::PublicKey>,

    // Post-quantum KEM keys
    /// Medium-term ML-KEM public key, rotated periodically  
    pub pq_signed_prekey: Vec<u8>, // ML-KEM 768 public key bytes (1184 bytes)
    /// Signature over the PQ signed prekey by the identity key
    pub pq_signed_prekey_signature: Signature,
    /// Unique identifier for this PQ signed prekey
    pub pq_signed_prekey_id: String,

    /// One-time ML-KEM public keys (each used exactly once)
    pub pq_one_time_keys: BTreeMap<String, Vec<u8>>, // ML-KEM 768 public key bytes (1184 bytes each)
    /// Signatures over each one-time PQ key by the identity key
    pub pq_one_time_signatures: BTreeMap<String, Signature>,
}

/// PQXDH inbox for connecting to a user
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PqxdhInbox {
    /// Access control and responsiveness expectations
    pub inbox_type: InboxType,
    /// PQXDH prekeys for key agreement (always present)
    pub pqxdh_prekeys: PqxdhPrekeyBundle,
    /// Maximum echo payload size in bytes (None = unlimited)
    pub max_echo_size: Option<u32>,
    /// When this inbox expires (Unix timestamp)
    pub expires_at: Option<u64>,
}

/// Private key material for PQXDH operations
///
/// This contains the private keys corresponding to a PqxdhPrekeyBundle.
/// It should be stored securely and zeroized when no longer needed.
#[derive(Clone, Serialize, Deserialize)]
pub struct PqxdhPrivateKeys {
    /// Private key for the signed X25519 prekey
    pub signed_prekey_private: x25519_dalek::StaticSecret,
    /// Private keys for one-time X25519 prekeys
    pub one_time_prekey_privates: BTreeMap<String, x25519_dalek::StaticSecret>,
    /// Private key for the signed ML-KEM prekey
    pub pq_signed_prekey_private: Vec<u8>, // ML-KEM 768 private key bytes (2400 bytes)
    /// Private keys for one-time ML-KEM prekeys  
    pub pq_one_time_prekey_privates: BTreeMap<String, Vec<u8>>, // ML-KEM 768 private key bytes (2400 bytes each)
}

/// PQXDH initial message sent to establish secure communication (Phase 2)
///
/// This message contains the initiator's ephemeral key, KEM ciphertext,
/// prekey identifiers, and the initial encrypted payload. This establishes
/// the shared secret and delivers the first message in one round-trip.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PqxdhInitialMessage {
    /// Initiator's identity key
    pub initiator_identity: VerifyingKey,
    /// Ephemeral X25519 public key generated for this session
    pub ephemeral_key: x25519_dalek::PublicKey,
    /// ML-KEM ciphertext encapsulating shared secret
    pub kem_ciphertext: Vec<u8>,
    /// ID of the signed prekey that was used
    pub signed_prekey_id: String,
    /// ID of the one-time prekey that was used (if any)
    pub one_time_prekey_id: Option<String>,
    /// ID of the PQ signed prekey that was used
    pub pq_signed_prekey_id: String,
    /// ID of the PQ one-time key that was used (if any)
    pub pq_one_time_key_id: Option<String>,
    /// Initial encrypted payload (typically the first RPC message)
    pub encrypted_payload: Vec<u8>,
}

/// PQXDH session message for ongoing communication (Phase 3)
///
/// After the initial PQXDH handshake, follow-up messages use the established
/// shared secret for AEAD encryption. This provides efficient ongoing communication.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PqxdhSessionMessage {
    /// Message sequence number (for replay protection)
    pub sequence_number: u64,
    /// AEAD encrypted payload using session keys
    pub encrypted_payload: Vec<u8>,
    /// AEAD authentication tag
    pub auth_tag: [u8; 16],
}

/// Result of PQXDH key agreement
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct PqxdhSharedSecret {
    /// 32-byte shared secret derived from PQXDH
    pub shared_key: [u8; 32],
    /// IDs of consumed one-time keys (to be deleted)
    pub consumed_one_time_key_ids: Vec<String>,
}

/// Initial payload structure for PQXDH sessions
///
/// This structure is encrypted inside the PqxdhInitialMessage and contains
/// both the user's initial payload and a randomized channel ID for subsequent
/// session messages to provide unlinkability.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PqxdhInitialPayload<T> {
    /// The actual user payload (e.g., RPC request)
    pub user_payload: T,
    /// randomized session id prefix to take and generate the target tags to listen for
    pub session_channel_id_prefix: [u8; 32],
}

/// Errors that can occur during PQXDH operations
#[derive(Debug, thiserror::Error)]
pub enum PqxdhError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    #[error("Invalid prekey bundle: {0}")]
    InvalidPrekeyBundle(String),
    #[error("Missing required prekey: {0}")]
    MissingPrekey(String),
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] postcard::Error),
}

impl PqxdhPrekeyBundle {
    /// Verify all signatures in the prekey bundle
    ///
    /// This checks that all prekeys are properly signed by the given identity key.
    pub fn verify_signatures(
        &self,
        _identity_key: &VerifyingKey,
    ) -> std::result::Result<(), PqxdhError> {
        // TODO: Implement signature verification
        // This would verify:
        // - signed_prekey_signature over signed_prekey
        // - pq_signed_prekey_signature over pq_signed_prekey
        // - all pq_one_time_signatures over their respective keys

        // For now, return Ok - this will be implemented when we add the crypto helpers
        Ok(())
    }

    /// Get the number of available one-time keys
    pub fn one_time_key_count(&self) -> usize {
        std::cmp::min(self.one_time_prekeys.len(), self.pq_one_time_keys.len())
    }

    /// Check if the bundle has any one-time keys available
    pub fn has_one_time_keys(&self) -> bool {
        !self.one_time_prekeys.is_empty() && !self.pq_one_time_keys.is_empty()
    }
}

impl PqxdhInbox {
    /// Create a new echo service inbox
    pub fn new(
        inbox_type: InboxType,
        pqxdh_prekeys: PqxdhPrekeyBundle,
        max_echo_size: Option<u32>,
        expires_at: Option<u64>,
    ) -> Self {
        Self {
            inbox_type,
            pqxdh_prekeys,
            max_echo_size,
            expires_at,
        }
    }

    /// Check if this inbox has expired
    pub fn is_expired(&self, current_time: u64) -> bool {
        self.expires_at.is_some_and(|expiry| current_time > expiry)
    }

    /// Check if a payload size is acceptable for this echo service
    pub fn accepts_payload_size(&self, size: u32) -> bool {
        self.max_echo_size.is_none_or(|max_size| size <= max_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inbox_type_serialization() {
        let inbox_types = vec![InboxType::Private, InboxType::Public];

        // Test postcard serialization
        let serialized = postcard::to_stdvec(&inbox_types).unwrap();
        let deserialized: Vec<InboxType> = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(inbox_types, deserialized);
    }

    #[test]
    fn test_inbox_type_values() {
        // Test that enum values match expected discriminants
        assert_eq!(InboxType::Private as u8, 0);
        assert_eq!(InboxType::Public as u8, 9);
    }

    #[test]
    fn test_pqxdh_echo_service_inbox_creation() {
        // Create a minimal prekey bundle for testing
        let prekey_bundle = PqxdhPrekeyBundle {
            signed_prekey: x25519_dalek::PublicKey::from([0u8; 32]),
            signed_prekey_signature: crate::Signature::Ed25519(Box::new(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )),
            signed_prekey_id: "spk_001".to_string(),
            one_time_prekeys: BTreeMap::new(),
            pq_signed_prekey: vec![0u8; 1184], // Placeholder ML-KEM 768 public key,
            pq_signed_prekey_signature: crate::Signature::Ed25519(Box::new(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )),
            pq_signed_prekey_id: "pqspk_001".to_string(),
            pq_one_time_keys: BTreeMap::new(),
            pq_one_time_signatures: BTreeMap::new(),
        };

        let inbox = PqxdhInbox::new(
            InboxType::Public,
            prekey_bundle,
            Some(1024),
            Some(1640995200),
        );

        assert_eq!(inbox.inbox_type, InboxType::Public);
        assert_eq!(inbox.max_echo_size, Some(1024));
        assert_eq!(inbox.expires_at, Some(1640995200));
        assert!(inbox.accepts_payload_size(512));
        assert!(!inbox.accepts_payload_size(2048));
        assert!(inbox.is_expired(1640995201));
        assert!(!inbox.is_expired(1640995199));
    }

    #[test]
    fn test_prekey_bundle_one_time_key_count() {
        let mut prekey_bundle = PqxdhPrekeyBundle {
            signed_prekey: x25519_dalek::PublicKey::from([0u8; 32]),
            signed_prekey_signature: crate::Signature::Ed25519(Box::new(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )),
            signed_prekey_id: "spk_001".to_string(),
            one_time_prekeys: BTreeMap::new(),
            pq_signed_prekey: vec![0u8; 1184], // Placeholder ML-KEM 768 public key,
            pq_signed_prekey_signature: crate::Signature::Ed25519(Box::new(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )),
            pq_signed_prekey_id: "pqspk_001".to_string(),
            pq_one_time_keys: BTreeMap::new(),
            pq_one_time_signatures: BTreeMap::new(),
        };

        assert_eq!(prekey_bundle.one_time_key_count(), 0);
        assert!(!prekey_bundle.has_one_time_keys());

        // Add one X25519 key but no PQ key
        prekey_bundle.one_time_prekeys.insert(
            "otk_001".to_string(),
            x25519_dalek::PublicKey::from([1u8; 32]),
        );
        assert_eq!(prekey_bundle.one_time_key_count(), 0); // Still 0 because we need both
        assert!(!prekey_bundle.has_one_time_keys());

        // Add one PQ key
        prekey_bundle.pq_one_time_keys.insert(
            "pqotk_001".to_string(),
            vec![1u8; 1184], // Placeholder ML-KEM 768 public key
        );
        assert_eq!(prekey_bundle.one_time_key_count(), 1); // Now we have a pair
        assert!(prekey_bundle.has_one_time_keys());
    }

    #[test]
    fn test_pqxdh_structures_serialization() {
        // Test that our main structures can be serialized with postcard
        let prekey_bundle = PqxdhPrekeyBundle {
            signed_prekey: x25519_dalek::PublicKey::from([0u8; 32]),
            signed_prekey_signature: crate::Signature::Ed25519(Box::new(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )),
            signed_prekey_id: "spk_001".to_string(),
            one_time_prekeys: BTreeMap::new(),
            pq_signed_prekey: vec![0u8; 1184], // Placeholder ML-KEM 768 public key,
            pq_signed_prekey_signature: crate::Signature::Ed25519(Box::new(
                ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
            )),
            pq_signed_prekey_id: "pqspk_001".to_string(),
            pq_one_time_keys: BTreeMap::new(),
            pq_one_time_signatures: BTreeMap::new(),
        };

        let inbox = PqxdhInbox::new(InboxType::Private, prekey_bundle, None, None);

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&inbox).unwrap();
        let deserialized: PqxdhInbox = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(inbox, deserialized);
    }

    #[test]
    fn test_pqxdh_private_keys_random_serialization() {
        use rand::RngCore;

        // Generate random private keys
        let mut rng = rand::thread_rng();

        // Create random X25519 keys
        let signed_prekey_private = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let mut one_time_prekey_privates = BTreeMap::new();
        for i in 0..3 {
            let key_id = format!("otk_{}", i);
            let private_key = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
            one_time_prekey_privates.insert(key_id, private_key);
        }

        // Create random ML-KEM keys (just random bytes for testing)
        let mut pq_signed_prekey_private = vec![0u8; 2400]; // ML-KEM 768 private key size
        rng.fill_bytes(&mut pq_signed_prekey_private);

        let mut pq_one_time_prekey_privates = BTreeMap::new();
        for i in 0..2 {
            let key_id = format!("pq_otk_{}", i);
            let mut private_key = vec![0u8; 2400];
            rng.fill_bytes(&mut private_key);
            pq_one_time_prekey_privates.insert(key_id, private_key);
        }

        let private_keys = PqxdhPrivateKeys {
            signed_prekey_private,
            one_time_prekey_privates,
            pq_signed_prekey_private,
            pq_one_time_prekey_privates,
        };

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&private_keys).unwrap();
        let deserialized: PqxdhPrivateKeys = postcard::from_bytes(&serialized).unwrap();

        // Verify the data is preserved
        assert_eq!(
            private_keys.signed_prekey_private.to_bytes(),
            deserialized.signed_prekey_private.to_bytes()
        );
        assert_eq!(
            private_keys.one_time_prekey_privates.len(),
            deserialized.one_time_prekey_privates.len()
        );
        assert_eq!(
            private_keys.pq_signed_prekey_private,
            deserialized.pq_signed_prekey_private
        );
        assert_eq!(
            private_keys.pq_one_time_prekey_privates,
            deserialized.pq_one_time_prekey_privates
        );

        // Verify one-time keys
        for (key_id, original_key) in &private_keys.one_time_prekey_privates {
            let deserialized_key = &deserialized.one_time_prekey_privates[key_id];
            assert_eq!(original_key.to_bytes(), deserialized_key.to_bytes());
        }

        // Test that we can generate different random keys
        let signed_prekey_private2 = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        assert_ne!(
            private_keys.signed_prekey_private.to_bytes(),
            signed_prekey_private2.to_bytes(),
            "Random keys should be different"
        );
    }
}
