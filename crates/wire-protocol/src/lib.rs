//! # Zoe Wire Protocol
//!
//! The wire protocol crate provides the core messaging infrastructure for the Zoe distributed
//! messaging system. It defines message formats, cryptographic primitives, transport security,
//! and RPC service interfaces.
//!
//! ## Key Features
//!
//! - **Versioned Message Protocol**: Forward-compatible message types with multiple encryption schemes
//! - **Hybrid Cryptography**: Support for both Ed25519 (legacy) and ML-DSA (post-quantum) signatures
//! - **Multiple Content Types**: Raw, ChaCha20-Poly1305, self-encrypted, and ephemeral ECDH encryption
//! - **Transport Security**: TLS certificate generation with embedded identity keys
//! - **RPC Services**: [`MessageService`] and [`BlobService`] for relay communication
//! - **Streaming Protocol**: Real-time message subscriptions and filtering
//! - **Challenge-Response Authentication**: Dynamic session management with configurable timeouts
//!
//! ## Quick Start
//!
//! ```rust
//! use zoe_wire_protocol::{
//!     MessageFull, Message, MessageV0, MessageV0Header, Content, Kind,
//!     KeyPair, VerifyingKey, SigningKey
//! };
//! use rand::rngs::OsRng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a keypair (supports Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87)
//! let keypair = KeyPair::generate(&mut OsRng);
//! let verifying_key = keypair.public_key();
//!
//! // Create message content (multiple encryption options available)
//! let content = Content::raw(b"Hello, Zoeyr!".to_vec());
//!
//! // Create message header
//! let header = MessageV0Header {
//!     sender: verifying_key.clone(),
//!     when: std::time::SystemTime::now()
//!         .duration_since(std::time::UNIX_EPOCH)
//!         .unwrap()
//!         .as_secs(),
//!     kind: Kind::Regular,
//!     tags: vec![], // Optional: Tag::Event, Tag::User, Tag::Channel, Tag::Protected
//! };
//!
//! // Create versioned message
//! let message = Message::new_v0_raw(
//!     content.as_raw().unwrap().clone(),
//!     verifying_key,
//!     header.when,
//!     header.kind,
//!     header.tags
//! );
//!
//! // Create full message with signature
//! let message_full = MessageFull::new(message, &keypair)?;
//!
//! // Access message properties
//! println!("Message ID: {}", message_full.id());
//! # Ok(())
//! # }
//! ```
//!
//! ## Message Structure
//!
//! Messages follow a versioned, forward-compatible structure:
//!
//! ```text
//! MessageFull
//! ├── id: Hash                    // Blake3 hash (computed from signature)
//! ├── signature: Signature        // Digital signature (Ed25519 or ML-DSA)
//! └── message: Message            // Versioned message content
//!     └── V0(MessageV0)
//!         ├── header: MessageV0Header
//!         │   ├── sender: VerifyingKey
//!         │   ├── when: u64
//!         │   ├── kind: Kind
//!         │   └── tags: Vec<Tag>
//!         └── content: Content    // Payload with encryption options
//! ```
//!
//! ## Content Encryption
//!
//! The protocol supports multiple encryption schemes:
//!
//! - [`Content::Raw`] - Unencrypted content
//! - [`Content::ChaCha20Poly1305`] - Context-based encryption with shared keys
//! - [`Content::Ed25519SelfEncrypted`] - Self-encryption using Ed25519 keys
//! - [`Content::MlDsaSelfEncrypted`] - Self-encryption using ML-DSA keys (post-quantum)
//! - [`Content::EphemeralEcdh`] - Public key encryption with perfect forward secrecy
//!
//! ## RPC Services
//!
//! The crate defines two main services for relay communication:
//!
//! - [`MessageService`] - Message publishing, retrieval, and real-time subscriptions
//! - [`BlobService`] - Binary blob storage and retrieval
//!
//! ## Transport Security
//!
//! TLS certificates can embed identity keys for authentication:
//!
//! ```rust
//! use zoe_wire_protocol::{generate_ed25519_cert_for_tls, extract_ed25519_public_key_from_cert};
//! # use rand::rngs::OsRng;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate Ed25519 certificate
//! let ed25519_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
//! let certs = generate_ed25519_cert_for_tls(&ed25519_key, "example.com")?;
//! let extracted_key = extract_ed25519_public_key_from_cert(&certs[0])?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Serialization
//!
//! All data structures use [postcard](https://docs.rs/postcard/) for efficient binary serialization:
//!
//! ```rust
//! use zoe_wire_protocol::MessageFull;
//! # use zoe_wire_protocol::*;
//! # fn example(message_full: MessageFull) -> std::result::Result<(), Box<dyn std::error::Error>> {
//!
//! // Serialize for transmission
//! let bytes = postcard::to_stdvec(&message_full)?;
//!
//! // Deserialize received data
//! let received: MessageFull = postcard::from_bytes(&bytes)?;
//! # Ok(())
//! # }
//! ```

pub mod blob;
pub mod challenge;
pub mod connection;
pub mod connection_info;
pub mod crypto;
pub mod inbox;
pub mod invitation;
pub mod keys;
pub mod message;
pub mod primitives;
pub mod relay;
pub mod services;
pub mod streaming;
pub mod version;

use std::ops::Deref;

pub use blob::*;
pub use challenge::*;
pub use connection_info::*;
pub use crypto::*;
pub use inbox::*;
pub use invitation::{
    generate_ephemeral_group_invite_id, GroupInvitationData, GroupMetadata, HandshakePurpose,
    HandshakeResponse, ProfileSetEvent, UserProfile, VerificationHandshakeRequest,
};
pub use message::*;
pub use relay::*;
use serde::Deserialize;
use serde::Serialize;
pub use services::*;
pub use streaming::*; // Re-export streaming protocol types
pub use version::*; // Re-export protocol version negotiation types

pub use primitives::*;
// Re-export keys types for convenient access
pub use keys::*;

// Re-export ML-DSA utility functions for message crypto
pub use crypto::{
    generate_ml_dsa_from_mnemonic, recover_ml_dsa_from_mnemonic, MlDsaSelfEncryptedContent,
};
// Re-export bip39 for mnemonic functionality
pub use bip39;

// Re-export Ed25519 types
pub use ed25519_dalek::SigningKey as Ed25519SigningKey;
pub use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;

// Hash type alias
pub type Hash = blake3::Hash;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq, Hash)]
pub struct ChannelId(Vec<u8>);

impl Deref for ChannelId {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for ChannelId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<[u8; 32]> for ChannelId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes.to_vec())
    }
}

impl AsRef<[u8]> for ChannelId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::ToSql for ChannelId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(self.0.as_slice()))
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::types::FromSql for ChannelId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Blob(bytes) => {
                if bytes.len() != 32 {
                    return Err(rusqlite::types::FromSqlError::InvalidBlobSize {
                        expected_size: 32,
                        blob_size: bytes.len(),
                    });
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(bytes);
                Ok(ChannelId::from(array))
            }
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

/// Convinience function to creates from simple byte slices
pub fn hash(data: &[u8]) -> Hash {
    blake3::hash(data)
}
