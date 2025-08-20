pub mod blob;
pub mod challenge;
pub mod connection;
pub mod crypto;
pub mod keys;
pub mod message;
pub mod relay;
pub mod relay_identity;
pub mod serde;
pub mod services;
pub mod streaming;

pub use blob::*;
pub use challenge::*;
pub use connection::*;
pub use crypto::*;
pub use message::*;
pub use relay::*;
pub use relay_identity::*;

// Type aliases for backward compatibility and convenience
pub type RelayIdentityKey = TransportPublicKey;
pub type ServerKeypair = TransportPrivateKey;
pub type ClientTransportKey = TransportPublicKey;
pub use services::*;
pub use streaming::*; // Re-export streaming protocol types

// Re-export keys types for convenient access
pub use keys::*;

// Re-export ML-DSA utility functions for message crypto
pub use crypto::{
    generate_ml_dsa_from_mnemonic, recover_ml_dsa_from_mnemonic, MlDsaSelfEncryptedContent,
};

// Re-export TLS certificate functions (ML-DSA-44 for transport layer)
// Re-export Ed25519 connection utilities (default)
pub use connection::{
    create_ed25519_server_config, extract_ed25519_public_key_from_cert,
    generate_ed25519_cert_for_tls, AcceptSpecificEd25519ServerCertVerifier,
};

// Re-export ML-DSA-44 connection utilities (when feature is enabled)
#[cfg(feature = "tls-ml-dsa-44")]
pub use connection::{extract_ml_dsa_44_public_key_from_cert, generate_ml_dsa_44_cert_for_tls};

// Re-export bip39 for mnemonic functionality
pub use bip39;

// Re-export Ed25519 types
pub use ed25519_dalek::SigningKey as Ed25519SigningKey;
pub use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;

// Hash type alias
pub type Hash = blake3::Hash;
