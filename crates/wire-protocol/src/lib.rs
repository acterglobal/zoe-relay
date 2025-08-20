pub mod blob;
pub mod challenge;
pub mod crypto;
pub mod message;
pub mod prelude;
pub mod relay;
pub mod serde;
pub mod services;
pub mod streaming;

pub use blob::*;
pub use challenge::*;
pub use crypto::*;
pub use message::*;
pub use relay::*;
pub use services::*;
pub use streaming::*; // Re-export streaming protocol types

// Re-export prelude types for convenient access
pub use prelude::*;

// Re-export ML-DSA utility functions
pub use crypto::{
    generate_ml_dsa_44_keypair_for_tls, generate_ml_dsa_from_mnemonic,
    load_ml_dsa_44_key_from_hex_for_tls, load_ml_dsa_44_public_key_from_hex,
    recover_ml_dsa_from_mnemonic, save_ml_dsa_44_key_to_hex_for_tls,
    save_ml_dsa_44_public_key_to_hex, MlDsaSelfEncryptedContent,
};

// Re-export TLS certificate functions (both new ML-DSA-44 and compatibility functions)
pub use crypto::{
    extract_ed25519_from_cert, // Compatibility function
    extract_public_key_from_cert,
    generate_deterministic_cert_from_ed25519, // Compatibility function
    generate_deterministic_cert_from_ml_dsa_44_for_tls,
    AcceptSpecificServerCertVerifier,
    ZoeClientCertVerifier,
};

// Re-export bip39 for mnemonic functionality
pub use bip39;
