//! Prelude module providing generic type aliases for cryptographic primitives
//!
//! This module allows other crates to use generic types like `zoe_wire_protocol::SigningKey`
//! without needing to know the specific ML-DSA implementation details.

use ml_dsa::KeyGen;

// Re-export signature traits that are commonly needed
pub use signature::{SignatureEncoding, Signer, Verifier};

// Re-export the KeyGen trait for key generation
pub use ml_dsa::KeyGen as MlDsaKeyGen;

// ML-DSA type aliases - these are the primary cryptographic primitives (using ML-DSA-65 for inner protocol)
pub type MlDsaParams = ml_dsa::MlDsa65;
pub type SigningKey = ml_dsa::SigningKey<MlDsaParams>;
pub type VerifyingKey = ml_dsa::VerifyingKey<MlDsaParams>;
pub type KeyPair = ml_dsa::KeyPair<MlDsaParams>;
pub type Signature = ml_dsa::Signature<MlDsaParams>;

// Ed25519 type aliases for compatibility (relay keys, etc.)
pub type Ed25519SigningKey = ed25519_dalek::SigningKey;
pub type Ed25519VerifyingKey = ed25519_dalek::VerifyingKey;
pub type Ed25519Signature = ed25519_dalek::Signature;

// Hash type alias
pub type Hash = blake3::Hash;

// Convenience re-exports of the parameter type
pub use ml_dsa::MlDsa44;
pub use ml_dsa::MlDsa65;

/// Generate a new ML-DSA keypair using the default parameters
pub fn generate_keypair<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> KeyPair {
    MlDsaParams::key_gen(rng)
}

/// Generate a new Ed25519 keypair for relay operations
pub fn generate_ed25519_relay_keypair<R: rand::CryptoRng + rand::RngCore>(
    rng: &mut R,
) -> Ed25519SigningKey {
    Ed25519SigningKey::generate(rng)
}

/// Helper to get verifying key from keypair
pub fn verifying_key_from_keypair(keypair: &KeyPair) -> VerifyingKey {
    keypair.verifying_key().clone()
}

/// Helper to get signing key from keypair
pub fn signing_key_from_keypair(keypair: &KeyPair) -> SigningKey {
    keypair.signing_key().clone()
}

/// Convert VerifyingKey to bytes for compatibility with existing serialization
pub fn verifying_key_to_bytes(key: &VerifyingKey) -> Vec<u8> {
    key.encode().as_slice().to_vec()
}

/// Create VerifyingKey from bytes
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, ml_dsa::Error> {
    let encoded = ml_dsa::EncodedVerifyingKey::<MlDsaParams>::try_from(bytes)
        .map_err(|_| ml_dsa::Error::new())?;
    Ok(ml_dsa::VerifyingKey::decode(&encoded))
}

/// Convert SigningKey to bytes for compatibility with existing serialization
pub fn signing_key_to_bytes(key: &SigningKey) -> Vec<u8> {
    key.encode().as_slice().to_vec()
}

/// Create SigningKey from bytes
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, ml_dsa::Error> {
    let encoded = ml_dsa::EncodedSigningKey::<MlDsaParams>::try_from(bytes)
        .map_err(|_| ml_dsa::Error::new())?;
    Ok(ml_dsa::SigningKey::decode(&encoded))
}
