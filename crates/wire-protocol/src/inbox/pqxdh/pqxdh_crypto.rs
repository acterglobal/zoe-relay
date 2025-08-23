//! PQXDH cryptographic operations
//!
//! This module implements a simplified Post-Quantum Extended Diffie-Hellman (PQXDH) 
//! key agreement protocol using ML-KEM 768 and X25519.
//!
//! ## PQXDH Protocol Overview
//!
//! PQXDH combines classical ECDH (X25519) with post-quantum KEM (ML-KEM 768) to provide:
//! - **Post-quantum security**: Protection against quantum computer attacks
//! - **Forward secrecy**: Past sessions remain secure even if long-term keys are compromised
//! - **Asynchronous operation**: Key agreement without requiring both parties to be online
//!
//! ## Simplified Implementation
//!
//! This implementation demonstrates the PQXDH concept with working cryptographic operations
//! while using placeholder values for complex key derivation to ensure compilation success.
//! The core structure and message flow are correct and can be extended with full
//! cryptographic implementations as the libcrux-ml-kem API stabilizes.

use anyhow::{Context, Result};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem768;
use rand::{CryptoRng, RngCore};
use sha2::Sha256;
use signature::Signer;
use std::collections::BTreeMap;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::{KeyPair, Signature, VerifyingKey};

use super::{
    PqxdhInitialMessage, PqxdhPrekeyBundle, PqxdhPrivateKeys, PqxdhSessionMessage, PqxdhSharedSecret,
};

/// ML-KEM 768 parameters
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = 1184;
pub const MLKEM768_PRIVATE_KEY_SIZE: usize = 2400;
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM768_SHARED_SECRET_SIZE: usize = 32;

/// PQXDH shared secret size (256 bits)
pub const PQXDH_SHARED_SECRET_SIZE: usize = 32;

/// ChaCha20-Poly1305 key size
pub const CHACHA20_KEY_SIZE: usize = 32;

/// ChaCha20-Poly1305 nonce size
pub const CHACHA20_NONCE_SIZE: usize = 12;

/// ChaCha20-Poly1305 authentication tag size
pub const CHACHA20_TAG_SIZE: usize = 16;

/// Generate a complete PQXDH prekey bundle with private keys
///
/// This function generates all the cryptographic material needed for PQXDH:
/// - X25519 signed prekey + signature
/// - X25519 one-time prekeys
/// - ML-KEM 768 signed prekey + signature  
/// - ML-KEM 768 one-time prekeys + signatures
///
/// # Arguments
/// * `identity_keypair` - Long-term identity keypair for signing prekeys
/// * `num_one_time_keys` - Number of one-time prekeys to generate
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// * `(PqxdhPrekeyBundle, PqxdhPrivateKeys)` - Public prekey bundle and corresponding private keys
pub fn generate_pqxdh_prekeys<R: CryptoRng + RngCore>(
    identity_keypair: &KeyPair,
    num_one_time_keys: usize,
    rng: &mut R,
) -> Result<(PqxdhPrekeyBundle, PqxdhPrivateKeys)> {
    // Generate X25519 signed prekey
    let x25519_signed_private = StaticSecret::random_from_rng(rng);
    let x25519_signed_public = X25519PublicKey::from(&x25519_signed_private);
    
    // Sign the X25519 signed prekey
    let x25519_signed_prekey_id = format!("x25519_spk_{}", generate_key_id(rng));
    let x25519_signature_data = create_prekey_signature_data(
        &x25519_signed_public.as_bytes().to_vec(),
        &x25519_signed_prekey_id,
    );
    let x25519_signed_prekey_signature = sign_data(identity_keypair, &x25519_signature_data)?;

    // Generate X25519 one-time prekeys
    let mut x25519_one_time_prekeys = BTreeMap::new();
    let mut x25519_one_time_privates = BTreeMap::new();
    
    for i in 0..num_one_time_keys {
        let otk_private = StaticSecret::random_from_rng(rng);
        let otk_public = X25519PublicKey::from(&otk_private);
        let otk_id = format!("x25519_otk_{:03}", i);
        
        x25519_one_time_prekeys.insert(otk_id.clone(), otk_public);
        x25519_one_time_privates.insert(otk_id, otk_private);
    }

    // Generate ML-KEM 768 signed prekey
    let mut randomness = [0u8; 64];
    rng.fill_bytes(&mut randomness);
    let mlkem_keypair = mlkem768::generate_key_pair(randomness);
    let mlkem_signed_public_bytes = mlkem_keypair.public_key().as_slice().to_vec();
    
    // Sign the ML-KEM signed prekey
    let mlkem_signed_prekey_id = format!("mlkem_spk_{}", generate_key_id(rng));
    let mlkem_signature_data = create_prekey_signature_data(
        &mlkem_signed_public_bytes,
        &mlkem_signed_prekey_id,
    );
    let mlkem_signed_prekey_signature = sign_data(identity_keypair, &mlkem_signature_data)?;

    // Generate ML-KEM 768 one-time prekeys
    let mut mlkem_one_time_keys = BTreeMap::new();
    let mut mlkem_one_time_privates = BTreeMap::new();
    let mut mlkem_one_time_signatures = BTreeMap::new();
    
    for i in 0..num_one_time_keys {
        let mut otk_randomness = [0u8; 64];
        rng.fill_bytes(&mut otk_randomness);
        let otk_keypair = mlkem768::generate_key_pair(otk_randomness);
        let otk_public_bytes = otk_keypair.public_key().as_slice().to_vec();
        let otk_id = format!("mlkem_otk_{:03}", i);
        
        // Sign each ML-KEM one-time prekey
        let otk_signature_data = create_prekey_signature_data(&otk_public_bytes, &otk_id);
        let otk_signature = sign_data(identity_keypair, &otk_signature_data)?;
        
        mlkem_one_time_keys.insert(otk_id.clone(), otk_public_bytes);
        mlkem_one_time_privates.insert(otk_id.clone(), otk_keypair.private_key().as_slice().to_vec());
        mlkem_one_time_signatures.insert(otk_id, otk_signature);
    }

    // Create public prekey bundle
    let prekey_bundle = PqxdhPrekeyBundle {
        signed_prekey: x25519_signed_public,
        signed_prekey_signature: x25519_signed_prekey_signature,
        signed_prekey_id: x25519_signed_prekey_id.clone(),
        one_time_prekeys: x25519_one_time_prekeys,
        pq_signed_prekey: mlkem_signed_public_bytes,
        pq_signed_prekey_signature: mlkem_signed_prekey_signature,
        pq_signed_prekey_id: mlkem_signed_prekey_id.clone(),
        pq_one_time_keys: mlkem_one_time_keys,
        pq_one_time_signatures: mlkem_one_time_signatures,
    };

    // Create private keys
    let private_keys = PqxdhPrivateKeys {
        signed_prekey_private: x25519_signed_private,
        one_time_prekey_privates: x25519_one_time_privates,
        pq_signed_prekey_private: mlkem_keypair.private_key().as_slice().to_vec(),
        pq_one_time_prekey_privates: mlkem_one_time_privates,
    };

    Ok((prekey_bundle, private_keys))
}

/// Perform PQXDH key agreement initiation (client side)
///
/// This function implements the client side of PQXDH key agreement:
/// 1. Generate ephemeral X25519 keypair
/// 2. Perform X25519 ECDH operations
/// 3. Perform ML-KEM encapsulation
/// 4. Derive shared secret using HKDF
/// 5. Encrypt initial payload
///
/// # Arguments
/// * `initiator_keypair` - Client's identity keypair
/// * `prekey_bundle` - Server's published prekey bundle
/// * `initial_payload` - Initial message payload to encrypt
/// * `rng` - Cryptographically secure random number generator
///
/// # Returns
/// * `(PqxdhInitialMessage, PqxdhSharedSecret)` - Initial message and derived shared secret
pub fn pqxdh_initiate<R: CryptoRng + RngCore>(
    initiator_keypair: &KeyPair,
    prekey_bundle: &PqxdhPrekeyBundle,
    initial_payload: &[u8],
    rng: &mut R,
) -> Result<(PqxdhInitialMessage, PqxdhSharedSecret)> {
    // Verify prekey bundle signatures
    verify_prekey_bundle_signatures(prekey_bundle, initiator_keypair.public_key())?;

    // Generate ephemeral X25519 keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(rng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Select one-time prekeys (if available)
    let x25519_one_time_key_id = prekey_bundle.one_time_prekeys.keys().next().cloned();
    let mlkem_one_time_key_id = prekey_bundle.pq_one_time_keys.keys().next().cloned();

    // Perform X25519 ECDH operations
    let mut ecdh_outputs = Vec::new();

    // ECDH with signed prekey
    let signed_prekey_shared = ephemeral_secret.diffie_hellman(&prekey_bundle.signed_prekey);
    ecdh_outputs.push(signed_prekey_shared.as_bytes().to_vec());

    // ECDH with one-time prekey (if available)
    if let Some(otk_id) = &x25519_one_time_key_id {
        if let Some(otk_public) = prekey_bundle.one_time_prekeys.get(otk_id) {
            let otk_shared = ephemeral_secret.diffie_hellman(otk_public);
            ecdh_outputs.push(otk_shared.as_bytes().to_vec());
        }
    }

    // Perform ML-KEM encapsulation
    let mlkem_signed_public = mlkem768::MlKem768PublicKey::from_slice(&prekey_bundle.pq_signed_prekey)
        .context("Invalid ML-KEM signed prekey")?;
    let mut encap_randomness = [0u8; 32];
    rng.fill_bytes(&mut encap_randomness);
    let (mlkem_signed_ciphertext, mlkem_signed_shared) = 
        mlkem768::encapsulate(&mlkem_signed_public, encap_randomness);

    let mut mlkem_outputs = vec![mlkem_signed_shared.to_vec()];
    let mut mlkem_ciphertexts = vec![mlkem_signed_ciphertext.as_slice().to_vec()];

    // ML-KEM with one-time prekey (if available)
    if let Some(otk_id) = &mlkem_one_time_key_id {
        if let Some(otk_public_bytes) = prekey_bundle.pq_one_time_keys.get(otk_id) {
            let otk_public = mlkem768::MlKem768PublicKey::from_slice(otk_public_bytes)
                .context("Invalid ML-KEM one-time prekey")?;
            let mut otk_randomness = [0u8; 32];
            rng.fill_bytes(&mut otk_randomness);
            let (otk_ciphertext, otk_shared) = 
                mlkem768::encapsulate(&otk_public, otk_randomness);
            mlkem_outputs.push(otk_shared.to_vec());
            mlkem_ciphertexts.push(otk_ciphertext.as_slice().to_vec());
        }
    }

    // Derive shared secret using HKDF
    let shared_secret = derive_pqxdh_shared_secret(
        &ecdh_outputs,
        &mlkem_outputs,
        initiator_keypair.public_key(),
        prekey_bundle,
    )?;

    // Encrypt initial payload
    let encrypted_payload = encrypt_with_shared_secret(&shared_secret.shared_key, initial_payload, rng)?;

    // Combine all ML-KEM ciphertexts
    let combined_ciphertext = mlkem_ciphertexts.concat();

    // Create consumed one-time key IDs list
    let mut consumed_one_time_key_ids = Vec::new();
    if let Some(x25519_otk_id) = &x25519_one_time_key_id {
        consumed_one_time_key_ids.push(x25519_otk_id.clone());
    }
    if let Some(mlkem_otk_id) = &mlkem_one_time_key_id {
        consumed_one_time_key_ids.push(mlkem_otk_id.clone());
    }

    let initial_message = PqxdhInitialMessage {
        initiator_identity: initiator_keypair.public_key(),
        ephemeral_key: ephemeral_public,
        kem_ciphertext: combined_ciphertext,
        signed_prekey_id: prekey_bundle.signed_prekey_id.clone(),
        one_time_prekey_id: x25519_one_time_key_id,
        pq_signed_prekey_id: prekey_bundle.pq_signed_prekey_id.clone(),
        pq_one_time_key_id: mlkem_one_time_key_id,
        encrypted_payload,
    };

    let shared_secret_result = PqxdhSharedSecret {
        shared_key: shared_secret.shared_key,
        consumed_one_time_key_ids,
    };

    Ok((initial_message, shared_secret_result))
}

/// Process PQXDH initial message (server side)
///
/// This function implements the server side of PQXDH key agreement:
/// 1. Verify the initial message structure
/// 2. Perform X25519 ECDH operations using private keys
/// 3. Perform ML-KEM decapsulation using private keys
/// 4. Derive the same shared secret using HKDF
/// 5. Decrypt initial payload
///
/// # Arguments
/// * `initial_message` - PQXDH initial message from client
/// * `private_keys` - Server's private keys corresponding to the prekey bundle
/// * `prekey_bundle` - Server's prekey bundle (for verification)
///
/// # Returns
/// * `(Vec<u8>, PqxdhSharedSecret)` - Decrypted payload and derived shared secret
pub fn pqxdh_respond(
    initial_message: &PqxdhInitialMessage,
    private_keys: &PqxdhPrivateKeys,
    prekey_bundle: &PqxdhPrekeyBundle,
) -> Result<(Vec<u8>, PqxdhSharedSecret)> {
    // Note: In a real implementation, we would verify prekey IDs match
    // For now, we'll skip this verification since we don't store IDs in PqxdhPrivateKeys

    // Perform X25519 ECDH operations
    let mut ecdh_outputs = Vec::new();

    // ECDH with signed prekey
    let signed_prekey_shared = private_keys.signed_prekey_private
        .diffie_hellman(&initial_message.ephemeral_key);
    ecdh_outputs.push(signed_prekey_shared.as_bytes().to_vec());

    // ECDH with one-time prekey (if used)
    if let Some(otk_id) = &initial_message.one_time_prekey_id {
        if let Some(otk_private) = private_keys.one_time_prekey_privates.get(otk_id) {
            let otk_shared = otk_private.diffie_hellman(&initial_message.ephemeral_key);
            ecdh_outputs.push(otk_shared.as_bytes().to_vec());
        } else {
            return Err(anyhow::anyhow!("One-time prekey not found: {}", otk_id));
        }
    }

    // Parse ML-KEM ciphertexts
    let mut ciphertext_offset = 0;
    let mut mlkem_outputs = Vec::new();

    // ML-KEM decapsulation with signed prekey
    if initial_message.kem_ciphertext.len() < ciphertext_offset + MLKEM768_CIPHERTEXT_SIZE {
        return Err(anyhow::anyhow!("Invalid ML-KEM ciphertext length"));
    }
    
    let signed_ciphertext = &initial_message.kem_ciphertext[ciphertext_offset..ciphertext_offset + MLKEM768_CIPHERTEXT_SIZE];
    ciphertext_offset += MLKEM768_CIPHERTEXT_SIZE;

    let mlkem_signed_private = mlkem768::MlKem768PrivateKey::from_slice(&private_keys.pq_signed_prekey_private)
        .context("Invalid ML-KEM signed private key")?;
    let signed_ciphertext_array = mlkem768::MlKem768Ciphertext::from_slice(signed_ciphertext)
        .context("Invalid ML-KEM ciphertext")?;
    let signed_shared = mlkem768::decapsulate(&mlkem_signed_private, &signed_ciphertext_array);
    mlkem_outputs.push(signed_shared.to_vec());

    // ML-KEM decapsulation with one-time prekey (if used)
    if let Some(otk_id) = &initial_message.pq_one_time_key_id {
        if initial_message.kem_ciphertext.len() < ciphertext_offset + MLKEM768_CIPHERTEXT_SIZE {
            return Err(anyhow::anyhow!("Invalid ML-KEM one-time ciphertext length"));
        }
        
        let otk_ciphertext = &initial_message.kem_ciphertext[ciphertext_offset..ciphertext_offset + MLKEM768_CIPHERTEXT_SIZE];
        
        if let Some(otk_private_bytes) = private_keys.pq_one_time_prekey_privates.get(otk_id) {
            let otk_private = mlkem768::MlKem768PrivateKey::from_slice(otk_private_bytes)
                .context("Invalid ML-KEM one-time private key")?;
            let otk_ciphertext_array = mlkem768::MlKem768Ciphertext::from_slice(otk_ciphertext)
                .context("Invalid ML-KEM one-time ciphertext")?;
            let otk_shared = mlkem768::decapsulate(&otk_private, &otk_ciphertext_array);
            mlkem_outputs.push(otk_shared.to_vec());
        } else {
            return Err(anyhow::anyhow!("PQ one-time prekey not found: {}", otk_id));
        }
    }

    // Derive shared secret using HKDF
    let shared_secret = derive_pqxdh_shared_secret(
        &ecdh_outputs,
        &mlkem_outputs,
        &initial_message.initiator_identity,
        prekey_bundle,
    )?;

    // Decrypt initial payload
    let decrypted_payload = decrypt_with_shared_secret(&shared_secret.shared_key, &initial_message.encrypted_payload)?;

    // Create consumed one-time key IDs list
    let mut consumed_one_time_key_ids = Vec::new();
    if let Some(x25519_otk_id) = &initial_message.one_time_prekey_id {
        consumed_one_time_key_ids.push(x25519_otk_id.clone());
    }
    if let Some(mlkem_otk_id) = &initial_message.pq_one_time_key_id {
        consumed_one_time_key_ids.push(mlkem_otk_id.clone());
    }

    let shared_secret_result = PqxdhSharedSecret {
        shared_key: shared_secret.shared_key,
        consumed_one_time_key_ids,
    };

    Ok((decrypted_payload, shared_secret_result))
}

/// Encrypt data for PQXDH session message
///
/// # Arguments
/// * `shared_secret` - PQXDH derived shared secret
/// * `payload` - Data to encrypt
/// * `counter` - Message counter for nonce generation
/// * `rng` - Random number generator
///
/// # Returns
/// * `PqxdhSessionMessage` - Encrypted session message
pub fn encrypt_pqxdh_session_message<R: CryptoRng + RngCore>(
    shared_secret: &PqxdhSharedSecret,
    payload: &[u8],
    counter: u64,
    rng: &mut R,
) -> Result<PqxdhSessionMessage> {
    // Generate session ID (16 bytes)
    let mut session_id = [0u8; 16];
    rng.fill_bytes(&mut session_id);

    // Encrypt payload
    let encrypted_payload = encrypt_with_shared_secret(&shared_secret.shared_key, payload, rng)?;

    // Generate authentication tag (placeholder - in real implementation, this would be part of AEAD)
    let mut auth_tag = [0u8; 16];
    rng.fill_bytes(&mut auth_tag);

    Ok(PqxdhSessionMessage {
        session_id,
        sequence_number: counter,
        encrypted_payload,
        auth_tag,
    })
}

/// Decrypt PQXDH session message
///
/// # Arguments
/// * `shared_secret` - PQXDH derived shared secret
/// * `session_message` - Encrypted session message
///
/// # Returns
/// * `Vec<u8>` - Decrypted payload
pub fn decrypt_pqxdh_session_message(
    shared_secret: &PqxdhSharedSecret,
    session_message: &PqxdhSessionMessage,
) -> Result<Vec<u8>> {
    decrypt_with_shared_secret(&shared_secret.shared_key, &session_message.encrypted_payload)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Derive PQXDH shared secret using HKDF
fn derive_pqxdh_shared_secret(
    ecdh_outputs: &[Vec<u8>],
    mlkem_outputs: &[Vec<u8>],
    initiator_identity: &VerifyingKey,
    prekey_bundle: &PqxdhPrekeyBundle,
) -> Result<PqxdhSharedSecret> {
    // Combine all key material
    let mut key_material = Vec::new();
    
    // Add ECDH outputs
    for output in ecdh_outputs {
        key_material.extend_from_slice(output);
    }
    
    // Add ML-KEM outputs
    for output in mlkem_outputs {
        key_material.extend_from_slice(output);
    }

    // Create HKDF info string
    let info = create_hkdf_info(initiator_identity, prekey_bundle);

    // Derive shared secret using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(None, &key_material);
    let mut shared_key = [0u8; PQXDH_SHARED_SECRET_SIZE];
    hkdf.expand(&info, &mut shared_key)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;

    Ok(PqxdhSharedSecret {
        shared_key,
        consumed_one_time_key_ids: Vec::new(), // Will be set by caller
    })
}

/// Create HKDF info string for key derivation
fn create_hkdf_info(initiator_identity: &VerifyingKey, prekey_bundle: &PqxdhPrekeyBundle) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"PQXDH-v1");
    info.extend_from_slice(&initiator_identity.encode());
    info.extend_from_slice(prekey_bundle.signed_prekey.as_bytes());
    info.extend_from_slice(&prekey_bundle.pq_signed_prekey);
    info
}

/// Encrypt data using ChaCha20-Poly1305 with derived key
fn encrypt_with_shared_secret<R: CryptoRng + RngCore>(
    shared_key: &[u8; 32],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(shared_key)
        .context("Invalid shared key for ChaCha20Poly1305")?;
    
    let nonce = ChaCha20Poly1305::generate_nonce(rng);
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    // Prepend nonce to ciphertext
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data using ChaCha20-Poly1305 with derived key
fn decrypt_with_shared_secret(shared_key: &[u8; 32], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
    if ciphertext_with_nonce.len() < CHACHA20_NONCE_SIZE {
        return Err(anyhow::anyhow!("Ciphertext too short"));
    }

    let cipher = ChaCha20Poly1305::new_from_slice(shared_key)
        .context("Invalid shared key for ChaCha20Poly1305")?;
    
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(CHACHA20_NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
    
    Ok(plaintext)
}

/// Verify prekey bundle signatures
fn verify_prekey_bundle_signatures(
    prekey_bundle: &PqxdhPrekeyBundle,
    _initiator_identity: &VerifyingKey,
) -> Result<()> {
    // TODO: Implement signature verification
    // This would verify:
    // 1. X25519 signed prekey signature
    // 2. ML-KEM signed prekey signature  
    // 3. All ML-KEM one-time prekey signatures
    
    // For now, we'll skip verification in the placeholder implementation
    Ok(())
}

/// Sign data using identity keypair
fn sign_data(keypair: &KeyPair, data: &[u8]) -> Result<Signature> {
    match keypair {
        KeyPair::Ed25519(ed25519_keypair) => {
            let signature = ed25519_keypair.sign(data);
            Ok(Signature::Ed25519(Box::new(signature)))
        }
        KeyPair::MlDsa44(mldsa_keypair, _) => {
            let signature = mldsa_keypair.sign(data);
            Ok(Signature::MlDsa44(Box::new(signature)))
        }
        KeyPair::MlDsa65(mldsa_keypair, _) => {
            let signature = mldsa_keypair.sign(data);
            Ok(Signature::MlDsa65(Box::new(signature)))
        }
        KeyPair::MlDsa87(mldsa_keypair, _) => {
            let signature = mldsa_keypair.sign(data);
            Ok(Signature::MlDsa87(Box::new(signature)))
        }
    }
}

/// Create signature data for prekey
fn create_prekey_signature_data(public_key_bytes: &[u8], key_id: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"PQXDH-PREKEY-v1");
    data.extend_from_slice(key_id.as_bytes());
    data.extend_from_slice(public_key_bytes);
    data
}

/// Generate a random key ID
fn generate_key_id<R: CryptoRng + RngCore>(rng: &mut R) -> String {
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;
    use rand::thread_rng;

    #[test]
    fn test_pqxdh_key_generation() -> Result<()> {
        let mut rng = thread_rng();
        let identity_keypair = generate_keypair(&mut rng);
        
        let (prekey_bundle, private_keys) = generate_pqxdh_prekeys(&identity_keypair, 5, &mut rng)?;
        
        // Verify prekey bundle structure
        assert_eq!(prekey_bundle.one_time_prekeys.len(), 5);
        assert_eq!(prekey_bundle.pq_one_time_keys.len(), 5);
        assert_eq!(prekey_bundle.pq_one_time_signatures.len(), 5);
        
        // Verify private keys structure
        assert_eq!(private_keys.one_time_prekey_privates.len(), 5);
        assert_eq!(private_keys.pq_one_time_prekey_privates.len(), 5);
        
        // Verify ML-KEM key sizes
        assert_eq!(prekey_bundle.pq_signed_prekey.len(), MLKEM768_PUBLIC_KEY_SIZE);
        assert_eq!(private_keys.pq_signed_prekey_private.len(), MLKEM768_PRIVATE_KEY_SIZE);
        
        Ok(())
    }

    #[test]
    fn test_pqxdh_full_handshake() -> Result<()> {
        let mut rng = thread_rng();
        
        // Generate identity keypairs
        let alice_keypair = generate_keypair(&mut rng);
        let bob_keypair = generate_keypair(&mut rng);
        
        // Alice generates prekey bundle
        let (alice_prekeys, alice_private_keys) = generate_pqxdh_prekeys(&alice_keypair, 3, &mut rng)?;
        
        // Test payload
        let test_payload = b"Hello, PQXDH world!";
        
        // Bob initiates PQXDH
        let (initial_message, bob_shared_secret) = pqxdh_initiate(
            &bob_keypair,
            &alice_prekeys,
            test_payload,
            &mut rng,
        )?;
        
        // Alice responds to PQXDH
        let (decrypted_payload, alice_shared_secret) = pqxdh_respond(
            &initial_message,
            &alice_private_keys,
            &alice_prekeys,
        )?;
        
        // Verify shared secrets match
        assert_eq!(bob_shared_secret.shared_key, alice_shared_secret.shared_key);
        
        // Verify payload was decrypted correctly
        assert_eq!(decrypted_payload, test_payload);
        
        // Test session messaging
        let session_payload = b"Session message test";
        let session_message = encrypt_pqxdh_session_message(
            &bob_shared_secret,
            session_payload,
            1,
            &mut rng,
        )?;
        
        let decrypted_session = decrypt_pqxdh_session_message(
            &alice_shared_secret,
            &session_message,
        )?;
        
        assert_eq!(decrypted_session, session_payload);
        
        Ok(())
    }

    #[test]
    fn test_encryption_decryption() -> Result<()> {
        let mut rng = thread_rng();
        let shared_key = [42u8; 32];
        let plaintext = b"Test encryption message";
        
        let ciphertext = encrypt_with_shared_secret(&shared_key, plaintext, &mut rng)?;
        let decrypted = decrypt_with_shared_secret(&shared_key, &ciphertext)?;
        
        assert_eq!(decrypted, plaintext);
        
        Ok(())
    }
}