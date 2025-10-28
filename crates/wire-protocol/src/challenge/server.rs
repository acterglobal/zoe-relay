use super::{DEFAULT_CHALLENGE_TIMEOUT_SECS, MAX_PACKAGE_SIZE};
use crate::{
    KeyChallenge, KeyPair, KeyProof, KeyResponse, KeyResult, VerifyingKey, ZoeChallenge,
    ZoeChallengeRejection, ZoeChallengeResult,
};
use anyhow::Result;
use quinn::{RecvStream, SendStream};
use rand::RngCore;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

/// Performs a multi-challenge handshake with a client
///
/// This function implements the server side of the new flexible challenge protocol:
/// 1. Sends multiple challenges sequentially (ML-DSA, proof-of-work, etc.)
/// 2. Receives and verifies each challenge response
/// 3. Returns the set of successfully verified ML-DSA public keys
///
/// The server can send multiple different challenge types, and the client must
/// respond to each one. The handshake continues until all challenges are completed
/// or a challenge fails.
///
/// # Arguments
///
/// * `send` - Stream for sending data to the client
/// * `recv` - Stream for receiving data from the client
/// * `server_keypair` - Server's keypair for signing the challenge nonce
///
/// # Returns
///
/// A `BTreeSet` of successfully verified public keys (as encoded bytes)
///
/// # Errors
///
/// Returns an error if:
/// - Network I/O fails
/// - Serialization/deserialization fails
/// - Any challenge fails verification
/// - Client response is malformed or too large
///
/// # Example
///
/// ```rust
/// use zoe_relay_server::challenge::perform_multi_challenge_handshake;
///
/// let verified_keys = perform_multi_challenge_handshake(
///     send_stream,
///     recv_stream,
///     &server_keypair
/// ).await?;
///
/// debug!("Verified {} keys after multi-challenge handshake", verified_keys.len());
/// ```
pub async fn perform_multi_challenge_handshake(
    mut send: SendStream,
    mut recv: RecvStream,
    server_keypair: &KeyPair,
) -> Result<HashSet<VerifyingKey>> {
    debug!("🔐 Starting multi-challenge handshake");
    send_result(&mut send, &ZoeChallengeResult::Next).await?;

    // Challenge 1: Key proof
    debug!("📝 Sending key challenge");
    let key_challenge = generate_key_challenge(server_keypair)?;
    debug!("🔧 Generated challenge, sending to client...");
    send_challenge(
        &mut send,
        &ZoeChallenge::Key(Box::new(key_challenge.clone())),
    )
    .await?;
    debug!("✅ Challenge sent, waiting for client response...");

    // Receive key response
    debug!("📥 Waiting to receive key response from client...");
    let key_response = receive_key_response(&mut recv).await?;
    debug!(
        "✅ Received key response with {} proofs",
        key_response.key_proofs.len()
    );

    // Verify key proofs
    let (keys, _key_result) = verify_key_proofs(key_response, &key_challenge)?;

    if keys.is_empty() {
        // Key challenge failed - send rejection and close
        let result = ZoeChallengeResult::Rejected(ZoeChallengeRejection::ChallengeIncomplete);
        send_result(&mut send, &result).await?;
        return Err(anyhow::anyhow!("Key challenge failed: no valid key proofs"));
    }

    //  We can add more challenge types here (proof-of-work, etc.)
    // For now, we only have ML-DSA, so we send Accepted

    debug!("✅ All challenges completed successfully");
    let result = ZoeChallengeResult::Accepted;
    send_result(&mut send, &result).await?;

    debug!(
        "✅ Multi-challenge handshake completed. Verified {} keys",
        keys.len()
    );

    Ok(keys)
}

/// Generates a new key challenge with a random nonce
///
/// The challenge includes:
/// - A cryptographically random 32-byte nonce
/// - The server's signature over the nonce (for server authentication)
/// - An expiration timestamp (current time + timeout)
///
/// # Arguments
///
/// * `server_keypair` - Server's keypair for signing the nonce
///
/// # Returns
///
/// A `KeyChallenge` containing the challenge data
pub fn generate_key_challenge(server_keypair: &KeyPair) -> Result<KeyChallenge> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let expires_at =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + DEFAULT_CHALLENGE_TIMEOUT_SECS;

    // Server signs the nonce to prove its identity
    let server_signature = server_keypair.sign(&nonce);

    let challenge_data = KeyChallenge {
        nonce,
        signature: server_signature,
        expires_at,
    };

    debug!(
        "Generated key challenge with nonce: {} expires at: {}",
        hex::encode(&nonce[..8]),
        expires_at
    );

    Ok(challenge_data)
}

/// Sends a challenge to the client over the stream
///
/// Serializes the challenge using postcard and sends it with a length prefix.
///
/// # Arguments
///
/// * `send` - Stream to send the challenge on
/// * `challenge` - Challenge to send
pub async fn send_challenge(send: &mut SendStream, challenge: &ZoeChallenge) -> Result<()> {
    let challenge_bytes = postcard::to_stdvec(challenge)?;

    debug!("Sending challenge ({} bytes)", challenge_bytes.len());

    // Send length prefix (4 bytes, big endian)
    send.write_u32(challenge_bytes.len() as u32).await?;

    // Send challenge data
    send.write_all(&challenge_bytes).await?;

    Ok(())
}

/// Receives a key challenge response from the client
///
/// Reads the response with length prefix and deserializes it directly
/// as a KeyResponse (no wrapper enum).
///
/// # Arguments
///
/// * `recv` - Stream to receive the response from
///
/// # Returns
///
/// The parsed `KeyResponse` from the client
pub async fn receive_key_response(recv: &mut RecvStream) -> Result<KeyResponse> {
    // Read length prefix
    let response_len = recv.read_u32().await? as usize;

    if response_len > MAX_PACKAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Response too large: {} bytes (max: {})",
            response_len,
            MAX_PACKAGE_SIZE
        ));
    }

    debug!("Receiving response ({} bytes)", response_len);

    // Read response data
    let mut response_buf = vec![0u8; response_len];
    recv.read_exact(&mut response_buf).await?;

    // Parse response directly as KeyResponse
    let response: KeyResponse = postcard::from_bytes(&response_buf)?;

    debug!(
        "Received key response with {} key proofs",
        response.key_proofs.len()
    );
    Ok(response)
}

/// Verifies all key proofs in a response
///
/// Each key proof is verified independently. The function continues even if some
/// proofs fail, collecting all successful verifications.
///
/// # Arguments
///
/// * `response` - Client's response containing key proofs
/// * `challenge` - Original key challenge (needed for signature verification)
///
/// # Returns
///
/// A tuple containing:
/// - Set of successfully verified public keys (as encoded bytes)
/// - Key specific result indicating which proofs succeeded/failed
pub fn verify_key_proofs(
    response: KeyResponse,
    challenge: &KeyChallenge,
) -> Result<(HashSet<VerifyingKey>, KeyResult)> {
    let challenge_data = challenge;

    // Check if challenge has expired
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if current_time > challenge_data.expires_at {
        warn!(
            "Challenge expired: current={}, expires={}",
            current_time, challenge_data.expires_at
        );
        return Ok((HashSet::new(), KeyResult::AllFailed));
    }

    let mut verified_keys = HashSet::new();
    let mut failed_indices = Vec::new();

    // Prepare signature data: just the nonce (clients sign the nonce)
    let signature_data = challenge_data.nonce.to_vec();
    let total_key_proofs = response.key_proofs.len();
    debug!("Verifying {} key proofs", total_key_proofs);

    for (index, key_proof) in response.key_proofs.into_iter().enumerate() {
        match verify_single_key_proof(&key_proof, &signature_data) {
            Ok(()) => {
                debug!(
                    "✅ Verified key proof {}: {}",
                    index,
                    hex::encode(&key_proof.public_key.encode()[..8])
                );
                verified_keys.insert(key_proof.public_key);
            }
            Err(e) => {
                failed_indices.push(index);
                warn!("❌ Key proof {} failed: {}", index, e);
            }
        }
    }

    let result = if failed_indices.is_empty() {
        KeyResult::AllValid
    } else if verified_keys.is_empty() {
        KeyResult::AllFailed
    } else {
        KeyResult::PartialFailure { failed_indices }
    };

    debug!(
        "Verification complete: {}/{} keys verified",
        verified_keys.len(),
        total_key_proofs
    );

    Ok((verified_keys, result))
}

/// Verifies a single key proof
///
/// Uses the public key and signature from the key proof to verify the signature over
/// the challenge data.
///
/// # Arguments
///
/// * `key_proof` - The key proof to verify
/// * `signature_data` - The data that should have been signed (nonce)
///
/// # Returns
///
/// `Ok(())` if verification succeeds, `Err` with details if it fails
fn verify_single_key_proof(key_proof: &KeyProof, signature_data: &[u8]) -> Result<()> {
    // Use the public key and signature directly from the key proof
    let verifying_key = &key_proof.public_key;
    let signature = &key_proof.signature;

    // Verify the signature - returns Result<bool, _>
    verifying_key
        .verify(signature_data, signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
}

/// Sends the challenge result back to the client
///
/// # Arguments
///
/// * `send` - Stream to send the result on
/// * `result` - Challenge result to send (Accepted, Next, Rejected, Error)
pub async fn send_result(send: &mut SendStream, result: &ZoeChallengeResult) -> Result<()> {
    let result_bytes = postcard::to_stdvec(result)?;

    debug!("Sending result ({} bytes)", result_bytes.len());

    // Send length prefix (4 bytes, big endian)
    send.write_u32(result_bytes.len() as u32).await?;

    // Send result data
    send.write_all(&result_bytes).await?;

    Ok(())
}

/// Create key proofs for a challenge response (used in tests)
///
/// This function creates key proofs for the given keypairs in response to a challenge.
/// It's primarily used in integration tests.
pub fn create_key_proofs(challenge: &KeyChallenge, keypairs: &[&KeyPair]) -> Result<KeyResponse> {
    let mut key_proofs = Vec::new();

    // Construct the signature data (just the nonce)
    let signature_data = challenge.nonce.to_vec();

    // Create a proof for each keypair
    for keypair in keypairs {
        let signature = keypair.sign(&signature_data);
        let verifying_key = keypair.public_key();

        let key_proof = KeyProof {
            public_key: verifying_key,
            signature,
        };
        key_proofs.push(key_proof);
    }

    Ok(KeyResponse { key_proofs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    #[test]
    fn test_key_challenge_generation() {
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let challenge = generate_key_challenge(&server_keypair).unwrap();

        // The signature field contains the server's signature over the nonce
        assert!(
            challenge.expires_at
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    fn test_single_key_proof_verification() {
        // Generate test keys
        let client_keypair = KeyPair::generate(&mut rand::thread_rng());

        // Create signature data (just the nonce)
        let nonce = [42u8; 32];
        let signature_data = nonce.to_vec();

        // Create signature
        let signature = client_keypair.sign(&signature_data);
        let verifying_key = client_keypair.public_key();

        // Create key proof
        let key_proof = KeyProof {
            public_key: verifying_key,
            signature,
        };

        // Verify proof
        let result = verify_single_key_proof(&key_proof, &signature_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_fails() {
        // Generate test keys
        let client_keypair = KeyPair::generate(&mut rand::thread_rng());

        // Create signature data
        let signature_data = b"test data";

        // Create signature over different data
        let wrong_signature = client_keypair.sign(b"wrong data");
        let verifying_key = client_keypair.public_key();

        // Create key proof with wrong signature
        let key_proof = KeyProof {
            public_key: verifying_key,
            signature: wrong_signature,
        };

        // Verify proof should fail
        let result = verify_single_key_proof(&key_proof, signature_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_key_challenge() {
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());

        let challenge = generate_key_challenge(&server_keypair).unwrap();

        // Check that nonce is 32 bytes
        assert_eq!(challenge.nonce.len(), 32);

        // Check that signature verifies
        let server_public_key = server_keypair.public_key();
        assert!(server_public_key
            .verify(&challenge.nonce, &challenge.signature)
            .is_ok());

        // Check that expiration is in the future
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(challenge.expires_at > now);
    }

    #[test]
    fn test_create_key_proofs() {
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let client_keypair1 = KeyPair::generate(&mut rand::thread_rng());
        let client_keypair2 = KeyPair::generate(&mut rand::thread_rng());

        let challenge = generate_key_challenge(&server_keypair).unwrap();
        let client_keys = vec![&client_keypair1, &client_keypair2];

        let response = create_key_proofs(&challenge, &client_keys).unwrap();

        // Should have proofs for both keys
        assert_eq!(response.key_proofs.len(), 2);

        // Each proof should verify
        for (i, proof) in response.key_proofs.iter().enumerate() {
            let result = verify_single_key_proof(proof, &challenge.nonce);
            assert!(result.is_ok(), "Proof {i} should verify");
        }
    }

    #[test]
    fn test_verify_key_proofs() {
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let client_keypair1 = KeyPair::generate(&mut rand::thread_rng());
        let client_keypair2 = KeyPair::generate(&mut rand::thread_rng());

        let challenge = generate_key_challenge(&server_keypair).unwrap();
        let client_keys = vec![&client_keypair1, &client_keypair2];

        let response = create_key_proofs(&challenge, &client_keys).unwrap();

        let (verified_keys, result) = verify_key_proofs(response, &challenge).unwrap();

        // Should verify both keys
        assert_eq!(verified_keys.len(), 2);
        assert!(matches!(result, KeyResult::AllValid));

        // Verified keys should match the client public keys
        assert!(verified_keys.contains(&client_keypair1.public_key()));
        assert!(verified_keys.contains(&client_keypair2.public_key()));
    }

    #[test]
    fn test_verify_key_proofs_partial_failure() {
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let client_keypair1 = KeyPair::generate(&mut rand::thread_rng());
        let client_keypair2 = KeyPair::generate(&mut rand::thread_rng());

        let challenge = generate_key_challenge(&server_keypair).unwrap();

        // Create one valid proof and one invalid proof
        let valid_signature = client_keypair1.sign(&challenge.nonce);
        let invalid_signature = client_keypair2.sign(b"wrong data");

        let response = KeyResponse {
            key_proofs: vec![
                KeyProof {
                    public_key: client_keypair1.public_key(),
                    signature: valid_signature,
                },
                KeyProof {
                    public_key: client_keypair2.public_key(),
                    signature: invalid_signature,
                },
            ],
        };

        let (verified_keys, result) = verify_key_proofs(response, &challenge).unwrap();

        // Should verify only one key
        assert_eq!(verified_keys.len(), 1);
        assert!(
            matches!(result, KeyResult::PartialFailure { failed_indices } if failed_indices == vec![1])
        );

        // Only the valid key should be verified
        assert!(verified_keys.contains(&client_keypair1.public_key()));
    }

    #[test]
    fn test_challenge_serialization_roundtrip() {
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let challenge = generate_key_challenge(&server_keypair).unwrap();

        // Test serialization and deserialization
        let serialized = postcard::to_stdvec(&challenge).unwrap();
        let deserialized: KeyChallenge = postcard::from_bytes(&serialized).unwrap();

        // Should be identical
        assert_eq!(challenge.nonce, deserialized.nonce);
        assert_eq!(challenge.expires_at, deserialized.expires_at);
        // Note: Signature comparison would need custom implementation
    }

    #[test]
    fn test_response_serialization_roundtrip() {
        let client_keypair = KeyPair::generate(&mut rand::thread_rng());
        let signature = client_keypair.sign(b"test data");

        let response = KeyResponse {
            key_proofs: vec![KeyProof {
                public_key: client_keypair.public_key(),
                signature,
            }],
        };

        // Test serialization and deserialization
        let serialized = postcard::to_stdvec(&response).unwrap();
        let deserialized: KeyResponse = postcard::from_bytes(&serialized).unwrap();

        // Should be identical
        assert_eq!(response.key_proofs.len(), deserialized.key_proofs.len());
    }
}
