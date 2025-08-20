use anyhow::Result;
use quinn::{RecvStream, SendStream};
use rand::RngCore;
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};
use zoe_wire_protocol::{
    KeyPair, MlDsaKeyProof, MlDsaMultiKeyChallenge, MlDsaMultiKeyResponse, MlDsaMultiKeyResult,
    Signature, VerifyingKey, ZoeChallenge, ZoeChallengeRejection, ZoeChallengeResult,
};
// MlDsa65 is imported in tests where needed

/// Default challenge timeout in seconds
const DEFAULT_CHALLENGE_TIMEOUT_SECS: u64 = 30;

/// Maximum size for challenge response messages (to prevent DoS)
const MAX_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB should be enough for many ML-DSA keys

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
/// use zoe_relay::challenge::perform_multi_challenge_handshake;
///
/// let verified_keys = perform_multi_challenge_handshake(
///     send_stream,
///     recv_stream,
///     &server_keypair
/// ).await?;
///
/// info!("Verified {} keys after multi-challenge handshake", verified_keys.len());
/// ```
pub async fn perform_multi_challenge_handshake(
    mut send: SendStream,
    mut recv: RecvStream,
    server_keypair: &KeyPair,
) -> Result<BTreeSet<Vec<u8>>> {
    info!("🔐 Starting multi-challenge handshake");

    // Challenge 1: ML-DSA key proof
    info!("📝 Sending ML-DSA challenge");
    let ml_dsa_challenge = generate_ml_dsa_challenge(server_keypair)?;
    send_challenge(
        &mut send,
        &ZoeChallenge::MlDsaMultiKey(ml_dsa_challenge.clone()),
    )
    .await?;

    // Receive ML-DSA response
    let ml_dsa_response = receive_ml_dsa_response(&mut recv).await?;

    // Verify ML-DSA proofs
    let (keys, _ml_dsa_result) = verify_ml_dsa_key_proofs(&ml_dsa_response, &ml_dsa_challenge)?;

    if keys.is_empty() {
        // ML-DSA challenge failed - send rejection and close
        let result = ZoeChallengeResult::Rejected(ZoeChallengeRejection::ChallengeIncomplete);
        send_result(&mut send, &result).await?;
        return Err(anyhow::anyhow!(
            "ML-DSA challenge failed: no valid key proofs"
        ));
    }

    //  We can add more challenge types here (proof-of-work, etc.)
    // For now, we only have ML-DSA, so we send Accepted

    info!("✅ All challenges completed successfully");
    let result = ZoeChallengeResult::Accepted;
    send_result(&mut send, &result).await?;

    info!(
        "✅ Multi-challenge handshake completed. Verified {} ML-DSA keys",
        keys.len()
    );

    Ok(keys)
}

/// Legacy single ML-DSA challenge function (for backward compatibility)
///
/// This is a simplified version that only performs the ML-DSA challenge.
/// New code should use `perform_multi_challenge_handshake` instead.
pub async fn perform_ml_dsa_handshake(
    send: SendStream,
    recv: RecvStream,
    server_keypair: &KeyPair,
) -> Result<BTreeSet<Vec<u8>>> {
    perform_multi_challenge_handshake(send, recv, server_keypair).await
}

/// Generates a new ML-DSA challenge with a random nonce
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
/// A `MlDsaMultiKeyChallenge` containing the challenge data
pub fn generate_ml_dsa_challenge(server_keypair: &KeyPair) -> Result<MlDsaMultiKeyChallenge> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let expires_at =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + DEFAULT_CHALLENGE_TIMEOUT_SECS;

    // Server signs the nonce to prove its identity
    let server_signature = server_keypair.sign(&nonce);

    let challenge_data = MlDsaMultiKeyChallenge {
        nonce,
        signature: server_signature,
        expires_at,
    };

    debug!(
        "Generated ML-DSA challenge with nonce: {} expires at: {}",
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

/// Receives an ML-DSA challenge response from the client
///
/// Reads the response with length prefix and deserializes it directly
/// as an MlDsaMultiKeyResponse (no wrapper enum).
///
/// # Arguments
///
/// * `recv` - Stream to receive the response from
///
/// # Returns
///
/// The parsed `MlDsaMultiKeyResponse` from the client
pub async fn receive_ml_dsa_response(recv: &mut RecvStream) -> Result<MlDsaMultiKeyResponse> {
    // Read length prefix
    let response_len = recv.read_u32().await? as usize;

    if response_len > MAX_RESPONSE_SIZE {
        return Err(anyhow::anyhow!(
            "Response too large: {} bytes (max: {})",
            response_len,
            MAX_RESPONSE_SIZE
        ));
    }

    debug!("Receiving response ({} bytes)", response_len);

    // Read response data
    let mut response_buf = vec![0u8; response_len];
    recv.read_exact(&mut response_buf).await?;

    // Parse response directly as MlDsaMultiKeyResponse
    let response: MlDsaMultiKeyResponse = postcard::from_bytes(&response_buf)?;

    debug!(
        "Received ML-DSA response with {} key proofs",
        response.key_proofs.len()
    );
    Ok(response)
}

/// Verifies all ML-DSA key proofs in a response
///
/// Each key proof is verified independently. The function continues even if some
/// proofs fail, collecting all successful verifications.
///
/// # Arguments
///
/// * `response` - Client's response containing key proofs
/// * `challenge` - Original ML-DSA challenge (needed for signature verification)
///
/// # Returns
///
/// A tuple containing:
/// - Set of successfully verified public keys (as encoded bytes)
/// - ML-DSA specific result indicating which proofs succeeded/failed
pub fn verify_ml_dsa_key_proofs(
    response: &MlDsaMultiKeyResponse,
    challenge: &MlDsaMultiKeyChallenge,
) -> Result<(BTreeSet<Vec<u8>>, MlDsaMultiKeyResult)> {
    let challenge_data = challenge;

    // Check if challenge has expired
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if current_time > challenge_data.expires_at {
        warn!(
            "Challenge expired: current={}, expires={}",
            current_time, challenge_data.expires_at
        );
        return Ok((BTreeSet::new(), MlDsaMultiKeyResult::AllFailed));
    }

    let mut verified_keys = BTreeSet::new();
    let mut failed_indices = Vec::new();

    // Prepare signature data: just the nonce (clients sign the nonce)
    let signature_data = challenge_data.nonce.to_vec();

    debug!("Verifying {} key proofs", response.key_proofs.len());

    for (index, key_proof) in response.key_proofs.iter().enumerate() {
        match verify_single_key_proof(key_proof, &signature_data) {
            Ok(()) => {
                verified_keys.insert(key_proof.public_key.clone());
                debug!(
                    "✅ Verified key proof {}: {}",
                    index,
                    hex::encode(&key_proof.public_key[..8])
                );
            }
            Err(e) => {
                failed_indices.push(index);
                warn!("❌ Key proof {} failed: {}", index, e);
            }
        }
    }

    let result = if failed_indices.is_empty() {
        MlDsaMultiKeyResult::AllValid
    } else if verified_keys.is_empty() {
        MlDsaMultiKeyResult::AllFailed
    } else {
        MlDsaMultiKeyResult::PartialFailure { failed_indices }
    };

    info!(
        "Verification complete: {}/{} keys verified",
        verified_keys.len(),
        response.key_proofs.len()
    );

    Ok((verified_keys, result))
}

/// Verifies a single ML-DSA key proof
///
/// Decodes the public key and signature, then verifies the signature over
/// the challenge data.
///
/// # Arguments
///
/// * `key_proof` - The key proof to verify
/// * `signature_data` - The data that should have been signed (nonce || server_public_key)
///
/// # Returns
///
/// `Ok(())` if verification succeeds, `Err` with details if it fails
fn verify_single_key_proof(key_proof: &MlDsaKeyProof, signature_data: &[u8]) -> Result<()> {
    // Deserialize the client's public key from the key proof
    let verifying_key: VerifyingKey = postcard::from_bytes(&key_proof.public_key)
        .map_err(|e| anyhow::anyhow!("Invalid public key encoding: {}", e))?;

    // Deserialize the client's signature from the key proof
    let signature: Signature = postcard::from_bytes(&key_proof.signature)
        .map_err(|e| anyhow::anyhow!("Invalid signature encoding: {}", e))?;

    // Verify the signature
    verifying_key
        .verify(signature_data, &signature)
        .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{KeyGen, MlDsa65};
    use signature::Signer;

    #[cfg(feature = "tls-ml-dsa-44")]
    use zoe_wire_protocol::generate_ml_dsa_44_keypair_for_tls;

    #[test]
    #[cfg(feature = "tls-ml-dsa-44")]
    fn test_ml_dsa_challenge_generation() {
        let server_ml_dsa_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_keypair = KeyPair::MlDsa44(server_ml_dsa_keypair);

        let challenge = generate_ml_dsa_challenge(&server_keypair).unwrap();

        // The server_public_key field now contains the server's signature over the nonce
        assert!(!challenge.server_public_key.is_empty());
        assert!(
            challenge.expires_at
                > SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
        );
    }

    #[test]
    #[cfg(feature = "tls-ml-dsa-44")]
    fn test_single_key_proof_verification() {
        // Generate test keys
        let ml_dsa_keypair = MlDsa65::key_gen(&mut rand::thread_rng());
        let client_keypair = KeyPair::MlDsa65(ml_dsa_keypair);

        // Create signature data (just the nonce)
        let nonce = [42u8; 32];
        let signature_data = nonce.to_vec();

        // Create signature
        let signature = client_keypair.sign(&signature_data);
        let verifying_key = client_keypair.public_key();

        // Create key proof
        let key_proof = MlDsaKeyProof {
            public_key: postcard::to_stdvec(&verifying_key).unwrap(),
            signature: postcard::to_stdvec(&signature).unwrap(),
        };

        // Verify proof
        let result = verify_single_key_proof(&key_proof, &signature_data);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_fails() {
        // Generate test keys
        let client_keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

        // Create signature data
        let signature_data = b"test data";

        // Create signature over different data
        let wrong_signature = client_keypair.sign(b"wrong data");
        let verifying_key = client_keypair.public_key();

        // Create key proof with wrong signature
        let key_proof = MlDsaKeyProof {
            public_key: postcard::to_stdvec(&verifying_key).unwrap(),
            signature: postcard::to_stdvec(&wrong_signature).unwrap(),
        };

        // Verify proof should fail
        let result = verify_single_key_proof(&key_proof, signature_data);
        assert!(result.is_err());
    }
}

/// Create key proofs for a challenge response (used in tests)
///
/// This function creates key proofs for the given keypairs in response to a challenge.
/// It's primarily used in integration tests.
pub fn create_key_proofs(
    challenge: &MlDsaMultiKeyChallenge,
    keypairs: &[&KeyPair],
) -> Result<MlDsaMultiKeyResponse> {
    let mut key_proofs = Vec::new();

    // Construct the signature data (just the nonce)
    let signature_data = challenge.nonce.to_vec();

    // Create a proof for each keypair
    for keypair in keypairs {
        let signature = keypair.sign(&signature_data);
        let verifying_key = keypair.public_key();

        let key_proof = MlDsaKeyProof {
            public_key: postcard::to_stdvec(&verifying_key)?,
            signature: postcard::to_stdvec(&signature)?,
        };
        key_proofs.push(key_proof);
    }

    Ok(MlDsaMultiKeyResponse { key_proofs })
}
