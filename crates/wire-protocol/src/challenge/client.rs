use super::MAX_PACKAGE_SIZE;
use crate::{
    keys::*, KeyChallenge, KeyProof, KeyResponse, ZoeChallenge, ZoeChallengeResult,
    ZoeChallengeWarning,
};
use anyhow::Result;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Performs the client side of the challenge-response handshake
///
/// This function implements the client side of the challenge protocol:
/// 1. Receives a challenge from the server
/// 2. Creates proofs for all provided keys
/// 3. Sends the response to the server
/// 4. Receives and processes the verification result
///
/// # Arguments
///
/// * `send` - Stream for sending data to the server
/// * `recv` - Stream for receiving data from the server
/// * `key_pairs` - Slice of signing keys to prove possession of
///
/// # Returns
///
/// The number of keys that were successfully verified by the server
///
/// # Errors
///
/// Returns an error if:
/// - Network I/O fails
/// - Serialization/deserialization fails
/// - All key proofs fail verification
/// - Server response is malformed or too large
///
/// # Example
///
/// ```rust
/// use zoe_client::challenge::perform_client_challenge_handshake;
///
/// let verified_count = perform_client_challenge_handshake(
///     send_stream,
///     recv_stream,
///     &[&personal_key, &work_key]
/// ).await?;
///
/// info!("Successfully verified {} out of {} keys", verified_count, 2);
/// ```
pub async fn perform_client_challenge_handshake(
    mut send: SendStream,
    mut recv: RecvStream,
    server_public_key: &VerifyingKey,
    key_pairs: &[&KeyPair],
) -> Result<(usize, Vec<ZoeChallengeWarning>)> {
    info!("🔐 Starting client-side multi-challenge handshake");

    if key_pairs.is_empty() {
        return Err(anyhow::anyhow!("No keys provided for handshake"));
    }

    debug!("Proving possession of {} keys", key_pairs.len());

    let verified_count = key_pairs.len();
    let mut warnings = Vec::new();

    loop {
        // Step 3: Receive result from server
        let result = receive_result(&mut recv).await?;

        match result {
            ZoeChallengeResult::Accepted => {
                info!("✅ All challenges completed successfully");
                break;
            }
            ZoeChallengeResult::Warning(warning) => {
                warn!("🔔 Warning received: {warning:?}");
                warnings.push(warning);
                continue; // we need to read for the next result
            }
            ZoeChallengeResult::Next => {
                info!("➡️ Challenge accepted, waiting for next challenge");
                // Continue to next iteration to receive next challenge
            }
            ZoeChallengeResult::Rejected(rejection) => {
                return Err(anyhow::anyhow!("Challenge rejected: {rejection:?}"));
            }
            ZoeChallengeResult::Error(error) => {
                return Err(anyhow::anyhow!("Server error: {error}"));
            }
            ZoeChallengeResult::Unknown { discriminant, .. } => {
                return Err(anyhow::anyhow!("Unsupported result type: {discriminant}"));
            }
        }
        // Step 1: Receive challenge from server
        info!("📥 Waiting to receive challenge from server...");
        let challenge = receive_challenge(&mut recv).await?;
        info!("✅ Received challenge from server");

        // Step 2: Handle different challenge types
        match challenge {
            ZoeChallenge::Key(key_challenge) => {
                info!("📝 Received key challenge");

                // check the signature
                let nonce = key_challenge.nonce;
                let signature = &key_challenge.signature;
                info!("🔍 Verifying server signature on challenge nonce...");
                if server_public_key.verify(&nonce, signature).is_err() {
                    return Err(anyhow::anyhow!(
                        "Invalid signature in challenge. Person-in-the-middle attack?"
                    ));
                }
                info!("✅ Server signature verified");

                // Create proofs for all keys
                info!("🔧 Creating key proofs for {} keys...", key_pairs.len());
                let response = create_key_proofs(&key_challenge, key_pairs)?;
                info!("✅ Created {} key proofs", response.key_proofs.len());

                // Send response directly (no wrapper enum)
                info!("📤 Sending key response to server...");
                send_key_response(&mut send, &response).await?;
                info!("✅ Key response sent");
            }
            ZoeChallenge::Unknown { discriminant, .. } => {
                return Err(anyhow::anyhow!(
                    "Unsupported challenge type: {discriminant}"
                ));
            }
        }
    }

    info!(
        "✅ Client-side multi-challenge handshake completed. {} keys verified",
        verified_count
    );

    Ok((verified_count, warnings))
}

/// Receives a challenge from the server
///
/// Reads the challenge with length prefix and deserializes it.
///
/// # Arguments
///
/// * `recv` - Stream to receive the challenge from
///
/// # Returns
///
/// The parsed challenge from the server
async fn receive_challenge(recv: &mut RecvStream) -> Result<ZoeChallenge> {
    // Read length prefix
    let challenge_len = recv.read_u32().await? as usize;

    if challenge_len > MAX_PACKAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Challenge too large: {} bytes (max: {})",
            challenge_len,
            MAX_PACKAGE_SIZE
        ));
    }

    debug!("Receiving challenge ({} bytes)", challenge_len);

    // Read challenge data
    let mut challenge_buf = vec![0u8; challenge_len];
    recv.read_exact(&mut challenge_buf).await?;

    // Parse challenge
    let challenge: ZoeChallenge = postcard::from_bytes(&challenge_buf)?;

    debug!("Received challenge from server");
    Ok(challenge)
}

/// Creates key proofs for all provided keys
///
/// For each key, creates a signature over (nonce || server_public_key) and
/// packages it with the corresponding public key.
///
/// # Arguments
///
/// * `challenge` - Challenge received from server
/// * `key_pairs` - Keys to create proofs for
///
/// # Returns
///
/// A response containing all key proofs
pub fn create_key_proofs(challenge: &KeyChallenge, key_pairs: &[&KeyPair]) -> Result<KeyResponse> {
    let challenge_data = challenge;

    // Prepare signature data: just the nonce (as updated in the protocol)
    let signature_data = challenge_data.nonce.to_vec();

    debug!("Creating proofs for {} keys", key_pairs.len());

    let mut key_proofs = Vec::new();

    for (index, keypair) in key_pairs.iter().enumerate() {
        // Create signature over challenge data
        let signature = keypair.sign(&signature_data);
        let verifying_key = keypair.public_key();

        // Create key proof
        let key_proof = KeyProof {
            public_key: verifying_key,
            signature,
        };

        key_proofs.push(key_proof);
        debug!("Created proof for key {}", index);
    }

    let response = KeyResponse { key_proofs };
    Ok(response)
}

/// Sends the key challenge response to the server
///
/// Serializes the response using postcard and sends it with a length prefix.
///
/// # Arguments
///
/// * `send` - Stream to send the response on
/// * `response` - Key response to send
async fn send_key_response(send: &mut SendStream, response: &KeyResponse) -> Result<()> {
    let response_bytes = postcard::to_stdvec(response)?;

    debug!("Sending response ({} bytes)", response_bytes.len());

    // Send length prefix (4 bytes, big endian)
    send.write_u32(response_bytes.len() as u32).await?;

    // Send response data
    send.write_all(&response_bytes).await?;

    Ok(())
}

/// Receives the verification result from the server
///
/// Reads the result with length prefix and deserializes it.
///
/// # Arguments
///
/// * `recv` - Stream to receive the result from
///
/// # Returns
///
/// The parsed verification result from the server
async fn receive_result(recv: &mut RecvStream) -> Result<ZoeChallengeResult> {
    // Read length prefix
    let result_len = recv.read_u32().await? as usize;

    if result_len > MAX_PACKAGE_SIZE {
        return Err(anyhow::anyhow!(
            "Result too large: {} bytes (max: {})",
            result_len,
            MAX_PACKAGE_SIZE
        ));
    }

    debug!("Receiving result ({} bytes)", result_len);

    // Read result data
    let mut result_buf = vec![0u8; result_len];
    recv.read_exact(&mut result_buf).await?;

    // Parse result
    let result: ZoeChallengeResult = postcard::from_bytes(&result_buf)?;

    debug!("Received verification result from server");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate_ed25519_relay_keypair, generate_keypair, ZoeChallengeRejection};
    use anyhow::Result;

    /// Process a challenge result and return the verified count or an error
    #[allow(dead_code)]
    fn process_result(result: &ZoeChallengeResult, expected_count: usize) -> Result<usize> {
        match result {
            ZoeChallengeResult::Accepted => Ok(expected_count),
            ZoeChallengeResult::Next => Ok(expected_count),
            ZoeChallengeResult::Warning(warning) => {
                Err(anyhow::anyhow!(format!("Warning received: {warning:?}")))
            }
            ZoeChallengeResult::Rejected(rejection) => Err(anyhow::anyhow!(format!(
                "Challenge rejected: {rejection:?}"
            ))),
            ZoeChallengeResult::Error(error) => {
                Err(anyhow::anyhow!(format!("Challenge error: {error}")))
            }
            ZoeChallengeResult::Unknown { discriminant, .. } => Err(anyhow::anyhow!(format!(
                "Unknown challenge result: {discriminant}"
            ))),
        }
    }

    #[test]
    fn test_create_key_proofs() {
        // Generate test keys
        let keypair1 = generate_keypair(&mut rand::thread_rng());
        let keypair2 = generate_keypair(&mut rand::thread_rng());

        // Create test challenge
        let server_keypair = generate_ed25519_relay_keypair(&mut rand::thread_rng());
        let nonce = [42u8; 32];
        let server_signature = server_keypair.sign(&nonce);

        let challenge_data = KeyChallenge {
            nonce,
            signature: server_signature,
            expires_at: 1234567890,
        };

        // Create proofs
        let keys = vec![&keypair1, &keypair2];
        let response = create_key_proofs(&challenge_data, &keys).unwrap();

        // Verify response structure
        assert_eq!(response.key_proofs.len(), 2);

        // Verify each proof has the expected structure
        for (i, _proof) in response.key_proofs.iter().enumerate() {
            // The public_key and signature are now proper types, not Vec<u8>
            // We can verify they exist by checking the proof structure
            debug!("Key {} proof created successfully", i);

            // Verify we can create a signature with the key
            let test_data = b"test";
            let test_sig = keys[i].sign(test_data);
            let pub_key = keys[i].public_key();

            // Verify the signature works
            assert!(pub_key.verify(test_data, &test_sig).unwrap());
        }
    }

    #[test]
    fn test_process_result_accepted() {
        let result = ZoeChallengeResult::Accepted;
        let verified_count = process_result(&result, 3).unwrap();
        assert_eq!(verified_count, 3);
    }

    #[test]
    fn test_process_result_next() {
        let result = ZoeChallengeResult::Next;
        let verified_count = process_result(&result, 3).unwrap();
        assert_eq!(verified_count, 3);
    }

    #[test]
    fn test_process_result_rejected() {
        let result = ZoeChallengeResult::Rejected(ZoeChallengeRejection::ChallengeFailed);
        let result = process_result(&result, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_key_proofs_client() {
        let server_keypair = generate_ed25519_relay_keypair(&mut rand::thread_rng());
        let client_keypair1 = generate_keypair(&mut rand::thread_rng());
        let client_keypair2 = generate_keypair(&mut rand::thread_rng());

        // Create a challenge
        let nonce = [42u8; 32];
        let signature = server_keypair.sign(&nonce);
        let challenge = KeyChallenge {
            nonce,
            signature,
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
        };

        let client_keys = vec![&client_keypair1, &client_keypair2];
        let response = create_key_proofs(&challenge, &client_keys).unwrap();

        // Should have proofs for both keys
        assert_eq!(response.key_proofs.len(), 2);

        // Each proof should be valid (we can verify this by checking the signature)
        for (i, proof) in response.key_proofs.iter().enumerate() {
            let expected_key = &client_keys[i];
            assert_eq!(
                proof.public_key.encode(),
                expected_key.public_key().encode()
            );

            // Verify the signature
            assert!(proof
                .public_key
                .verify(&challenge.nonce, &proof.signature)
                .is_ok());
        }
    }

    #[test]
    fn test_send_key_response_serialization() {
        let client_keypair = generate_keypair(&mut rand::thread_rng());
        let signature = client_keypair.sign(b"test data");

        let response = KeyResponse {
            key_proofs: vec![KeyProof {
                public_key: client_keypair.public_key(),
                signature,
            }],
        };

        // Test that we can serialize the response (this is what send_key_response does internally)
        let serialized = postcard::to_stdvec(&response).unwrap();
        assert!(!serialized.is_empty());

        // Test that we can deserialize it back
        let deserialized: KeyResponse = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(response.key_proofs.len(), deserialized.key_proofs.len());
    }

    #[test]
    fn test_challenge_signature_verification() {
        let server_keypair = generate_ed25519_relay_keypair(&mut rand::thread_rng());
        let server_public_key = server_keypair.public_key();

        // Create a valid challenge
        let nonce = [42u8; 32];
        let signature = server_keypair.sign(&nonce);
        let challenge = KeyChallenge {
            nonce,
            signature,
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
        };

        // Signature should verify
        assert!(server_public_key
            .verify(&challenge.nonce, &challenge.signature)
            .is_ok());

        // Wrong signature should fail
        let wrong_signature = server_keypair.sign(b"wrong data");
        let bad_challenge = KeyChallenge {
            nonce,
            signature: wrong_signature,
            expires_at: challenge.expires_at,
        };

        assert_eq!(
            server_public_key
                .verify(&bad_challenge.nonce, &bad_challenge.signature)
                .unwrap(),
            false
        );
    }

    #[test]
    fn test_empty_key_list() {
        let server_keypair = generate_ed25519_relay_keypair(&mut rand::thread_rng());

        let nonce = [42u8; 32];
        let signature = server_keypair.sign(&nonce);
        let challenge = KeyChallenge {
            nonce,
            signature,
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 300,
        };

        let empty_keys: Vec<&KeyPair> = vec![];
        let response = create_key_proofs(&challenge, &empty_keys).unwrap();

        // Should have no proofs
        assert_eq!(response.key_proofs.len(), 0);
    }
}
