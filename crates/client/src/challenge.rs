use crate::ClientError;
use anyhow::Result;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};
use zoe_wire_protocol::{
    MlDsaKeyProof, MlDsaMultiKeyChallenge, MlDsaMultiKeyResponse, ZoeChallenge, ZoeChallengeResult,
    keys::*,
};

/// Maximum size for challenge messages (to prevent DoS)
const MAX_CHALLENGE_SIZE: usize = 1024; // Should be enough for challenge data

/// Maximum size for result messages
const MAX_RESULT_SIZE: usize = 1024; // Should be enough for result data

/// Performs the client side of the ML-DSA challenge-response handshake
///
/// This function implements the client side of the challenge protocol:
/// 1. Receives a challenge from the server
/// 2. Creates proofs for all provided ML-DSA keys
/// 3. Sends the response to the server
/// 4. Receives and processes the verification result
///
/// # Arguments
///
/// * `send` - Stream for sending data to the server
/// * `recv` - Stream for receiving data from the server
/// * `ml_dsa_keys` - Slice of ML-DSA signing keys to prove possession of
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
/// use zoe_client::challenge::perform_client_ml_dsa_handshake;
///
/// let verified_count = perform_client_ml_dsa_handshake(
///     send_stream,
///     recv_stream,
///     &[&personal_key, &work_key]
/// ).await?;
///
/// info!("Successfully verified {} out of {} keys", verified_count, 2);
/// ```
pub async fn perform_client_ml_dsa_handshake(
    mut send: SendStream,
    mut recv: RecvStream,
    server_public_key: &VerifyingKey,
    ml_dsa_keys: &[&KeyPair],
) -> Result<usize> {
    info!("🔐 Starting client-side multi-challenge handshake");

    if ml_dsa_keys.is_empty() {
        return Err(anyhow::anyhow!("No ML-DSA keys provided for handshake"));
    }

    debug!("Proving possession of {} ML-DSA keys", ml_dsa_keys.len());

    let ml_dsa_verified_count = ml_dsa_keys.len();

    loop {
        // Step 1: Receive challenge from server
        let challenge = receive_challenge(&mut recv).await?;

        // Step 2: Handle different challenge types
        match challenge {
            ZoeChallenge::MlDsaMultiKey(ml_dsa_challenge) => {
                info!("📝 Received ML-DSA challenge");

                // check the signature
                let nonce = ml_dsa_challenge.nonce;
                let signature = &ml_dsa_challenge.signature;
                if server_public_key.verify(&nonce, signature).is_err() {
                    return Err(anyhow::anyhow!(
                        "Invalid signature in challenge. Person-in-the-middle attack?"
                    ));
                }

                // Create proofs for all keys
                let response = create_ml_dsa_key_proofs(&ml_dsa_challenge, ml_dsa_keys)?;

                // Send response directly (no wrapper enum)
                send_ml_dsa_response(&mut send, &response).await?;
            }
            ZoeChallenge::Unknown { discriminant, .. } => {
                return Err(anyhow::anyhow!(
                    "Unsupported challenge type: {}",
                    discriminant
                ));
            }
        }

        // Step 3: Receive result from server
        let result = receive_result(&mut recv).await?;

        match result {
            ZoeChallengeResult::Accepted => {
                info!("✅ All challenges completed successfully");
                break;
            }
            ZoeChallengeResult::Next => {
                info!("➡️ Challenge accepted, waiting for next challenge");
                // Continue to next iteration to receive next challenge
            }
            ZoeChallengeResult::Rejected(rejection) => {
                return Err(anyhow::anyhow!("Challenge rejected: {:?}", rejection));
            }
            ZoeChallengeResult::Error(error) => {
                return Err(anyhow::anyhow!("Server error: {}", error));
            }
            ZoeChallengeResult::Unknown { discriminant, .. } => {
                return Err(anyhow::anyhow!("Unsupported result type: {}", discriminant));
            }
        }
    }

    info!(
        "✅ Client-side multi-challenge handshake completed. {} ML-DSA keys verified",
        ml_dsa_verified_count
    );

    Ok(ml_dsa_verified_count)
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

    if challenge_len > MAX_CHALLENGE_SIZE {
        return Err(anyhow::anyhow!(
            "Challenge too large: {} bytes (max: {})",
            challenge_len,
            MAX_CHALLENGE_SIZE
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

/// Creates key proofs for all provided ML-DSA keys
///
/// For each key, creates a signature over (nonce || server_public_key) and
/// packages it with the corresponding public key.
///
/// # Arguments
///
/// * `challenge` - Challenge received from server
/// * `ml_dsa_keys` - Keys to create proofs for
///
/// # Returns
///
/// A response containing all key proofs
pub fn create_ml_dsa_key_proofs(
    challenge: &MlDsaMultiKeyChallenge,
    ml_dsa_keys: &[&KeyPair],
) -> Result<MlDsaMultiKeyResponse> {
    let challenge_data = challenge;

    // Prepare signature data: just the nonce (as updated in the protocol)
    let signature_data = challenge_data.nonce.to_vec();

    debug!("Creating proofs for {} keys", ml_dsa_keys.len());

    let mut key_proofs = Vec::new();

    for (index, ml_dsa_keypair) in ml_dsa_keys.iter().enumerate() {
        // Create signature over challenge data
        let signature = ml_dsa_keypair.sign(&signature_data);
        let verifying_key = ml_dsa_keypair.public_key();

        // Create key proof
        let key_proof = MlDsaKeyProof {
            public_key: postcard::to_stdvec(&verifying_key)?,
            signature: postcard::to_stdvec(&signature)?,
        };

        key_proofs.push(key_proof);
        debug!("Created proof for key {}", index);
    }

    let response = MlDsaMultiKeyResponse { key_proofs };
    Ok(response)
}

/// Sends the ML-DSA challenge response to the server
///
/// Serializes the response using postcard and sends it with a length prefix.
///
/// # Arguments
///
/// * `send` - Stream to send the response on
/// * `response` - ML-DSA response to send
async fn send_ml_dsa_response(
    send: &mut SendStream,
    response: &MlDsaMultiKeyResponse,
) -> Result<()> {
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

    if result_len > MAX_RESULT_SIZE {
        return Err(anyhow::anyhow!(
            "Result too large: {} bytes (max: {})",
            result_len,
            MAX_RESULT_SIZE
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

/// Process a challenge result and return the verified count or an error
#[allow(dead_code)]
fn process_result(
    result: &ZoeChallengeResult,
    expected_count: usize,
) -> Result<usize, ClientError> {
    match result {
        ZoeChallengeResult::Accepted => Ok(expected_count),
        ZoeChallengeResult::Next => Ok(expected_count),
        ZoeChallengeResult::Rejected(rejection) => Err(ClientError::Generic(format!(
            "Challenge rejected: {rejection:?}"
        ))),
        ZoeChallengeResult::Error(error) => {
            Err(ClientError::Generic(format!("Challenge error: {error}")))
        }
        ZoeChallengeResult::Unknown { discriminant, .. } => Err(ClientError::Generic(format!(
            "Unknown challenge result: {discriminant}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{KeyGen, MlDsa65};
    use signature::Signer;
    use zoe_wire_protocol::MlDsaMultiKeyChallenge;

    #[test]
    fn test_create_key_proofs() {
        // Generate test keys
        let keypair1 = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));
        let keypair2 = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));

        // Create test challenge
        let test_data = [1u8, 2, 3, 4];
        let signature = match &keypair1 {
            KeyPair::MlDsa65(kp) => kp.sign(&test_data),
            _ => panic!("Expected MlDsa65 keypair"),
        };
        let challenge_data = MlDsaMultiKeyChallenge {
            nonce: [42u8; 32],
            signature: zoe_wire_protocol::Signature::MlDsa65(Box::new(signature)),
            expires_at: 1234567890,
        };
        let challenge = ZoeChallenge::MlDsaMultiKey(Box::new(challenge_data.clone()));

        // Create proofs
        let keys = vec![&keypair1, &keypair2];
        let response = create_ml_dsa_key_proofs(&challenge_data, &keys).unwrap();

        // Verify response structure
        assert_eq!(response.key_proofs.len(), 2);

        // Verify each proof has the expected structure
        for (i, proof) in response.key_proofs.iter().enumerate() {
            assert!(
                !proof.public_key.is_empty(),
                "Key {} public key should not be empty",
                i
            );
            assert!(
                !proof.signature.is_empty(),
                "Key {} signature should not be empty",
                i
            );
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
        use zoe_wire_protocol::ZoeChallengeRejection;
        let result = ZoeChallengeResult::Rejected(ZoeChallengeRejection::ChallengeFailed);
        let result = process_result(&result, 3);
        assert!(result.is_err());
    }
}
