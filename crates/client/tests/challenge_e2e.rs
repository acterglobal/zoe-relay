//! End-to-end integration tests for the client-side challenge protocol

use anyhow::Result;
use ml_dsa::{KeyGen, MlDsa65};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use zoe_client::challenge::create_ml_dsa_key_proofs;
use zoe_wire_protocol::{MlDsaMultiKeyChallenge, ZoeChallenge, ZoeChallengeResult};

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn test_create_single_key_proof() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create challenge
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [42u8; 32],
        server_public_key: server_public_key.to_bytes().to_vec(),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Create key proof
    let response = create_ml_dsa_key_proofs(&challenge, &[&client_keypair])?;

    // Verify response structure
    assert_eq!(response.key_proofs.len(), 1);
    assert!(!response.key_proofs[0].public_key.is_empty());
    assert!(!response.key_proofs[0].signature.is_empty());

    // Verify the public key matches
    let expected_public_key = client_keypair.verifying_key().encode().as_slice().to_vec();
    assert_eq!(response.key_proofs[0].public_key, expected_public_key);

    Ok(())
}

#[tokio::test]
async fn test_create_multiple_key_proofs() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();

    let client_keypair1 = MlDsa65::key_gen(&mut rand::thread_rng());
    let client_keypair2 = MlDsa65::key_gen(&mut rand::thread_rng());
    let client_keypair3 = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create challenge
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [123u8; 32],
        server_public_key: server_public_key.to_bytes().to_vec(),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Create key proofs for multiple keys
    let keypairs = [&client_keypair1, &client_keypair2, &client_keypair3];
    let response = create_ml_dsa_key_proofs(&challenge, &keypairs)?;

    // Verify response structure
    assert_eq!(response.key_proofs.len(), 3);

    // Verify each proof
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

        // Verify the public key matches the expected keypair
        let expected_public_key = keypairs[i].verifying_key().encode().as_slice().to_vec();
        assert_eq!(proof.public_key, expected_public_key);
    }

    Ok(())
}

#[tokio::test]
async fn test_client_server_communication() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create in-memory duplex streams
    let (client_stream, server_stream) = duplex(1024 * 1024); // 1MB buffer
    let (server_read, server_write) = tokio::io::split(server_stream);
    let (client_read, client_write) = tokio::io::split(client_stream);

    // Server task: send challenge and verify response
    let server_task = tokio::spawn(async move {
        let mut server_read = server_read;
        let mut server_write = server_write;

        // Create and send challenge
        let challenge = MlDsaMultiKeyChallenge {
            nonce: [99u8; 32],
            server_public_key: server_public_key.to_bytes().to_vec(),
            expires_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30,
        };
        let challenge_enum = ZoeChallenge::MlDsaMultiKey(challenge.clone());

        // Send challenge
        let challenge_bytes = postcard::to_stdvec(&challenge_enum).unwrap();
        server_write
            .write_u32(challenge_bytes.len() as u32)
            .await
            .unwrap();
        server_write.write_all(&challenge_bytes).await.unwrap();

        // Receive response
        let response_len = server_read.read_u32().await.unwrap() as usize;
        let mut response_buf = vec![0u8; response_len];
        server_read.read_exact(&mut response_buf).await.unwrap();
        let response: zoe_wire_protocol::MlDsaMultiKeyResponse =
            postcard::from_bytes(&response_buf).unwrap();

        // Verify response
        use zoe_relay::challenge::verify_ml_dsa_key_proofs;
        let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &challenge).unwrap();

        // Send result
        let result_enum = if verified_keys.is_empty() {
            ZoeChallengeResult::Error("No keys verified".to_string())
        } else {
            ZoeChallengeResult::Accepted
        };
        let result_bytes = postcard::to_stdvec(&result_enum).unwrap();
        server_write
            .write_u32(result_bytes.len() as u32)
            .await
            .unwrap();
        server_write.write_all(&result_bytes).await.unwrap();

        verified_keys.len()
    });

    // Client task: receive challenge and send response
    let client_task = tokio::spawn(async move {
        let mut client_read = client_read;
        let mut client_write = client_write;

        // Receive challenge
        let challenge_len = client_read.read_u32().await.unwrap() as usize;
        let mut challenge_buf = vec![0u8; challenge_len];
        client_read.read_exact(&mut challenge_buf).await.unwrap();
        let challenge: ZoeChallenge = postcard::from_bytes(&challenge_buf).unwrap();

        // Create response
        let response = match challenge {
            ZoeChallenge::MlDsaMultiKey(ml_dsa_challenge) => {
                create_ml_dsa_key_proofs(&ml_dsa_challenge, &[&client_keypair]).unwrap()
            }
            _ => panic!("Unexpected challenge type"),
        };

        // Send response
        let response_bytes = postcard::to_stdvec(&response).unwrap();
        client_write
            .write_u32(response_bytes.len() as u32)
            .await
            .unwrap();
        client_write.write_all(&response_bytes).await.unwrap();

        // Receive result
        let result_len = client_read.read_u32().await.unwrap() as usize;
        let mut result_buf = vec![0u8; result_len];
        client_read.read_exact(&mut result_buf).await.unwrap();
        let result: ZoeChallengeResult = postcard::from_bytes(&result_buf).unwrap();

        match result {
            ZoeChallengeResult::Accepted => true,
            _ => false,
        }
    });

    // Wait for both tasks
    let (server_verified_count, client_success) = tokio::try_join!(server_task, client_task)?;

    // Verify results
    assert_eq!(server_verified_count, 1);
    assert!(client_success);

    Ok(())
}

#[tokio::test]
async fn test_signature_verification() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create challenge
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [77u8; 32],
        server_public_key: server_public_key.to_bytes().to_vec(),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Create key proof
    let response = create_ml_dsa_key_proofs(&challenge, &[&client_keypair])?;
    let key_proof = &response.key_proofs[0];

    // Manually verify the signature is correct
    use signature::Verifier;

    // Reconstruct signature data
    let signature_data = [&challenge.nonce[..], &challenge.server_public_key[..]].concat();

    // Decode the public key and signature
    let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa65> = key_proof
        .public_key
        .as_slice()
        .try_into()
        .expect("Invalid public key length");
    let verifying_key = ml_dsa::VerifyingKey::<MlDsa65>::decode(encoded_key);

    let signature = ml_dsa::Signature::<MlDsa65>::try_from(key_proof.signature.as_slice())
        .expect("Invalid signature");

    // Verify signature
    verifying_key
        .verify(&signature_data, &signature)
        .expect("Signature verification failed");

    Ok(())
}

#[tokio::test]
async fn test_serialization_roundtrips() -> Result<()> {
    init_tracing();

    // Test challenge serialization
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();

    let original_challenge = ZoeChallenge::MlDsaMultiKey(MlDsaMultiKeyChallenge {
        nonce: [55u8; 32],
        server_public_key: server_public_key.to_bytes().to_vec(),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    });

    let serialized = postcard::to_stdvec(&original_challenge)?;
    let deserialized: ZoeChallenge = postcard::from_bytes(&serialized)?;

    match (original_challenge, deserialized) {
        (ZoeChallenge::MlDsaMultiKey(orig), ZoeChallenge::MlDsaMultiKey(deser)) => {
            assert_eq!(orig.nonce, deser.nonce);
            assert_eq!(orig.server_public_key, deser.server_public_key);
            assert_eq!(orig.expires_at, deser.expires_at);
        }
        _ => panic!("Challenge type mismatch after serialization"),
    }

    // Test result serialization
    let results = vec![
        ZoeChallengeResult::Accepted,
        ZoeChallengeResult::Next,
        ZoeChallengeResult::Error("Test error".to_string()),
    ];

    for original_result in results {
        let serialized = postcard::to_stdvec(&original_result)?;
        let deserialized: ZoeChallengeResult = postcard::from_bytes(&serialized)?;

        match (&original_result, &deserialized) {
            (ZoeChallengeResult::Accepted, ZoeChallengeResult::Accepted) => {}
            (ZoeChallengeResult::Next, ZoeChallengeResult::Next) => {}
            (ZoeChallengeResult::Error(orig), ZoeChallengeResult::Error(deser)) => {
                assert_eq!(orig, deser);
            }
            _ => panic!(
                "Result type mismatch: {:?} != {:?}",
                original_result, deserialized
            ),
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_key_list() -> Result<()> {
    init_tracing();

    // Test that empty key list works correctly
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();

    let challenge = MlDsaMultiKeyChallenge {
        nonce: [1u8; 32],
        server_public_key: server_public_key.to_bytes().to_vec(),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Create proofs with empty key list
    let response = create_ml_dsa_key_proofs(&challenge, &[])?;

    // Should succeed but return empty response
    assert_eq!(response.key_proofs.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_forward_compatibility() -> Result<()> {
    init_tracing();

    // Test unknown challenge type
    let unknown_challenge = ZoeChallenge::Unknown {
        discriminant: 999,
        data: vec![1, 2, 3],
    };

    let serialized = postcard::to_stdvec(&unknown_challenge)?;
    let deserialized: ZoeChallenge = postcard::from_bytes(&serialized)?;

    match deserialized {
        ZoeChallenge::Unknown { discriminant, data } => {
            assert_eq!(discriminant, 999);
            assert_eq!(data, vec![1, 2, 3]);
        }
        _ => panic!("Expected Unknown challenge"),
    }

    // Test unknown result type
    let unknown_result = ZoeChallengeResult::Unknown {
        discriminant: 888,
        data: vec![4, 5, 6],
    };

    let serialized = postcard::to_stdvec(&unknown_result)?;
    let deserialized: ZoeChallengeResult = postcard::from_bytes(&serialized)?;

    match deserialized {
        ZoeChallengeResult::Unknown { discriminant, data } => {
            assert_eq!(discriminant, 888);
            assert_eq!(data, vec![4, 5, 6]);
        }
        _ => panic!("Expected Unknown result"),
    }

    Ok(())
}
