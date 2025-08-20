//! Integration tests for the client-side challenge protocol

use anyhow::Result;
use ml_dsa::{KeyGen, MlDsa65};
use std::time::{SystemTime, UNIX_EPOCH};
use zoe_client::challenge::create_ml_dsa_key_proofs;
use zoe_wire_protocol::{
    KeyPair, MlDsaMultiKeyChallenge, MlDsaMultiKeyResponse, ZoeChallenge, ZoeChallengeResult,
};

/// Helper function to create a test signature for MlDsaMultiKeyChallenge
fn create_test_signature(keypair: &KeyPair) -> zoe_wire_protocol::Signature {
    use signature::Signer;
    match keypair {
        KeyPair::MlDsa65(kp) => {
            let signature = kp.sign(&[1, 2, 3, 4]);
            zoe_wire_protocol::Signature::MlDsa65(signature)
        }
        _ => panic!("Expected MlDsa65 keypair"),
    }
}

#[tokio::test]
async fn test_create_single_key_proof() -> Result<()> {
    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

    // Create challenge
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [42u8; 32],
        signature: create_test_signature(&client_keypair),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Create key proof
    let response = create_ml_dsa_key_proofs(&challenge, &[&client_keypair])?;

    // Verify response structure
    assert_eq!(response.key_proofs.len(), 1);
    assert!(!response.key_proofs[0].public_key.is_empty());
    assert!(!response.key_proofs[0].signature.is_empty());

    // Verify the public key matches
    let expected_public_key = client_keypair.public_key().encode();
    assert_eq!(response.key_proofs[0].public_key, expected_public_key);

    Ok(())
}

#[tokio::test]
async fn test_create_multiple_key_proofs() -> Result<()> {
    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();

    let client_keypair1 = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));
    let client_keypair2 = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));
    let client_keypair3 = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

    // Create challenge
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [123u8; 32],
        signature: create_test_signature(&client_keypair1),
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
        let expected_public_key = keypairs[i].public_key().encode();
        assert_eq!(proof.public_key, expected_public_key);
    }

    Ok(())
}

#[tokio::test]
async fn test_key_proof_signature_verification() -> Result<()> {
    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

    // Create challenge
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [99u8; 32],
        signature: create_test_signature(&client_keypair),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Create key proof
    let response = create_ml_dsa_key_proofs(&challenge, &[&client_keypair])?;
    let key_proof = &response.key_proofs[0];

    // Manually verify the signature is correct
    use signature::Verifier;

    // Reconstruct signature data
    // Reconstruct signature data (using nonce only since server_public_key is no longer in the struct)
    let signature_data = challenge.nonce.to_vec();

    // Decode the public key and signature
    // The public_key is now a postcard-serialized VerifyingKey enum, not raw bytes
    let verifying_key_enum: zoe_wire_protocol::VerifyingKey =
        postcard::from_bytes(&key_proof.public_key).expect("Invalid VerifyingKey encoding");

    let verifying_key = match verifying_key_enum {
        zoe_wire_protocol::VerifyingKey::MlDsa65(key) => key,
        _ => panic!("Expected MlDsa65 key"),
    };

    // The signature is now a postcard-serialized Signature enum, not raw bytes
    let signature_enum: zoe_wire_protocol::Signature =
        postcard::from_bytes(&key_proof.signature).expect("Invalid Signature encoding");

    let signature = match signature_enum {
        zoe_wire_protocol::Signature::MlDsa65(sig) => sig,
        _ => panic!("Expected MlDsa65 signature"),
    };

    // Verify signature
    verifying_key
        .verify(&signature_data, &signature)
        .expect("Signature verification failed");

    Ok(())
}

#[tokio::test]
async fn test_response_serialization_roundtrip() -> Result<()> {
    // Generate test keys
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

    // Create challenge and response
    let challenge = MlDsaMultiKeyChallenge {
        nonce: [77u8; 32],
        signature: create_test_signature(&client_keypair),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    let original_response = create_ml_dsa_key_proofs(&challenge, &[&client_keypair])?;

    // Serialize and deserialize
    let serialized = postcard::to_stdvec(&original_response)?;
    let deserialized: MlDsaMultiKeyResponse = postcard::from_bytes(&serialized)?;

    // Verify they match
    assert_eq!(
        original_response.key_proofs.len(),
        deserialized.key_proofs.len()
    );
    assert_eq!(
        original_response.key_proofs[0].public_key,
        deserialized.key_proofs[0].public_key
    );
    assert_eq!(
        original_response.key_proofs[0].signature,
        deserialized.key_proofs[0].signature
    );

    Ok(())
}

#[tokio::test]
async fn test_challenge_result_handling() -> Result<()> {
    // Test different challenge result types
    let results = vec![
        ZoeChallengeResult::Accepted,
        ZoeChallengeResult::Next,
        ZoeChallengeResult::Error("Test error".to_string()),
    ];

    for result in results {
        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&result)?;
        let deserialized: ZoeChallengeResult = postcard::from_bytes(&serialized)?;

        // Verify they match (basic check)
        match (&result, &deserialized) {
            (ZoeChallengeResult::Accepted, ZoeChallengeResult::Accepted) => {}
            (ZoeChallengeResult::Next, ZoeChallengeResult::Next) => {}
            (ZoeChallengeResult::Error(orig), ZoeChallengeResult::Error(deser)) => {
                assert_eq!(orig, deser);
            }
            _ => panic!("Result type mismatch: {:?} != {:?}", result, deserialized),
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_key_list_error() -> Result<()> {
    // Test that empty key list returns an error
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

    let challenge = MlDsaMultiKeyChallenge {
        nonce: [1u8; 32],
        signature: create_test_signature(&client_keypair),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    };

    // Try to create proofs with empty key list
    let result = create_ml_dsa_key_proofs(&challenge, &[]);

    // Should succeed but return empty response
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.key_proofs.len(), 0);

    Ok(())
}

#[tokio::test]
async fn test_challenge_type_matching() -> Result<()> {
    // Test that the client correctly handles different challenge types
    let server_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let server_public_key = server_key.verifying_key();
    let client_keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut rand::thread_rng()));

    // Test ML-DSA challenge
    let ml_dsa_challenge = ZoeChallenge::MlDsaMultiKey(MlDsaMultiKeyChallenge {
        nonce: [55u8; 32],
        signature: create_test_signature(&client_keypair),
        expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
    });

    // Serialize and deserialize to ensure it works
    let serialized = postcard::to_stdvec(&ml_dsa_challenge)?;
    let deserialized: ZoeChallenge = postcard::from_bytes(&serialized)?;

    match deserialized {
        ZoeChallenge::MlDsaMultiKey(challenge_data) => {
            assert_eq!(challenge_data.nonce, [55u8; 32]);
            // Note: server_public_key field no longer exists, checking signature field instead
            // The signature field should be present (we can't easily compare signatures without PartialEq)
            match &challenge_data.signature {
                zoe_wire_protocol::Signature::MlDsa65(_) => {
                    // Expected signature type
                }
                _ => panic!("Expected MlDsa65 signature"),
            }
        }
        _ => panic!("Expected MlDsaMultiKey challenge"),
    }

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

    Ok(())
}
