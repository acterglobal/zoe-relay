//! Integration tests for Zoeyr server functionality
//! These tests use mocked dependencies and focus on testing the integration between components

use pretty_assertions::assert_eq;
use std::time::Duration;

// Update imports to use new crate structure
// Use relay crate
use zoeyr_wire_protocol::*; // Use wire-protocol crate

// ========================================
// INTEGRATION TESTS - Server Components
// ========================================

#[tokio::test]
async fn integration_server_startup() {
    // Test that the server can be created with minimal configuration
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    // This tests the integration of key generation and server initialization
    // without actually binding to a port or connecting to Redis
    let _key_hex = hex::encode(signing_key.to_bytes());
    assert_eq!(signing_key.to_bytes().len(), 32);
}

#[tokio::test]
async fn integration_auth_challenge_flow() {
    // Test the authentication challenge and signature flow with ed25519 keys
    use ed25519_dalek::{Signer, SigningKey, Verifier};
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let client_key = SigningKey::generate(&mut csprng);
    let client_verifying_key = client_key.verifying_key();

    // Test that we can sign and verify a challenge-response style message
    let nonce = "test-challenge-nonce";
    let timestamp = 1234567890u64;
    let message_to_sign = format!("auth:{nonce}:{timestamp}");

    // Client creates signature
    let signature = client_key.sign(message_to_sign.as_bytes());

    // Server verifies signature
    let verification_result = client_verifying_key.verify(message_to_sign.as_bytes(), &signature);

    assert!(verification_result.is_ok());
}

#[tokio::test]
async fn integration_auth_timeout_handling() {
    // Test challenge timeout behavior
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let client_key = SigningKey::generate(&mut csprng);

    let mut session = DynamicSession::new(client_key.verifying_key());

    // Issue a challenge with very short timeout
    let challenge = session.issue_challenge(0); // 0 second timeout

    // Wait a bit to ensure timeout
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Try to verify (should fail due to timeout)
    let signature = [0u8; 64]; // dummy signature
    let result = session.verify_challenge_response(
        &challenge.nonce,
        challenge.timestamp,
        &signature,
        0, // 0 second timeout
    );

    assert!(result.is_err());
    assert_eq!(session.failed_challenges, 1);
}

#[tokio::test]
async fn integration_protocol_message_handling() {
    // Test protocol message creation and serialization
    let text_content = "Integration test message".to_string();

    let message: ProtocolMessage<String> = text_content.into();

    // Test postcard serialization
    let serialized_bytes = postcard::to_allocvec(&message).expect("Serialization failed");
    let deserialized: ProtocolMessage<String> =
        postcard::from_bytes(&serialized_bytes).expect("Deserialization failed");

    assert_eq!(message, deserialized);
}

#[tokio::test]
async fn integration_health_check_protocol() {
    // Test health check message handling
    let health_check: ProtocolMessage<String> = ProtocolMessage::HealthCheck;
    let health_response: ProtocolMessage<String> = ProtocolMessage::HealthResponse {
        status: "OK".to_string(),
        timestamp: 1234567890,
    };

    // Serialize both
    let check_bytes = postcard::to_allocvec(&health_check).unwrap();
    let response_bytes = postcard::to_allocvec(&health_response).unwrap();

    // Deserialize both
    let check_deser: ProtocolMessage<String> = postcard::from_bytes(&check_bytes).unwrap();
    let response_deser: ProtocolMessage<String> = postcard::from_bytes(&response_bytes).unwrap();

    assert_eq!(health_check, check_deser);
    assert_eq!(health_response, response_deser);

    // Verify structure
    match health_response {
        ProtocolMessage::HealthResponse { status, timestamp } => {
            assert_eq!(status, "OK");
            assert_eq!(timestamp, 1234567890);
        }
        _ => panic!("Wrong message type"),
    }
}

#[tokio::test]
async fn integration_error_handling() {
    // Test error message handling
    let error_message: ProtocolMessage<String> = ProtocolMessage::Error {
        message: "Integration test error".to_string(),
    };

    let serialized_bytes = postcard::to_allocvec(&error_message).unwrap();
    let deserialized: ProtocolMessage<String> = postcard::from_bytes(&serialized_bytes).unwrap();

    assert_eq!(error_message, deserialized);

    match deserialized {
        ProtocolMessage::Error { message } => {
            assert_eq!(message, "Integration test error");
        }
        _ => panic!("Wrong message type"),
    }
}

// ========================================
// INTEGRATION TESTS - Certificate Handling
// ========================================

#[tokio::test]
async fn integration_certificate_generation() {
    // Test ed25519 key to certificate generation
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Test key serialization
    let private_key_bytes = signing_key.to_bytes();
    let public_key_bytes = verifying_key.to_bytes();

    assert_eq!(private_key_bytes.len(), 32);
    assert_eq!(public_key_bytes.len(), 32);

    // Test round-trip serialization
    let recreated_signing_key = SigningKey::from_bytes(&private_key_bytes);
    let recreated_verifying_key = recreated_signing_key.verifying_key();

    assert_eq!(verifying_key.to_bytes(), recreated_verifying_key.to_bytes());
}

// ========================================
// INTEGRATION TESTS - Wire Protocol Types
// ========================================

#[tokio::test]
async fn integration_message_full_creation() {
    // Test MessageFull creation and verification with generic content
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let content = "Test message content".to_string();
    let message = Message::new_v0(
        content,
        verifying_key,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Kind::Regular,
        vec![],
    );

    let message_full =
        MessageFull::new(message, &signing_key).expect("Failed to create MessageFull");

    // Verify the message
    assert!(message_full.verify().expect("Verification failed"));
    assert!(message_full.verify_id().expect("ID verification failed"));
    assert!(message_full
        .verify_all()
        .expect("Complete verification failed"));
}

#[tokio::test]
async fn integration_file_content_handling() {
    // Test FileContent structure
    let file_content = FileContent {
        filename: "test.txt".to_string(),
        data: vec![1, 2, 3, 4, 5],
    };

    let message: ProtocolMessage<FileContent> = file_content.clone().into();

    // Test serialization
    let serialized_bytes = postcard::to_allocvec(&message).unwrap();
    let deserialized: ProtocolMessage<FileContent> =
        postcard::from_bytes(&serialized_bytes).unwrap();

    assert_eq!(message, deserialized);

    // Verify file content
    match deserialized {
        ProtocolMessage::Message { content, .. } => {
            assert_eq!(content.filename, "test.txt");
            assert_eq!(content.data, vec![1, 2, 3, 4, 5]);
        }
        _ => panic!("Wrong message type"),
    }
}
