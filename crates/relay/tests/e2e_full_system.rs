//! End-to-end tests for the full system
//! These tests require external dependencies (Redis) and test the complete integration

use ed25519_dalek::SigningKey;
use pretty_assertions::assert_eq;
use rand::rngs::OsRng;
use zoeyr_message_store::{RedisStorage, RelayConfig};
use zoeyr_wire_protocol::{Kind, Message, MessageFull, ProtocolMessage};

#[tokio::test]
#[ignore] // Requires Redis
async fn e2e_message_storage_and_retrieval() {
    // This test requires a Redis instance running on localhost:6379
    let mut relay_config = RelayConfig::default();
    relay_config.redis.url = "redis://localhost:6379".to_string();

    let storage = RedisStorage::new(relay_config)
        .await
        .expect("Failed to create Redis storage");

    // Create a test message
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let content = "E2E test message".to_string();

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

    let signed_message = MessageFull::new(message, &signing_key).expect("Failed to sign message");

    // Test message storage
    storage
        .store_message(&signed_message)
        .await
        .expect("Failed to store message");

    // Test message retrieval
    let retrieved = storage
        .get_message(signed_message.id.as_bytes())
        .await
        .expect("Failed to retrieve message")
        .expect("Message not found");

    assert_eq!(signed_message.content(), retrieved.content());
    assert_eq!(signed_message.id, retrieved.id);
}

#[tokio::test]
#[ignore] // Requires Redis
async fn e2e_duplicate_message_prevention() {
    // Test that the same message cannot be stored twice
    let mut relay_config = RelayConfig::default();
    relay_config.redis.url = "redis://localhost:6379".to_string();

    let storage = RedisStorage::new(relay_config)
        .await
        .expect("Failed to create Redis storage");

    // Create a test message
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let content = "Duplicate test message".to_string();

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

    let signed_message = MessageFull::new(message, &signing_key).expect("Failed to sign message");

    // Store message first time - should succeed
    let result1 = storage.store_message(&signed_message).await.unwrap();
    assert!(result1.is_some());

    // Try to store the same message again - should be detected as duplicate
    let result2 = storage.store_message(&signed_message).await.unwrap();
    assert!(result2.is_none());

    // This should either succeed silently (idempotent) or return a specific duplicate error
    // The behavior depends on the storage implementation
    let retrieved = storage
        .get_message(signed_message.id.as_bytes())
        .await
        .expect("Failed to retrieve message")
        .expect("Message not found");

    assert_eq!(signed_message.content(), retrieved.content());
}

#[tokio::test]
async fn e2e_protocol_message_round_trip() {
    // Test protocol message creation and parsing without storage
    let text_message: ProtocolMessage<String> = "E2E protocol test".to_string().into();

    // Test postcard serialization round trip
    let serialized_data = postcard::to_allocvec(&text_message).unwrap();
    let parsed_message: ProtocolMessage<String> = postcard::from_bytes(&serialized_data).unwrap();
    assert_eq!(text_message, parsed_message);
}
