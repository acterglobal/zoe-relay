use crate::*;
use ed25519_dalek::SigningKey;
use rand::thread_rng;
use std::collections::HashMap;
use zoe_wire_protocol::Tag;

fn create_test_keys() -> (SigningKey, SigningKey) {
    let mut rng = thread_rng();
    let alice_key = SigningKey::generate(&mut rng);
    let bob_key = SigningKey::generate(&mut rng);
    (alice_key, bob_key)
}

fn create_test_group_config() -> CreateGroupConfig {
    CreateGroupConfig {
        name: "Test Group".to_string(),
        description: Some("A test group for unit tests".to_string()),
        metadata: {
            let mut metadata = HashMap::new();
            metadata.insert("category".to_string(), "testing".to_string());
            metadata
        },
        settings: GroupSettings::default(),
        encryption_key: None, // Auto-generate
    }
}

#[test]
fn test_create_encrypted_group() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    let result = dga
        .create_group(config.clone(), &alice_key, timestamp)
        .unwrap();

    // Verify group was created
    assert!(dga.get_group_state(&result.group_id).is_some());

    // Verify group has encryption key
    assert!(dga.group_keys.contains_key(&result.group_id));

    // Verify group state
    let group_state = dga.get_group_state(&result.group_id).unwrap();
    assert_eq!(group_state.name, config.name);
    assert_eq!(group_state.description, config.description);
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&alice_key.verifying_key()));
    assert_eq!(
        group_state.get_member_role(&alice_key.verifying_key()),
        Some(&GroupRole::Owner)
    );
}

#[test]
fn test_encrypt_decrypt_group_event() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Create a test event
    let original_event = create_group_activity_event(
        "test_activity".to_string(),
        b"Hello, encrypted world!".to_vec(),
        {
            let mut metadata = HashMap::new();
            metadata.insert("test".to_string(), "value".to_string());
            metadata
        },
    );

    // Get encryption key
    let encryption_state = dga.group_keys.get(&result.group_id).unwrap();

    // Encrypt the event
    let encrypted_payload = dga
        .encrypt_group_event(&original_event, &encryption_state.current_key)
        .unwrap();

    // Decrypt the event
    let decrypted_event = dga
        .decrypt_group_event(&encrypted_payload, &encryption_state.current_key)
        .unwrap();

    // Verify they match
    assert_eq!(original_event, decrypted_event);
}

#[test]
fn test_process_encrypted_create_group_event() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group and get the message
    let result = dga
        .create_group(config.clone(), &alice_key, timestamp)
        .unwrap();

    // Create a fresh DGA instance and add the encryption key
    let mut fresh_dga = DigitalGroupAssistant::new();
    let encryption_key = dga
        .group_keys
        .get(&result.group_id)
        .unwrap()
        .current_key
        .clone();
    fresh_dga.add_group_key(result.group_id, encryption_key);

    // Process the create group message
    fresh_dga.process_group_event(&result.message).unwrap();

    // Verify the group was created
    let group_state = fresh_dga.get_group_state(&result.group_id).unwrap();
    assert_eq!(group_state.name, config.name);
    assert_eq!(group_state.description, config.description);
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&alice_key.verifying_key()));
}

#[test]
fn test_encrypted_group_activity() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Create and send an activity event
    let activity_event = create_group_activity_event(
        "welcome_message".to_string(),
        b"Welcome to our encrypted group!".to_vec(),
        {
            let mut metadata = HashMap::new();
            metadata.insert("message_type".to_string(), "announcement".to_string());
            metadata
        },
    );

    let activity_message = dga
        .create_group_event_message(result.group_id, activity_event, &alice_key, timestamp + 1)
        .unwrap();

    // Process the activity
    dga.process_group_event(&activity_message).unwrap();

    // Verify Alice is still the only member (she was already the creator)
    let group_state = dga.get_group_state(&result.group_id).unwrap();
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&alice_key.verifying_key()));
}

#[test]
fn test_new_member_via_activity() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Alice creates group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Simulate Bob getting the encryption key via inbox system
    // (In reality, this would happen through a separate secure channel)
    let encryption_key = dga
        .group_keys
        .get(&result.group_id)
        .unwrap()
        .current_key
        .clone();

    // Create a separate DGA instance for Bob and give him the key
    let mut bob_dga = DigitalGroupAssistant::new();
    bob_dga.add_group_key(result.group_id, encryption_key);

    // Bob needs to know about the group state too (would sync via events)
    // For test purposes, we'll just copy the state
    let group_state = dga.get_group_state(&result.group_id).unwrap().clone();
    bob_dga.groups.insert(result.group_id, group_state);

    // Bob sends an activity
    let bob_activity = create_group_activity_event(
        "greeting".to_string(),
        b"Hello everyone! Thanks for the key.".to_vec(),
        HashMap::new(),
    );

    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 10)
        .unwrap();

    // Alice processes Bob's message
    dga.process_group_event(&bob_message).unwrap();

    // Verify Bob is now an active member
    let group_state = dga.get_group_state(&result.group_id).unwrap();
    assert_eq!(group_state.members.len(), 2);
    assert!(group_state.is_member(&alice_key.verifying_key()));
    assert!(group_state.is_member(&bob_key.verifying_key()));
    assert_eq!(
        group_state.get_member_role(&bob_key.verifying_key()),
        Some(&GroupRole::Member)
    );
}

#[test]
fn test_role_update() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group and add Bob as member
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Simulate Bob joining by sending an activity
    let encryption_key = dga
        .group_keys
        .get(&result.group_id)
        .unwrap()
        .current_key
        .clone();
    let mut bob_dga = DigitalGroupAssistant::new();
    bob_dga.add_group_key(result.group_id, encryption_key);
    let group_state = dga.get_group_state(&result.group_id).unwrap().clone();
    bob_dga.groups.insert(result.group_id, group_state);

    let bob_activity = create_group_activity_event(
        "join_greeting".to_string(),
        b"Hello!".to_vec(),
        HashMap::new(),
    );
    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 5)
        .unwrap();
    dga.process_group_event(&bob_message).unwrap();

    // Alice promotes Bob to Admin
    let role_update = create_role_update_event(bob_key.verifying_key(), GroupRole::Admin);

    let role_message = dga
        .create_group_event_message(result.group_id, role_update, &alice_key, timestamp + 10)
        .unwrap();

    dga.process_group_event(&role_message).unwrap();

    // Verify Bob's role was updated
    let group_state = dga.get_group_state(&result.group_id).unwrap();
    assert_eq!(
        group_state.get_member_role(&bob_key.verifying_key()),
        Some(&GroupRole::Admin)
    );
}

#[test]
fn test_leave_group_event() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group and add Bob
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Add Bob as a member first
    let encryption_key = dga
        .group_keys
        .get(&result.group_id)
        .unwrap()
        .current_key
        .clone();
    let mut bob_dga = DigitalGroupAssistant::new();
    bob_dga.add_group_key(result.group_id, encryption_key);
    let group_state = dga.get_group_state(&result.group_id).unwrap().clone();
    bob_dga.groups.insert(result.group_id, group_state);

    let bob_activity =
        create_group_activity_event("join".to_string(), b"Joining".to_vec(), HashMap::new());
    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 5)
        .unwrap();
    dga.process_group_event(&bob_message).unwrap();

    // Verify Bob is a member
    assert_eq!(
        dga.get_group_state(&result.group_id).unwrap().members.len(),
        2
    );

    // Bob leaves the group
    let leave_event = create_leave_group_event(Some("Thanks for having me!".to_string()));

    let leave_message = bob_dga
        .create_group_event_message(result.group_id, leave_event, &bob_key, timestamp + 10)
        .unwrap();

    dga.process_group_event(&leave_message).unwrap();

    // Verify Bob is no longer in active members
    let group_state = dga.get_group_state(&result.group_id).unwrap();
    assert_eq!(group_state.members.len(), 1);
    assert!(!group_state.is_member(&bob_key.verifying_key()));
    assert!(group_state.is_member(&alice_key.verifying_key()));
}

#[test]
fn test_missing_encryption_key_error() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Remove the encryption key to simulate not having it
    dga.group_keys.remove(&result.group_id);

    // Try to create an event without the key
    let activity_event =
        create_group_activity_event("test".to_string(), b"test".to_vec(), HashMap::new());

    let result =
        dga.create_group_event_message(result.group_id, activity_event, &alice_key, timestamp + 1);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("No encryption key available")
    );
}

#[test]
fn test_invalid_key_id_decryption_error() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Create a fake encrypted payload with wrong key ID
    let fake_payload = EncryptedGroupPayload {
        ciphertext: vec![1, 2, 3, 4, 5],
        nonce: [0; 12],
        key_id: vec![99, 99, 99], // Wrong key ID
    };

    let encryption_key = &dga.group_keys.get(&result.group_id).unwrap().current_key;
    let result = dga.decrypt_group_event(&fake_payload, encryption_key);

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Key ID mismatch"));
}

#[test]
fn test_permission_denied_for_role_update() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Add Bob as a regular member
    let encryption_key = dga
        .group_keys
        .get(&result.group_id)
        .unwrap()
        .current_key
        .clone();
    let mut bob_dga = DigitalGroupAssistant::new();
    bob_dga.add_group_key(result.group_id, encryption_key);
    let group_state = dga.get_group_state(&result.group_id).unwrap().clone();
    bob_dga.groups.insert(result.group_id, group_state);

    let bob_activity =
        create_group_activity_event("join".to_string(), b"Joining".to_vec(), HashMap::new());
    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 5)
        .unwrap();
    dga.process_group_event(&bob_message).unwrap();

    // Bob (regular member) tries to update Alice's role (should fail)
    let role_update = create_role_update_event(
        alice_key.verifying_key(),
        GroupRole::Member, // Trying to demote the owner
    );

    let role_message = bob_dga
        .create_group_event_message(result.group_id, role_update, &bob_key, timestamp + 10)
        .unwrap();

    // This should fail when processed
    let result = dga.process_group_event(&role_message);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Permission denied")
    );
}

#[test]
fn test_subscription_filter_creation() {
    let mut dga = DigitalGroupAssistant::new();
    let (alice_key, _bob_key) = create_test_keys();
    let config = create_test_group_config();
    let timestamp = 1234567890;

    // Create group
    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Create subscription filter
    let filter = dga
        .create_group_subscription_filter(&result.group_id)
        .unwrap();

    // Verify filter
    match filter {
        Tag::Event { id, relays } => {
            assert_eq!(id, result.group_id);
            assert!(relays.is_empty());
        }
        _ => panic!("Expected Event tag"),
    }
}

#[test]
fn test_group_key_generation() {
    let key_id = vec![1, 2, 3, 4];
    let timestamp = 1234567890;

    let key1 = DigitalGroupAssistant::generate_group_key(key_id.clone(), timestamp);
    let key2 = DigitalGroupAssistant::generate_group_key(key_id.clone(), timestamp);

    // Keys should be different (random generation)
    assert_ne!(key1.key, key2.key);

    // But metadata should match
    assert_eq!(key1.key_id, key2.key_id);
    assert_eq!(key1.created_at, key2.created_at);

    // Key should be proper length
    assert_eq!(key1.key.len(), 32); // 256 bits
}
