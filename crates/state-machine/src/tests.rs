use crate::*;
use ed25519_dalek::SigningKey;
use rand::thread_rng;
use std::collections::BTreeMap;
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
            let mut metadata = BTreeMap::new();
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
    let original_event = create_group_activity_event(());

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
    let activity_event = create_group_activity_event(());

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
    let bob_activity = create_group_activity_event(());

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

    let bob_activity = create_group_activity_event(());
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

    let bob_activity = create_group_activity_event(());
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
    let activity_event = create_group_activity_event(());

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

    // Create a fake encrypted payload with invalid ciphertext
    let fake_payload = ChaCha20Poly1305Content {
        ciphertext: vec![1, 2, 3, 4, 5], // Invalid ciphertext
        nonce: [0; 12],                  // All zeros nonce
    };

    let encryption_key = &dga.group_keys.get(&result.group_id).unwrap().current_key;
    let result = dga.decrypt_group_event(&fake_payload, encryption_key);

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("decryption failed")
    );
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

    let bob_activity = create_group_activity_event(());
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
    let timestamp = 1234567890;

    let key1 = DigitalGroupAssistant::generate_group_key(timestamp);
    let key2 = DigitalGroupAssistant::generate_group_key(timestamp);

    // Keys should be different (random generation)
    assert_ne!(key1.key, key2.key);

    // Key IDs should also be different (randomly generated)
    assert_ne!(key1.key_id, key2.key_id);
    assert_eq!(key1.created_at, key2.created_at);

    // Key should be proper length
    assert_eq!(key1.key.len(), 32); // 256 bits
}

#[test]
fn test_create_key_from_mnemonic() {
    use crate::MnemonicPhrase;
    use bip39::Language;

    // Use a known test mnemonic
    let mnemonic = MnemonicPhrase::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        Language::English
    ).unwrap();

    let group_name = "test-group";
    let passphrase = "test-passphrase";
    let timestamp = 1640995200;

    let key = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic, passphrase, group_name, timestamp,
    )
    .unwrap();

    // Verify key properties
    assert_eq!(key.key.len(), 32);
    assert_eq!(key.created_at, timestamp);
    assert!(key.derivation_info.is_some());

    let derivation_info = key.derivation_info.as_ref().unwrap();
    assert_eq!(
        derivation_info.method,
        zoe_wire_protocol::crypto::KeyDerivationMethod::Bip39Argon2
    );
    assert_eq!(derivation_info.context, "dga-group-test-group");
}

#[test]
fn test_recover_key_from_mnemonic() {
    use crate::MnemonicPhrase;

    // Generate a mnemonic and derive a key
    let mnemonic = MnemonicPhrase::generate().unwrap();
    let group_name = "recovery-test-group";
    let passphrase = "recovery-passphrase";
    let timestamp = 1640995200;

    // Create initial key
    let original_key = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic, passphrase, group_name, timestamp,
    )
    .unwrap();

    // Extract salt for recovery
    let derivation_info = original_key.derivation_info.as_ref().unwrap();
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&derivation_info.salt);

    // Recover the key using the same parameters
    let recovered_key = DigitalGroupAssistant::recover_key_from_mnemonic(
        &mnemonic, passphrase, group_name, &salt, timestamp,
    )
    .unwrap();

    // Keys should be identical
    assert_eq!(original_key.key, recovered_key.key);
    assert_eq!(original_key.key_id, recovered_key.key_id);
    assert_eq!(original_key.created_at, recovered_key.created_at);
}

#[test]
fn test_mnemonic_key_integration_with_group_creation() {
    use crate::{CreateGroupConfig, GroupSettings, MnemonicPhrase};
    use ed25519_dalek::SigningKey;

    let mut dga = DigitalGroupAssistant::new();
    let alice_key = SigningKey::generate(&mut rand::thread_rng());
    let timestamp = chrono::Utc::now().timestamp() as u64;

    // Generate mnemonic and create encryption key
    let mnemonic = MnemonicPhrase::generate().unwrap();
    let encryption_key = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic,
        "test-passphrase",
        "integration-test-group",
        timestamp,
    )
    .unwrap();

    // Create group with mnemonic-derived key
    let config = CreateGroupConfig {
        name: "Integration Test Group".to_string(),
        description: Some("Testing mnemonic key integration".to_string()),
        metadata: {
            let mut metadata = BTreeMap::new();
            metadata.insert("key_source".to_string(), "mnemonic".to_string());
            metadata
        },
        settings: GroupSettings::default(),
        encryption_key: Some(encryption_key.clone()),
    };

    let result = dga.create_group(config, &alice_key, timestamp).unwrap();

    // Verify group was created successfully
    assert!(dga.groups.contains_key(&result.group_id));
    assert!(dga.group_keys.contains_key(&result.group_id));

    // Verify the key is properly stored
    let stored_key = &dga.group_keys.get(&result.group_id).unwrap().current_key;
    assert_eq!(stored_key.key, encryption_key.key);
    assert_eq!(stored_key.key_id, encryption_key.key_id);
}

#[test]
fn test_invalid_mnemonic_phrase_error() {
    use crate::MnemonicPhrase;
    use zoe_wire_protocol::bip39::Language;

    // Test with invalid mnemonic phrase
    let result = MnemonicPhrase::from_phrase(
        "invalid mnemonic phrase that should fail checksum",
        Language::English,
    );

    assert!(result.is_err());
}

#[test]
fn test_mnemonic_key_different_contexts_produce_different_keys() {
    use crate::MnemonicPhrase;

    let mnemonic = MnemonicPhrase::generate().unwrap();
    let passphrase = "same-passphrase";
    let timestamp = 1640995200;

    // Same mnemonic, different contexts should produce different keys
    let key1 = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic,
        passphrase,
        "group-one",
        timestamp,
    )
    .unwrap();

    let key2 = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic,
        passphrase,
        "group-two",
        timestamp,
    )
    .unwrap();

    // Keys should be different
    assert_ne!(key1.key, key2.key);
    assert_ne!(key1.key_id, key2.key_id);

    // But derivation info should show different contexts
    let info1 = key1.derivation_info.as_ref().unwrap();
    let info2 = key2.derivation_info.as_ref().unwrap();
    assert_eq!(info1.context, "dga-group-group-one");
    assert_eq!(info2.context, "dga-group-group-two");
}

#[test]
fn test_mnemonic_key_different_passphrases_produce_different_keys() {
    use crate::MnemonicPhrase;

    let mnemonic = MnemonicPhrase::generate().unwrap();
    let group_name = "same-group";
    let timestamp = 1640995200;

    // Same mnemonic, different passphrases should produce different keys
    let key1 = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic,
        "passphrase-one",
        group_name,
        timestamp,
    )
    .unwrap();

    let key2 = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic,
        "passphrase-two",
        group_name,
        timestamp,
    )
    .unwrap();

    // Keys should be different
    assert_ne!(key1.key, key2.key);
    assert_ne!(key1.key_id, key2.key_id);

    // Context should be the same, but salts should be different (random)
    let info1 = key1.derivation_info.as_ref().unwrap();
    let info2 = key2.derivation_info.as_ref().unwrap();
    assert_eq!(info1.context, info2.context);
    assert_ne!(info1.salt, info2.salt); // Different random salts
}
