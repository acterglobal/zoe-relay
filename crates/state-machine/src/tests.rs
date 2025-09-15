use crate::group::{
    create_group_activity_event, create_leave_group_event, create_role_update_event,
};
use crate::*;
use rand::thread_rng;
use zoe_app_primitives::group::events::key_info::GroupKeyInfo;
use zoe_app_primitives::group::events::roles::GroupRole;
use zoe_app_primitives::group::events::settings::GroupSettings;
use zoe_app_primitives::group::events::{CreateGroup, GroupActivityEvent, GroupInfo};
use zoe_app_primitives::metadata::Metadata;
use zoe_wire_protocol::{KeyPair, Tag};

fn create_test_keys() -> (KeyPair, KeyPair) {
    let mut rng = thread_rng();
    let alice_key = KeyPair::generate_ml_dsa65(&mut rng);
    let bob_key = KeyPair::generate_ml_dsa65(&mut rng);
    (alice_key, bob_key)
}

fn create_test_group() -> CreateGroup {
    let metadata = vec![
        Metadata::Description("A test group for unit tests".to_string()),
        Metadata::Generic {
            key: "category".to_string(),
            value: "testing".to_string(),
        },
    ];

    let group_info = GroupInfo {
        name: "Test Group".to_string(),
        settings: GroupSettings::default(),
        key_info: GroupKeyInfo::new_chacha20_poly1305(
            vec![], // This will be filled in by create_group
            zoe_wire_protocol::crypto::KeyDerivationInfo {
                method: zoe_wire_protocol::crypto::KeyDerivationMethod::ChaCha20Poly1305Keygen,
                salt: vec![],
                argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
                context: "dga-group-key".to_string(),
            },
        ),
        metadata,
    };

    CreateGroup::new(group_info)
}

#[tokio::test]
async fn test_create_encrypted_group() {
    let dga = GroupManager::builder().build();
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Verify group was created
    let group_state = dga.group_state(&result.group_id).await;
    assert!(group_state.is_some());

    // Verify group has encryption key (now part of GroupSession)
    let group_session = dga.group_session(&result.group_id).await;
    assert!(group_session.is_some());

    // Verify group state
    let group_state = group_state.unwrap();
    assert_eq!(group_state.name, "Test Group");
    assert_eq!(
        group_state.description(),
        Some("A test group for unit tests".to_string())
    );
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&alice_key.public_key()));
    assert_eq!(
        group_state.member_role(&alice_key.public_key()),
        Some(GroupRole::Owner)
    );
}

// Note: encrypt_group_event and decrypt_group_event methods were removed
// This test is commented out as the methods no longer exist
// #[tokio::test]
// async fn test_encrypt_decrypt_group_event() {
//     // Test removed - encryption/decryption is now handled internally
// }

#[tokio::test]
async fn test_process_encrypted_create_group_event() {
    let dga = GroupManager::builder().build();
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group and get the message
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Create a fresh DGA instance and add the complete group session
    let fresh_dga = GroupManager::builder().build();
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    fresh_dga
        .add_group_session(result.group_id, group_session)
        .await;

    // Process the create group message
    fresh_dga
        .process_group_event(&result.message)
        .await
        .unwrap();

    // Verify the group was created
    let group_state = fresh_dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.name, "Test Group");
    assert_eq!(
        group_state.description(),
        Some("A test group for unit tests".to_string())
    );
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&alice_key.public_key()));
}

#[tokio::test]
async fn test_encrypted_group_activity() {
    let dga = GroupManager::builder().build();
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Create and send an activity event
    let activity_event = create_group_activity_event(());

    let activity_message = dga
        .create_group_event_message(result.group_id, activity_event, &alice_key, timestamp + 1)
        .await
        .unwrap();

    // Process the activity
    dga.process_group_event(&activity_message).await.unwrap();

    // Verify Alice is still the only member (she was already the creator)
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&alice_key.public_key()));
}

#[tokio::test]
async fn test_new_member_via_activity() {
    let dga = GroupManager::builder().build();
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Alice creates group
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Simulate Bob getting the group session via inbox system
    // (In reality, this would happen through a separate secure channel)

    // Create a separate DGA instance for Bob and give him the complete session
    let bob_dga = GroupManager::builder().build();
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id, group_session)
        .await;

    // Bob now has the complete group session, no need for separate state management

    // Bob sends an activity
    let bob_activity = create_group_activity_event(());

    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 10)
        .await
        .unwrap();

    // Alice processes Bob's message
    dga.process_group_event(&bob_message).await.unwrap();

    // Verify Bob is now an active member
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.members.len(), 2);
    assert!(group_state.is_member(&alice_key.public_key()));
    assert!(group_state.is_member(&bob_key.public_key()));
    assert_eq!(
        group_state.member_role(&bob_key.public_key()),
        Some(GroupRole::Member)
    );
}

#[tokio::test]
async fn test_role_update() {
    let dga = GroupManager::builder().build();
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group and add Bob as member
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Simulate Bob joining by sending an activity
    let bob_dga = GroupManager::builder().build();
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id, group_session)
        .await;

    let bob_activity = create_group_activity_event(());
    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 5)
        .await
        .unwrap();
    dga.process_group_event(&bob_message).await.unwrap();

    // Alice promotes Bob to Admin
    let role_update: GroupActivityEvent<()> =
        create_role_update_event(bob_key.public_key(), GroupRole::Admin);

    let role_message = dga
        .create_group_event_message(result.group_id, role_update, &alice_key, timestamp + 10)
        .await
        .unwrap();

    dga.process_group_event(&role_message).await.unwrap();

    // Verify Bob's role was updated
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(
        group_state.member_role(&bob_key.public_key()),
        Some(GroupRole::Admin)
    );
}

#[tokio::test]
async fn test_leave_group_event() {
    let dga = GroupManager::builder().build();
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group and add Bob
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Add Bob as a member first
    let bob_dga = GroupManager::builder().build();
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id, group_session)
        .await;
    let bob_activity = create_group_activity_event(());
    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 5)
        .await
        .unwrap();
    dga.process_group_event(&bob_message).await.unwrap();

    // Verify Bob is a member
    assert_eq!(
        dga.group_state(&result.group_id)
            .await
            .unwrap()
            .members
            .len(),
        2
    );

    // Bob leaves the group
    let leave_event: GroupActivityEvent<()> =
        create_leave_group_event(Some("Thanks for having me!".to_string()));

    let leave_message = bob_dga
        .create_group_event_message(result.group_id, leave_event, &bob_key, timestamp + 10)
        .await
        .unwrap();

    dga.process_group_event(&leave_message).await.unwrap();

    // Verify Bob is no longer in active members
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.members.len(), 1);
    assert!(!group_state.is_member(&bob_key.public_key()));
    assert!(group_state.is_member(&alice_key.public_key()));
}

#[tokio::test]
async fn test_missing_group_session_error() {
    let dga = GroupManager::builder().build();
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Remove the group session to simulate not having it
    dga.remove_group_session(&result.group_id).await;

    // Try to create an event without the group session
    let activity_event = create_group_activity_event(());

    let result = dga
        .create_group_event_message(result.group_id, activity_event, &alice_key, timestamp + 1)
        .await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Group not found"));
}

// Note: This test was removed because decrypt_group_event method no longer exists
// Encryption/decryption is now handled internally by the GroupManager
// #[tokio::test]
// async fn test_invalid_key_id_decryption_error() {
//     // Test removed - decryption is now handled internally
// }

#[tokio::test]
async fn test_permission_denied_for_role_update() {
    let dga = GroupManager::builder().build();
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Add Bob as a regular member
    let bob_dga = GroupManager::builder().build();
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id, group_session)
        .await;
    let bob_activity = create_group_activity_event(());
    let bob_message = bob_dga
        .create_group_event_message(result.group_id, bob_activity, &bob_key, timestamp + 5)
        .await
        .unwrap();
    dga.process_group_event(&bob_message).await.unwrap();

    // Bob (regular member) tries to update Alice's role (should fail)
    let role_update: GroupActivityEvent<()> = create_role_update_event(
        alice_key.public_key(),
        GroupRole::Member, // Trying to demote the owner
    );

    let role_message = bob_dga
        .create_group_event_message(result.group_id, role_update, &bob_key, timestamp + 10)
        .await
        .unwrap();

    // This should fail when processed
    let result = dga.process_group_event(&role_message).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Permission denied")
    );
}

#[tokio::test]
async fn test_subscription_filter_creation() {
    let dga = GroupManager::builder().build();
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Create group
    let result = dga
        .create_group(create_group, None, &alice_key, timestamp)
        .await
        .unwrap();

    // Create subscription filter
    let filter = dga
        .create_group_subscription_filter(&result.group_id)
        .await
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

#[tokio::test]
async fn test_group_key_generation() {
    let timestamp = 1234567890;

    let key1 = GroupManager::generate_group_key(timestamp);
    let key2 = GroupManager::generate_group_key(timestamp);

    // Keys should be different (random generation)
    assert_ne!(key1.key, key2.key);

    // Key IDs should also be different (randomly generated)
    assert_ne!(key1.key_id, key2.key_id);
    assert_eq!(key1.created_at, key2.created_at);

    // Key should be proper length
    assert_eq!(key1.key.len(), 32); // 256 bits
}

#[tokio::test]
async fn test_create_key_from_mnemonic() {
    use zoe_wire_protocol::MnemonicPhrase;
    use zoe_wire_protocol::bip39::Language;

    // Use a known test mnemonic
    let mnemonic = MnemonicPhrase::from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        Language::English
    ).unwrap();

    let group_name = "test-group";
    let passphrase = "test-passphrase";
    let timestamp = 1640995200;

    let key = GroupManager::create_key_from_mnemonic(&mnemonic, passphrase, group_name, timestamp)
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

#[tokio::test]
async fn test_recover_key_from_mnemonic() {
    use zoe_wire_protocol::MnemonicPhrase;

    // Generate a mnemonic and derive a key
    let mnemonic = MnemonicPhrase::generate().unwrap();
    let group_name = "recovery-test-group";
    let passphrase = "recovery-passphrase";
    let timestamp = 1640995200;

    // Create initial key
    let original_key =
        GroupManager::create_key_from_mnemonic(&mnemonic, passphrase, group_name, timestamp)
            .unwrap();

    // Extract salt for recovery
    let derivation_info = original_key.derivation_info.as_ref().unwrap();
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&derivation_info.salt);

    // Recover the key using the same parameters
    let recovered_key = GroupManager::recover_key_from_mnemonic(
        &mnemonic, passphrase, group_name, &salt, timestamp,
    )
    .unwrap();

    // Keys should be identical
    assert_eq!(original_key.key, recovered_key.key);
    assert_eq!(original_key.key_id, recovered_key.key_id);
    assert_eq!(original_key.created_at, recovered_key.created_at);
}

#[tokio::test]
async fn test_mnemonic_key_integration_with_group_creation() {
    use zoe_app_primitives::group::events::settings::GroupSettings;
    use zoe_wire_protocol::MnemonicPhrase;

    let dga = GroupManager::builder().build();
    let alice_key = KeyPair::generate_ml_dsa65(&mut rand::thread_rng());
    let timestamp = chrono::Utc::now().timestamp() as u64;

    // Generate mnemonic and create encryption key
    let mnemonic = MnemonicPhrase::generate().unwrap();
    let encryption_key = GroupManager::create_key_from_mnemonic(
        &mnemonic,
        "test-passphrase",
        "integration-test-group",
        timestamp,
    )
    .unwrap();

    // Create group with mnemonic-derived key
    let metadata = vec![
        Metadata::Description("Testing mnemonic key integration".to_string()),
        Metadata::Generic {
            key: "key_source".to_string(),
            value: "mnemonic".to_string(),
        },
    ];

    let group_info = GroupInfo {
        name: "Integration Test Group".to_string(),
        settings: GroupSettings::default(),
        key_info: GroupKeyInfo::new_chacha20_poly1305(
            vec![], // This will be filled in by create_group
            zoe_wire_protocol::crypto::KeyDerivationInfo {
                method: zoe_wire_protocol::crypto::KeyDerivationMethod::ChaCha20Poly1305Keygen,
                salt: vec![],
                argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
                context: "dga-group-key".to_string(),
            },
        ),
        metadata,
    };

    let create_group = CreateGroup::new(group_info);

    let result = dga
        .create_group(
            create_group,
            Some(encryption_key.clone()),
            &alice_key,
            timestamp,
        )
        .await
        .unwrap();

    // Verify group was created successfully
    assert!(dga.group_session(&result.group_id).await.is_some());
    assert!(dga.group_session(&result.group_id).await.is_some());

    // Verify the key is properly stored
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    let stored_key = &group_session.current_key;
    assert_eq!(stored_key.key, encryption_key.key);
    assert_eq!(stored_key.key_id, encryption_key.key_id);
}

#[tokio::test]
async fn test_invalid_mnemonic_phrase_error() {
    use zoe_wire_protocol::MnemonicPhrase;
    use zoe_wire_protocol::bip39::Language;

    // Test with invalid mnemonic phrase
    let result = MnemonicPhrase::from_phrase(
        "invalid mnemonic phrase that should fail checksum",
        Language::English,
    );

    assert!(result.is_err());
}

#[tokio::test]
async fn test_mnemonic_key_different_contexts_produce_different_keys() {
    use zoe_wire_protocol::MnemonicPhrase;

    let mnemonic = MnemonicPhrase::generate().unwrap();
    let passphrase = "same-passphrase";
    let timestamp = 1640995200;

    // Same mnemonic, different contexts should produce different keys
    let key1 =
        GroupManager::create_key_from_mnemonic(&mnemonic, passphrase, "group-one", timestamp)
            .unwrap();

    let key2 =
        GroupManager::create_key_from_mnemonic(&mnemonic, passphrase, "group-two", timestamp)
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

#[tokio::test]
async fn test_mnemonic_key_different_passphrases_produce_different_keys() {
    use zoe_wire_protocol::MnemonicPhrase;

    let mnemonic = MnemonicPhrase::generate().unwrap();
    let group_name = "same-group";
    let timestamp = 1640995200;

    // Same mnemonic, different passphrases should produce different keys
    let key1 =
        GroupManager::create_key_from_mnemonic(&mnemonic, "passphrase-one", group_name, timestamp)
            .unwrap();

    let key2 =
        GroupManager::create_key_from_mnemonic(&mnemonic, "passphrase-two", group_name, timestamp)
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

#[tokio::test]
async fn test_group_manager_cloning_preserves_broadcast_channel() {
    use tokio::time::{Duration, timeout};

    // Create a GroupManager
    let manager1 = GroupManager::builder().build();

    // Clone it multiple times to simulate real-world usage
    let manager2 = manager1.clone();
    let manager3 = manager1.clone();
    let manager4 = manager1.clone();

    // Subscribe to updates from one of the clones
    let mut receiver1 = manager2.subscribe_to_updates();
    let mut receiver2 = manager3.subscribe_to_updates();

    // Create a test group to generate an update
    let (alice_key, _) = create_test_keys();
    let create_group = create_test_group();
    let timestamp = 1234567890;

    // Drop some manager instances to test that the channel stays open
    drop(manager2);
    drop(manager3);

    // Create a group using the remaining manager - this should broadcast an update
    let result = manager1
        .create_group(create_group, None, &alice_key, timestamp)
        .await;

    assert!(result.is_ok(), "Group creation should succeed");

    // Both receivers should still work even though some managers were dropped
    // This verifies that Arc-wrapped broadcast components keep the channel open
    let update1 = timeout(Duration::from_millis(100), receiver1.recv()).await;
    let update2 = timeout(Duration::from_millis(100), receiver2.recv()).await;

    assert!(
        update1.is_ok(),
        "First receiver should receive update despite manager being dropped"
    );
    assert!(
        update2.is_ok(),
        "Second receiver should receive update despite manager being dropped"
    );

    // Verify the updates are GroupAdded events
    match update1.unwrap().unwrap() {
        GroupDataUpdate::GroupAdded(_) => (),
        other => panic!("Expected GroupAdded, got {other:?}"),
    }

    match update2.unwrap().unwrap() {
        GroupDataUpdate::GroupAdded(_) => (),
        other => panic!("Expected GroupAdded, got {other:?}"),
    }

    // Drop the remaining managers
    drop(manager1);
    drop(manager4);

    // Create a new manager and verify it can still create its own broadcast channel
    let new_manager = GroupManager::builder().build();
    let mut new_receiver = new_manager.subscribe_to_updates();

    // Create another group to test the new manager
    let create_group2 = create_test_group();
    let result2 = new_manager
        .create_group(create_group2, None, &alice_key, timestamp + 1)
        .await;

    assert!(result2.is_ok(), "New manager should work independently");

    // New receiver should get the update
    let update3 = timeout(Duration::from_millis(100), new_receiver.recv()).await;
    assert!(update3.is_ok(), "New manager's receiver should work");

    match update3.unwrap().unwrap() {
        GroupDataUpdate::GroupAdded(_) => (),
        other => panic!("Expected GroupAdded, got {other:?}"),
    }
}
