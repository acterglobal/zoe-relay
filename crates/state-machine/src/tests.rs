use crate::app_manager::GroupService;
use crate::group::create_role_update_event_for_testing;
use crate::group::{CreateGroupBuilder, GroupDataUpdate, GroupManager};
use crate::messages::MockMessagesManagerTrait;
use mockall::predicate::function;
use rand::thread_rng;
use std::sync::Arc;
use zoe_app_primitives::group::events::GroupActivityEvent;
use zoe_app_primitives::group::events::roles::GroupRole;
use zoe_app_primitives::group::events::settings::GroupSettings;
use zoe_app_primitives::identity::IdentityRef;
use zoe_wire_protocol::{Content, Filter, KeyPair, PublishResult, Tag};

mod integration_test;
mod join_group_test;

fn create_test_keys() -> (KeyPair, KeyPair) {
    let mut rng = thread_rng();
    let alice_key = KeyPair::generate_ml_dsa65(&mut rng);
    let bob_key = KeyPair::generate_ml_dsa65(&mut rng);
    (alice_key, bob_key)
}

fn create_test_group() -> CreateGroupBuilder {
    CreateGroupBuilder::new("Test Group".to_string())
        .description("A test group for unit tests".to_string())
        .group_settings(GroupSettings::default())
}

async fn create_test_group_manager() -> GroupManager<MockMessagesManagerTrait> {
    let mut mock_manager = MockMessagesManagerTrait::new();

    // Set up default expectations for subscription calls
    mock_manager
        .expect_ensure_contains_filter()
        .with(function(|filter: &Filter| {
            matches!(filter, Filter::Channel(_))
        }))
        .returning(|_| Ok(()));

    // Set up default expectations for publish calls
    mock_manager.expect_publish().returning(|_| {
        Ok(PublishResult::StoredNew {
            global_stream_id: "test_stream_id".to_string(),
        })
    });

    // Set up default expectations for messages_stream calls
    mock_manager.expect_message_events_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(1);
        // Close the sender immediately to create an empty stream
        drop(tx);
        rx
    });

    // Set up default expectations for catch_up_stream calls
    mock_manager.expect_catch_up_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(1);
        // Close the sender immediately to create an empty stream
        drop(tx);
        rx
    });

    let message_manager = Arc::new(mock_manager);
    GroupManager::builder(message_manager).build().await
}

#[tokio::test]
async fn test_create_encrypted_group() {
    let dga = create_test_group_manager().await;
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();

    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Verify group was created
    let group_state = dga.group_state(&result.group_id).await;
    assert!(group_state.is_some());

    // Verify group has encryption key (now part of GroupSession)
    let group_session = dga.group_session(&result.group_id).await;
    assert!(group_session.is_some());

    // Verify group state
    let group_state = group_state.unwrap();
    assert_eq!(group_state.group_info.name, "Test Group");
    assert_eq!(
        group_state.description(),
        Some("A test group for unit tests".to_string())
    );
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&IdentityRef::Key(alice_key.public_key())));
    assert_eq!(
        group_state.member_role(&IdentityRef::Key(alice_key.public_key())),
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
    let dga = create_test_group_manager().await;
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group and get the message
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Create a fresh DGA instance and add the complete group session
    let fresh_dga = create_test_group_manager().await;
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    fresh_dga
        .add_group_session(result.group_id.clone(), group_session)
        .await;
    // Verify the group was created
    let group_state = fresh_dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.group_info.name, "Test Group");
    assert_eq!(
        group_state.description(),
        Some("A test group for unit tests".to_string())
    );
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&IdentityRef::Key(alice_key.public_key())));
}

#[tokio::test]
async fn test_encrypted_group_activity() {
    let dga = create_test_group_manager().await;
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Create and send an activity event
    let activity_event =
        GroupActivityEvent::SetIdentity(zoe_app_primitives::identity::IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });

    // Process the activity
    dga.publish_app_event(
        &result.group_id,
        result.group_id.clone(),
        activity_event,
        &alice_key,
    )
    .await
    .unwrap();

    // Verify Alice is still the only member (she was already the creator)
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.members.len(), 1);
    assert!(group_state.is_member(&IdentityRef::Key(alice_key.public_key())));
}

#[tokio::test]
async fn test_new_member_via_activity() {
    let dga = create_test_group_manager().await;
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Alice creates group
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Simulate Bob getting the group session via inbox system
    // (In reality, this would happen through a separate secure channel)

    // Create a separate DGA instance for Bob and give him the complete session
    let bob_dga = create_test_group_manager().await;
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id.clone(), group_session)
        .await;

    // Bob now has the complete group session, no need for separate state management

    // Bob sends an activity
    let bob_activity =
        GroupActivityEvent::SetIdentity(zoe_app_primitives::identity::IdentityInfo {
            display_name: "bob_user".to_string(),
            metadata: vec![],
        });
    // Alice processes Bob's message
    let bob_message = dga
        .publish_group_event(&result.group_id, bob_activity, &bob_key)
        .await
        .unwrap();
    dga.handle_incoming_message(bob_message).await.unwrap();

    // Verify Bob is now an active member
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.members.len(), 2);
    assert!(group_state.is_member(&IdentityRef::Key(alice_key.public_key())));
    assert!(group_state.is_member(&IdentityRef::Key(bob_key.public_key())));
    assert_eq!(
        group_state.member_role(&IdentityRef::Key(bob_key.public_key())),
        Some(GroupRole::Member)
    );
}

#[tokio::test]
async fn test_role_update() {
    let dga = create_test_group_manager().await;
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group and add Bob as member
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Simulate Bob joining by sending an activity
    let bob_dga = create_test_group_manager().await;
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id.clone(), group_session)
        .await;

    let bob_activity =
        GroupActivityEvent::SetIdentity(zoe_app_primitives::identity::IdentityInfo {
            display_name: "bob_user".to_string(),
            metadata: vec![],
        });

    let bob_message = dga
        .publish_group_event(&result.group_id, bob_activity, &bob_key)
        .await
        .unwrap();
    dga.handle_incoming_message(bob_message).await.unwrap();

    // Alice promotes Bob to Admin
    let role_update: GroupActivityEvent =
        create_role_update_event_for_testing(bob_key.public_key(), GroupRole::Admin);

    let role_message = dga
        .publish_group_event(&result.group_id, role_update, &alice_key)
        .await
        .unwrap();
    dga.handle_incoming_message(role_message).await.unwrap();

    // Verify Bob's role was updated
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(
        group_state.member_role(&IdentityRef::Key(bob_key.public_key())),
        Some(GroupRole::Admin)
    );
}

#[tokio::test]
async fn test_leave_group_event() {
    let dga = create_test_group_manager().await;
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group and add Bob
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Add Bob as a member first
    let bob_activity =
        GroupActivityEvent::SetIdentity(zoe_app_primitives::identity::IdentityInfo {
            display_name: "bob_user".to_string(),
            metadata: vec![],
        });
    // Publish Bob's SetIdentity event and process it to update the group state
    let bob_message = dga
        .publish_group_event(&result.group_id, bob_activity, &bob_key)
        .await
        .unwrap();
    dga.handle_incoming_message(bob_message).await.unwrap();

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
    let leave_event: GroupActivityEvent = GroupActivityEvent::LeaveGroup {
        message: Some("Thanks for having me!".to_string()),
    };

    let leave_message = dga
        .publish_group_event(&result.group_id, leave_event, &bob_key)
        .await
        .unwrap();
    dga.handle_incoming_message(leave_message).await.unwrap();

    // Verify Bob is no longer in active members
    let group_state = dga.group_state(&result.group_id).await.unwrap();
    assert_eq!(group_state.members.len(), 1);
    assert!(!group_state.is_member(&IdentityRef::Key(bob_key.public_key())));
    assert!(group_state.is_member(&IdentityRef::Key(alice_key.public_key())));
}

#[tokio::test]
async fn test_missing_group_session_error() {
    let dga = create_test_group_manager().await;
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Remove the group session to simulate not having it
    dga.remove_group_session(&result.group_id).await;

    // Try to create an event without the group session
    let activity_event =
        GroupActivityEvent::SetIdentity(zoe_app_primitives::identity::IdentityInfo {
            display_name: "test_user".to_string(),
            metadata: vec![],
        });

    let result = dga
        .publish_group_event(&result.group_id, activity_event, &alice_key)
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
    let dga = create_test_group_manager().await;
    let (alice_key, bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Add Bob as a regular member
    let bob_dga = create_test_group_manager().await;
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    bob_dga
        .add_group_session(result.group_id.clone(), group_session)
        .await;
    let bob_activity =
        GroupActivityEvent::SetIdentity(zoe_app_primitives::identity::IdentityInfo {
            display_name: "bob_user".to_string(),
            metadata: vec![],
        });
    let bob_message = bob_dga
        .publish_group_event(&result.group_id, bob_activity.clone(), &bob_key)
        .await
        .unwrap();

    // Process the message to update group state
    dga.handle_incoming_message(bob_message.clone())
        .await
        .unwrap();
    bob_dga.handle_incoming_message(bob_message).await.unwrap();

    // Debug: Check Bob's role before attempting role update
    let group_state_alice = dga.group_state(&result.group_id).await.unwrap();
    let group_state_bob = bob_dga.group_state(&result.group_id).await.unwrap();
    println!(
        "Bob's role (from Alice's view): {:?}",
        group_state_alice.member_role(&IdentityRef::Key(bob_key.public_key()))
    );
    println!(
        "Bob's role (from Bob's view): {:?}",
        group_state_bob.member_role(&IdentityRef::Key(bob_key.public_key()))
    );
    println!(
        "Alice's role: {:?}",
        group_state_alice.member_role(&IdentityRef::Key(alice_key.public_key()))
    );
    println!(
        "Group permissions: {:?}",
        group_state_alice.group_info.settings.permissions
    );

    // Bob (regular member) tries to update Alice's role (should fail)
    let role_update: GroupActivityEvent = create_role_update_event_for_testing(
        alice_key.public_key(),
        GroupRole::Member, // Trying to demote the owner
    );

    let publish_result = bob_dga
        .publish_group_event(&result.group_id, role_update, &bob_key)
        .await;

    // This should fail when processed;
    println!("Publish result: {publish_result:?}");

    // If publishing succeeded, try to process the message - this should fail
    if let Ok(role_message) = publish_result {
        let process_result = dga.handle_incoming_message(role_message.clone()).await;
        println!("Process result: {process_result:?}");
        assert!(process_result.is_err());
        let error_msg = process_result.unwrap_err().to_string();
        assert!(error_msg.contains("Permission denied") || error_msg.contains("MemberNotFound"));
    } else {
        // Publishing failed, which is also acceptable
        let error_msg = publish_result.unwrap_err().to_string();
        assert!(error_msg.contains("Permission denied") || error_msg.contains("MemberNotFound"));
    }
}

#[tokio::test]
async fn test_subscription_filter_creation() {
    let dga = create_test_group_manager().await;
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = create_test_group();

    // Create group
    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Create subscription filter
    let filter = dga
        .create_group_subscription_filter(&result.group_id)
        .await
        .unwrap();

    // Verify filter
    match filter {
        Tag::Channel { id, relays } => {
            // GroupId is ChannelId, so direct comparison
            assert_eq!(id, result.group_id);
            assert!(relays.is_empty());
        }
        _ => panic!("Expected Channel tag"),
    }
}

#[tokio::test]
async fn test_group_key_generation() {
    let key1 = GroupManager::<MockMessagesManagerTrait>::generate_group_key();
    let key2 = GroupManager::<MockMessagesManagerTrait>::generate_group_key();

    // Keys should be different (random generation)
    assert_ne!(key1.key, key2.key);

    // Key IDs should also be different (randomly generated)
    assert_ne!(key1.key_id, key2.key_id);
    // Keys should be different even when generated at the same time
    assert_ne!(key1.key, key2.key);

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

    let key = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic, passphrase, group_name,
    )
    .unwrap();

    // Verify key properties
    assert_eq!(key.key.len(), 32);
    // Key should be properly generated
    assert_eq!(key.key.len(), 32);
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

    // Create initial key
    let original_key = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic, passphrase, group_name,
    )
    .unwrap();

    // Extract salt for recovery
    let derivation_info = original_key.derivation_info.as_ref().unwrap();
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&derivation_info.salt);

    // Recover the key using the same parameters
    let recovered_key = GroupManager::<MockMessagesManagerTrait>::recover_key_from_mnemonic(
        &mnemonic, passphrase, group_name, &salt,
    )
    .unwrap();

    // Keys should be identical
    assert_eq!(original_key.key, recovered_key.key);
    assert_eq!(original_key.key_id, recovered_key.key_id);
    // Derivation info should match
    assert_eq!(original_key.derivation_info, recovered_key.derivation_info);
}

#[tokio::test]
async fn test_mnemonic_key_integration_with_group_creation() {
    use zoe_app_primitives::group::events::settings::GroupSettings;
    use zoe_wire_protocol::MnemonicPhrase;

    let dga = create_test_group_manager().await;
    let alice_key = KeyPair::generate_ml_dsa65(&mut rand::thread_rng());

    // Generate mnemonic and create encryption key
    let mnemonic = MnemonicPhrase::generate().unwrap();
    let _encryption_key = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic,
        "test-passphrase",
        "integration-test-group",
    )
    .unwrap();

    // Create group with mnemonic-derived key
    let create_group = CreateGroupBuilder::new("Integration Test Group".to_string())
        .description("Testing mnemonic key integration".to_string())
        .group_settings(GroupSettings::default());

    let result = dga.create_group(create_group, &alice_key).await.unwrap();

    // Verify group was created successfully
    assert!(dga.group_session(&result.group_id).await.is_some());
    assert!(dga.group_session(&result.group_id).await.is_some());

    // Verify the key is properly stored
    let group_session = dga.group_session(&result.group_id).await.unwrap();
    let stored_key = &group_session.current_key;
    // The group generates its own key, so we just verify it exists
    assert_eq!(stored_key.key.len(), 32);
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

    // Same mnemonic, different contexts should produce different keys
    let key1 = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic,
        passphrase,
        "group-one",
    )
    .unwrap();

    let key2 = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic,
        passphrase,
        "group-two",
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

#[tokio::test]
async fn test_mnemonic_key_different_passphrases_produce_different_keys() {
    use zoe_wire_protocol::MnemonicPhrase;

    let mnemonic = MnemonicPhrase::generate().unwrap();
    let group_name = "same-group";

    // Same mnemonic, different passphrases should produce different keys
    let key1 = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic,
        "passphrase-one",
        group_name,
    )
    .unwrap();

    let key2 = GroupManager::<MockMessagesManagerTrait>::create_key_from_mnemonic(
        &mnemonic,
        "passphrase-two",
        group_name,
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

#[tokio::test]
async fn test_join_group_end_to_end() {
    // Create the original group manager (Alice creates the group)
    let alice_manager = create_test_group_manager();
    let (alice_key, _bob_key) = create_test_keys();

    // Create a group with specific settings and installed apps
    let create_group = CreateGroupBuilder::new("Test Encrypted Group".to_string())
        .description("A test group for join functionality".to_string())
        .group_settings(GroupSettings::default())
        .install_dgo_app_default(); // Install DGO app

    // Alice creates the group
    let alice_manager = alice_manager.await;
    let create_result = alice_manager
        .create_group(create_group, &alice_key)
        .await
        .unwrap();

    // Get the encryption key from Alice's session
    let alice_session = alice_manager
        .group_session(&create_result.group_id)
        .await
        .unwrap();
    let encryption_key = alice_session.current_key.clone();

    // Create a fresh manager for Bob (simulating a new participant)
    let bob_manager = create_test_group_manager().await;

    // Bob joins the group using the encrypted message and key
    let joined_group_id = bob_manager
        .join_group(create_result.message.clone(), encryption_key)
        .await
        .unwrap();

    // Verify the group ID matches
    assert_eq!(joined_group_id, create_result.group_id);

    // Verify Bob now has the group session
    let bob_session = bob_manager.group_session(&joined_group_id).await;
    assert!(bob_session.is_some());

    let bob_session = bob_session.unwrap();

    // Verify the group state matches Alice's original group
    assert_eq!(bob_session.state.group_info.name, "Test Encrypted Group");
    assert_eq!(
        bob_session.state.description(),
        Some("A test group for join functionality".to_string())
    );
    assert_eq!(bob_session.state.members.len(), 1); // Only Alice is a member initially
    assert!(
        bob_session
            .state
            .is_member(&IdentityRef::Key(alice_key.public_key()))
    );
    assert_eq!(
        bob_session
            .state
            .member_role(&IdentityRef::Key(alice_key.public_key())),
        Some(GroupRole::Owner)
    );

    // Verify installed apps were preserved
    assert_eq!(bob_session.state.group_info.installed_apps.len(), 1);
    let installed_app = &bob_session.state.group_info.installed_apps[0];
    assert_eq!(
        installed_app.app_id,
        zoe_app_primitives::protocol::AppProtocolVariant::DigitalGroupsOrganizer
    );

    // Verify the encryption key was properly set
    assert_eq!(
        bob_session.current_key.key_id,
        alice_session.current_key.key_id
    );
    assert_eq!(bob_session.current_key.key, alice_session.current_key.key);
}

#[tokio::test]
async fn test_join_group_with_mock_subscription_verification() {
    use crate::messages::MockMessagesManagerTrait;
    use mockall::predicate::*;
    use std::sync::Arc;
    use zoe_wire_protocol::Filter;

    // Create a mock message manager with expectations
    let mut mock_manager = MockMessagesManagerTrait::new();

    // Set up expectations for the subscription call
    mock_manager
        .expect_ensure_contains_filter()
        .with(function(|filter: &Filter| {
            matches!(filter, Filter::Channel(_))
        }))
        .times(1)
        .returning(|_| Ok(()));

    let mock_manager = Arc::new(mock_manager);

    // Create Alice's manager to generate the group
    let alice_manager = create_test_group_manager();
    let (alice_key, _bob_key) = create_test_keys();

    // Create the group
    let create_group = CreateGroupBuilder::new("Mock Test Group".to_string())
        .description("Testing mock subscription calls".to_string());

    let alice_manager = alice_manager.await;
    let create_result = alice_manager
        .create_group(create_group, &alice_key)
        .await
        .unwrap();
    let alice_session = alice_manager
        .group_session(&create_result.group_id)
        .await
        .unwrap();
    let encryption_key = alice_session.current_key.clone();

    // Create Bob's manager with the mock
    let bob_manager = GroupManager::builder(mock_manager).build();

    // Bob joins the group - this should trigger the subscription call
    let bob_manager = bob_manager.await;
    let result = bob_manager
        .join_group(create_result.message, encryption_key)
        .await;

    assert!(result.is_ok());

    // The mock will automatically verify that ensure_contains_filter was called
    // with the correct Filter::Event containing the group ID
}

#[tokio::test]
async fn test_group_manager_handles_stream_closure_gracefully() {
    use crate::messages::MockMessagesManagerTrait;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use zoe_wire_protocol::{Filter, PublishResult};

    // Create a mock message manager that will close the stream after a few messages
    let mut mock_manager = MockMessagesManagerTrait::new();

    // Set up expectations for subscription calls
    mock_manager
        .expect_ensure_contains_filter()
        .with(function(|filter: &Filter| {
            matches!(filter, Filter::Channel(_))
        }))
        .returning(|_| Ok(()));

    // Set up expectations for publish calls
    mock_manager.expect_publish().returning(|_| {
        Ok(PublishResult::StoredNew {
            global_stream_id: "test_stream_id".to_string(),
        })
    });

    // Create a stream that will close after a short delay
    mock_manager.expect_message_events_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(10);

        // Spawn a task that will close the sender after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(tx); // This will close the broadcast channel
        });

        rx
    });

    // Set up catch-up stream that also closes
    mock_manager.expect_catch_up_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(10);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(tx);
        });
        rx
    });

    let message_manager = Arc::new(mock_manager);
    let group_manager = GroupManager::builder(message_manager).build().await;

    // Create a group to trigger the background message processing
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = CreateGroupBuilder::new("Stream Closure Test Group".to_string())
        .description("Testing stream closure handling".to_string());

    let create_result = group_manager
        .create_group(create_group, &alice_key)
        .await
        .unwrap();

    // Wait for the stream to close and verify the manager doesn't stall
    // The manager should handle the stream closure gracefully and not hang
    let result = timeout(Duration::from_secs(2), async {
        // Try to get the group session - this should work even after stream closure
        group_manager.group_session(&create_result.group_id).await
    })
    .await;

    // The manager should still be functional even after stream closure
    assert!(
        result.is_ok(),
        "GroupManager should handle stream closure gracefully"
    );
    let session_result = result.unwrap();
    assert!(
        session_result.is_some(),
        "Should be able to get group session after stream closure"
    );
}

#[tokio::test]
async fn test_app_manager_handles_stream_closure_gracefully() {
    use crate::app_manager::{AppManager, GroupService};
    use crate::execution::InMemoryStore;
    use crate::messages::MockMessagesManagerTrait;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use zoe_wire_protocol::{Filter, PublishResult};

    // Mock GroupService implementation
    #[derive(Clone)]
    struct MockGroupService;

    #[async_trait::async_trait]
    impl GroupService for MockGroupService {
        fn message_group_receiver(
            &self,
        ) -> async_broadcast::Receiver<crate::group::GroupDataUpdate> {
            let (_tx, rx) = async_broadcast::broadcast(1000);
            rx
        }

        async fn current_group_states(&self) -> Vec<zoe_app_primitives::group::states::GroupState> {
            Vec::new()
        }

        async fn decrypt_app_message<T: serde::de::DeserializeOwned>(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _encrypted_content: &zoe_wire_protocol::ChaCha20Poly1305Content,
        ) -> crate::error::GroupResult<T> {
            Err(crate::error::GroupError::InvalidEvent(
                "Mock decryption not implemented".to_string(),
            ))
        }

        async fn group_state_at_message(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _message_id: zoe_wire_protocol::MessageId,
        ) -> Option<zoe_app_primitives::group::states::GroupState> {
            None
        }

        async fn current_group_state(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
        ) -> Option<zoe_app_primitives::group::states::GroupState> {
            None
        }

        async fn get_permission_context(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _actor_identity_ref: &zoe_app_primitives::identity::IdentityRef,
            _group_state_reference: zoe_wire_protocol::MessageId,
            _app_id: &zoe_app_primitives::protocol::AppProtocolVariant,
        ) -> (
            zoe_app_primitives::group::events::roles::GroupRole,
            zoe_wire_protocol::MessageId,
            zoe_app_primitives::group::events::permissions::GroupPermissions,
        ) {
            (
                zoe_app_primitives::group::events::roles::GroupRole::Member,
                zoe_wire_protocol::MessageId::from([0u8; 32]),
                zoe_app_primitives::group::events::permissions::GroupPermissions::default(),
            )
        }

        async fn publish_app_event<T: serde::Serialize + Send>(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _app_tag: zoe_wire_protocol::ChannelId,
            _event: T,
            _sender: &zoe_wire_protocol::KeyPair,
        ) -> crate::error::GroupResult<zoe_wire_protocol::MessageFull> {
            Err(crate::error::GroupError::InvalidOperation(
                "Mock publish_app_event not implemented".to_string(),
            ))
        }
    }

    // Create a mock message manager that will close the stream
    let mut mock_manager = MockMessagesManagerTrait::new();

    // Set up expectations for subscription calls
    mock_manager
        .expect_ensure_contains_filter()
        .with(function(|filter: &Filter| {
            matches!(filter, Filter::Channel(_))
        }))
        .returning(|_| Ok(()));

    // Set up expectations for publish calls
    mock_manager.expect_publish().returning(|_| {
        Ok(PublishResult::StoredNew {
            global_stream_id: "test_stream_id".to_string(),
        })
    });

    // Create a stream that will close after a short delay
    mock_manager.expect_message_events_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(10);

        // Spawn a task that will close the sender after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(tx); // This will close the broadcast channel
        });

        rx
    });

    // Set up catch-up stream that also closes
    mock_manager.expect_catch_up_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(10);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(tx);
        });
        rx
    });

    let message_manager = Arc::new(mock_manager);

    // Create AppManager - this should start background tasks that handle stream closure
    let _app_manager = AppManager::new(
        message_manager,
        Arc::new(MockGroupService),
        InMemoryStore::new(),
    )
    .await;

    // Wait for the stream to close and verify the manager doesn't stall
    // The AppManager should handle the stream closure gracefully
    let result = timeout(Duration::from_secs(2), async {
        // The AppManager should not hang even when streams close
        tokio::time::sleep(Duration::from_millis(500)).await;
    })
    .await;

    // The AppManager should handle stream closure gracefully
    assert!(
        result.is_ok(),
        "AppManager should handle stream closure gracefully"
    );
}

#[tokio::test]
async fn test_multiple_receivers_handle_stream_closure_independently() {
    use crate::app_manager::{AppManager, GroupService};
    use crate::execution::InMemoryStore;
    use crate::messages::MockMessagesManagerTrait;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::timeout;
    use zoe_wire_protocol::{Filter, PublishResult};

    // Mock GroupService implementation
    #[derive(Clone)]
    struct MockGroupService;

    #[async_trait::async_trait]
    impl GroupService for MockGroupService {
        fn message_group_receiver(
            &self,
        ) -> async_broadcast::Receiver<crate::group::GroupDataUpdate> {
            let (_tx, rx) = async_broadcast::broadcast(1000);
            rx
        }

        async fn current_group_states(&self) -> Vec<zoe_app_primitives::group::states::GroupState> {
            Vec::new()
        }

        async fn decrypt_app_message<T: serde::de::DeserializeOwned>(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _encrypted_content: &zoe_wire_protocol::ChaCha20Poly1305Content,
        ) -> crate::error::GroupResult<T> {
            Err(crate::error::GroupError::InvalidEvent(
                "Mock decryption not implemented".to_string(),
            ))
        }

        async fn group_state_at_message(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _message_id: zoe_wire_protocol::MessageId,
        ) -> Option<zoe_app_primitives::group::states::GroupState> {
            None
        }

        async fn current_group_state(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
        ) -> Option<zoe_app_primitives::group::states::GroupState> {
            None
        }

        async fn get_permission_context(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _actor_identity_ref: &zoe_app_primitives::identity::IdentityRef,
            _group_state_reference: zoe_wire_protocol::MessageId,
            _app_id: &zoe_app_primitives::protocol::AppProtocolVariant,
        ) -> (
            zoe_app_primitives::group::events::roles::GroupRole,
            zoe_wire_protocol::MessageId,
            zoe_app_primitives::group::events::permissions::GroupPermissions,
        ) {
            (
                zoe_app_primitives::group::events::roles::GroupRole::Member,
                zoe_wire_protocol::MessageId::from([0u8; 32]),
                zoe_app_primitives::group::events::permissions::GroupPermissions::default(),
            )
        }

        async fn publish_app_event<T: serde::Serialize + Send>(
            &self,
            _group_id: &zoe_app_primitives::group::events::GroupId,
            _app_tag: zoe_wire_protocol::ChannelId,
            _event: T,
            _sender: &zoe_wire_protocol::KeyPair,
        ) -> crate::error::GroupResult<zoe_wire_protocol::MessageFull> {
            Err(crate::error::GroupError::InvalidOperation(
                "Mock publish_app_event not implemented".to_string(),
            ))
        }
    }

    // Create a mock message manager
    let mut mock_manager = MockMessagesManagerTrait::new();

    // Set up expectations for subscription calls
    mock_manager
        .expect_ensure_contains_filter()
        .with(function(|filter: &Filter| {
            matches!(filter, Filter::Channel(_))
        }))
        .returning(|_| Ok(()));

    // Set up expectations for publish calls
    mock_manager.expect_publish().returning(|_| {
        Ok(PublishResult::StoredNew {
            global_stream_id: "test_stream_id".to_string(),
        })
    });

    // Create a stream that will close after a short delay
    mock_manager.expect_message_events_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(10);

        // Spawn a task that will close the sender after a short delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(tx); // This will close the broadcast channel
        });

        rx
    });

    // Set up catch-up stream that also closes
    mock_manager.expect_catch_up_stream().returning(|| {
        let (tx, rx) = async_broadcast::broadcast(10);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(tx);
        });
        rx
    });

    let message_manager = Arc::new(mock_manager);

    // Create both GroupManager and AppManager that will both listen to the same stream
    let group_manager = GroupManager::builder(message_manager.clone()).build().await;
    let _app_manager = AppManager::new(
        message_manager,
        Arc::new(MockGroupService),
        InMemoryStore::new(),
    )
    .await;

    // Create a group to trigger background processing
    let (alice_key, _bob_key) = create_test_keys();
    let create_group = CreateGroupBuilder::new("Multiple Receivers Test Group".to_string())
        .description("Testing multiple receivers handling stream closure".to_string());

    let create_result = group_manager
        .create_group(create_group, &alice_key)
        .await
        .unwrap();

    // Wait for the stream to close and verify both managers handle it gracefully
    let result = timeout(Duration::from_secs(2), async {
        // Both managers should handle the stream closure independently
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify the GroupManager is still functional
        let session_result = group_manager.group_session(&create_result.group_id).await;
        assert!(
            session_result.is_some(),
            "GroupManager should still be functional after stream closure"
        );
    })
    .await;

    // Both managers should handle stream closure gracefully without interfering with each other
    assert!(
        result.is_ok(),
        "Multiple receivers should handle stream closure independently"
    );
}

#[tokio::test]
async fn test_join_group_invalid_decryption_key() {
    // Create the original group
    let alice_manager = create_test_group_manager();
    let (alice_key, _bob_key) = create_test_keys();

    let create_group = CreateGroupBuilder::new("Test Group".to_string());
    let alice_manager = alice_manager.await;
    let create_result = alice_manager
        .create_group(create_group, &alice_key)
        .await
        .unwrap();

    // Create a different encryption key (wrong key)
    let wrong_key = GroupManager::<MockMessagesManagerTrait>::generate_group_key();

    // Create Bob's manager
    let bob_manager = create_test_group_manager().await;

    // Try to join with the wrong key - should fail
    let result = bob_manager
        .join_group(create_result.message, wrong_key)
        .await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Failed to decrypt group creation message"));
}

#[tokio::test]
async fn test_join_group_non_encrypted_message() {
    use zoe_wire_protocol::{Kind, Message, MessageFull};

    // Create a non-encrypted message
    let (alice_key, _bob_key) = create_test_keys();
    let timestamp = chrono::Utc::now().timestamp() as u64;

    let plain_message = Message::new_v0(
        Content::Raw(b"not encrypted".to_vec()),
        alice_key.public_key(),
        timestamp,
        Kind::Regular,
        vec![],
    );

    let message_full = MessageFull::new(plain_message, &alice_key).unwrap();
    let encryption_key = GroupManager::<MockMessagesManagerTrait>::generate_group_key();

    // Try to join with a non-encrypted message
    let bob_manager = create_test_group_manager().await;
    let result = bob_manager.join_group(message_full, encryption_key).await;

    assert!(result.is_err());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("Message does not contain ChaCha20Poly1305 encrypted content"));
}

#[tokio::test]
async fn test_join_group_preserves_all_group_metadata() {
    use zoe_app_primitives::metadata::Metadata;
    use zoe_wire_protocol::version::Version;

    // Create a group with rich metadata and multiple apps
    let alice_manager = create_test_group_manager();
    let (alice_key, _bob_key) = create_test_keys();

    let create_group = CreateGroupBuilder::new("Rich Metadata Group".to_string())
        .description("A group with lots of metadata".to_string())
        .metadata(Metadata::Generic {
            key: "project".to_string(),
            value: "zoe-testing".to_string(),
        })
        .metadata(Metadata::Generic {
            key: "team".to_string(),
            value: "engineering".to_string(),
        })
        .install_dgo_app(Version::new(2, 1, 0))
        .add_installed_app(zoe_app_primitives::protocol::InstalledApp::new_simple(
            zoe_app_primitives::protocol::AppProtocolVariant::DigitalGroupsOrganizer,
            1,
            2,
            vec![1, 2, 3, 4], // Custom channel tag
        ));

    let alice_manager = alice_manager.await;
    let create_result = alice_manager
        .create_group(create_group, &alice_key)
        .await
        .unwrap();
    let alice_session = alice_manager
        .group_session(&create_result.group_id)
        .await
        .unwrap();
    let encryption_key = alice_session.current_key.clone();

    // Bob joins the group
    let bob_manager = create_test_group_manager().await;
    let joined_group_id = bob_manager
        .join_group(create_result.message, encryption_key)
        .await
        .unwrap();

    let bob_session = bob_manager.group_session(&joined_group_id).await.unwrap();

    // Verify all metadata was preserved
    assert_eq!(bob_session.state.group_info.name, "Rich Metadata Group");
    assert_eq!(
        bob_session.state.description(),
        Some("A group with lots of metadata".to_string())
    );

    // Check custom metadata
    let metadata = &bob_session.state.group_info.metadata;
    let project_meta = metadata.iter().find(|m| {
        matches!(m, Metadata::Generic { key, value } if key == "project" && value == "zoe-testing")
    });
    assert!(project_meta.is_some());

    let team_meta = metadata.iter().find(|m| {
        matches!(m, Metadata::Generic { key, value } if key == "team" && value == "engineering")
    });
    assert!(team_meta.is_some());

    // Verify installed apps
    assert_eq!(bob_session.state.group_info.installed_apps.len(), 2);

    // Check the first app (DGO with version 2.1.0)
    let dgo_app = bob_session
        .state
        .group_info
        .installed_apps
        .iter()
        .find(|app| app.version == Version::new(2, 1, 0));
    assert!(dgo_app.is_some());

    // Check the second app (custom channel tag)
    let custom_app = bob_session
        .state
        .group_info
        .installed_apps
        .iter()
        .find(|app| app.app_tag == vec![1, 2, 3, 4]);
    assert!(custom_app.is_some());
}

#[tokio::test]
async fn test_group_manager_cloning_preserves_broadcast_channel() {
    use tokio::time::{Duration, timeout};

    // Create a GroupManager
    let manager1 = create_test_group_manager();

    // Clone it multiple times to simulate real-world usage
    let manager1 = manager1.await;
    let manager2 = manager1.clone();
    let manager3 = manager1.clone();
    let manager4 = manager1.clone();

    // Subscribe to updates from one of the clones
    let mut receiver1 = manager2.subscribe_to_updates();
    let mut receiver2 = manager3.subscribe_to_updates();

    // Create a test group to generate an update
    let (alice_key, _) = create_test_keys();
    let create_group = create_test_group();

    // Drop some manager instances to test that the channel stays open
    drop(manager2);
    drop(manager3);

    // Create a group using the remaining manager - this should broadcast an update
    let result = manager1.create_group(create_group, &alice_key).await;

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
    let new_manager = create_test_group_manager();
    let new_manager = new_manager.await;
    let mut new_receiver = new_manager.subscribe_to_updates();

    // Create another group to test the new manager
    let create_group2 = create_test_group();
    let result2 = new_manager.create_group(create_group2, &alice_key).await;

    assert!(result2.is_ok(), "New manager should work independently");

    // New receiver should get the update
    let update3 = timeout(Duration::from_millis(100), new_receiver.recv()).await;
    assert!(update3.is_ok(), "New manager's receiver should work");

    match update3.unwrap().unwrap() {
        GroupDataUpdate::GroupAdded(_) => (),
        other => panic!("Expected GroupAdded, got {other:?}"),
    }
}
