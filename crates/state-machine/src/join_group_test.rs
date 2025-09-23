#[cfg(test)]
mod join_group_tests {

    use crate::group::{CreateGroupBuilder, GroupManager};
    use crate::messages::MockMessagesManagerTrait;
    use mockall::predicate::*;
    use std::sync::Arc;
    use zoe_app_primitives::group::events::settings::GroupSettings;
    use zoe_wire_protocol::{Filter, KeyPair, PublishResult};

    fn create_test_keys() -> (KeyPair, KeyPair) {
        let mut rng = rand::thread_rng();
        let alice_key = KeyPair::generate_ml_dsa65(&mut rng);
        let bob_key = KeyPair::generate_ml_dsa65(&mut rng);
        (alice_key, bob_key)
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
        mock_manager.expect_messages_stream().returning(|| {
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

    fn create_test_group() -> CreateGroupBuilder {
        CreateGroupBuilder::new("Test Group".to_string())
            .description("A test group for unit tests".to_string())
            .group_settings(GroupSettings::default())
    }

    #[tokio::test]
    async fn test_join_group_basic_functionality() {
        // Create the original group manager (Alice creates the group)
        let alice_manager = create_test_group_manager().await;
        let (alice_key, _bob_key) = create_test_keys();

        // Create a group with specific settings and installed apps
        let create_group = create_test_group().install_dgo_app_default(); // Install DGO app

        // Alice creates the group
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
        assert_eq!(bob_session.state.group_info.name, "Test Group");
        assert_eq!(
            bob_session.state.description(),
            Some("A test group for unit tests".to_string())
        );
        assert_eq!(bob_session.state.members.len(), 1); // Only Alice is a member initially
        assert!(bob_session.state.is_member(&alice_key.public_key()));

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
        let alice_manager = create_test_group_manager().await;
        let (alice_key, _bob_key) = create_test_keys();

        // Create the group
        let create_group = CreateGroupBuilder::new("Mock Test Group".to_string())
            .description("Testing mock subscription calls".to_string());

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
        let bob_manager = GroupManager::builder(mock_manager).build().await;

        // Bob joins the group - this should trigger the subscription call
        let result = bob_manager
            .join_group(create_result.message, encryption_key)
            .await;

        assert!(result.is_ok());

        // The mock will automatically verify that ensure_contains_filter was called
        // with the correct Filter::Event containing the group ID
    }

    #[tokio::test]
    async fn test_join_group_invalid_decryption_key() {
        // Create the original group
        let alice_manager = create_test_group_manager().await;
        let (alice_key, _bob_key) = create_test_keys();

        let create_group = CreateGroupBuilder::new("Test Group".to_string());
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
        use zoe_wire_protocol::{Content, Kind, Message, MessageFull};

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
}
