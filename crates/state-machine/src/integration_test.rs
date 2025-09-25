//! Integration tests for GroupManager + ExecutorManager
//!
//! This module contains tests that verify the complete integration between
//! GroupManager and ExecutorManager for app-specific message processing.

#[cfg(test)]
mod tests {
    use mockall::predicate::function;
    use std::sync::Arc;
    use zoe_app_primitives::{group::events::settings::GroupSettings, protocol::default_dgo_app};
    use zoe_wire_protocol::{Filter, KeyPair, PublishResult};

    use crate::{
        group::{CreateGroupBuilder, GroupManager},
        messages::MockMessagesManagerTrait,
    };

    /// Helper function to create a test GroupManager with ExecutorManager
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

    #[tokio::test]
    async fn test_complete_app_integration_flow() {
        // Create a GroupManager with integrated ExecutorManager
        let group_manager = create_test_group_manager().await;

        // Generate keypair for the test
        let mut rng = rand::thread_rng();
        let alice_keypair = KeyPair::generate(&mut rng);

        // Create a group with a DGO app installed
        let dgo_app = default_dgo_app();
        let create_group = CreateGroupBuilder::new("Test Group".to_string())
            .description("A test group with DGO app".to_string())
            .group_settings(GroupSettings::default())
            .add_installed_app(dgo_app.clone());

        // Create the group
        let create_result = group_manager
            .create_group(create_group, &alice_keypair)
            .await
            .expect("Failed to create group");

        // Verify the group was created
        let group_session = group_manager
            .group_session(&create_result.group_id)
            .await
            .expect("Group session should exist");

        // Verify the app was installed
        assert_eq!(group_session.state.group_info.installed_apps.len(), 1);
        assert_eq!(
            group_session.state.group_info.installed_apps[0].app_id,
            dgo_app.app_id
        );

        // Note: Executor functionality is now handled by AppManager
        // This test focuses on group creation and app installation notification
        println!("Group created successfully with app installation");

        println!("✅ Complete app integration flow test passed!");
        println!("   - Group created: {:?}", create_result.group_id);
        println!("   - App installed: {:?}", dgo_app.app_id);
    }

    #[tokio::test]
    async fn test_multiple_apps_in_group() {
        let group_manager = create_test_group_manager().await;
        let mut rng = rand::thread_rng();
        let alice_keypair = KeyPair::generate(&mut rng);

        // Create a group with multiple DGO apps (different channels)
        let dgo_app1 = default_dgo_app();
        let mut dgo_app2 = default_dgo_app();
        dgo_app2.app_tag = vec![2, 2, 2, 2]; // Different channel

        let create_group = CreateGroupBuilder::new("Multi-App Group".to_string())
            .description("A group with multiple apps".to_string())
            .group_settings(GroupSettings::default())
            .add_installed_app(dgo_app1.clone())
            .add_installed_app(dgo_app2.clone());

        let create_result = group_manager
            .create_group(create_group, &alice_keypair)
            .await
            .expect("Failed to create group");

        // Verify both apps were installed
        let group_session = group_manager
            .group_session(&create_result.group_id)
            .await
            .expect("Group session should exist");

        assert_eq!(group_session.state.group_info.installed_apps.len(), 2);

        // Note: Executor functionality is now handled by AppManager
        // This test focuses on multiple app installation in groups
        println!("Multiple apps installed successfully");

        println!("✅ Multiple apps integration test passed!");
        println!(
            "   - Apps installed: {}",
            group_session.state.group_info.installed_apps.len()
        );
        println!("   - Executors: Handled by AppManager");
    }

    #[tokio::test]
    async fn test_init_app_manager() {
        use crate::app_manager::AppManager;

        // Test the decoupled architecture with AppManager
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
        let group_manager = create_test_group_manager().await;
        let group_manager = Arc::new(group_manager);

        // Create AppManager with GroupManager as group service
        let store = crate::execution::InMemoryStore::new();
        let _app_manager =
            AppManager::new(message_manager.clone(), group_manager.clone(), store).await;

    }
}
