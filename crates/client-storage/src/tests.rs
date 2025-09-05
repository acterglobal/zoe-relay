#[cfg(test)]
mod integration_tests {
    use crate::sqlite::SqliteMessageStorage;
    use crate::storage::{MessageQuery, MessageStorage, StateNamespace, StorageConfig};
    use rand::rngs::OsRng;
    use tempfile::TempDir;
    use zoe_wire_protocol::{
        Content, KeyId, KeyPair, Kind, Message, MessageFull, MessageId, MessageV0, MessageV0Header,
        Tag,
    };

    // Helper function to create a test message
    fn create_test_message(content: &str, keypair: &KeyPair) -> MessageFull {
        let message = Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender: keypair.public_key(),
                when: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                kind: Kind::Regular,
                tags: vec![Tag::Protected],
            },
            content: Content::raw(content.as_bytes().to_vec()),
        });

        MessageFull::new(message, keypair).unwrap()
    }

    // Helper function to create a test message with specific timestamp
    fn create_message_with_time(content: &str, keypair: &KeyPair, timestamp: u64) -> MessageFull {
        let message = Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender: keypair.public_key(),
                when: timestamp,
                kind: Kind::Regular,
                tags: vec![Tag::Protected],
            },
            content: Content::raw(content.as_bytes().to_vec()),
        });

        MessageFull::new(message, keypair).unwrap()
    }

    // Helper function to extract timestamp from a MessageFull
    fn get_message_timestamp(message: &MessageFull) -> u64 {
        match message.message() {
            Message::MessageV0(msg) => msg.header.when,
        }
    }

    fn create_test_storage_config() -> (StorageConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig {
            database_path: temp_dir.path().join("test.db"),
            max_query_limit: Some(100),
            enable_wal_mode: false, // Disable WAL for tests to avoid file locking issues
            cache_size_kb: Some(1024),
        };
        (config, temp_dir)
    }

    #[tokio::test]
    async fn test_storage_creation_and_health_check() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [0u8; 32];

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        assert!(storage.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_store_and_retrieve_message() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [1u8; 32];
        let keypair = KeyPair::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();
        let message = create_test_message("Hello, world!", &keypair);
        let message_id = message.id();

        // Store the message
        storage.store_message(&message).await.unwrap();

        // Retrieve the message
        let retrieved = storage.get_message(message_id).await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id(), message.id());
        // Both messages should have the same author
        let original_author = match message.message() {
            Message::MessageV0(msg) => msg.header.sender.clone(),
        };
        let retrieved_author = match retrieved.message() {
            Message::MessageV0(msg) => msg.header.sender.clone(),
        };
        assert_eq!(retrieved_author, original_author);

        // Compare message content
        let original_content = match message.message() {
            Message::MessageV0(msg) => &msg.content,
        };
        let retrieved_content = match retrieved.message() {
            Message::MessageV0(msg) => &msg.content,
        };
        assert_eq!(original_content, retrieved_content);
    }

    #[tokio::test]
    async fn test_message_not_found() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [2u8; 32];

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Try to retrieve a non-existent message
        let fake_message_id = MessageId::from_bytes([0u8; 32]);
        let result = storage.get_message(&fake_message_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_message() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [3u8; 32];
        let keypair = KeyPair::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();
        let message = create_test_message("To be deleted", &keypair);
        let message_id = message.id();

        // Store the message
        storage.store_message(&message).await.unwrap();

        // Verify it exists
        let retrieved = storage.get_message(message_id).await.unwrap();
        assert!(retrieved.is_some());

        // Delete the message
        let deleted = storage.delete_message(message_id).await.unwrap();
        assert!(deleted);

        // Verify it's gone
        let retrieved = storage.get_message(message_id).await.unwrap();
        assert!(retrieved.is_none());

        // Try to delete again
        let deleted_again = storage.delete_message(message_id).await.unwrap();
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn test_query_messages_by_author() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [4u8; 32];
        let keypair1 = KeyPair::generate(&mut OsRng);
        let keypair2 = KeyPair::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Store messages from two different authors
        let message1 = create_test_message("Message from author 1", &keypair1);
        let message2 = create_test_message("Another message from author 1", &keypair1);
        let message3 = create_test_message("Message from author 2", &keypair2);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();
        storage.store_message(&message3).await.unwrap();

        // Query messages from author 1
        let author1_messages = storage
            .get_messages_by_author(&keypair1.public_key(), None)
            .await
            .unwrap();

        assert_eq!(author1_messages.len(), 2);
        for msg in &author1_messages {
            let author = match msg.message() {
                Message::MessageV0(m) => m.header.sender.clone(),
            };
            assert_eq!(author, keypair1.public_key());
        }

        // Query messages from author 2
        let author2_messages = storage
            .get_messages_by_author(&keypair2.public_key(), Some(1))
            .await
            .unwrap();

        assert_eq!(author2_messages.len(), 1);
        let author = match author2_messages[0].message() {
            Message::MessageV0(m) => m.header.sender.clone(),
        };
        assert_eq!(author, keypair2.public_key());
    }

    #[tokio::test]
    async fn test_query_messages_with_timestamp_filter() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [5u8; 32];
        let keypair = KeyPair::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        let base_time = 1000000000u64; // Some base timestamp

        // Create messages with different timestamps
        let message1 = create_message_with_time("Old message", &keypair, base_time);
        let message2 = create_message_with_time("Recent message", &keypair, base_time + 1000);
        let message3 = create_message_with_time("Future message", &keypair, base_time + 2000);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();
        storage.store_message(&message3).await.unwrap();

        // Query messages since base_time + 500
        let recent_messages = storage
            .get_messages_since(base_time + 500, None)
            .await
            .unwrap();

        assert_eq!(recent_messages.len(), 2);
        for msg in &recent_messages {
            assert!(get_message_timestamp(msg) >= base_time + 500);
        }

        // Query with specific time range
        let query = MessageQuery {
            after_timestamp: Some(base_time + 500),
            before_timestamp: Some(base_time + 1500),
            limit: Some(10),
            ..Default::default()
        };

        let filtered_messages = storage.query_messages(&query).await.unwrap();
        assert_eq!(filtered_messages.len(), 1);
        assert_eq!(
            get_message_timestamp(&filtered_messages[0]),
            base_time + 1000
        );
    }

    #[tokio::test]
    async fn test_message_count_and_stats() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [6u8; 32];
        let keypair = KeyPair::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Initially empty
        assert_eq!(storage.get_message_count().await.unwrap(), 0);

        // Add some messages
        let message1 = create_test_message("First message", &keypair);
        let message2 = create_test_message("Second message", &keypair);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();

        // Check count
        assert_eq!(storage.get_message_count().await.unwrap(), 2);

        // Check stats
        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.message_count, 2);
        assert_eq!(stats.unique_authors, 1);
        assert!(stats.storage_size_bytes > 0);
        assert!(stats.oldest_message_timestamp.is_some());
        assert!(stats.newest_message_timestamp.is_some());
        assert!(stats.newest_message_timestamp >= stats.oldest_message_timestamp);
    }

    #[tokio::test]
    async fn test_clear_all_messages() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [7u8; 32];
        let keypair = KeyPair::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Add some messages
        let message1 = create_test_message("Message 1", &keypair);
        let message2 = create_test_message("Message 2", &keypair);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();

        assert_eq!(storage.get_message_count().await.unwrap(), 2);

        // Clear all messages
        storage.clear_all_messages().await.unwrap();

        assert_eq!(storage.get_message_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_maintenance() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [8u8; 32];

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Maintenance should complete successfully
        storage.maintenance().await.unwrap();
    }

    #[tokio::test]
    async fn test_encryption_key_verification() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key1 = [9u8; 32];
        let encryption_key2 = [10u8; 32];
        let keypair = KeyPair::generate(&mut OsRng);

        // Create storage with first key
        let storage1 = SqliteMessageStorage::new(config.clone(), &encryption_key1)
            .await
            .unwrap();
        let message = create_test_message("Encrypted message", &keypair);
        storage1.store_message(&message).await.unwrap();
        drop(storage1);

        // Try to open with wrong key - should fail
        let result = SqliteMessageStorage::new(config.clone(), &encryption_key2).await;
        assert!(result.is_err());

        // Open with correct key - should succeed
        let storage2 = SqliteMessageStorage::new(config, &encryption_key1)
            .await
            .unwrap();
        let retrieved = storage2.get_message(message.id()).await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [11u8; 32];
        let _signing_key = KeyPair::generate_ml_dsa65(&mut OsRng);

        let storage = std::sync::Arc::new(
            SqliteMessageStorage::new(config, &encryption_key)
                .await
                .unwrap(),
        );

        // Spawn multiple tasks that store messages concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let storage = storage.clone();
            // Generate a new keypair for each task since KeyPair doesn't implement Clone
            let keypair = KeyPair::generate(&mut OsRng);

            let handle = tokio::spawn(async move {
                let message = create_test_message(&format!("Concurrent message {i}"), &keypair);
                storage.store_message(&message).await.unwrap();
                *message.id()
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        let mut message_ids = Vec::new();
        for handle in handles {
            let id = handle.await.unwrap();
            message_ids.push(id);
        }

        // Verify all messages were stored
        assert_eq!(storage.get_message_count().await.unwrap(), 10);

        // Verify we can retrieve all messages
        for id in message_ids {
            let message = storage.get_message(&id).await.unwrap();
            assert!(message.is_some());
        }
    }

    #[tokio::test]
    async fn test_message_sync_tracking_basic() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [12u8; 32];
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Create test messages
        let keypair = KeyPair::generate(&mut OsRng);
        let message1 = create_test_message("Test message 1", &keypair);
        let message2 = create_test_message("Test message 2", &keypair);

        // Store messages
        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();

        // Create relay keys and their IDs
        let relay1_key = KeyPair::generate(&mut OsRng).public_key();
        let relay2_key = KeyPair::generate(&mut OsRng).public_key();
        let relay1_id: KeyId = relay1_key.id();
        let relay2_id: KeyId = relay2_key.id();

        // Initially, all messages should be unsynced for both relays
        let unsynced_relay1 = storage
            .get_unsynced_messages_for_relay(&relay1_id, None)
            .await
            .unwrap();
        let unsynced_relay2 = storage
            .get_unsynced_messages_for_relay(&relay2_id, None)
            .await
            .unwrap();

        assert_eq!(unsynced_relay1.len(), 2);
        assert_eq!(unsynced_relay2.len(), 2);

        // Mark message1 as synced to relay1
        storage
            .mark_message_synced(message1.id(), &relay1_id, "100")
            .await
            .unwrap();

        // Now relay1 should have only message2 as unsynced
        let unsynced_relay1 = storage
            .get_unsynced_messages_for_relay(&relay1_id, None)
            .await
            .unwrap();
        let unsynced_relay2 = storage
            .get_unsynced_messages_for_relay(&relay2_id, None)
            .await
            .unwrap();

        assert_eq!(unsynced_relay1.len(), 1);
        assert_eq!(unsynced_relay1[0].id(), message2.id());
        assert_eq!(unsynced_relay2.len(), 2); // Still has both messages

        // Mark message1 as synced to relay2 as well
        storage
            .mark_message_synced(message1.id(), &relay2_id, "200")
            .await
            .unwrap();

        // Now both relays should only have message2 as unsynced
        let unsynced_relay1 = storage
            .get_unsynced_messages_for_relay(&relay1_id, None)
            .await
            .unwrap();
        let unsynced_relay2 = storage
            .get_unsynced_messages_for_relay(&relay2_id, None)
            .await
            .unwrap();

        assert_eq!(unsynced_relay1.len(), 1);
        assert_eq!(unsynced_relay2.len(), 1);
        assert_eq!(unsynced_relay1[0].id(), message2.id());
        assert_eq!(unsynced_relay2[0].id(), message2.id());
    }

    #[tokio::test]
    async fn test_get_message_sync_status() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [13u8; 32];
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Create test message
        let keypair = KeyPair::generate(&mut OsRng);
        let message = create_test_message("Test sync status message", &keypair);
        storage.store_message(&message).await.unwrap();

        // Create relay keys and their IDs
        let relay1_key = KeyPair::generate(&mut OsRng).public_key();
        let relay2_key = KeyPair::generate(&mut OsRng).public_key();
        let relay1_id: KeyId = relay1_key.id();
        let relay2_id: KeyId = relay2_key.id();

        // Initially, no sync status
        let sync_status = storage.get_message_sync_status(message.id()).await.unwrap();
        assert_eq!(sync_status.len(), 0);

        // Mark as synced to relay1 and relay2
        storage
            .mark_message_synced(message.id(), &relay1_id, "100")
            .await
            .unwrap();
        storage
            .mark_message_synced(message.id(), &relay2_id, "200")
            .await
            .unwrap();

        // Check sync status
        let mut sync_status = storage.get_message_sync_status(message.id()).await.unwrap();
        sync_status.sort_by(|a, b| a.global_stream_id.cmp(&b.global_stream_id)); // Sort for predictable testing

        assert_eq!(sync_status.len(), 2);
        assert_eq!(sync_status[0].relay_id, relay1_id);
        assert_eq!(sync_status[0].global_stream_id, "100");
        assert_eq!(sync_status[1].relay_id, relay2_id);
        assert_eq!(sync_status[1].global_stream_id, "200");
    }

    #[tokio::test]
    async fn test_individual_message_sync_verification() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [14u8; 32];
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Create test messages
        let keypair = KeyPair::generate(&mut OsRng);
        let message1 = create_test_message("Synced message 1", &keypair);
        let message2 = create_test_message("Synced message 2", &keypair);
        let message3 = create_test_message("Unsynced message", &keypair);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();
        storage.store_message(&message3).await.unwrap();

        // Create relay key
        let relay_key = KeyPair::generate(&mut OsRng).public_key();
        let relay_id: KeyId = relay_key.id();

        // Initially, no messages have sync status
        let message1_status = storage
            .get_message_sync_status(message1.id())
            .await
            .unwrap();
        let message2_status = storage
            .get_message_sync_status(message2.id())
            .await
            .unwrap();
        assert_eq!(message1_status.len(), 0);
        assert_eq!(message2_status.len(), 0);

        // Mark message1 and message2 as synced (but not message3)
        storage
            .mark_message_synced(message1.id(), &relay_id, "100")
            .await
            .unwrap();
        storage
            .mark_message_synced(message2.id(), &relay_id, "200")
            .await
            .unwrap();

        // Verify sync status for individual messages
        let message1_status = storage
            .get_message_sync_status(message1.id())
            .await
            .unwrap();
        let message2_status = storage
            .get_message_sync_status(message2.id())
            .await
            .unwrap();
        let message3_status = storage
            .get_message_sync_status(message3.id())
            .await
            .unwrap();

        assert_eq!(message1_status.len(), 1);
        assert_eq!(message1_status[0].global_stream_id, "100");
        assert_eq!(message2_status.len(), 1);
        assert_eq!(message2_status[0].global_stream_id, "200");
        assert_eq!(message3_status.len(), 0); // Should not be synced
    }

    #[tokio::test]
    async fn test_sync_status_update_replace() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [15u8; 32];
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Create test message
        let keypair = KeyPair::generate(&mut OsRng);
        let message = create_test_message("Update test message", &keypair);
        storage.store_message(&message).await.unwrap();

        // Create relay key
        let relay_key = KeyPair::generate(&mut OsRng).public_key();
        let relay_id: KeyId = relay_key.id();

        // Mark as synced with initial stream ID
        storage
            .mark_message_synced(message.id(), &relay_id, "100")
            .await
            .unwrap();

        let sync_status = storage.get_message_sync_status(message.id()).await.unwrap();
        assert_eq!(sync_status.len(), 1);
        assert_eq!(sync_status[0].global_stream_id, "100");

        // Update with new stream ID (should replace, not add)
        storage
            .mark_message_synced(message.id(), &relay_id, "150")
            .await
            .unwrap();

        let sync_status = storage.get_message_sync_status(message.id()).await.unwrap();
        assert_eq!(sync_status.len(), 1);
        assert_eq!(sync_status[0].global_stream_id, "150");
    }

    #[tokio::test]
    async fn test_sync_with_limit() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [16u8; 32];
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Create multiple test messages
        let keypair = KeyPair::generate(&mut OsRng);
        let mut messages = Vec::new();
        for i in 0..5 {
            let message = create_test_message(&format!("Message {i}"), &keypair);
            storage.store_message(&message).await.unwrap();
            messages.push(message);
        }

        let relay_key = KeyPair::generate(&mut OsRng).public_key();
        let relay_id: KeyId = relay_key.id();

        // Test unsynced messages with limit
        let unsynced_limited = storage
            .get_unsynced_messages_for_relay(&relay_id, Some(3))
            .await
            .unwrap();
        assert_eq!(unsynced_limited.len(), 3);

        // Mark 2 messages as synced
        storage
            .mark_message_synced(messages[0].id(), &relay_id, "100")
            .await
            .unwrap();
        storage
            .mark_message_synced(messages[1].id(), &relay_id, "101")
            .await
            .unwrap();

        // Test unsynced should now have 3 messages
        let unsynced_after = storage
            .get_unsynced_messages_for_relay(&relay_id, None)
            .await
            .unwrap();
        assert_eq!(unsynced_after.len(), 3);

        // Verify sync status of marked messages
        let msg0_status = storage
            .get_message_sync_status(messages[0].id())
            .await
            .unwrap();
        let msg1_status = storage
            .get_message_sync_status(messages[1].id())
            .await
            .unwrap();

        assert_eq!(msg0_status.len(), 1);
        assert_eq!(msg0_status[0].global_stream_id, "100");
        assert_eq!(msg1_status.len(), 1);
        assert_eq!(msg1_status[0].global_stream_id, "101");
    }

    // ============================================================================
    // STATE STORAGE TESTS
    // ============================================================================

    mod state_storage_tests {
        use super::*;
        use crate::storage::StateStorage;
        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct TestState {
            counter: u64,
            name: String,
            active: bool,
        }

        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct ComplexState {
            data: std::collections::BTreeMap<String, Vec<u8>>,
            timestamp: u64,
            nested: Option<TestState>,
        }

        async fn create_test_storage() -> SqliteMessageStorage {
            let temp_dir = TempDir::new().unwrap();
            let config = StorageConfig {
                database_path: temp_dir.path().join("test_state.db"),
                ..Default::default()
            };

            let encryption_key = [42u8; 32];
            SqliteMessageStorage::new(config, &encryption_key)
                .await
                .unwrap()
        }

        #[tokio::test]
        async fn test_store_and_get() {
            let storage = create_test_storage().await;

            let test_state = TestState {
                counter: 42,
                name: "test".to_string(),
                active: true,
            };

            // Store state
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"test_key",
                    &test_state,
                )
                .await
                .unwrap();

            // Retrieve state
            let retrieved: Option<TestState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"test_key")
                .await
                .unwrap();

            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap(), test_state);
        }

        #[tokio::test]
        async fn test_get_nonexistent_state() {
            let storage = create_test_storage().await;

            let retrieved: Option<TestState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"nonexistent")
                .await
                .unwrap();

            assert!(retrieved.is_none());
        }

        #[tokio::test]
        async fn test_overwrite_state() {
            let storage = create_test_storage().await;

            let state1 = TestState {
                counter: 1,
                name: "first".to_string(),
                active: true,
            };

            let state2 = TestState {
                counter: 2,
                name: "second".to_string(),
                active: false,
            };

            // Store first state
            storage
                .store(&StateNamespace::Custom(b"test".to_vec()), b"key", &state1)
                .await
                .unwrap();

            // Overwrite with second state
            storage
                .store(&StateNamespace::Custom(b"test".to_vec()), b"key", &state2)
                .await
                .unwrap();

            // Retrieve should return second state
            let retrieved: Option<TestState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"key")
                .await
                .unwrap();
            assert_eq!(retrieved.unwrap(), state2);
        }

        #[tokio::test]
        async fn test_delete() {
            let storage = create_test_storage().await;

            let test_state = TestState {
                counter: 100,
                name: "delete_me".to_string(),
                active: true,
            };

            // Store state
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"delete_key",
                    &test_state,
                )
                .await
                .unwrap();

            // Verify it exists
            let exists = storage
                .has(&StateNamespace::Custom(b"test".to_vec()), b"delete_key")
                .await
                .unwrap();
            assert!(exists);

            // Delete state
            let deleted = storage
                .delete(&StateNamespace::Custom(b"test".to_vec()), b"delete_key")
                .await
                .unwrap();
            assert!(deleted);

            // Verify it's gone
            let exists = storage
                .has(&StateNamespace::Custom(b"test".to_vec()), b"delete_key")
                .await
                .unwrap();
            assert!(!exists);

            let retrieved: Option<TestState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"delete_key")
                .await
                .unwrap();
            assert!(retrieved.is_none());
        }

        #[tokio::test]
        async fn test_delete_nonexistent_state() {
            let storage = create_test_storage().await;

            let deleted = storage
                .delete(&StateNamespace::Custom(b"test".to_vec()), b"nonexistent")
                .await
                .unwrap();
            assert!(!deleted);
        }

        #[tokio::test]
        async fn test_has() {
            let storage = create_test_storage().await;

            let test_state = TestState {
                counter: 50,
                name: "exists".to_string(),
                active: false,
            };

            // Initially doesn't exist
            let exists = storage
                .has(&StateNamespace::Custom(b"test".to_vec()), b"exists_key")
                .await
                .unwrap();
            assert!(!exists);

            // Store state
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"exists_key",
                    &test_state,
                )
                .await
                .unwrap();

            // Now it exists
            let exists = storage
                .has(&StateNamespace::Custom(b"test".to_vec()), b"exists_key")
                .await
                .unwrap();
            assert!(exists);
        }

        #[tokio::test]
        async fn test_list_keys() {
            let storage = create_test_storage().await;

            let state1 = TestState {
                counter: 1,
                name: "one".to_string(),
                active: true,
            };

            let state2 = TestState {
                counter: 2,
                name: "two".to_string(),
                active: false,
            };

            // Initially empty
            let keys = storage.list_keys().await.unwrap();
            assert!(keys.is_empty());

            // Store some states
            storage
                .store(&StateNamespace::Custom(b"test".to_vec()), b"key_b", &state1)
                .await
                .unwrap();
            storage
                .store(&StateNamespace::Custom(b"test".to_vec()), b"key_a", &state2)
                .await
                .unwrap();
            storage
                .store(&StateNamespace::Custom(b"test".to_vec()), b"key_c", &state1)
                .await
                .unwrap();

            // List keys (should be sorted)
            let keys = storage.list_keys().await.unwrap();
            assert_eq!(
                keys,
                vec![b"key_a".to_vec(), b"key_b".to_vec(), b"key_c".to_vec()]
            );
        }

        #[tokio::test]
        async fn test_count() {
            let storage = create_test_storage().await;

            let test_state = TestState {
                counter: 0,
                name: "counter".to_string(),
                active: true,
            };

            // Initially zero
            let count = storage.count().await.unwrap();
            assert_eq!(count, 0);

            // Add some states
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"count1",
                    &test_state,
                )
                .await
                .unwrap();
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"count2",
                    &test_state,
                )
                .await
                .unwrap();
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"count3",
                    &test_state,
                )
                .await
                .unwrap();

            let count = storage.count().await.unwrap();
            assert_eq!(count, 3);

            // Delete one
            storage
                .delete(&StateNamespace::Custom(b"test".to_vec()), b"count2")
                .await
                .unwrap();

            let count = storage.count().await.unwrap();
            assert_eq!(count, 2);
        }

        #[tokio::test]
        async fn test_clear() {
            let storage = create_test_storage().await;

            let test_state = TestState {
                counter: 999,
                name: "clear_test".to_string(),
                active: true,
            };

            // Add multiple states
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"clear1",
                    &test_state,
                )
                .await
                .unwrap();
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"clear2",
                    &test_state,
                )
                .await
                .unwrap();
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"clear3",
                    &test_state,
                )
                .await
                .unwrap();

            // Verify they exist
            let count = storage.count().await.unwrap();
            assert_eq!(count, 3);

            // Clear all
            storage.clear().await.unwrap();

            // Verify all gone
            let count = storage.count().await.unwrap();
            assert_eq!(count, 0);

            let keys = storage.list_keys().await.unwrap();
            assert!(keys.is_empty());
        }

        #[tokio::test]
        async fn test_complex_state_serialization() {
            let storage = create_test_storage().await;

            let mut data = std::collections::BTreeMap::new();
            data.insert("key1".to_string(), vec![1, 2, 3, 4]);
            data.insert("key2".to_string(), vec![255, 0, 128]);

            let complex_state = ComplexState {
                data,
                timestamp: 1234567890,
                nested: Some(TestState {
                    counter: 42,
                    name: "nested".to_string(),
                    active: false,
                }),
            };

            // Store complex state
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"complex",
                    &complex_state,
                )
                .await
                .unwrap();

            // Retrieve and verify
            let retrieved: Option<ComplexState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"complex")
                .await
                .unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap(), complex_state);
        }

        #[tokio::test]
        async fn test_different_types_same_key() {
            let storage = create_test_storage().await;

            // Store a TestState
            let test_state = TestState {
                counter: 123,
                name: "type_test".to_string(),
                active: true,
            };
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"same_key",
                    &test_state,
                )
                .await
                .unwrap();

            // Try to retrieve as wrong type - should fail
            let wrong_type: Result<Option<ComplexState>, _> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"same_key")
                .await;
            assert!(wrong_type.is_err());

            // Retrieve as correct type - should work
            let correct_type: Option<TestState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"same_key")
                .await
                .unwrap();
            assert_eq!(correct_type.unwrap(), test_state);
        }

        #[tokio::test]
        async fn test_empty_and_special_keys() {
            let storage = create_test_storage().await;

            let test_state = TestState {
                counter: 1,
                name: "special".to_string(),
                active: true,
            };

            // Test various key formats
            let special_keys = vec![
                b"".as_slice(),                       // Empty key
                b" ".as_slice(),                      // Space
                b"key with spaces".as_slice(),        // Spaces in key
                b"key-with-dashes".as_slice(),        // Dashes
                b"key_with_underscores".as_slice(),   // Underscores
                b"key.with.dots".as_slice(),          // Dots
                b"key/with/slashes".as_slice(),       // Slashes
                b"key\\with\\backslashes".as_slice(), // Backslashes
                "🚀emoji_key".as_bytes(),             // Unicode
                b"very_long_key_name_that_goes_on_and_on_and_on_to_test_length_limits".as_slice(), // Long key
            ];

            for key in special_keys {
                storage
                    .store(&StateNamespace::Custom(b"test".to_vec()), key, &test_state)
                    .await
                    .unwrap();
                let retrieved: Option<TestState> = storage
                    .get(&StateNamespace::Custom(b"test".to_vec()), key)
                    .await
                    .unwrap();
                assert_eq!(retrieved.unwrap(), test_state);
            }
        }

        #[tokio::test]
        async fn test_large_state_data() {
            let storage = create_test_storage().await;

            // Create a large state with lots of data
            let mut large_data = std::collections::BTreeMap::new();
            for i in 0..1000 {
                large_data.insert(format!("key_{}", i), vec![i as u8; 100]);
            }

            let large_state = ComplexState {
                data: large_data,
                timestamp: 9876543210,
                nested: Some(TestState {
                    counter: u64::MAX,
                    name: "x".repeat(1000), // Large string
                    active: true,
                }),
            };

            // Store and retrieve large state
            storage
                .store(
                    &StateNamespace::Custom(b"test".to_vec()),
                    b"large",
                    &large_state,
                )
                .await
                .unwrap();

            let retrieved: Option<ComplexState> = storage
                .get(&StateNamespace::Custom(b"test".to_vec()), b"large")
                .await
                .unwrap();
            assert!(retrieved.is_some());
            assert_eq!(retrieved.unwrap(), large_state);
        }

        #[tokio::test]
        async fn test_concurrent_state_operations() {
            let storage = std::sync::Arc::new(create_test_storage().await);

            let _test_state = TestState {
                counter: 0,
                name: "concurrent".to_string(),
                active: true,
            };

            // Spawn multiple tasks that store state concurrently
            let mut handles = vec![];
            for i in 0..10 {
                let storage_clone = storage.clone();
                let state = TestState {
                    counter: i,
                    name: format!("concurrent_{}", i),
                    active: i % 2 == 0,
                };

                let handle = tokio::spawn(async move {
                    storage_clone
                        .store(
                            &StateNamespace::Custom(b"test".to_vec()),
                            format!("concurrent_{}", i).as_bytes(),
                            &state,
                        )
                        .await
                        .unwrap();
                });
                handles.push(handle);
            }

            // Wait for all tasks to complete
            for handle in handles {
                handle.await.unwrap();
            }

            // Verify all states were stored
            let count = storage.count().await.unwrap();
            assert_eq!(count, 10);

            // Verify we can retrieve all states
            for i in 0..10 {
                let retrieved: Option<TestState> = storage
                    .get(
                        &StateNamespace::Custom(b"test".to_vec()),
                        format!("concurrent_{}", i).as_bytes(),
                    )
                    .await
                    .unwrap();
                assert!(retrieved.is_some());
                assert_eq!(retrieved.unwrap().counter, i);
            }
        }

        #[tokio::test]
        async fn test_state_persistence_across_connections() {
            let temp_dir = TempDir::new().unwrap();
            let db_path = temp_dir.path().join("persistence_test.db");
            let encryption_key = [123u8; 32];

            let test_state = TestState {
                counter: 777,
                name: "persistent".to_string(),
                active: true,
            };

            // Create first storage instance and store data
            {
                let config = StorageConfig {
                    database_path: db_path.clone(),
                    ..Default::default()
                };
                let storage = SqliteMessageStorage::new(config, &encryption_key)
                    .await
                    .unwrap();

                storage
                    .store(
                        &StateNamespace::Custom(b"test".to_vec()),
                        b"persist_key",
                        &test_state,
                    )
                    .await
                    .unwrap();
            } // Storage instance goes out of scope

            // Create second storage instance and verify data persists
            {
                let config = StorageConfig {
                    database_path: db_path,
                    ..Default::default()
                };
                let storage = SqliteMessageStorage::new(config, &encryption_key)
                    .await
                    .unwrap();

                let retrieved: Option<TestState> = storage
                    .get(&StateNamespace::Custom(b"test".to_vec()), b"persist_key")
                    .await
                    .unwrap();
                assert!(retrieved.is_some());
                assert_eq!(retrieved.unwrap(), test_state);
            }
        }
    }
}
