#[cfg(test)]
mod integration_tests {
    use crate::sqlite::SqliteMessageStorage;
    use crate::storage::{MessageQuery, MessageStorage, StorageConfig};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;
    use zoe_wire_protocol::{Content, Hash, Kind, Message, MessageFull, MessageV0, Tag};

    // Helper function to create a test message
    fn create_test_message(content: &str, signing_key: &SigningKey) -> MessageFull {
        let message = Message::MessageV0(MessageV0 {
            sender: signing_key.verifying_key(),
            when: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: Content::raw(content.as_bytes().to_vec()),
        });

        MessageFull::new(message, signing_key).unwrap()
    }

    // Helper function to create a test message with specific timestamp
    fn create_message_with_time(
        content: &str,
        signing_key: &SigningKey,
        timestamp: u64,
    ) -> MessageFull {
        let message = Message::MessageV0(MessageV0 {
            sender: signing_key.verifying_key(),
            when: timestamp,
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: Content::raw(content.as_bytes().to_vec()),
        });

        MessageFull::new(message, signing_key).unwrap()
    }

    // Helper function to extract timestamp from a MessageFull
    fn get_message_timestamp(message: &MessageFull) -> u64 {
        match &*message.message {
            Message::MessageV0(msg) => msg.when,
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
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();
        let message = create_test_message("Hello, world!", &signing_key);
        let message_id = message.id;

        // Store the message
        storage.store_message(&message).await.unwrap();

        // Retrieve the message
        let retrieved = storage.get_message(&message_id).await.unwrap();
        assert!(retrieved.is_some());

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, message.id);
        // Both messages should have the same author
        let original_author = match &*message.message {
            Message::MessageV0(msg) => msg.sender,
        };
        let retrieved_author = match &*retrieved.message {
            Message::MessageV0(msg) => msg.sender,
        };
        assert_eq!(retrieved_author, original_author);

        // Compare message content
        let original_content = match &*message.message {
            Message::MessageV0(msg) => &msg.content,
        };
        let retrieved_content = match &*retrieved.message {
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
        let fake_hash = Hash::from_bytes([0u8; 32]);
        let result = storage.get_message(&fake_hash).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_message() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [3u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();
        let message = create_test_message("To be deleted", &signing_key);
        let message_id = message.id;

        // Store the message
        storage.store_message(&message).await.unwrap();

        // Verify it exists
        let retrieved = storage.get_message(&message_id).await.unwrap();
        assert!(retrieved.is_some());

        // Delete the message
        let deleted = storage.delete_message(&message_id).await.unwrap();
        assert!(deleted);

        // Verify it's gone
        let retrieved = storage.get_message(&message_id).await.unwrap();
        assert!(retrieved.is_none());

        // Try to delete again
        let deleted_again = storage.delete_message(&message_id).await.unwrap();
        assert!(!deleted_again);
    }

    #[tokio::test]
    async fn test_query_messages_by_author() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [4u8; 32];
        let signing_key1 = SigningKey::generate(&mut OsRng);
        let signing_key2 = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Store messages from two different authors
        let message1 = create_test_message("Message from author 1", &signing_key1);
        let message2 = create_test_message("Another message from author 1", &signing_key1);
        let message3 = create_test_message("Message from author 2", &signing_key2);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();
        storage.store_message(&message3).await.unwrap();

        // Query messages from author 1
        let author1_messages = storage
            .get_messages_by_author(&signing_key1.verifying_key(), None)
            .await
            .unwrap();

        assert_eq!(author1_messages.len(), 2);
        for msg in &author1_messages {
            let author = match &*msg.message {
                Message::MessageV0(m) => m.sender,
            };
            assert_eq!(author, signing_key1.verifying_key());
        }

        // Query messages from author 2
        let author2_messages = storage
            .get_messages_by_author(&signing_key2.verifying_key(), Some(1))
            .await
            .unwrap();

        assert_eq!(author2_messages.len(), 1);
        let author = match &*author2_messages[0].message {
            Message::MessageV0(m) => m.sender,
        };
        assert_eq!(author, signing_key2.verifying_key());
    }

    #[tokio::test]
    async fn test_query_messages_with_timestamp_filter() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [5u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        let base_time = 1000000000u64; // Some base timestamp

        // Create messages with different timestamps
        let message1 = create_message_with_time("Old message", &signing_key, base_time);
        let message2 = create_message_with_time("Recent message", &signing_key, base_time + 1000);
        let message3 = create_message_with_time("Future message", &signing_key, base_time + 2000);

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
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Initially empty
        assert_eq!(storage.get_message_count().await.unwrap(), 0);

        // Add some messages
        let message1 = create_test_message("First message", &signing_key);
        let message2 = create_test_message("Second message", &signing_key);

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
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Add some messages
        let message1 = create_test_message("Message 1", &signing_key);
        let message2 = create_test_message("Message 2", &signing_key);

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
        let signing_key = SigningKey::generate(&mut OsRng);

        // Create storage with first key
        let storage1 = SqliteMessageStorage::new(config.clone(), &encryption_key1)
            .await
            .unwrap();
        let message = create_test_message("Encrypted message", &signing_key);
        storage1.store_message(&message).await.unwrap();
        drop(storage1);

        // Try to open with wrong key - should fail
        let result = SqliteMessageStorage::new(config.clone(), &encryption_key2).await;
        assert!(result.is_err());

        // Open with correct key - should succeed
        let storage2 = SqliteMessageStorage::new(config, &encryption_key1)
            .await
            .unwrap();
        let retrieved = storage2.get_message(&message.id).await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [11u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = std::sync::Arc::new(
            SqliteMessageStorage::new(config, &encryption_key)
                .await
                .unwrap(),
        );

        // Spawn multiple tasks that store messages concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let storage = storage.clone();
            let signing_key = signing_key.clone();

            let handle = tokio::spawn(async move {
                let message = create_test_message(&format!("Concurrent message {i}"), &signing_key);
                storage.store_message(&message).await.unwrap();
                message.id
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
        let signing_key = SigningKey::generate(&mut OsRng);
        let message1 = create_test_message("Test message 1", &signing_key);
        let message2 = create_test_message("Test message 2", &signing_key);

        // Store messages
        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();

        // Create relay keys
        let relay1_key = SigningKey::generate(&mut OsRng).verifying_key();
        let relay2_key = SigningKey::generate(&mut OsRng).verifying_key();

        // Initially, all messages should be unsynced for both relays
        let unsynced_relay1 = storage
            .get_unsynced_messages_for_relay(&relay1_key, None)
            .await
            .unwrap();
        let unsynced_relay2 = storage
            .get_unsynced_messages_for_relay(&relay2_key, None)
            .await
            .unwrap();

        assert_eq!(unsynced_relay1.len(), 2);
        assert_eq!(unsynced_relay2.len(), 2);

        // Mark message1 as synced to relay1
        storage
            .mark_message_synced(&message1.id, &relay1_key, "100")
            .await
            .unwrap();

        // Now relay1 should have only message2 as unsynced
        let unsynced_relay1 = storage
            .get_unsynced_messages_for_relay(&relay1_key, None)
            .await
            .unwrap();
        let unsynced_relay2 = storage
            .get_unsynced_messages_for_relay(&relay2_key, None)
            .await
            .unwrap();

        assert_eq!(unsynced_relay1.len(), 1);
        assert_eq!(unsynced_relay1[0].id, message2.id);
        assert_eq!(unsynced_relay2.len(), 2); // Still has both messages

        // Mark message1 as synced to relay2 as well
        storage
            .mark_message_synced(&message1.id, &relay2_key, "200")
            .await
            .unwrap();

        // Now both relays should only have message2 as unsynced
        let unsynced_relay1 = storage
            .get_unsynced_messages_for_relay(&relay1_key, None)
            .await
            .unwrap();
        let unsynced_relay2 = storage
            .get_unsynced_messages_for_relay(&relay2_key, None)
            .await
            .unwrap();

        assert_eq!(unsynced_relay1.len(), 1);
        assert_eq!(unsynced_relay2.len(), 1);
        assert_eq!(unsynced_relay1[0].id, message2.id);
        assert_eq!(unsynced_relay2[0].id, message2.id);
    }

    #[tokio::test]
    async fn test_get_message_sync_status() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [13u8; 32];
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .unwrap();

        // Create test message
        let signing_key = SigningKey::generate(&mut OsRng);
        let message = create_test_message("Test sync status message", &signing_key);
        storage.store_message(&message).await.unwrap();

        // Create relay keys
        let relay1_key = SigningKey::generate(&mut OsRng).verifying_key();
        let relay2_key = SigningKey::generate(&mut OsRng).verifying_key();

        // Initially, no sync status
        let sync_status = storage.get_message_sync_status(&message.id).await.unwrap();
        assert_eq!(sync_status.len(), 0);

        // Mark as synced to relay1 and relay2
        storage
            .mark_message_synced(&message.id, &relay1_key, "100")
            .await
            .unwrap();
        storage
            .mark_message_synced(&message.id, &relay2_key, "200")
            .await
            .unwrap();

        // Check sync status
        let mut sync_status = storage.get_message_sync_status(&message.id).await.unwrap();
        sync_status.sort_by(|a, b| a.global_stream_id.cmp(&b.global_stream_id)); // Sort for predictable testing

        assert_eq!(sync_status.len(), 2);
        assert_eq!(sync_status[0].relay_pubkey, relay1_key);
        assert_eq!(sync_status[0].global_stream_id, "100");
        assert_eq!(sync_status[1].relay_pubkey, relay2_key);
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
        let signing_key = SigningKey::generate(&mut OsRng);
        let message1 = create_test_message("Synced message 1", &signing_key);
        let message2 = create_test_message("Synced message 2", &signing_key);
        let message3 = create_test_message("Unsynced message", &signing_key);

        storage.store_message(&message1).await.unwrap();
        storage.store_message(&message2).await.unwrap();
        storage.store_message(&message3).await.unwrap();

        // Create relay key
        let relay_key = SigningKey::generate(&mut OsRng).verifying_key();

        // Initially, no messages have sync status
        let message1_status = storage.get_message_sync_status(&message1.id).await.unwrap();
        let message2_status = storage.get_message_sync_status(&message2.id).await.unwrap();
        assert_eq!(message1_status.len(), 0);
        assert_eq!(message2_status.len(), 0);

        // Mark message1 and message2 as synced (but not message3)
        storage
            .mark_message_synced(&message1.id, &relay_key, "100")
            .await
            .unwrap();
        storage
            .mark_message_synced(&message2.id, &relay_key, "200")
            .await
            .unwrap();

        // Verify sync status for individual messages
        let message1_status = storage.get_message_sync_status(&message1.id).await.unwrap();
        let message2_status = storage.get_message_sync_status(&message2.id).await.unwrap();
        let message3_status = storage.get_message_sync_status(&message3.id).await.unwrap();

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
        let signing_key = SigningKey::generate(&mut OsRng);
        let message = create_test_message("Update test message", &signing_key);
        storage.store_message(&message).await.unwrap();

        // Create relay key
        let relay_key = SigningKey::generate(&mut OsRng).verifying_key();

        // Mark as synced with initial stream ID
        storage
            .mark_message_synced(&message.id, &relay_key, "100")
            .await
            .unwrap();

        let sync_status = storage.get_message_sync_status(&message.id).await.unwrap();
        assert_eq!(sync_status.len(), 1);
        assert_eq!(sync_status[0].global_stream_id, "100");

        // Update with new stream ID (should replace, not add)
        storage
            .mark_message_synced(&message.id, &relay_key, "150")
            .await
            .unwrap();

        let sync_status = storage.get_message_sync_status(&message.id).await.unwrap();
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
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut messages = Vec::new();
        for i in 0..5 {
            let message = create_test_message(&format!("Message {i}"), &signing_key);
            storage.store_message(&message).await.unwrap();
            messages.push(message);
        }

        let relay_key = SigningKey::generate(&mut OsRng).verifying_key();

        // Test unsynced messages with limit
        let unsynced_limited = storage
            .get_unsynced_messages_for_relay(&relay_key, Some(3))
            .await
            .unwrap();
        assert_eq!(unsynced_limited.len(), 3);

        // Mark 2 messages as synced
        storage
            .mark_message_synced(&messages[0].id, &relay_key, "100")
            .await
            .unwrap();
        storage
            .mark_message_synced(&messages[1].id, &relay_key, "101")
            .await
            .unwrap();

        // Test unsynced should now have 3 messages
        let unsynced_after = storage
            .get_unsynced_messages_for_relay(&relay_key, None)
            .await
            .unwrap();
        assert_eq!(unsynced_after.len(), 3);

        // Verify sync status of marked messages
        let msg0_status = storage
            .get_message_sync_status(&messages[0].id)
            .await
            .unwrap();
        let msg1_status = storage
            .get_message_sync_status(&messages[1].id)
            .await
            .unwrap();

        assert_eq!(msg0_status.len(), 1);
        assert_eq!(msg0_status[0].global_stream_id, "100");
        assert_eq!(msg1_status.len(), 1);
        assert_eq!(msg1_status[0].global_stream_id, "101");
    }
}
