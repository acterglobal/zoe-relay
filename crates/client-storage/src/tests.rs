#[cfg(test)]
mod integration_tests {
    use crate::storage::{MessageQuery, MessageStorage, StorageConfig};
    use crate::sqlite::SqliteMessageStorage;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;
    use zoe_wire_protocol::{Hash, Kind, Message, MessageV0, MessageFull, Tag, Content};

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
    fn create_message_with_time(content: &str, signing_key: &SigningKey, timestamp: u64) -> MessageFull {
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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();
        
        assert!(storage.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn test_store_and_retrieve_message() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [1u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();
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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();
        
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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();
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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();

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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();

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
        assert_eq!(get_message_timestamp(&filtered_messages[0]), base_time + 1000);
    }

    #[tokio::test]
    async fn test_message_count_and_stats() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [6u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();

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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();

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

        let storage = SqliteMessageStorage::new(config, &encryption_key).await.unwrap();

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
        let storage1 = SqliteMessageStorage::new(config.clone(), &encryption_key1).await.unwrap();
        let message = create_test_message("Encrypted message", &signing_key);
        storage1.store_message(&message).await.unwrap();
        drop(storage1);

        // Try to open with wrong key - should fail
        let result = SqliteMessageStorage::new(config.clone(), &encryption_key2).await;
        assert!(result.is_err());

        // Open with correct key - should succeed
        let storage2 = SqliteMessageStorage::new(config, &encryption_key1).await.unwrap();
        let retrieved = storage2.get_message(&message.id).await.unwrap();
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_concurrent_access() {
        let (config, _temp_dir) = create_test_storage_config();
        let encryption_key = [11u8; 32];
        let signing_key = SigningKey::generate(&mut OsRng);

        let storage = std::sync::Arc::new(
            SqliteMessageStorage::new(config, &encryption_key).await.unwrap()
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
}