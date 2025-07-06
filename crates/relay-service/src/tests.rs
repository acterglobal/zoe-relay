#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::config::RelayConfig;
    use crate::error::Result;
    use crate::service::RelayService;
    use crate::storage::{MessageFilters, RedisStorage, Storage};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use testcontainers::{clients::Cli, Container, GenericImage};
    use tokio::time::{sleep, Duration};
    use zoeyr_wire_protocol::{
        ed25519_dalek::{SigningKey, VerifyingKey},
        Kind, Message, MessageFull, StoreKey, Tag,
    };
    use rand::rngs::OsRng;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestContent {
        text: String,
        value: u32,
        timestamp: u64,
    }

    /// Test helper to create a test message
    fn create_test_message(content: TestContent) -> Result<MessageFull<TestContent>> {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
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
        
        MessageFull::new(message, &signing_key)
    }

    /// Test helper to create a Redis container
    async fn create_redis_container() -> Result<(Container<'static, GenericImage>, String)> {
        let docker = Cli::default();
        let redis_image = GenericImage::new("redis", "7-alpine")
            .with_exposed_port(6379);
        let redis_container = docker.run(redis_image);
        let redis_url = format!("redis://localhost:{}", redis_container.get_host_port_ipv4(6379));
        
        // Wait for Redis to be ready
        sleep(Duration::from_secs(2)).await;
        
        Ok((redis_container, redis_url))
    }

    /// Test helper to create storage with Redis container
    async fn create_test_storage(redis_url: &str) -> Result<Arc<dyn Storage>> {
        let mut config = RelayConfig::default();
        config.redis.url = redis_url.to_string();
        
        let storage = RedisStorage::new(config).await?;
        Ok(Arc::new(storage))
    }

    #[tokio::test]
    async fn test_message_storage_and_retrieval() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        // Create test message
        let content = TestContent {
            text: "Hello, World!".to_string(),
            value: 42,
            timestamp: 1234567890,
        };
        let message = create_test_message(content)?;
        
        // Store message
        storage.store_message(&message).await?;
        
        // Retrieve message
        let id = hex::encode(message.id.as_bytes());
        let retrieved = storage.get_message::<TestContent>(&id).await?;
        
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, message.id);
        assert_eq!(retrieved.message.content, message.message.content);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_message_querying() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        // Create and store multiple messages
        let messages = vec![
            create_test_message(TestContent {
                text: "Message 1".to_string(),
                value: 1,
                timestamp: 1234567890,
            })?,
            create_test_message(TestContent {
                text: "Message 2".to_string(),
                value: 2,
                timestamp: 1234567891,
            })?,
            create_test_message(TestContent {
                text: "Message 3".to_string(),
                value: 3,
                timestamp: 1234567892,
            })?,
        ];
        
        for message in &messages {
            storage.store_message(message).await?;
        }
        
        // Query messages
        let filters = MessageFilters {
            authors: None,
            kinds: None,
            tags: None,
            since: None,
            until: None,
            limit: Some(10),
        };
        
        let results = storage.query_messages(&filters, Some(10)).await?;
        assert_eq!(results.len(), 3);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_ephemeral_messages() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        // Create ephemeral message with 2-second TTL
        let content = TestContent {
            text: "Ephemeral message".to_string(),
            value: 999,
            timestamp: 1234567890,
        };
        
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        let message = Message::new_v0(
            content,
            verifying_key,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Kind::Emphemeral(Some(2)), // 2 seconds TTL
            vec![],
        );
        
        let message_full = MessageFull::new(message, &signing_key)?;
        
        // Store message
        storage.store_message(&message_full).await?;
        
        // Verify message exists
        let id = hex::encode(message_full.id.as_bytes());
        let retrieved = storage.get_message::<TestContent>(&id).await?;
        assert!(retrieved.is_some());
        
        // Wait for TTL to expire
        sleep(Duration::from_secs(3)).await;
        
        // Clean up ephemeral messages
        let cleaned = storage.cleanup_ephemeral().await?;
        assert!(cleaned > 0);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_rate_limiting() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        let client_id = "test_client_123";
        
        // First request should succeed
        let allowed = storage.check_rate_limit(client_id).await?;
        assert!(allowed);
        
        // Make many requests quickly to trigger rate limit
        for _ in 0..100 {
            storage.check_rate_limit(client_id).await?;
        }
        
        // Should be rate limited now
        let allowed = storage.check_rate_limit(client_id).await?;
        assert!(!allowed);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_user_data_storage() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        let user_id = "user123";
        let key = "profile";
        let data = r#"{"name": "John Doe", "age": 30}"#;
        
        // Store user data
        storage.store_user_data(user_id, key, data).await?;
        
        // Retrieve user data
        let retrieved = storage.get_user_data(user_id, key).await?;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);
        
        // Test non-existent data
        let not_found = storage.get_user_data(user_id, "nonexistent").await?;
        assert!(not_found.is_none());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_store_operations() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        let user_id = "user456";
        let store_key = StoreKey::PublicUserInfo;
        
        // Clear store (should not error even if empty)
        storage.clear_user_store(user_id, &store_key).await?;
        
        Ok(())
    }

    #[tokio::test]
    async fn test_message_with_tags() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        let content = TestContent {
            text: "Tagged message".to_string(),
            value: 777,
            timestamp: 1234567890,
        };
        
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        
        // Create message with various tags
        let tags = vec![
            Tag::Protected,
            Tag::User {
                id: b"user123".to_vec(),
                relays: vec!["relay1".to_string()],
            },
            Tag::Channel {
                id: b"channel456".to_vec(),
                relays: vec!["relay2".to_string()],
            },
        ];
        
        let message = Message::new_v0(
            content,
            verifying_key,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Kind::Regular,
            tags,
        );
        
        let message_full = MessageFull::new(message, &signing_key)?;
        
        // Store message
        storage.store_message(&message_full).await?;
        
        // Retrieve and verify
        let id = hex::encode(message_full.id.as_bytes());
        let retrieved = storage.get_message::<TestContent>(&id).await?;
        
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.message.tags.len(), 3);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_relay_service_integration() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        
        let mut config = RelayConfig::default();
        config.redis.url = redis_url;
        config.service.port = 0; // Use random port for testing
        
        // Create relay service
        let service = RelayService::<TestContent>::new(config).await?;
        
        // Verify service components
        assert!(service.storage().as_any().is::<RedisStorage>());
        
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::error::Result;
    use crate::storage::{MessageFilters, Storage};
    use mockall::predicate::*;
    use mockall::*;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use zoeyr_wire_protocol::{Kind, MessageFull, StoreKey, Tag};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestContent {
        text: String,
        value: u32,
    }

    mock! {
        StorageMock {}
        
        #[async_trait::async_trait]
        impl Storage for StorageMock {
            async fn store_message<T>(&self, message: &MessageFull<T>) -> Result<()>
            where
                T: Serialize + for<'de> Deserialize<'de> + Send + Sync;
            
            async fn get_message<T>(&self, id: &str) -> Result<Option<MessageFull<T>>>
            where
                T: Serialize + for<'de> Deserialize<'de> + Send + Sync;
            
            async fn query_messages<T>(
                &self,
                filters: &MessageFilters,
                limit: Option<usize>,
            ) -> Result<Vec<MessageFull<T>>>
            where
                T: Serialize + for<'de> Deserialize<'de> + Send + Sync;
            
            async fn store_user_data(&self, user_id: &str, key: &str, data: &str) -> Result<()>;
            async fn get_user_data(&self, user_id: &str, key: &str) -> Result<Option<String>>;
            async fn clear_user_store(&self, user_id: &str, store_key: &StoreKey) -> Result<()>;
            async fn check_rate_limit(&self, client_id: &str) -> Result<bool>;
            async fn cleanup_ephemeral(&self) -> Result<usize>;
        }
    }

    #[tokio::test]
    async fn test_storage_mock() {
        let mut mock = MockStorageMock::new();
        
        // Set up expectations
        mock.expect_check_rate_limit()
            .with(eq("test_client"))
            .times(1)
            .returning(|_| Ok(true));
        
        // Test the mock
        let result = mock.check_rate_limit("test_client").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_message_filters() {
        let filters = MessageFilters {
            authors: Some(vec!["author1".to_string(), "author2".to_string()]),
            kinds: Some(vec![Kind::Regular, Kind::Emphemeral(None)]),
            tags: Some(vec![Tag::Protected]),
            since: Some(1234567890),
            until: Some(1234567999),
            limit: Some(100),
        };
        
        assert_eq!(filters.authors.as_ref().unwrap().len(), 2);
        assert_eq!(filters.kinds.as_ref().unwrap().len(), 2);
        assert_eq!(filters.tags.as_ref().unwrap().len(), 1);
        assert_eq!(filters.limit, Some(100));
    }
} 