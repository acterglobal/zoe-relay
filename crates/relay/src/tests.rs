#[cfg(test)]
mod integration_tests {
    use zoeyr_message_store::{RelayConfig, RedisStorage};
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use testcontainers::{core::ContainerPort, Container, GenericImage, clients::Cli};
    use tokio::time::{sleep, Duration};
    use zoeyr_wire_protocol::{
        Kind, Message, MessageFull, Tag,
        generate_ed25519_keypair,
    };
    use anyhow::Result;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestContent {
        text: String,
        value: u32,
        timestamp: u64,
    }

    /// Test helper to create a test message
    fn create_test_message(content: TestContent) -> Result<MessageFull<TestContent>> {
        let signing_key = generate_ed25519_keypair();
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
        
        Ok(MessageFull::new(message, &signing_key)?)
    }

    /// Test helper to create a Redis container
    async fn create_redis_container() -> Result<(Container<GenericImage>, String)> {
        let docker = Cli::default();
        let redis_image = GenericImage::new("redis", "7-alpine")
            .with_exposed_port(ContainerPort::Tcp(6379));
        let redis_container = docker.run(redis_image);
        let redis_url = format!("redis://localhost:{}", redis_container.get_host_port_ipv4(6379));
        
        // Wait for Redis to be ready
        sleep(Duration::from_secs(2)).await;
        
        Ok((redis_container, redis_url))
    }

    /// Test helper to create storage with Redis container
    async fn create_test_storage(redis_url: &str) -> Result<Arc<RedisStorage>> {
        let config = RelayConfig {
            redis: zoeyr_message_store::RedisConfig {
                url: redis_url.to_string(),
                pool_size: 10,
            },
            ..Default::default()
        };
        
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
        let message = create_test_message(content.clone())?;
        
        // Store message
        storage.store_message(&message).await?;
        
        // Retrieve message
        let retrieved = storage.get_message::<TestContent>(message.id.as_bytes()).await?;
        
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, message.id);
        assert_eq!(*retrieved.content(), content);
        
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
        
        let signing_key = generate_ed25519_keypair();
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
        let retrieved = storage.get_message::<TestContent>(message_full.id.as_bytes()).await?;
        assert!(retrieved.is_some());
        
        Ok(())
    }

    #[tokio::test]
    async fn test_message_with_tags() -> Result<()> {
        let (_container, redis_url) = create_redis_container().await?;
        let storage = create_test_storage(&redis_url).await?;
        
        // Create message with tags
        let content = TestContent {
            text: "Tagged message".to_string(),
            value: 123,
            timestamp: 1234567890,
        };
        
        let signing_key = generate_ed25519_keypair();
        let verifying_key = signing_key.verifying_key();
        
        let tags = vec![
            Tag::User { 
                id: b"user123".to_vec(),
                relays: vec![]
            },
            Tag::Channel { 
                id: b"general".to_vec(),
                relays: vec![]
            },
        ];
        
        let message = Message::new_v0(
            content.clone(),
            verifying_key,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Kind::Regular,
            tags.clone(),
        );
        
        let message_full = MessageFull::new(message, &signing_key)?;
        
        // Store message
        storage.store_message(&message_full).await?;
        
        // Retrieve and verify
        let retrieved = storage.get_message::<TestContent>(message_full.id.as_bytes()).await?;
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(*retrieved.content(), content);
        assert_eq!(retrieved.tags().len(), 2);
        
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::QuicTarpcServer;
    use zoeyr_message_store::MessageFilters;
    use serde::{Deserialize, Serialize};
    use anyhow::Result;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestContent {
        text: String,
        value: u32,
    }

    #[tokio::test]
    async fn test_message_filters() {
        let filters = MessageFilters {
            authors: Some(vec![b"author1".to_vec(), b"author2".to_vec()]),
            channels: Some(vec![b"general".to_vec()]),
            events: Some(vec![b"event123".to_vec()]),
            users: Some(vec![b"user456".to_vec()]),
        };
        
        assert_eq!(filters.authors.as_ref().unwrap().len(), 2);
        assert_eq!(filters.channels.as_ref().unwrap().len(), 1);
        assert_eq!(filters.events.as_ref().unwrap().len(), 1);
        assert_eq!(filters.users.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_quic_tarpc_server_creation() -> Result<()> {
        use zoeyr_wire_protocol::generate_ed25519_keypair;
        use std::net::SocketAddr;
        
        let addr: SocketAddr = "127.0.0.1:0".parse()?;
        let server_key = generate_ed25519_keypair();
        
        // Create a mock service for testing
        #[derive(Clone)]
        struct MockService;
        
        impl tarpc::server::Serve for MockService {
            type Req = ();
            type Resp = ();
            
            async fn serve(
                self,
                _ctx: tarpc::context::Context,
                _req: Self::Req,
            ) -> Result<Self::Resp, tarpc::ServerError> {
                Ok(())
            }
        }
        
        let _server = QuicTarpcServer::new(addr, server_key, MockService);
        
        Ok(())
    }
} 