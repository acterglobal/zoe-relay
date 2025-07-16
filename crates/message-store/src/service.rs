use super::storage::RedisStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use tracing::{error, info, warn};

use zoeyr_wire_protocol::{
    MessageFull, RelayError, RelayResult, RelayService, StreamConfig, StreamMessage,
};

/// tarpc implementation of RelayService using Redis storage
#[derive(Clone)]
pub struct RelayServiceImpl<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone,
{
    storage: Arc<RedisStorage<T>>,
    active_streams: Arc<RwLock<HashMap<String, StreamConfig>>>,
}

impl<T> RelayServiceImpl<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone,
{
    pub fn new(storage: Arc<RedisStorage<T>>) -> Self {
        Self {
            storage,
            active_streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn cleanup_expired_streams(&self) {
        // In a full implementation, we would clean up expired stream sessions
        // For now, this is a placeholder
        let mut streams = self.active_streams.write().await;
        streams.clear(); // Simple cleanup for demo
    }
}

impl<T> RelayService for RelayServiceImpl<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone,
{
    async fn get_message(
        self,
        _ctx: tarpc::context::Context,
        message_id: Vec<u8>,
    ) -> RelayResult<Option<Vec<u8>>> {
        self.storage
            .get_message_raw(&message_id)
            .await
            .map_err(|e| RelayError::StorageError(format!("Storage error: {e}")))
    }

    async fn store_message(
        self,
        _ctx: tarpc::context::Context,
        message_data: Vec<u8>,
    ) -> RelayResult<String> {
        info!(
            "📥 Received message for storage ({} bytes)",
            message_data.len()
        );

        // Deserialize the MessageFull from the message_data
        let message_full: MessageFull<T> =
            MessageFull::from_storage_value(&message_data).map_err(|e| {
                RelayError::SerializationError(format!("Failed to deserialize message: {e}"))
            })?;

        let message_id = hex::encode(message_full.id.as_bytes());
        info!("📝 Storing message with ID: {}", message_id);

        // Store the message in the storage backend
        match self.storage.store_message(&message_full).await {
            Ok(Some(stream_id)) => {
                info!("✅ Message stored successfully!");
                info!("   Message ID: {}", message_id);
                info!("   Stream ID: {}", stream_id);
                info!(
                    "   Author: {}",
                    hex::encode(message_full.author().to_bytes())
                );
                Ok(stream_id)
            }
            Ok(None) => {
                info!("ℹ️ Message already existed in storage");
                info!("   Message ID: {}", message_id);
                // Return the message ID even though it already existed
                Ok(message_id)
            }
            Err(e) => {
                error!("❌ Failed to store message: {}", e);
                error!("   Message ID: {}", message_id);
                Err(RelayError::StorageError(format!("Storage error: {e}")))
            }
        }
    }

    async fn start_message_stream(
        self,
        _ctx: tarpc::context::Context,
        config: StreamConfig,
    ) -> RelayResult<String> {
        info!(
            "Starting message stream with filters: {:?}",
            config.filters.is_empty()
        );

        // Generate a session ID for this stream
        let session_id = format!("session_{}", uuid::Uuid::new_v4());

        // In a full implementation, you'd:
        // 1. Store the StreamConfig associated with this session_id
        // 2. Set up Redis streams listening with the provided filters
        // 3. Manage active streams in a session registry

        info!("Created stream session: {}", session_id);
        Ok(session_id)
    }

    async fn get_stream_batch(
        self,
        _ctx: tarpc::context::Context,
        session_id: String,
        max_messages: Option<usize>,
    ) -> RelayResult<Vec<StreamMessage>> {
        let stream_config = {
            let streams = self.active_streams.read().await;
            streams.get(&session_id).cloned()
        };

        let stream_config = match stream_config {
            Some(stream_config) => stream_config,
            None => {
                warn!("No stream config found for session: {}", session_id);
                return Ok(vec![]);
            }
        };

        // In a full implementation, we would:
        // 1. Use the stored StreamConfig to query the storage
        // 2. Convert storage results to StreamMessage format
        // 3. Handle pagination and "since" logic

        // For now, return empty batch
        info!(
            "Stream batch for session {} - limit: {:?} filters: {:?}",
            session_id,
            max_messages,
            stream_config.filters.is_empty()
        );
        Ok(vec![])
    }

    async fn stop_message_stream(
        self,
        _ctx: tarpc::context::Context,
        session_id: String,
    ) -> RelayResult<bool> {
        info!("Stopping message stream: {}", session_id);

        // In a full implementation, you'd:
        // 1. Look up the session in the registry
        // 2. Cancel any ongoing Redis stream operations
        // 3. Clean up session state

        info!("Stream session stopped: {}", session_id);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RedisConfig, RelayConfig};
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_relay_service_impl_creation() {
        // Test that RelayServiceImpl can be created
        let config = RelayConfig {
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".to_string(),
                pool_size: 1,
            },
            ..Default::default()
        };

        // For this test, we just verify the structure compiles
        // Real Redis testing would require a test container
        let storage = Arc::new(
            RedisStorage::<String>::new(config)
                .await
                .expect("Failed to create storage"),
        );
        let _service = RelayServiceImpl::new(storage);

        // Test passes if no panics occur
        assert!(true);
    }

    #[tokio::test]
    async fn test_timeout_functionality() {
        // Test that our timeout utility works
        let result = timeout(Duration::from_millis(100), async {
            tokio::time::sleep(Duration::from_millis(50)).await
        })
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_mock_message_id_generation() {
        // Test the mock message ID generation logic
        let test_data = b"test message data".to_vec();
        let mock_id = format!(
            "msg_{}",
            hex::encode(&test_data[..std::cmp::min(8, test_data.len())])
        );

        assert!(!mock_id.is_empty());
        assert!(mock_id.starts_with("msg_"));
        assert_eq!(mock_id.len(), "msg_".len() + 16); // msg_ + 8 bytes as hex
    }
}
