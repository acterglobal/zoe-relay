use crate::error::Result;
use redis::{aio::ConnectionManager, AsyncCommands, RedisResult};
use serde::{Deserialize, Serialize};
use zoeyr_wire_protocol::{Kind, MessageFull, StoreKey, Tag};

/// Redis key prefixes for different data types
const MESSAGE_STREAM_NAME: &str = "messages:";
const ID_KEY: &str = "id:";
const AUTHOR_KEY: &str = "author:";
const TIMESTAMP_KEY: &str = "timestamp:";
const EVENT_KEY: &str = "event:";
const USER_KEY: &str = "user:";
const CHANNEL_KEY: &str = "channel:";
const PROTECTED_KEY: &str = "protected:";

/// Message filters for querying
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageFilters {
    pub authors: Option<Vec<String>>,
    pub kinds: Option<Vec<Kind>>,
    pub tags: Option<Vec<Tag>>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
}

impl MessageFilters {
    /// Deserialize from storage value
    pub fn from_storage_value(value: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(value)?;
        let filters: Self = postcard::from_bytes(&bytes)?;
        Ok(filters)
    }

    /// Serialize to storage value
    pub fn to_storage_value(&self) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let bytes = postcard::to_vec::<_, 4096>(self)?;
        Ok(hex::encode(bytes))
    }
}

/// Trait for types that can be serialized to/from storage values
pub trait StorageValue {
    fn from_storage_value(value: &str) -> std::result::Result<Self, Box<dyn std::error::Error>>
    where
        Self: Sized;
    
    fn to_storage_value(&self) -> std::result::Result<String, Box<dyn std::error::Error>>;
}

impl StorageValue for StoreKey {
    fn from_storage_value(value: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(value)?;
        let store_key: Self = postcard::from_bytes(&bytes)?;
        Ok(store_key)
    }

    fn to_storage_value(&self) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let bytes = postcard::to_vec::<_, 4096>(self)?;
        Ok(hex::encode(bytes))
    }
}

impl StorageValue for Kind {
    fn from_storage_value(value: &str) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let bytes = hex::decode(value)?;
        let kind: Self = postcard::from_bytes(&bytes)?;
        Ok(kind)
    }

    fn to_storage_value(&self) -> std::result::Result<String, Box<dyn std::error::Error>> {
        let bytes = postcard::to_vec::<_, 4096>(self)?;
        Ok(hex::encode(bytes))
    }
}

/// Redis-based storage implementation
pub struct RedisStorage {
    pub conn: tokio::sync::Mutex<ConnectionManager>,
    pub config: crate::config::RelayConfig,
}

impl RedisStorage {
    pub async fn new(config: crate::config::RelayConfig) -> Result<Self> {
        let client = redis::Client::open(config.redis.url.as_str())?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn: tokio::sync::Mutex::new(conn), config })
    }

    /// Store the given message, use tags and metadata to index and inform
    /// subscribers.
    /// 
    /// Returns true if this message was newly saved, false if it was already found
    /// Note: messages aren't checked for validity in this function. It is expected that
    /// its key uniquely identifies to an immutable message and that it is confirmed before
    /// calling this function.
    pub async fn store_message<T>(&self, message: &MessageFull<T>) -> Result<bool>
    where
        T: Serialize + for<'de> Deserialize<'de> + Send + Sync,
    {
        let id = message.id.as_bytes().to_vec();
        let value = message.storage_value()?;
        let timestamp = message.when();
        let author_bytes = message.author().to_bytes();
        let mut pipe = redis::pipe();

        let tm = if let Some(timeout) = message.storage_timeout() {
            // timeout of 0 is the same as no timeout.
            if timeout > 0 {
                // FIXME: also check against local time ...
                Some(timeout)
            } else {
                None
            }
        } else {
            None
        };


        // Handle ephemeral messages
        if let Some(timeout) = tm {
            pipe.set_ex::<_, _>(&id, &value, timeout);
            // index_keys.push(("ephemeral", &timeout));
        } else {
            pipe.set::<_, _>(&id, &value);
        }

        let mut xadd = pipe.cmd("XADD").arg(MESSAGE_STREAM_NAME).arg("*");
        xadd = xadd.arg(ID_KEY).arg(&id.as_slice());
        xadd = xadd.arg(AUTHOR_KEY).arg(&author_bytes);
        xadd = xadd.arg(TIMESTAMP_KEY).arg(&timestamp.to_le_bytes());
        

        // Store the indizes
        
        for tag in message.tags() {
            match tag {
                Tag::Event { id: event_id, .. } => {
                    xadd = xadd.arg(EVENT_KEY).arg(&event_id.as_bytes().to_vec());
                }
                Tag::User { id: user_id, .. } => {
                    xadd = xadd.arg(USER_KEY).arg(&user_id);
                }
                Tag::Channel { id: channel_id, .. } => {    
                    xadd = xadd.arg(CHANNEL_KEY).arg(&channel_id);
                }
                Tag::Protected => {
                    xadd = xadd.arg(PROTECTED_KEY).arg(true);
                }
            }
        }

        let mut conn = self.conn.lock().await;
        if conn.exists(id).await? {
            // we have already stored and dealt with this item.
            return Ok(false);
        }
        let _: () = pipe.query_async(&mut *conn).await?;
        
        Ok(true)
    }

    pub async fn get_message<T>(&self, id: &[u8]) -> Result<Option<MessageFull<T>>>
    where
        T: Serialize + for<'de> Deserialize<'de> + Send + Sync,
    {
        let mut conn = self.conn.lock().await;
        let result: RedisResult<Option<String>> = conn.get(id).await;
        
        match result? {
            Some(data) => {
                // Use the model's deserialization method
                let message = MessageFull::<T>::from_storage_value(&data)?;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    pub async fn query_messages<T>(
        &self,
        _filters: &MessageFilters,
        _limit: Option<usize>,
    ) -> Result<Vec<MessageFull<T>>>
    where
        T: Serialize + for<'de> Deserialize<'de> + Send + Sync,
    {
        unimplemented!()
    }


    pub async fn get_user_data(&self, _user_id: &str, _key: &str) -> Result<Option<String>> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayConfig;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestContent {
        text: String,
        value: u32,
    }

    #[test]
    fn test_message_filters_serialization() {
        let filters = MessageFilters {
            authors: Some(vec!["author1".to_string(), "author2".to_string()]),
            kinds: Some(vec![Kind::Regular, Kind::Emphemeral(Some(60))]),
            tags: Some(vec![Tag::Protected]),
            since: Some(1000),
            until: Some(2000),
            limit: Some(50),
        };

        let serialized = filters.to_storage_value().unwrap();
        let deserialized = MessageFilters::from_storage_value(&serialized).unwrap();
        
        assert_eq!(filters, deserialized);
    }

    #[test]
    fn test_store_key_serialization() {
        let store_key = StoreKey::PublicUserInfo;
        let serialized = store_key.to_storage_value().unwrap();
        let deserialized = StoreKey::from_storage_value(&serialized).unwrap();
        
        assert_eq!(store_key, deserialized);
    }

    #[test]
    fn test_kind_serialization() {
        let kind = Kind::Emphemeral(Some(30));
        let serialized = kind.to_storage_value().unwrap();
        let deserialized = Kind::from_storage_value(&serialized).unwrap();
        
        assert_eq!(kind, deserialized);
    }

    #[test]
    fn test_redis_storage_creation() {
        let config = RelayConfig::default();
        // This test just verifies that the config can be created
        assert_eq!(config.redis.url, "redis://127.0.0.1:6379");
        assert_eq!(config.service.max_message_size, 1024 * 1024);
    }

    #[test]
    fn test_message_key_generation() {
        // Test the key generation logic directly
        let key = format!("{}{}", MESSAGE_PREFIX, "test_id");
        assert_eq!(key, "message:test_id");
    }

    #[test]
    fn test_user_data_key_generation() {
        // Test the key generation logic directly
        let key = format!("{}{}:{}", USER_PREFIX, "user123", "profile");
        assert_eq!(key, "user:user123:profile");
    }

    #[test]
    fn test_ephemeral_key_generation() {
        // Test the key generation logic directly
        let key = format!("{}{}", EPHEMERAL_PREFIX, "test_id");
        assert_eq!(key, "ephemeral:test_id");
    }
} 