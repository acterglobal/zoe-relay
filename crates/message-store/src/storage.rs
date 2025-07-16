use std::{marker::PhantomData, sync::Arc};

use futures_util::Stream;
use redis::{aio::ConnectionManager, AsyncCommands, SetOptions};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zoeyr_wire_protocol::{MessageFull, StoreKey, Tag};

use crate::error::RelayError;

type Result<T> = std::result::Result<T, RelayError>;

// Redis key prefixes for different data types
const MESSAGE_STREAM_NAME: &str = "message_stream";
const ID_KEY: &str = "id";
const EVENT_KEY: &str = "event";
const AUTHOR_KEY: &str = "author";
const USER_KEY: &str = "user";
const CHANNEL_KEY: &str = "channel";

/// Message filtering criteria for querying stored messages
#[derive(Debug, Clone, Default)]
pub struct MessageFilters {
    pub authors: Option<Vec<Vec<u8>>>,
    pub channels: Option<Vec<Vec<u8>>>,
    pub events: Option<Vec<Vec<u8>>>,
    pub users: Option<Vec<Vec<u8>>>,
}

impl MessageFilters {
    pub fn is_empty(&self) -> bool {
        self.authors.is_none()
            && self.channels.is_none()
            && self.events.is_none()
            && self.users.is_none()
    }
}

/// Redis-backed storage for the relay service
#[derive(Clone)]
pub struct RedisStorage<T> {
    pub conn: Arc<tokio::sync::Mutex<ConnectionManager>>,
    pub config: crate::config::RelayConfig,
    _type: PhantomData<T>,
}

// internal API
impl<T> RedisStorage<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone,
{
    async fn get_inner<R: redis::FromRedisValue>(&self, id: &str) -> Result<Option<R>> {
        info!("Reading: {id}");
        let mut conn = self.conn.lock().await;

        return conn.get(id).await.map_err(RelayError::Redis);
    }
    /// Retrieve a specific message by ID as its raw data
    async fn get_inner_raw(&self, id: &str) -> Result<Option<Vec<u8>>> {
        self.get_inner::<Vec<u8>>(id).await
    }
    /// Retrieve a specific string
    async fn get_inner_full(&self, id: &str) -> Result<Option<MessageFull<T>>> {
        let mut conn = self.conn.lock().await.clone();
        Self::get_full(&mut conn, id).await
    }

    async fn get_full(conn: &mut ConnectionManager, id: &str) -> Result<Option<MessageFull<T>>> {
        let Some(value): Option<Vec<u8>> = conn.get(id).await? else {
            return Ok(None);
        };
        let message = MessageFull::from_storage_value(&value)
            .map_err(|e| RelayError::Serialization(e.to_string()))?;
        Ok(Some(message))
    }
}

impl<T> RedisStorage<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone,
{
    /// Create a new Redis storage instance
    pub async fn new(config: crate::config::RelayConfig) -> Result<Self> {
        let client = redis::Client::open(config.redis.url.clone()).map_err(RelayError::Redis)?;

        let conn_manager = ConnectionManager::new(client)
            .await
            .map_err(RelayError::Redis)?;

        Ok(Self {
            conn: Arc::new(tokio::sync::Mutex::new(conn_manager)),
            config,
            _type: Default::default(),
        })
    }

    /// Retrieve a specific message by ID as its raw data
    pub async fn get_message_raw(&self, id: &[u8]) -> Result<Option<Vec<u8>>> {
        let message_id = hex::encode(id);
        self.get_inner_raw(&message_id).await
    }
    /// Store a message in Redis and publish to stream for real-time delivery
    /// Returns the stream ID if the message was newly stored, None if it already existed
    pub async fn store_message(&self, message: &MessageFull<T>) -> Result<Option<String>> {
        let mut conn = self.conn.lock().await;

        // Serialize the message
        let storage_value = message
            .storage_value()
            .map_err(|e| RelayError::Serialization(e.to_string()))?;

        let message_id = hex::encode(message.id.as_bytes());

        // Check if the message already exists first
        let exists: bool = conn.exists(&message_id).await.map_err(RelayError::Redis)?;

        if exists {
            // Message already exists, return None
            info!("Message already exists, ignoring to store");
            return Ok(None);
        }

        // Build SET command - only add expiration if timeout is set and > 0
        let mut set_cmd = redis::cmd("SET");
        set_cmd.arg(&message_id).arg(storage_value.to_vec());

        if let Some(timeout) = message.storage_timeout() {
            if timeout > 0 {
                set_cmd.arg("EX").arg(timeout);
            }
        }

        set_cmd.arg("NX"); // Only set if key doesn't exist

        let was_set: bool = set_cmd
            .query_async(&mut *conn)
            .await
            .map_err(RelayError::Redis)?;

        if !was_set {
            // Another thread/process stored the message in the meantime
            return Ok(None);
        }

        // Add to stream for real-time delivery only if we successfully stored it
        let mut xadd_cmd = redis::cmd("XADD");
        xadd_cmd.arg(MESSAGE_STREAM_NAME).arg("*"); // auto-generate ID

        // Add the message data
        xadd_cmd.arg(ID_KEY).arg(storage_value.to_vec());

        // Extract indexable tags from the message and add directly to command
        for tag in message.tags() {
            match tag {
                Tag::Event { id: event_id, .. } => {
                    xadd_cmd.arg(EVENT_KEY).arg(event_id.as_bytes().to_vec());
                }
                Tag::User { id: user_id, .. } => {
                    xadd_cmd.arg(USER_KEY).arg(user_id.clone());
                }
                Tag::Channel { id: channel_id, .. } => {
                    xadd_cmd.arg(CHANNEL_KEY).arg(channel_id.clone());
                }
                Tag::Protected => {
                    // Protected messages aren't added to public stream
                }
            }
        }

        // Add author information
        xadd_cmd
            .arg(AUTHOR_KEY)
            .arg(message.author().to_bytes().to_vec());

        // Execute XADD and get the stream entry ID
        let stream_id: String = xadd_cmd
            .query_async(&mut *conn)
            .await
            .map_err(RelayError::Redis)?;

        // post processing the message: if we are meant to store this.
        if let Some(storage_key) = message.store_key() {
            let author_id = hex::encode(message.author().as_bytes());
            let storage_key_enc: u32 = storage_key.into();
            let storage_id = format!("{author_id}:{storage_key_enc}");

            info!(
                redis_key = storage_id,
                message_id = message_id,
                "storing for key"
            );

            if let Some(previous_id) = conn
                .set_options(&storage_id, &message_id, SetOptions::default().get(true))
                .await?
            {
                // there was something set, we need to make sure this isn't a problem
                let mut previous_id: String = previous_id;
                'retry: loop {
                    info!(redis_key = previous_id, "checking previous message");
                    let Some(previous_message) = Self::get_full(&mut conn, &previous_id).await?
                    else {
                        // we are good, nothing was here
                        info!(
                            redis_key = storage_id,
                            "No previous message found, all good"
                        );
                        break 'retry;
                    };
                    info!("previous message found. comparing timestamps");
                    let prev_when = previous_message.when();
                    let msg_when = message.when();
                    if msg_when > prev_when {
                        // new message is newer, we are good, continue
                        info!(redis_key = previous_id, "We are newer, ignore");
                        break 'retry;
                    } else if prev_when == msg_when {
                        // timestamp was the same, we need to check the id
                        if previous_message.id.as_bytes() < message.id.as_bytes() {
                            // our ID is greater, we won,
                            info!(redis_key = previous_id, "We are older, ignore");
                            break 'retry;
                        }
                    }

                    info!(
                        redis_key = previous_id,
                        "The previous message needs to be restored"
                    );

                    // we need to revert back.
                    let Some(new_previous_id): Option<String> = conn
                        .set_options(&storage_id, &previous_id, SetOptions::default().get(true))
                        .await?
                    else {
                        // FIXME: potential clearing bug?
                        warn!("Restored without it being set. curious...");
                        break 'retry;
                    };

                    if new_previous_id == previous_id || new_previous_id == message_id {
                        // we are all good
                        break 'retry;
                    } else {
                        previous_id = new_previous_id;
                    }
                }
            }
        }

        Ok(Some(stream_id))
    }

    /// Retrieve a specific message by ID
    pub async fn get_message(&self, id: &[u8]) -> Result<Option<MessageFull<T>>> {
        let message_id = hex::encode(id);
        self.get_inner_full(&message_id).await
    }

    /// Listen for messages matching filters (streaming)
    pub async fn listen_for_messages<'a>(
        &'a self,
        filters: &'a MessageFilters,
        since: Option<String>,
        limit: Option<usize>,
    ) -> Result<impl Stream<Item = Result<(Option<Vec<u8>>, String)>> + 'a> {
        if filters.is_empty() {
            return Err(RelayError::EmptyFilters);
        }

        let mut conn = self.conn.lock().await.clone();
        let mut since = since;
        let mut block = false;

        Ok(async_stream::stream! {
            loop {
                let mut read = redis::cmd("XREAD");

                if block {
                    read.arg("BLOCK").arg(10000);
                } else {
                    match &limit {
                        Some(l) if *l > 0 => {
                            read.arg("COUNT").arg(l);
                        }
                        _ => {}
                    }
                }
                read.arg("STREAMS").arg(MESSAGE_STREAM_NAME);
                if let Some(since) = &since {
                    read.arg(since);
                } else {
                    read.arg("0-0"); // default is to start at 0
                }

                let stream_result = match read.query_async(&mut conn).await {
                    Ok(stream_result) => stream_result,
                    Err(e) => {
                        yield Err(RelayError::Redis(e));
                        break;
                    }
                };

                // Parse the XREAD response - it's a Vec of (stream_name, Vec of (id, Vec of (field, value)))
                let rows: Vec<(String, Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>)> = match redis::from_redis_value(&stream_result) {
                    Ok(rows) => rows,
                    Err(e) => {
                        yield Err(RelayError::Redis(e));
                        break;
                    }
                };

                if rows.is_empty() {
                    // nothing found yet, we move to blocking mode
                    if !block {
                        block = true;
                        // we yield once empty when switching block mode
                        yield Ok((None, since.clone().unwrap_or_else(|| "0-0".to_string())));
                    }
                    continue;
                }

                // TODO: would be nice to collapse this a bit
                // and maybe have this tested separately as well

                for (stream_key, entries) in rows {
                    if stream_key != MESSAGE_STREAM_NAME {
                        // should never happen in reality
                        continue;
                    }
                    'messages: for (height, meta) in entries {
                        let mut should_yield = false;
                        let mut id = None;

                        'meta: for (key, value) in meta {
                            // Convert Vec<u8> key to string for comparison
                            let key_str = String::from_utf8_lossy(&key);
                            since = Some(height.clone());

                            // yielding if our filters match
                            match key_str.as_ref() {
                                ID_KEY => {
                                    id = Some(value);
                                    if should_yield {
                                        // already matched, so we yield and continue
                                        yield Ok((id.clone(), height.clone()));
                                        continue 'messages;
                                    }
                                }
                                EVENT_KEY => {
                                    let event_id = value;
                                    if filters.events.is_some() && filters.events.as_ref().unwrap().contains(&event_id) {
                                        let Some(msg_id) = id else {
                                            // we don't have an id yet, mark for yielding,
                                            // once it is found
                                            should_yield = true;
                                            continue 'meta;
                                        };
                                        // we have a match, yield it
                                        yield Ok((Some(msg_id), height.clone()));
                                        continue 'messages;
                                    }
                                }
                                AUTHOR_KEY => {
                                    let author_id = value;
                                    if filters.authors.is_some() && filters.authors.as_ref().unwrap().contains(&author_id) {
                                        let Some(msg_id) = id else {
                                            // we don't have an id yet, mark for yielding,
                                            // once it is found
                                            should_yield = true;
                                            continue 'meta;
                                        };
                                        // we have a match, yield it
                                        yield Ok((Some(msg_id), height.clone()));
                                        continue 'messages;
                                    }
                                }
                                USER_KEY => {
                                    let user_id = value;
                                    if filters.users.is_some() && filters.users.as_ref().unwrap().contains(&user_id) {
                                        let Some(msg_id) = id else {
                                            // we don't have an id yet, mark for yielding,
                                            // once it is found
                                            should_yield = true;
                                            continue 'meta;
                                        };
                                        // we have a match, yield it
                                        yield Ok((Some(msg_id), height.clone()));
                                        continue 'messages;
                                    }
                                }
                                CHANNEL_KEY => {
                                    let channel_id = value;
                                    if filters.channels.is_some() && filters.channels.as_ref().unwrap().contains(&channel_id) {
                                        let Some(msg_id) = id else {
                                            // we don't have an id yet, mark for yielding,
                                            // once it is found
                                            should_yield = true;
                                            continue 'meta;
                                        };
                                        // we have a match, yield it
                                        yield Ok((Some(msg_id), height.clone()));
                                        continue 'messages;
                                    }
                                }
                                _ => {
                                    // irrelevant key, continue
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    pub async fn get_user_data(
        &self,
        user_id: &[u8],
        key: StoreKey,
    ) -> Result<Option<MessageFull<T>>> {
        let message_id = hex::encode(user_id);
        let storage_key: u32 = key.into();
        let target_key = format!("{message_id}:{storage_key}");
        let Some(message_id) = self.get_inner::<String>(&target_key).await? else {
            return Ok(None);
        };

        self.get_inner_full(&message_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RedisConfig, RelayConfig, ServiceConfig};

    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use zoeyr_wire_protocol::{Kind, Message, StoreKey, Tag};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    struct TestContent {
        text: String,
        value: u32,
    }

    /// Helper function to create a test configuration with a test Redis instance
    fn create_test_config() -> RelayConfig {
        RelayConfig {
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".to_string(),
                pool_size: 5,
            },
            service: ServiceConfig {
                max_message_size: 1024 * 1024,
                ephemeral_retention: 3600,
                debug: true,
                bind_address: "127.0.0.1".to_string(),
                port: 8080,
            },
        }
    }

    /// Helper function to create a test message with given content
    fn create_test_message(content: TestContent) -> Result<MessageFull<TestContent>> {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        create_test_message_with_kind(content, Kind::Regular, &signing_key, 0)
    }

    fn create_test_message_with_kind(
        content: TestContent,
        kind: Kind,
        signing_key: &SigningKey,
        time_shift: u64,
    ) -> Result<MessageFull<TestContent>> {
        let verifying_key = signing_key.verifying_key();
        let message = Message::new_v0(
            content,
            verifying_key,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(time_shift),
            kind,
            vec![],
        );

        Ok(MessageFull::new(message, signing_key)?)
    }

    /// Helper function to create a test message with tags
    fn create_test_message_with_tags(
        content: TestContent,
        tags: Vec<Tag>,
    ) -> Result<MessageFull<TestContent>> {
        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

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

        Ok(MessageFull::new(message, &signing_key)?)
    }

    #[tokio::test]
    async fn test_store_and_retrieve_message() {
        // Skip test if Redis is not available
        let config = create_test_config();
        let storage = match RedisStorage::<TestContent>::new(config.clone()).await {
            Ok(storage) => storage,
            Err(_) => {
                eprintln!("Skipping test: Redis not available at {}", config.redis.url);
                return;
            }
        };

        // Create a test message
        let test_content = TestContent {
            text: "Hello, World!".to_string(),
            value: 42,
        };

        let message =
            create_test_message(test_content.clone()).expect("Failed to create test message");

        // Store the message
        let stored = storage
            .store_message(&message)
            .await
            .expect("Failed to store message");
        assert!(stored.is_some(), "Message should be newly stored");

        // Retrieve the message
        let retrieved = storage
            .get_message(message.id.as_bytes())
            .await
            .expect("Failed to retrieve message")
            .expect("Message should be found");

        // Verify the retrieved message matches the original
        assert_eq!(retrieved.id, message.id, "Message IDs should match");
        assert_eq!(
            retrieved.content(),
            message.content(),
            "Message content should match"
        );
        assert_eq!(
            retrieved.author(),
            message.author(),
            "Message sender should match"
        );
        assert_eq!(
            retrieved.when(),
            message.when(),
            "Message timestamp should match"
        );
        assert_eq!(
            retrieved.kind(),
            message.kind(),
            "Message kind should match"
        );
        assert_eq!(
            retrieved.tags(),
            message.tags(),
            "Message tags should match"
        );
        assert_eq!(
            retrieved.signature, message.signature,
            "Message signature should match"
        );

        // Verify the message is valid
        assert!(
            retrieved.verify_all().expect("Failed to verify message"),
            "Retrieved message should be valid"
        );
    }

    #[tokio::test]
    async fn test_store_and_retrieve_user_data_message_with_overwrite() {
        let _ = env_logger::try_init();
        // Skip test if Redis is not available
        let config = create_test_config();
        let storage = match RedisStorage::<TestContent>::new(config.clone()).await {
            Ok(storage) => storage,
            Err(_) => {
                eprintln!("Skipping test: Redis not available at {}", config.redis.url);
                return;
            }
        };

        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        // Create a test message
        let test_content = TestContent {
            text: "Updated Display Name".to_string(),
            value: 42,
        };

        let message = create_test_message_with_kind(
            test_content.clone(),
            Kind::Store(StoreKey::PublicUserInfo),
            &signing_key,
            20, // oldest
        )
        .expect("Failed to create test message");

        // a second message, a bit younger but soon too old if synced late
        let too_old_message = create_test_message_with_kind(
            test_content.clone(),
            Kind::Store(StoreKey::PublicUserInfo),
            &signing_key,
            10, // second oldest
        )
        .expect("Failed to create test message");

        // building a new message with a higher timestamp
        let message2 = create_test_message_with_kind(
            test_content.clone(),
            Kind::Store(StoreKey::PublicUserInfo),
            &signing_key,
            5, // middle old
        )
        .expect("Failed to create test message");

        let user_id = message.author().as_bytes();

        // Store the message
        let stored = storage
            .store_message(&message)
            .await
            .expect("Failed to store message");
        assert!(stored.is_some(), "Message should be newly stored");

        // Retrieve the message, which is never and thus should have overwritten.
        let retrieved = storage
            .get_user_data(user_id, StoreKey::PublicUserInfo)
            .await
            .expect("Failed to retrieve message")
            .expect("Message should be found");

        // Verify the retrieved message matches the original
        assert_eq!(retrieved.id, message.id, "Message IDs should match");
        assert_eq!(
            retrieved.content(),
            message.content(),
            "Message content should match"
        );
        assert_eq!(
            retrieved.author(),
            message.author(),
            "Message sender should match"
        );
        assert_eq!(
            retrieved.when(),
            message.when(),
            "Message timestamp should match"
        );
        assert_eq!(
            retrieved.kind(),
            message.kind(),
            "Message kind should match"
        );
        assert_eq!(
            retrieved.tags(),
            message.tags(),
            "Message tags should match"
        );
        assert_eq!(
            retrieved.signature, message.signature,
            "Message signature should match"
        );

        // Verify the message is valid
        assert!(
            retrieved.verify_all().expect("Failed to verify message"),
            "Retrieved message should be valid"
        );

        // Store the message
        let stored = storage
            .store_message(&message2)
            .await
            .expect("Failed to store message");
        assert!(stored.is_some(), "Message should be newly stored");

        // Retrieve the message
        let retrieved = storage
            .get_user_data(user_id, StoreKey::PublicUserInfo)
            .await
            .expect("Failed to retrieve message")
            .expect("Message should be found");

        assert_eq!(retrieved.id, message2.id, "Message IDs should match");
        assert_eq!(
            retrieved.content(),
            message2.content(),
            "Message content should match"
        );

        // now we try to old one

        // Store the message
        let stored = storage
            .store_message(&too_old_message)
            .await
            .expect("Failed to store message");
        assert!(stored.is_some(), "Message should be newly stored");

        // Retrieve the message again.
        let retrieved = storage
            .get_user_data(user_id, StoreKey::PublicUserInfo)
            .await
            .expect("Failed to retrieve message")
            .expect("Message should be found");

        assert_eq!(retrieved.id, message2.id, "Message IDs should match");
        assert_eq!(
            retrieved.content(),
            message2.content(),
            "Message content should match previouusly stored"
        );
    }

    #[tokio::test]
    async fn test_store_duplicate_message() {
        // Skip test if Redis is not available
        let config = create_test_config();
        let storage = match RedisStorage::<TestContent>::new(config.clone()).await {
            Ok(storage) => storage,
            Err(_) => {
                eprintln!("Skipping test: Redis not available at {}", config.redis.url);
                return;
            }
        };

        // Create a test message
        let test_content = TestContent {
            text: "Duplicate test".to_string(),
            value: 123,
        };

        let message = create_test_message(test_content).expect("Failed to create test message");

        // Store the message first time
        let stored_first = storage
            .store_message(&message)
            .await
            .expect("Failed to store message");
        assert!(stored_first.is_some(), "First storage should succeed");

        // Try to store the same message again
        let stored_second = storage
            .store_message(&message)
            .await
            .expect("Failed to store message");
        assert!(
            stored_second.is_none(),
            "Second storage should return None (already exists)"
        );

        // Verify the message can still be retrieved
        let retrieved = storage
            .get_message(message.id.as_bytes())
            .await
            .expect("Failed to retrieve message")
            .expect("Message should be found");

        assert_eq!(
            retrieved.id, message.id,
            "Retrieved message should match original"
        );
    }

    #[tokio::test]
    async fn test_store_message_with_tags() {
        // Skip test if Redis is not available
        let config = create_test_config();
        let storage = match RedisStorage::<TestContent>::new(config.clone()).await {
            Ok(storage) => storage,
            Err(_) => {
                eprintln!("Skipping test: Redis not available at {}", config.redis.url);
                return;
            }
        };

        // Create test content
        let test_content = TestContent {
            text: "Message with tags".to_string(),
            value: 999,
        };

        // Create tags
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test_event_1234567890abcdef");
        let event_id = hasher.finalize();
        let user_id = b"test_user_123".to_vec();
        let channel_id = b"test_channel_456".to_vec();

        let tags = vec![
            Tag::Event {
                id: event_id,
                relays: vec!["relay1".to_string()],
            },
            Tag::User {
                id: user_id.clone(),
                relays: vec!["relay2".to_string()],
            },
            Tag::Channel {
                id: channel_id.clone(),
                relays: vec!["relay3".to_string()],
            },
            Tag::Protected,
        ];

        let message = create_test_message_with_tags(test_content.clone(), tags.clone())
            .expect("Failed to create test message with tags");

        // Store the message
        let stored = storage
            .store_message(&message)
            .await
            .expect("Failed to store message");
        assert!(stored.is_some(), "Message should be newly stored");

        // Retrieve the message
        let retrieved = storage
            .get_message(message.id.as_bytes())
            .await
            .expect("Failed to retrieve message")
            .expect("Message should be found");

        // Verify the retrieved message matches the original
        assert_eq!(
            retrieved.content(),
            message.content(),
            "Message content should match"
        );
        assert_eq!(
            retrieved.tags(),
            message.tags(),
            "Message tags should match"
        );
        assert_eq!(retrieved.tags().len(), 4, "Should have 4 tags");

        // Verify the message is valid
        assert!(
            retrieved.verify_all().expect("Failed to verify message"),
            "Retrieved message should be valid"
        );
    }

    #[tokio::test]
    async fn test_retrieve_nonexistent_message() {
        // Skip test if Redis is not available
        let config = create_test_config();
        let storage = match RedisStorage::<TestContent>::new(config.clone()).await {
            Ok(storage) => storage,
            Err(_) => {
                eprintln!("Skipping test: Redis not available at {}", config.redis.url);
                return;
            }
        };

        // Create a fake message ID
        let fake_id = b"nonexistent_message_id_12345";

        // Try to retrieve a message that doesn't exist
        let retrieved = storage
            .get_message(fake_id)
            .await
            .expect("Should not error when retrieving nonexistent message");

        assert!(
            retrieved.is_none(),
            "Should return None for nonexistent message"
        );
    }

    #[tokio::test]
    async fn test_ephemeral_message() {
        // Skip test if Redis is not available
        let config = create_test_config();
        let storage = match RedisStorage::<TestContent>::new(config.clone()).await {
            Ok(storage) => storage,
            Err(_) => {
                eprintln!("Skipping test: Redis not available at {}", config.redis.url);
                return;
            }
        };

        // Create a test message with ephemeral kind (5 second timeout)
        let test_content = TestContent {
            text: "Ephemeral message".to_string(),
            value: 777,
        };

        let mut secret_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        let message = Message::new_v0(
            test_content,
            verifying_key,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Kind::Emphemeral(Some(5)), // 5 second timeout
            vec![],
        );

        let message_full =
            MessageFull::new(message, &signing_key).expect("Failed to create ephemeral message");

        // Store the ephemeral message
        let stored = storage
            .store_message(&message_full)
            .await
            .expect("Failed to store ephemeral message");
        assert!(stored.is_some(), "Ephemeral message should be newly stored");

        // Verify it can be retrieved immediately
        let retrieved = storage
            .get_message(message_full.id.as_bytes())
            .await
            .expect("Failed to retrieve ephemeral message")
            .expect("Ephemeral message should be found immediately");

        assert_eq!(
            retrieved.id, message_full.id,
            "Retrieved ephemeral message should match original"
        );

        // Note: We don't test the actual expiration here as it would require waiting
        // and could make the test flaky. In a real integration test, you might want
        // to use a shorter timeout and wait, or mock the time functionality.
    }
}
