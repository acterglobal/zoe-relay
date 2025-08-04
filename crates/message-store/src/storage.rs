use std::sync::Arc;

use futures_util::Stream;
use redis::{aio::ConnectionManager, AsyncCommands, SetOptions};
use tracing::{debug, error, info, warn};
use zoe_wire_protocol::{FilterField, MessageFilters, MessageFull, StoreKey, Tag};

use crate::error::{MessageStoreError, Result};

// Redis key prefixes for different data types
const GLOBAL_MESSAGES_STREAM_NAME: &str = "message_stream";
const ID_KEY: &str = "id";
const EXPIRATION_KEY: &str = "exp";
const EVENT_KEY: &str = "event";
const AUTHOR_KEY: &str = "author";
const USER_KEY: &str = "user";
const CHANNEL_KEY: &str = "channel";
const STREAM_HEIGHT_KEY: &str = "stream_height";

pub type GlobalStreamHeight = String;
pub type LocalStreamHeight = String;
pub type CatchUpItem = (MessageFull, (GlobalStreamHeight, LocalStreamHeight));
pub type GlobalStreamItem = (Option<MessageFull>, GlobalStreamHeight);

/// Redis-backed storage for the relay service
#[derive(Clone)]
pub struct RedisMessageStorage {
    pub conn: Arc<tokio::sync::Mutex<ConnectionManager>>,
    pub client: redis::Client,
}

// internal API
impl RedisMessageStorage {
    async fn get_inner<R: redis::FromRedisValue>(&self, id: &str) -> Result<Option<R>> {
        info!("Reading: {id}");
        let mut conn = self.conn.lock().await;

        return conn.get(id).await.map_err(MessageStoreError::Redis);
    }
    /// Retrieve a specific message by ID as its raw data
    async fn get_inner_raw(&self, id: &str) -> Result<Option<Vec<u8>>> {
        self.get_inner::<Vec<u8>>(id).await
    }
    /// Retrieve a specific string
    async fn get_inner_full(&self, id: &str) -> Result<Option<MessageFull>> {
        let mut conn = self.conn.lock().await.clone();
        Self::get_full(&mut conn, id).await
    }

    async fn get_message_full(
        conn: &mut ConnectionManager,
        id: &[u8],
    ) -> Result<Option<MessageFull>> {
        let message_id = hex::encode(id);
        Self::get_full(conn, &message_id).await
    }

    async fn get_full(conn: &mut ConnectionManager, id: &str) -> Result<Option<MessageFull>> {
        let Some(value): Option<Vec<u8>> = conn.get(id).await? else {
            return Ok(None);
        };
        let message = MessageFull::from_storage_value(&value)
            .map_err(|e| MessageStoreError::Serialization(e.to_string()))?;
        Ok(Some(message))
    }

    async fn add_to_index_stream(
        conn: &mut ConnectionManager,
        stream_name: &str,
        message_id: &[u8],
        stream_height: &str,
        expiration_time: Option<u64>,
    ) -> Result<String> {
        // Create XADD command for channel stream
        let mut channel_xadd = redis::cmd("XADD");
        channel_xadd
            .arg(stream_name)
            .arg("*") // auto-generate ID for channel stream
            .arg(ID_KEY)
            .arg(message_id)
            .arg(STREAM_HEIGHT_KEY)
            .arg(stream_height); // Reference to main stream entry

        if let Some(expiration_time) = expiration_time {
            channel_xadd
                .arg(EXPIRATION_KEY)
                .arg(expiration_time.to_le_bytes().to_vec());
        }

        // Execute channel stream XADD
        let tags_stream_id: String = channel_xadd
            .query_async(conn)
            .await
            .map_err(MessageStoreError::Redis)?;

        debug!(
            "Added message {} to stream {}",
            hex::encode(message_id),
            stream_name
        );

        Ok(tags_stream_id)
    }
}

type RedisStreamResult = Vec<(String, Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>)>;

impl RedisMessageStorage {
    /// Create a new Redis storage instance
    pub async fn new(redis_url: String) -> Result<Self> {
        let client = redis::Client::open(redis_url).map_err(MessageStoreError::Redis)?;

        let conn_manager = ConnectionManager::new(client.clone())
            .await
            .map_err(MessageStoreError::Redis)?;

        Ok(Self {
            conn: Arc::new(tokio::sync::Mutex::new(conn_manager)),
            client,
        })
    }

    /// Retrieve a specific message by ID as its raw data
    pub async fn get_message_raw(&self, id: &[u8]) -> Result<Option<Vec<u8>>> {
        let message_id = hex::encode(id);
        self.get_inner_raw(&message_id).await
    }
    /// Store a message in Redis and publish to stream for real-time delivery
    /// Returns the stream ID if the message was newly stored, None if it already existed
    pub async fn store_message(&self, message: &MessageFull) -> Result<Option<String>> {
        let mut conn = { self.conn.lock().await.clone() };

        // Serialize the message
        let storage_value = message
            .storage_value()
            .map_err(|e| MessageStoreError::Serialization(e.to_string()))?;

        let msg_id_bytes = message.id.as_bytes();
        let message_id = hex::encode(msg_id_bytes);

        // Build SET command - only add expiration if timeout is set and > 0
        let mut set_cmd = redis::cmd("SET");
        set_cmd.arg(&message_id).arg(storage_value.to_vec());
        let mut ex_time = None;

        if let Some(timeout) = message.storage_timeout() {
            if timeout > 0 {
                let expiration_time = message.when().saturating_add(timeout);
                if expiration_time
                    < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs()
                {
                    debug!("Message is expired, ignoring to store");
                    return Ok(None);
                }
                set_cmd.arg("EX").arg(timeout);
                ex_time = Some(expiration_time);
            }
        }

        set_cmd.arg("NX"); // Only set if key doesn't exist

        let was_set: bool = set_cmd
            .query_async(&mut conn)
            .await
            .map_err(MessageStoreError::Redis)?;

        if !was_set {
            // Was already stored, nothing for us to do.
            return Ok(None);
        }

        // Add to stream for real-time delivery only if we successfully stored it
        let mut xadd_cmd = redis::cmd("XADD");
        xadd_cmd.arg(GLOBAL_MESSAGES_STREAM_NAME).arg("*"); // auto-generate ID

        if let Some(expiration_time) = ex_time {
            xadd_cmd
                .arg(EXPIRATION_KEY)
                .arg(expiration_time.to_le_bytes().to_vec());
        }
        // Add the message data
        xadd_cmd.arg(ID_KEY).arg(msg_id_bytes);

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
        let stream_height: String = xadd_cmd
            .query_async(&mut conn)
            .await
            .map_err(MessageStoreError::Redis)?;

        Self::add_to_index_stream(
            &mut conn,
            &format!("author:{}:stream", hex::encode(message.author().as_bytes())),
            msg_id_bytes,
            &stream_height,
            ex_time,
        )
        .await?;

        // NEW: Also add to per-channel streams for ordered catch-up
        for tag in message.tags() {
            let tags_stream = match tag {
                Tag::Channel { id: channel_id, .. } => {
                    format!("channel:{}:stream", hex::encode(channel_id))
                }
                Tag::Event { id, .. } => {
                    format!("event:{}:stream", hex::encode(id.as_bytes()))
                }
                Tag::User { id, .. } => {
                    format!("user:{}:stream", hex::encode(id))
                }
                _ => continue, // not a custom stream
            };

            Self::add_to_index_stream(
                &mut conn,
                &tags_stream,
                msg_id_bytes,
                &stream_height,
                ex_time,
            )
            .await?;
        }

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

        Ok(Some(stream_height))
    }

    /// Retrieve a specific message by ID
    pub async fn get_message(&self, id: &[u8]) -> Result<Option<MessageFull>> {
        let mut conn = { self.conn.lock().await.clone() };
        Self::get_message_full(&mut conn, id).await
    }

    /// Catch up on a specific tag stream
    pub async fn catch_up<'a>(
        &'a self,
        tag_type: FilterField,
        tag_id: &[u8],
        since: Option<String>,
    ) -> Result<impl Stream<Item = Result<CatchUpItem>> + 'a> {
        let channel_stream = match tag_type {
            FilterField::Channel => format!("channel:{}:stream", hex::encode(tag_id)),
            FilterField::Event => format!("event:{}:stream", hex::encode(tag_id)),
            FilterField::User => format!("user:{}:stream", hex::encode(tag_id)),
            FilterField::Author => format!("author:{}:stream", hex::encode(tag_id)),
        };

        let mut conn = {
            // our streaming is complicated, we want an async conenction
            // but if we reuse the existing connection all other requests
            // will block. so we need to get a new connection for streaming.
            self.client
                .get_connection_manager()
                .await
                .map_err(MessageStoreError::Redis)?
        };
        let mut fetch_con = {
            // and one we need to read actual message data
            self.client
                .get_connection_manager()
                .await
                .map_err(MessageStoreError::Redis)?
        };
        let mut last_seen_height = since.unwrap_or_else(|| "0-0".to_string());

        Ok(async_stream::stream! {
            loop {
                let mut read = redis::cmd("XREAD");

                read.arg("STREAMS")
                    .arg(&channel_stream)
                    .arg(&last_seen_height);

                let stream_result = match read.query_async(&mut conn).await {
                    Ok(stream_result) => stream_result,
                    Err(e) => {
                        yield Err(MessageStoreError::Redis(e));
                        break;
                    }
                };

                // Parse the XREAD response - it's a Vec of (stream_name, Vec of (id, Vec of (field, value)))
                let rows: RedisStreamResult = match redis::from_redis_value(&stream_result) {
                    Ok(rows) => rows,
                    Err(e) => {
                        yield Err(MessageStoreError::Redis(e));
                        break;
                    }
                };

                if rows.is_empty() {
                    // nothing found, we are done
                    break;
                }

                for (_, entries) in rows {
                    'messages: for (height, meta) in entries {
                        let mut id = None;
                        last_seen_height = height.clone();
                        let mut stream_height = None;

                        'meta: for (key, value) in meta {
                            // Convert Vec<u8> key to string for comparison
                            let key_str = String::from_utf8_lossy(&key);

                            // yielding if our filters match
                            match key_str.as_ref() {
                                ID_KEY => {
                                    id = Some(value);
                                }

                                //  reading of metadata:
                                //  is this already expired?
                                EXPIRATION_KEY => {
                                    let expiration_time = match value.try_into().map(u64::from_le_bytes) {
                                        Ok(expiration_time) => expiration_time,
                                        Err(e) => {
                                            error!("Message has a bad expiration time: {:?}", e);
                                            continue 'meta;
                                        }
                                    };
                                    let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                                    if expiration_time < current_time {
                                        // the message is expired, we don't yield it
                                        debug!("Message is expired, ignoring to yield");
                                        continue 'messages;
                                    }

                                }
                                // reading the height
                                STREAM_HEIGHT_KEY => {
                                    stream_height = Some(String::from_utf8_lossy(&value).to_string());
                                }
                                _ => {
                                    // irrelevant key, continue
                                }
                            }
                        }

                        // Now decide whether to yield based on collected info
                        let Some(msg_id) = id else {
                            error!("Message ID not found in stream info");
                            continue 'messages;
                        };


                        let Some(msg_full) = Self::get_message_full(&mut fetch_con, &msg_id).await? else {
                            // we need to fetch the message
                            error!("Message not found in storage. odd");
                            continue 'messages;
                        };
                        yield Ok((msg_full, (stream_height.clone().unwrap_or_else(|| "0-0".to_string()), height.clone())));
                    }
                }
            }
        })
    }

    /// Listen for messages matching filters (streaming)
    pub async fn listen_for_messages<'a>(
        &'a self,
        filters: &'a MessageFilters,
        since: Option<String>,
        limit: Option<usize>,
    ) -> Result<impl Stream<Item = Result<GlobalStreamItem>> + 'a> {
        if filters.is_empty() {
            return Err(MessageStoreError::EmptyFilters);
        }

        let mut conn = {
            // our streaming is complicated, we want an async conenction
            // but if we reuse the existing connection all other requests
            // will block. so we need to get a new connection for streaming.
            self.client
                .get_connection_manager()
                .await
                .map_err(MessageStoreError::Redis)?
        };
        let mut fetch_con = {
            // and one we need to read actual message data
            self.client
                .get_connection_manager()
                .await
                .map_err(MessageStoreError::Redis)?
        };
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
                read.arg("STREAMS").arg(GLOBAL_MESSAGES_STREAM_NAME);
                if let Some(since) = &since {
                    read.arg(since);
                } else {
                    read.arg("0-0"); // default is to start at 0
                }

                let stream_result = match read.query_async(&mut conn).await {
                    Ok(stream_result) => stream_result,
                    Err(e) => {
                        yield Err(MessageStoreError::Redis(e));
                        break;
                    }
                };

                // Parse the XREAD response - it's a Vec of (stream_name, Vec of (id, Vec of (field, value)))
                let rows: RedisStreamResult = match redis::from_redis_value(&stream_result) {
                    Ok(rows) => rows,
                    Err(e) => {
                        yield Err(MessageStoreError::Redis(e));
                        break;
                    }
                };

                if rows.is_empty() {
                    // nothing found yet, we move to blocking mode
                    if !block {
                        block = true;
                        info!("Switching to blocking mode");
                        // we yield once empty when switching block mode
                        yield Ok((None, since.clone().unwrap_or_else(|| "0-0".to_string())));
                    }
                    continue;
                }

                // TODO: would be nice to collapse this a bit
                // and maybe have this tested separately as well

                let mut did_yield = false;
                let mut last_seen_height = since.clone();

                for (_, entries) in rows {
                    'messages: for (height, meta) in entries {
                        let mut should_yield = false;
                        let mut id = None;
                        last_seen_height = Some(height.clone());

                        'meta: for (key, value) in meta {
                            // Convert Vec<u8> key to string for comparison
                            let key_str = String::from_utf8_lossy(&key);
                            since = Some(height.clone());

                            // yielding if our filters match
                            match key_str.as_ref() {
                                ID_KEY => {
                                    id = Some(value);
                                    // ignored
                                }

                                //  reading of metadata:
                                //  is this already expired?
                                EXPIRATION_KEY => {
                                    let expiration_time = match value.try_into().map(u64::from_le_bytes) {
                                        Ok(expiration_time) => expiration_time,
                                        Err(e) => {
                                            error!("Message has a bad expiration time: {:?}", e);
                                            continue 'meta;
                                        }
                                    };
                                    let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                                    if expiration_time < current_time {
                                        // the message is expired, we don't yield it
                                        debug!("Message is expired, ignoring to yield");
                                        continue 'messages;
                                    }

                                }

                                // checking for filters
                                EVENT_KEY => {
                                    let event_id = value;
                                    if filters.events.is_some() && filters.events.as_ref().unwrap().contains(&event_id) {
                                        should_yield = true;
                                        break 'meta;
                                    }
                                }
                                AUTHOR_KEY => {
                                    let author_id = value;
                                    if filters.authors.is_some() && filters.authors.as_ref().unwrap().contains(&author_id) {
                                        should_yield = true;
                                        break 'meta;
                                    }
                                }
                                USER_KEY => {
                                    let user_id = value;
                                    if filters.users.is_some() && filters.users.as_ref().unwrap().contains(&user_id) {
                                        should_yield = true;
                                        break 'meta;
                                    }
                                }
                                CHANNEL_KEY => {
                                    let channel_id = value;
                                    if filters.channels.is_some() && filters.channels.as_ref().unwrap().contains(&channel_id) {
                                        should_yield = true;
                                        break 'meta;
                                    }
                                }
                                _ => {
                                    // irrelevant key, continue
                                }
                            }
                        }

                        // Now decide whether to yield based on collected info
                        if should_yield {
                            let Some(msg_id) = id else {
                                error!("Message ID not found in stream info");
                                continue 'messages;
                            };
                            info!("Message ID found in stream info: {}", hex::encode(&msg_id));
                            let Some(msg_full) = Self::get_message_full(&mut fetch_con, &msg_id).await? else {
                                // we need to fetch the message
                                error!("Message not found in storage. odd");
                                continue 'messages;
                            };
                            yield Ok((Some(msg_full), height.clone()));
                            did_yield = true;
                        }
                    }
                }

                if !did_yield {
                    info!("No messages matched filters, yielding empty");
                    yield Ok((None, last_seen_height.clone().unwrap_or_else(|| "0-0".to_string())));
                }
            }
        })
    }

    pub async fn get_user_data(
        &self,
        user_id: &[u8],
        key: StoreKey,
    ) -> Result<Option<MessageFull>> {
        let message_id = hex::encode(user_id);
        let storage_key: u32 = key.into();
        let target_key = format!("{message_id}:{storage_key}");
        let Some(message_id) = self.get_inner::<String>(&target_key).await? else {
            return Ok(None);
        };
        self.get_inner_full(&message_id).await
    }
}
