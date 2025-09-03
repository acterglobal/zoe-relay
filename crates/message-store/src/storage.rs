use std::sync::Arc;

use futures_util::Stream;
use redis::{
    aio::{ConnectionManager, ConnectionManagerConfig},
    AsyncCommands, SetOptions,
};
use tracing::{debug, error, info, trace, warn};
use zoe_wire_protocol::{
    Filter, Hash, KeyId, MessageFilters, MessageFull, PublishResult, StoreKey, Tag,
};

use crate::error::{MessageStoreError, Result};

// Redis key prefixes for different data types
const GLOBAL_MESSAGES_STREAM_NAME: &str = "message_stream";
const MESSAGE_TO_STREAM_ID_PREFIX: &str = "msg_stream_id:";
const ID_KEY: &str = "id";
const EXPIRATION_KEY: &str = "exp";
const EVENT_KEY: &str = "event";
const AUTHOR_KEY: &str = "author";
const USER_KEY: &str = "user";
const CHANNEL_KEY: &str = "channel";
const STREAM_HEIGHT_KEY: &str = "stream_height";

// Lua script for atomic message storage
const STORE_MESSAGE_SCRIPT: &str = r#"
local message_key = KEYS[1]
local stream_id_key = KEYS[2] 
local global_stream = KEYS[3]

local message_data = ARGV[1]
local message_id_bytes = ARGV[2]
local author_bytes = ARGV[3]
local expiration_time = ARGV[4] -- empty string if no expiration
local timeout = ARGV[5] -- empty string if no timeout

-- Try to store message with NX (only if not exists)
local set_result
if expiration_time ~= "" and timeout ~= "" then
    set_result = redis.call('SET', message_key, message_data, 'EX', timeout, 'NX')
else
    set_result = redis.call('SET', message_key, message_data, 'NX')  
end

-- If message already exists, return existing stream ID
if not set_result then
    local existing_stream_id = redis.call('GET', stream_id_key)
    if existing_stream_id then
        return {'EXISTS', existing_stream_id}
    else
        return {'ERROR', 'Message exists but no stream ID mapping found'}
    end
end

-- Message is new - add to global stream
local xadd_args = {global_stream, '*', 'id', message_id_bytes, 'author', author_bytes}

-- Add expiration if provided  
if expiration_time ~= "" then
    table.insert(xadd_args, 'exp')
    -- Decode hex-encoded expiration time back to bytes
    local exp_bytes = {}
    for i = 1, #expiration_time, 2 do
        local byte = expiration_time:sub(i, i+1)
        table.insert(exp_bytes, string.char(tonumber(byte, 16)))
    end
    table.insert(xadd_args, table.concat(exp_bytes))
end

-- Add tags from remaining ARGV (starting at index 6)
for i = 6, #ARGV, 2 do
    if ARGV[i] and ARGV[i+1] then
        table.insert(xadd_args, ARGV[i])     -- tag key
        table.insert(xadd_args, ARGV[i+1])   -- tag value  
    end
end

local stream_id = redis.call('XADD', unpack(xadd_args))

-- Store the mapping from message-id to stream-id
redis.call('SET', stream_id_key, stream_id)

return {'STORED', stream_id}
"#;

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

        // Try to deserialize the message - if it fails, log the error and return None
        // This handles cases where old data with incompatible serialization formats exists
        match MessageFull::from_storage_value(&value) {
            Ok(message) => Ok(Some(message)),
            Err(e) => {
                tracing::warn!("Failed to deserialize message {}: {}. Skipping corrupted/incompatible message.", id, e);
                Ok(None)
            }
        }
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
        debug!("Connecting to Redis at {}", redis_url);
        let client = redis::Client::open(redis_url).map_err(MessageStoreError::Redis)?;
        trace!("Starting connection manager");

        let mut conn_manager = ConnectionManager::new_with_config(
            client.clone(),
            ConnectionManagerConfig::default()
                .set_connection_timeout(std::time::Duration::from_secs(5)),
        )
        .await
        .map_err(MessageStoreError::Redis)?;

        // tyr to reach the server
        conn_manager.ping::<()>().await?;

        trace!("Connection manager started");

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
    /// Returns PublishResult indicating if message was newly stored or already existed with stream ID  
    ///
    /// This method uses a Lua script to ensure atomicity of core operations:
    /// 1. Message storage (SET NX)
    /// 2. Global stream addition (XADD)
    /// 3. Stream ID mapping (SET)
    pub async fn store_message(&self, message: &MessageFull) -> Result<PublishResult> {
        let mut conn = { self.conn.lock().await.clone() };

        // Check expiration early to avoid unnecessary work
        let (ex_time, timeout_str) = if let Some(timeout) = message.storage_timeout() {
            if timeout > 0 {
                let expiration_time = message.when().saturating_add(timeout);
                if expiration_time
                    < std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs()
                {
                    debug!("Message is expired, ignoring to store");
                    return Ok(PublishResult::Expired);
                }
                (Some(expiration_time), timeout.to_string())
            } else {
                (None, String::new())
            }
        } else {
            (None, String::new())
        };

        // Serialize the message
        let storage_value = message
            .storage_value()
            .map_err(|e| MessageStoreError::Serialization(e.to_string()))?;

        let msg_id_bytes = message.id().as_bytes();
        let message_id = hex::encode(msg_id_bytes);

        // Prepare Redis keys
        let stream_id_key = format!("{MESSAGE_TO_STREAM_ID_PREFIX}{message_id}");

        // Collect all script arguments upfront
        let mut script_args = vec![
            storage_value.to_vec(),                    // ARGV[1] - message data
            msg_id_bytes.to_vec(),                     // ARGV[2] - message ID bytes
            message.author().id().as_bytes().to_vec(), // ARGV[3] - author ID bytes
        ];
        script_args.push(
            ex_time
                .map_or(String::new(), |t| hex::encode(t.to_le_bytes()))
                .into_bytes(),
        ); // ARGV[4] - expiration time
        script_args.push(timeout_str.into_bytes()); // ARGV[5] - timeout

        // Add tag data to script arguments
        for tag in message.tags() {
            match tag {
                Tag::Event { id: event_id, .. } => {
                    script_args.push(EVENT_KEY.as_bytes().to_vec());
                    script_args.push(event_id.as_bytes().to_vec());
                }
                Tag::User { id: user_id, .. } => {
                    script_args.push(USER_KEY.as_bytes().to_vec());
                    script_args.push(user_id.as_bytes().to_vec());
                }
                Tag::Channel { id: channel_id, .. } => {
                    script_args.push(CHANNEL_KEY.as_bytes().to_vec());
                    script_args.push(channel_id.clone());
                }
                Tag::Protected => {
                    // Protected messages aren't added to public stream
                }
            }
        }

        // Execute atomic Lua script
        let script_result: Vec<String> = redis::Script::new(STORE_MESSAGE_SCRIPT)
            .key(&message_id) // KEYS[1] - message key
            .key(&stream_id_key) // KEYS[2] - stream ID mapping key
            .key(GLOBAL_MESSAGES_STREAM_NAME) // KEYS[3] - global stream name
            .arg(script_args)
            .invoke_async(&mut conn)
            .await
            .map_err(MessageStoreError::Redis)?;

        let (result_type, stream_id) = match script_result.as_slice() {
            [result_type, stream_id] => (result_type, stream_id),
            _ => {
                return Err(MessageStoreError::Internal(
                    "Invalid response from store_message script".to_string(),
                ))
            }
        };

        let publish_result = match result_type.as_str() {
            "EXISTS" => PublishResult::AlreadyExists {
                global_stream_id: stream_id.clone(),
            },
            "STORED" => PublishResult::StoredNew {
                global_stream_id: stream_id.clone(),
            },
            "ERROR" => {
                error!("Script error: {}", stream_id);
                return Err(MessageStoreError::Internal(stream_id.clone()));
            }
            _ => {
                return Err(MessageStoreError::Internal(format!(
                    "Unknown script result type: {result_type}"
                )))
            }
        };

        let PublishResult::StoredNew {
            ref global_stream_id,
        } = publish_result
        else {
            return Ok(publish_result);
        };
        // Only proceed with index streams if message was newly stored

        // Add to index streams (eventually consistent)
        // These operations are not critical for correctness, so we handle them separately
        Self::add_to_index_stream(
            &mut conn,
            &format!("author:{}:stream", hex::encode(message.author().id())),
            msg_id_bytes,
            global_stream_id,
            ex_time,
        )
        .await?;

        // Also add to per-channel streams for ordered catch-up
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
                global_stream_id,
                ex_time,
            )
            .await?;
        }

        // Handle storage key updates (user data storage)
        if let Some(storage_key) = message.store_key() {
            let author_id = hex::encode(message.author().id());
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
                // Handle storage key conflict resolution
                let mut previous_id: String = previous_id;
                'retry: loop {
                    info!(redis_key = previous_id, "checking previous message");
                    let Some(previous_message) = Self::get_full(&mut conn, &previous_id).await?
                    else {
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
                        if previous_message.signature() < message.signature() {
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

        Ok(publish_result)
    }

    /// Check which messages the server already has and return their global stream IDs.
    /// Returns a vec of `Option<String>` in the same order as the input, where:
    /// - `Some(stream_id)` means the server has the message with that global stream ID  
    /// - `None` means the server doesn't have this message yet
    pub async fn check_messages(&self, message_ids: &[Hash]) -> Result<Vec<Option<String>>> {
        if message_ids.is_empty() {
            return Ok(vec![]);
        }

        let mut conn = { self.conn.lock().await.clone() };

        let mut pipe = redis::pipe();
        let stream_id_keys: Vec<String> = message_ids
            .iter()
            .map(|id| {
                format!(
                    "{MESSAGE_TO_STREAM_ID_PREFIX}{}",
                    hex::encode(id.as_bytes())
                )
            })
            .collect();

        // Add all GET commands to pipeline
        for stream_id_key in &stream_id_keys {
            pipe.get(stream_id_key);
        }

        // Execute pipeline
        let pipeline_results: Vec<Option<String>> = pipe
            .query_async(&mut conn)
            .await
            .map_err(MessageStoreError::Redis)?;

        Ok(pipeline_results)
    }

    /// Retrieve a specific message by ID
    pub async fn get_message(&self, id: &[u8]) -> Result<Option<MessageFull>> {
        let mut conn = { self.conn.lock().await.clone() };
        Self::get_message_full(&mut conn, id).await
    }

    /// Catch up on a specific filter stream
    pub async fn catch_up<'a>(
        &'a self,
        filter: &Filter,
        since: Option<String>,
    ) -> Result<impl Stream<Item = Result<CatchUpItem>> + 'a> {
        let channel_stream = match filter {
            Filter::Channel(channel_id) => format!("channel:{}:stream", hex::encode(channel_id)),
            Filter::Event(event_id) => format!("event:{}:stream", hex::encode(event_id.as_bytes())),
            Filter::User(user_id) => format!("user:{}:stream", hex::encode(user_id)),
            Filter::Author(author_id) => format!("author:{}:stream", hex::encode(author_id)),
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
                        error!(error=?e, "Error reading messages at catch up");
                        yield Err(MessageStoreError::Redis(e));
                        break;
                    }
                };

                // Parse the XREAD response - it's a Vec of (stream_name, Vec of (id, Vec of (field, value)))
                let rows: RedisStreamResult = match redis::from_redis_value(&stream_result) {
                    Ok(rows) => rows,
                    Err(e) => {
                        error!(error=?e, "Error parsing messages at catch up");
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
                                            error!(error=?e, "Message has a bad expiration time");
                                            continue 'meta;
                                        }
                                    };
                                    let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                                    if expiration_time < current_time {
                                        // the message is expired, we don't yield it
                                        debug!("Message is expired, ignoring to yield in catch up");
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
                            error!("Message ID not found in stream info at catch up");
                            continue 'messages;
                        };


                        let Some(msg_full) = Self::get_message_full(&mut fetch_con, &msg_id).await? else {
                            // we need to fetch the message
                            error!("Message not found in storage at catch up. odd...");
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

                debug!("redis listening for messages with filters: {:?}", filters);

                let stream_result = match read.query_async(&mut conn).await {
                    Ok(stream_result) => stream_result,
                    Err(e) => {
                        error!("Error reading messages: {:?}", e);
                        yield Err(MessageStoreError::Redis(e));
                        break;
                    }
                };

                // Parse the XREAD response - it's a Vec of (stream_name, Vec of (id, Vec of (field, value)))
                let rows: RedisStreamResult = match redis::from_redis_value(&stream_result) {
                    Ok(rows) => rows,
                    Err(e) => {
                        error!("Error parsing messages: {:?}", e);
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
                                        debug!("Message is expired, ignoring to yield in regular listen");
                                        continue 'messages;
                                    }

                                }

                                // checking for filters
                                EVENT_KEY => {
                                    if let Some(filter_list) = &filters.filters {
                                        for filter in filter_list {
                                            if let Filter::Event(event_id) = filter {
                                                if value == event_id.as_bytes() {
                                                    should_yield = true;
                                                    break 'meta;
                                                }
                                            }
                                        }
                                    }
                                }
                                AUTHOR_KEY => {
                                    if let Some(filter_list) = &filters.filters {
                                        for filter in filter_list {
                                            if let Filter::Author(author_id) = filter {
                                                if value == author_id.as_bytes() {
                                                    should_yield = true;
                                                    break 'meta;
                                                }
                                            }
                                        }
                                    }
                                }
                                USER_KEY => {
                                    if let Some(filter_list) = &filters.filters {
                                        for filter in filter_list {
                                            if let Filter::User(user_id) = filter {
                                                if value == user_id.as_bytes() {
                                                    should_yield = true;
                                                    break 'meta;
                                                }
                                            }
                                        }
                                    }
                                }
                                CHANNEL_KEY => {
                                    if let Some(filter_list) = &filters.filters {
                                        for filter in filter_list {
                                            if let Filter::Channel(channel_id) = filter {
                                                if value == channel_id.as_slice() {
                                                    should_yield = true;
                                                    break 'meta;
                                                }
                                            }
                                        }
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
                                // Message not found or failed to deserialize - skip it
                                tracing::debug!("Message {} not found or corrupted, skipping", hex::encode(&msg_id));
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
        user_id: KeyId,
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
