use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::{Arc, Mutex};
use zoe_state_machine::{
    execution::{ExecutorError, ExecutorStore},
    messages::SubscriptionState,
};
use zoe_wire_protocol::{Hash, KeyId, MessageFull, MessageId, Tag};

use super::migrations;
use crate::error::{Result, StorageError};
use crate::storage::{
    BlobStorage, BlobUploadStatus, MessageQuery, MessageStorage, RelaySyncStatus, StateStorage,
    StorageConfig, StorageStats,
};

/// SQLite-based message storage with SQLCipher encryption
#[derive(Clone)]
pub struct SqliteMessageStorage {
    conn: Arc<Mutex<Connection>>,
    config: StorageConfig,
}

impl SqliteMessageStorage {
    /// Create a new SQLite storage instance with encryption
    pub async fn new(config: StorageConfig, encryption_key: &[u8; 32]) -> Result<Self> {
        let db_path = &config.database_path;

        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(StorageError::Io)?;
        }

        let mut conn = Connection::open(db_path).map_err(StorageError::Database)?;

        // Set up SQLCipher encryption
        Self::setup_encryption(&mut conn, encryption_key)?;

        // Configure SQLite for optimal performance
        Self::configure_sqlite(&mut conn, &config)?;

        // Run migrations to ensure schema is up to date
        migrations::run_migrations(&mut conn)?;

        // Verify database is accessible
        Self::verify_database_access(&mut conn)?;

        tracing::info!(
            "SQLite message storage initialized at: {}",
            db_path.display()
        );

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            config,
        })
    }

    /// Set up SQLCipher encryption on the database connection
    fn setup_encryption(conn: &mut Connection, encryption_key: &[u8; 32]) -> Result<()> {
        let key_hex = hex::encode(encryption_key);

        // Set the encryption key using execute_batch for PRAGMA commands
        conn.execute_batch(&format!("PRAGMA key = '{key_hex}';"))
            .map_err(|e| StorageError::Encryption(format!("Failed to set encryption key: {e}")))?;

        // Verify we can access the database (will fail if wrong key)
        let _count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(|e| {
                StorageError::Encryption(format!(
                    "Database access verification failed - invalid key?: {e}"
                ))
            })?;

        tracing::debug!("Database encryption configured successfully");
        Ok(())
    }

    /// Configure SQLite for optimal performance in embedded/mobile scenarios
    fn configure_sqlite(conn: &mut Connection, config: &StorageConfig) -> Result<()> {
        let mut pragma_statements = vec![
            "PRAGMA foreign_keys = ON".to_string(), // Enable foreign key constraints
            "PRAGMA temp_store = memory".to_string(), // Store temp tables in RAM
        ];

        // Configure WAL mode if enabled
        if config.enable_wal_mode {
            pragma_statements.push("PRAGMA journal_mode = WAL".to_string());
            pragma_statements.push("PRAGMA synchronous = NORMAL".to_string());
        } else {
            pragma_statements.push("PRAGMA synchronous = FULL".to_string());
        }

        // Set cache size if configured
        if let Some(cache_size_kb) = config.cache_size_kb {
            // SQLite cache_size is in pages, negative value means KB
            pragma_statements.push(format!("PRAGMA cache_size = -{cache_size_kb}"));
        }

        // Memory mapping for better performance (128MB)
        pragma_statements.push("PRAGMA mmap_size = 134217728".to_string());

        // Execute all pragma statements
        for pragma in pragma_statements {
            conn.execute_batch(&format!("{pragma};"))
                .map_err(StorageError::Database)?;
            tracing::debug!("Applied: {}", pragma);
        }

        Ok(())
    }

    /// Verify database is accessible and has expected schema
    fn verify_database_access(conn: &mut Connection) -> Result<()> {
        // Check that required tables exist
        let required_tables = [
            "messages",
            "storage_metadata",
            "tag_events",
            "tag_users",
            "tag_channels",
        ];

        let table_names = required_tables
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(",");

        let table_count: i32 = conn
            .prepare(&format!(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ({table_names})"
            ))
            .map_err(StorageError::Database)?
            .query_row([], |row| row.get(0))
            .map_err(StorageError::Database)?;

        if table_count < required_tables.len() as i32 {
            return Err(StorageError::Internal(format!(
                "Required tables not found - expected {}, found {}. Migration may have failed",
                required_tables.len(),
                table_count
            )));
        }

        tracing::debug!(
            "Database access verification successful - found all {} required tables",
            table_count
        );
        Ok(())
    }

    /// Build complete SQL query and parameters for message queries using tag tables
    fn build_query_sql(
        query: &MessageQuery,
        config: &StorageConfig,
    ) -> Result<(String, Vec<Box<dyn rusqlite::ToSql>>)> {
        let mut joins = Vec::new();
        let mut conditions = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        // Handle tag filtering with appropriate joins
        if let Some(tag) = &query.tag {
            match tag {
                Tag::Event { id: event_id, .. } => {
                    joins.push("INNER JOIN tag_events te ON m.id = te.message_id".to_string());
                    conditions.push("te.event_id = ?".to_string());
                    params.push(Box::new(event_id.as_bytes().to_vec()));
                }
                Tag::User { id: user_id, .. } => {
                    joins.push("INNER JOIN tag_users tu ON m.id = tu.message_id".to_string());
                    conditions.push("tu.user_id = ?".to_string());
                    params.push(Box::new(*user_id));
                }
                Tag::Channel { id: channel_id, .. } => {
                    joins.push("INNER JOIN tag_channels tc ON m.id = tc.message_id".to_string());
                    conditions.push("tc.group_id = ?".to_string());
                    params.push(Box::new(channel_id.clone()));
                }
                Tag::Protected => {
                    // Protected tag requires deserializing message data - handled post-query
                    // For now, we don't add any specific join/condition
                }
            }
        }

        // Handle author filtering
        if let Some(author) = &query.author {
            conditions.push("m.author = ?".to_string());
            params.push(Box::new(
                author.to_bytes().expect("Failed to serialize author key"),
            ));
        }

        // Handle timestamp filtering
        if let Some(after_timestamp) = query.after_timestamp {
            conditions.push("m.timestamp >= ?".to_string());
            params.push(Box::new(after_timestamp as i64));
        }

        if let Some(before_timestamp) = query.before_timestamp {
            conditions.push("m.timestamp <= ?".to_string());
            params.push(Box::new(before_timestamp as i64));
        }

        // Build the complete SQL
        let joins_clause = if joins.is_empty() {
            String::new()
        } else {
            format!(" {}", joins.join(" "))
        };

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };

        let order_clause = if query.ascending {
            " ORDER BY m.timestamp ASC"
        } else {
            " ORDER BY m.timestamp DESC"
        };

        let limit = query
            .limit
            .unwrap_or(config.max_query_limit.unwrap_or(1000));
        let offset = query.offset.unwrap_or(0);

        // Add limit and offset parameters
        params.push(Box::new(limit));
        params.push(Box::new(offset));

        let sql = format!(
            "SELECT DISTINCT m.data FROM messages m{joins_clause}{where_clause}{order_clause} LIMIT ? OFFSET ?"
        );

        Ok((sql, params))
    }
}

#[async_trait]
impl MessageStorage for SqliteMessageStorage {
    async fn store_message(&self, message: &MessageFull) -> Result<bool> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let id = message.id().as_bytes();

        // Check if message already exists
        let exists = conn
            .prepare("SELECT 1 FROM messages WHERE id = ?")?
            .query_row(params![id], |_| Ok(true))
            .optional()?
            .is_some();

        if exists {
            // already stored, nothing else to do here
            return Ok(true);
        }

        // Serialize the entire message for key-value storage
        let data = postcard::to_stdvec(message)?;

        // Extract fields for indexing
        let (author, timestamp, tags) = match message.message() {
            zoe_wire_protocol::Message::MessageV0(msg) => {
                let author = msg.sender.encode().as_slice().to_vec();
                let timestamp = msg.when as i64;
                (author, timestamp, &msg.tags)
            }
        };

        // Start transaction for atomic updates
        let tx = conn.savepoint()?;

        // Store the message in key-value format
        tx.execute(
            "INSERT OR REPLACE INTO messages (id, data, author, timestamp) VALUES (?, ?, ?, ?)",
            params![id, data, author, timestamp],
        )?;

        // Insert tag entries
        for tag in tags {
            match tag {
                Tag::Event { id: event_id, .. } => {
                    tx.execute(
                        "INSERT OR REPLACE INTO tag_events (message_id, event_id) VALUES (?, ?)",
                        params![id, event_id.as_bytes()],
                    )?;
                }
                Tag::User { id: user_id, .. } => {
                    tx.execute(
                        "INSERT OR REPLACE INTO tag_users (message_id, user_id) VALUES (?, ?)",
                        params![id, user_id],
                    )?;
                }
                Tag::Channel { id: channel_id, .. } => {
                    tx.execute(
                        "INSERT OR REPLACE INTO tag_channels (message_id, channel_id) VALUES (?, ?)",
                        params![id, channel_id],
                    )?;
                }
                Tag::Protected => {
                    // Protected tag isn't indexed for
                }
            }
        }

        tx.commit()?;
        tracing::debug!(message_id = %message.id(), "Stored message");
        Ok(false)
    }

    async fn get_message(&self, id: &MessageId) -> Result<Option<MessageFull>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let result = conn
            .prepare("SELECT data FROM messages WHERE id = ?")?
            .query_row(params![id.as_bytes()], |row| {
                let data: Vec<u8> = row.get("data")?;
                Ok(data)
            })
            .optional()?;

        match result {
            Some(data) => {
                let message: MessageFull = postcard::from_bytes(&data)?;
                Ok(Some(message))
            }
            None => Ok(None),
        }
    }

    async fn delete_message(&self, id: &MessageId) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        // Delete from messages table - foreign key constraints will cascade to tag tables
        let changes = conn.execute("DELETE FROM messages WHERE id = ?", params![id.as_bytes()])?;

        Ok(changes > 0)
    }

    async fn query_messages(&self, query: &MessageQuery) -> Result<Vec<MessageFull>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let (sql, params) = Self::build_query_sql(query, &self.config)?;
        let mut stmt = conn.prepare(&sql)?;

        // Convert dynamic parameters to rusqlite-compatible format
        let param_refs: Vec<&dyn rusqlite::ToSql> = params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt.query_map(&*param_refs, |row| {
            let data: Vec<u8> = row.get("data")?;
            Ok(data)
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let data = row?;
            let message: MessageFull = postcard::from_bytes(&data)?;

            // Handle Protected tag filtering (requires post-query filtering)
            if let Some(target_tag) = &query.tag
                && matches!(target_tag, Tag::Protected)
                && !message.tags().contains(target_tag)
            {
                continue;
            }

            messages.push(message);
        }

        Ok(messages)
    }

    async fn get_message_count(&self) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let count: i64 = conn
            .prepare("SELECT COUNT(*) FROM messages")?
            .query_row([], |row| row.get(0))?;

        Ok(count as u64)
    }

    async fn get_storage_stats(&self) -> Result<StorageStats> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let message_count: i64 = conn
            .prepare("SELECT COUNT(*) FROM messages")?
            .query_row([], |row| row.get(0))?;

        let unique_authors: i64 = conn
            .prepare("SELECT COUNT(DISTINCT author) FROM messages")?
            .query_row([], |row| row.get(0))?;

        let (oldest_timestamp, newest_timestamp): (Option<i64>, Option<i64>) = conn
            .prepare("SELECT MIN(timestamp), MAX(timestamp) FROM messages")?
            .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))?;

        // Get database file size
        let storage_size_bytes = std::fs::metadata(&self.config.database_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(StorageStats {
            message_count: message_count as u64,
            storage_size_bytes,
            unique_authors: unique_authors as u64,
            oldest_message_timestamp: oldest_timestamp.map(|t| t as u64),
            newest_message_timestamp: newest_timestamp.map(|t| t as u64),
        })
    }

    async fn clear_all_messages(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        conn.execute("DELETE FROM messages", [])?;
        tracing::info!("Cleared all messages from storage");
        Ok(())
    }

    async fn get_storage_size(&self) -> Result<u64> {
        let size = std::fs::metadata(&self.config.database_path)
            .map(|m| m.len())
            .unwrap_or(0);
        Ok(size)
    }

    async fn maintenance(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        // Run VACUUM to reclaim space and optimize database
        conn.execute("VACUUM", [])?;

        // Analyze tables for query optimization
        conn.execute("ANALYZE", [])?;

        tracing::info!("Database maintenance completed");
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        // Simple query to verify database is accessible
        match conn.query_row("SELECT 1", [], |_| Ok(())) {
            Ok(_) => Ok(true),
            Err(e) => {
                tracing::error!("Health check failed: {}", e);
                Ok(false)
            }
        }
    }

    async fn mark_message_synced(
        &self,
        message_id: &MessageId,
        relay_id: &KeyId,
        global_stream_id: &str,
    ) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let message_id_bytes = message_id.as_bytes();
        let relay_id_bytes = relay_id.as_bytes();

        conn.execute(
            "INSERT OR REPLACE INTO relay_sync_status (message_id, relay_id, global_stream_id) VALUES (?1, ?2, ?3)",
            params![message_id_bytes, &relay_id_bytes[..], global_stream_id],
        )?;

        tracing::debug!(
            "Marked message {} as synced to relay {} with stream ID {}",
            hex::encode(message_id_bytes),
            hex::encode(relay_id_bytes),
            global_stream_id
        );

        Ok(())
    }

    async fn get_unsynced_messages_for_relay(
        &self,
        relay_id: &KeyId,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();
        let limit_clause = if let Some(l) = limit {
            format!(" LIMIT {l}")
        } else if let Some(default_limit) = self.config.max_query_limit {
            format!(" LIMIT {default_limit}")
        } else {
            String::new()
        };

        let query = format!(
            "SELECT m.data FROM messages m 
             LEFT JOIN relay_sync_status r ON m.id = r.message_id AND r.relay_id = ?1
             WHERE r.message_id IS NULL
             ORDER BY m.timestamp DESC{limit_clause}"
        );

        let mut stmt = conn.prepare(&query)?;
        let message_iter = stmt.query_map(params![&relay_id_bytes[..]], |row| {
            let data: Vec<u8> = row.get(0)?;
            Ok(data)
        })?;

        let mut messages = Vec::new();
        for message_result in message_iter {
            let data = message_result?;
            let message: MessageFull =
                postcard::from_bytes(&data).map_err(StorageError::Serialization)?;
            messages.push(message);
        }

        tracing::debug!(
            "Found {} unsynced messages for relay {}",
            messages.len(),
            hex::encode(relay_id_bytes)
        );

        Ok(messages)
    }

    async fn get_message_sync_status(
        &self,
        message_id: &MessageId,
    ) -> Result<Vec<RelaySyncStatus>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let message_id_bytes = message_id.as_bytes();

        let mut stmt = conn.prepare(
            "SELECT relay_id, global_stream_id, synced_at FROM relay_sync_status WHERE message_id = ?1"
        )?;

        let sync_iter = stmt.query_map(params![message_id_bytes], |row| {
            let relay_id_bytes: Vec<u8> = row.get(0)?;
            let global_stream_id: String = row.get(1)?;
            let synced_at: i64 = row.get(2)?;
            Ok((relay_id_bytes, global_stream_id, synced_at))
        })?;

        let mut sync_statuses = Vec::new();
        for sync_result in sync_iter {
            let (relay_id_bytes, global_stream_id, synced_at) = sync_result?;

            let relay_id = if relay_id_bytes.len() == 32 {
                let mut array = [0u8; 32];
                array.copy_from_slice(&relay_id_bytes);
                KeyId::from_bytes(array)
            } else {
                return Err(StorageError::Internal(format!(
                    "Invalid relay ID length: expected 32 bytes, got {}",
                    relay_id_bytes.len()
                )));
            };

            sync_statuses.push(RelaySyncStatus {
                relay_id,
                global_stream_id,
                synced_at: synced_at as u64,
            });
        }

        Ok(sync_statuses)
    }

    // Subscription state management methods

    async fn store_subscription_state(
        &self,
        relay_id: &KeyId,
        state: &SubscriptionState,
    ) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();
        let state_data = postcard::to_stdvec(state).map_err(|e| {
            StorageError::Internal(format!("Failed to serialize subscription state: {e}"))
        })?;

        conn.execute(
            "INSERT OR REPLACE INTO subscription_states (relay_id, state_data, updated_at) VALUES (?1, ?2, strftime('%s', 'now'))",
            params![&relay_id_bytes[..], state_data],
        )?;

        tracing::debug!(
            "Stored subscription state for relay {}",
            hex::encode(relay_id_bytes)
        );

        Ok(())
    }

    async fn get_subscription_state(&self, relay_id: &KeyId) -> Result<Option<SubscriptionState>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();

        let mut stmt =
            conn.prepare("SELECT state_data FROM subscription_states WHERE relay_id = ?1")?;

        let result = stmt.query_row(params![&relay_id_bytes[..]], |row| {
            let state_data: Vec<u8> = row.get(0)?;
            Ok(state_data)
        });

        match result {
            Ok(state_data) => {
                let state = postcard::from_bytes(&state_data).map_err(|e| {
                    StorageError::Internal(format!("Failed to deserialize subscription state: {e}"))
                })?;
                Ok(Some(state))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Database(e)),
        }
    }

    async fn get_all_subscription_states(
        &self,
    ) -> Result<std::collections::HashMap<KeyId, SubscriptionState>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT relay_id, state_data FROM subscription_states ORDER BY updated_at DESC",
        )?;

        let state_iter = stmt.query_map([], |row| {
            let relay_id_bytes: Vec<u8> = row.get(0)?;
            let state_data: Vec<u8> = row.get(1)?;
            Ok((relay_id_bytes, state_data))
        })?;

        let mut states = std::collections::HashMap::new();
        for state_result in state_iter {
            let (relay_id_bytes, state_data) = state_result?;

            let relay_id = if relay_id_bytes.len() == 32 {
                let mut array = [0u8; 32];
                array.copy_from_slice(&relay_id_bytes);
                KeyId::from_bytes(array)
            } else {
                return Err(StorageError::Internal(format!(
                    "Invalid relay ID length: expected 32 bytes, got {}",
                    relay_id_bytes.len()
                )));
            };

            let state = postcard::from_bytes(&state_data).map_err(|e| {
                StorageError::Internal(format!("Failed to deserialize subscription state: {e}"))
            })?;

            states.insert(relay_id, state);
        }

        Ok(states)
    }

    async fn delete_subscription_state(&self, relay_id: &KeyId) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();

        let rows_affected = conn.execute(
            "DELETE FROM subscription_states WHERE relay_id = ?1",
            params![&relay_id_bytes[..]],
        )?;

        tracing::debug!(
            "Deleted subscription state for relay {}, rows affected: {}",
            hex::encode(relay_id_bytes),
            rows_affected
        );

        Ok(rows_affected > 0)
    }
}

#[async_trait]
impl StateStorage for SqliteMessageStorage {
    async fn store<T>(&self, namespace: &crate::StateNamespace, key: &[u8], value: &T) -> Result<()>
    where
        T: serde::Serialize + Send + Sync + 'static,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let value_data = postcard::to_stdvec(value)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize state value: {e}")))?;

        let namespace_blob = postcard::to_stdvec(namespace)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize namespace: {e}")))?;

        conn.execute(
            "INSERT OR REPLACE INTO state_storage (namespace, key, value_data, updated_at) VALUES (?1, ?2, ?3, strftime('%s', 'now'))",
            params![namespace_blob, key, value_data],
        )?;

        tracing::debug!(
            "Stored state for namespace {:?}, key: {:?}",
            namespace_blob,
            key
        );

        Ok(())
    }

    async fn get<T>(&self, namespace: &crate::StateNamespace, key: &[u8]) -> Result<Option<T>>
    where
        T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let namespace_blob = postcard::to_stdvec(namespace)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize namespace: {e}")))?;

        let mut stmt =
            conn.prepare("SELECT value_data FROM state_storage WHERE namespace = ?1 AND key = ?2")?;

        let result = stmt.query_row(params![namespace_blob, key], |row| {
            let value_data: Vec<u8> = row.get(0)?;
            Ok(value_data)
        });

        match result {
            Ok(value_data) => {
                let value = postcard::from_bytes(&value_data).map_err(|e| {
                    StorageError::Internal(format!("Failed to deserialize state value: {e}"))
                })?;
                Ok(Some(value))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(StorageError::Database(e)),
        }
    }

    async fn delete(&self, namespace: &crate::StateNamespace, key: &[u8]) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let namespace_blob = postcard::to_stdvec(namespace)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize namespace: {e}")))?;

        let rows_affected = conn.execute(
            "DELETE FROM state_storage WHERE namespace = ?1 AND key = ?2",
            params![namespace_blob, key],
        )?;

        tracing::debug!(
            "Deleted state for namespace {:?}, key: {:?}, rows affected: {}",
            namespace_blob,
            key,
            rows_affected
        );

        Ok(rows_affected > 0)
    }

    async fn has(&self, namespace: &crate::StateNamespace, key: &[u8]) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let namespace_blob = postcard::to_stdvec(namespace)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize namespace: {e}")))?;

        let mut stmt =
            conn.prepare("SELECT 1 FROM state_storage WHERE namespace = ?1 AND key = ?2")?;

        let exists = stmt
            .query_row(params![namespace_blob, key], |_| Ok(()))
            .optional()?;

        Ok(exists.is_some())
    }

    async fn list_keys(&self) -> Result<Vec<Vec<u8>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let mut stmt = conn.prepare("SELECT key FROM state_storage ORDER BY key")?;

        let key_iter = stmt.query_map([], |row| {
            let key: Vec<u8> = row.get(0)?;
            Ok(key)
        })?;

        let mut keys = Vec::new();
        for key_result in key_iter {
            keys.push(key_result?);
        }

        Ok(keys)
    }

    async fn list_keys_in_namespace(
        &self,
        namespace: &crate::StateNamespace,
    ) -> Result<Vec<Vec<u8>>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let namespace_blob = postcard::to_stdvec(namespace)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize namespace: {e}")))?;

        let mut stmt =
            conn.prepare("SELECT key FROM state_storage WHERE namespace = ?1 ORDER BY key")?;

        let key_iter = stmt.query_map([namespace_blob], |row| {
            let key: Vec<u8> = row.get(0)?;
            Ok(key)
        })?;

        let mut keys = Vec::new();
        for key_result in key_iter {
            keys.push(key_result?);
        }

        Ok(keys)
    }

    async fn list_namespace_data<T>(
        &self,
        namespace: &crate::StateNamespace,
    ) -> Result<Vec<(Vec<u8>, T)>>
    where
        T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let namespace_blob = postcard::to_stdvec(namespace)
            .map_err(|e| StorageError::Internal(format!("Failed to serialize namespace: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT key, value_data FROM state_storage WHERE namespace = ?1 ORDER BY key",
        )?;

        Ok(stmt
            .query_map([namespace_blob], |row| {
                let key: Vec<u8> = row.get(0)?;
                let value_data: Vec<u8> = row.get(1)?;
                Ok((key, value_data))
            })?
            .filter_map(|data| {
                let (key, value_data) = match data {
                    Ok(data) => data,
                    Err(e) => {
                        tracing::error!(error=?e, "Failed to read data from state storage");
                        return None;
                    }
                };
                let value = match postcard::from_bytes(&value_data) {
                    Ok(value) => value,
                    Err(e) => {
                        tracing::error!(error=?e, "Failed to deserialize state value");
                        return None;
                    }
                };
                Some((key, value))
            })
            .collect::<Vec<_>>())
    }

    async fn clear(&self) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let rows_affected = conn.execute("DELETE FROM state_storage", [])?;

        tracing::debug!("Cleared all state data, rows affected: {}", rows_affected);

        Ok(())
    }

    async fn count(&self) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM state_storage", [], |row| row.get(0))?;

        Ok(count as u64)
    }
}

#[async_trait]
impl BlobStorage for SqliteMessageStorage {
    async fn mark_blob_uploaded(
        &self,
        blob_hash: &Hash,
        relay_id: &KeyId,
        blob_size: u64,
    ) -> Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let blob_hash_bytes = blob_hash.as_bytes();
        let relay_id_bytes = relay_id.as_bytes();

        conn.execute(
            "INSERT OR REPLACE INTO blob_upload_status (blob_hash, relay_id, blob_size, uploaded_at) VALUES (?1, ?2, ?3, strftime('%s', 'now'))",
            params![&blob_hash_bytes[..], &relay_id_bytes[..], blob_size as i64],
        )?;

        tracing::debug!(
            "Marked blob {} as uploaded to relay {} (size: {} bytes)",
            hex::encode(blob_hash_bytes),
            hex::encode(relay_id_bytes),
            blob_size
        );

        Ok(())
    }

    async fn is_blob_uploaded(&self, blob_hash: &Hash, relay_id: &KeyId) -> Result<bool> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let blob_hash_bytes = blob_hash.as_bytes();
        let relay_id_bytes = relay_id.as_bytes();

        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM blob_upload_status WHERE blob_hash = ?1 AND relay_id = ?2",
                params![&blob_hash_bytes[..], &relay_id_bytes[..]],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);

        Ok(exists)
    }

    async fn get_unuploaded_blobs_for_relay(
        &self,
        relay_id: &KeyId,
        _limit: Option<usize>,
    ) -> Result<Vec<Hash>> {
        let _conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();

        // This is a placeholder implementation - in a real system, you'd need to track
        // all blobs that should be uploaded (perhaps from a separate blobs table)
        // For now, we return an empty list since we don't have a comprehensive blob registry
        tracing::warn!(
            "get_unuploaded_blobs_for_relay called for relay {} - returning empty list (no blob registry)",
            hex::encode(relay_id_bytes)
        );

        Ok(Vec::new())
    }

    async fn get_blob_upload_status(&self, blob_hash: &Hash) -> Result<Vec<BlobUploadStatus>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let mut stmt = conn.prepare(
            "SELECT blob_hash, relay_id, uploaded_at, blob_size FROM blob_upload_status WHERE blob_hash = ?1"
        )?;

        let blob_hash_bytes = blob_hash.as_bytes();
        let status_iter = stmt.query_map(params![&blob_hash_bytes[..]], |row| {
            let blob_hash_bytes: Vec<u8> = row.get(0)?;
            let relay_id_bytes: Vec<u8> = row.get(1)?;
            let uploaded_at: i64 = row.get(2)?;
            let blob_size: i64 = row.get(3)?;

            let blob_hash = if blob_hash_bytes.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&blob_hash_bytes);
                Hash::from(bytes)
            } else {
                return Err(rusqlite::Error::InvalidColumnType(
                    0,
                    "blob_hash".to_string(),
                    rusqlite::types::Type::Blob,
                ));
            };

            let relay_id = if relay_id_bytes.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&relay_id_bytes);
                KeyId(Hash::from(bytes))
            } else {
                return Err(rusqlite::Error::InvalidColumnType(
                    1,
                    "relay_id".to_string(),
                    rusqlite::types::Type::Blob,
                ));
            };

            Ok(BlobUploadStatus {
                blob_hash,
                relay_id,
                uploaded_at: uploaded_at as u64,
                blob_size: blob_size as u64,
            })
        })?;

        let mut statuses = Vec::new();
        for status in status_iter {
            statuses.push(status?);
        }

        Ok(statuses)
    }

    async fn get_uploaded_blobs_for_relay(
        &self,
        relay_id: &Hash,
        limit: Option<usize>,
    ) -> Result<Vec<BlobUploadStatus>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();
        let limit_clause = limit.map(|l| format!(" LIMIT {l}")).unwrap_or_default();

        let query = format!(
            "SELECT blob_hash, relay_id, uploaded_at, blob_size FROM blob_upload_status WHERE relay_id = ?1 ORDER BY uploaded_at DESC{limit_clause}"
        );

        let mut stmt = conn.prepare(&query)?;

        let status_iter = stmt.query_map(params![&relay_id_bytes[..]], |row| {
            let blob_hash_bytes: Vec<u8> = row.get(0)?;
            let relay_id_bytes: Vec<u8> = row.get(1)?;
            let uploaded_at: i64 = row.get(2)?;
            let blob_size: i64 = row.get(3)?;

            let blob_hash = if blob_hash_bytes.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&blob_hash_bytes);
                Hash::from(bytes)
            } else {
                return Err(rusqlite::Error::InvalidColumnType(
                    0,
                    "blob_hash".to_string(),
                    rusqlite::types::Type::Blob,
                ));
            };

            let relay_id = if relay_id_bytes.len() == 32 {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(&relay_id_bytes);
                KeyId(Hash::from(bytes))
            } else {
                return Err(rusqlite::Error::InvalidColumnType(
                    1,
                    "relay_id".to_string(),
                    rusqlite::types::Type::Blob,
                ));
            };

            Ok(BlobUploadStatus {
                blob_hash,
                relay_id,
                uploaded_at: uploaded_at as u64,
                blob_size: blob_size as u64,
            })
        })?;

        let mut statuses = Vec::new();
        for status in status_iter {
            statuses.push(status?);
        }

        Ok(statuses)
    }

    async fn remove_blob_upload_record(
        &self,
        blob_hash: &Hash,
        relay_id: Option<KeyId>,
    ) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let blob_hash_bytes = blob_hash.as_bytes();
        let rows_affected = if let Some(relay_id) = relay_id {
            let relay_id_bytes = relay_id.as_bytes();
            conn.execute(
                "DELETE FROM blob_upload_status WHERE blob_hash = ?1 AND relay_id = ?2",
                params![&blob_hash_bytes[..], &relay_id_bytes[..]],
            )?
        } else {
            conn.execute(
                "DELETE FROM blob_upload_status WHERE blob_hash = ?1",
                params![&blob_hash_bytes[..]],
            )?
        };

        tracing::debug!(
            "Removed {} blob upload records for hash {}",
            rows_affected,
            hex::encode(blob_hash_bytes)
        );

        Ok(rows_affected as u64)
    }

    async fn get_uploaded_blob_count_for_relay(&self, relay_id: &KeyId) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blob_upload_status WHERE relay_id = ?1",
            params![&relay_id_bytes[..]],
            |row| row.get(0),
        )?;

        Ok(count as u64)
    }

    async fn get_uploaded_blob_size_for_relay(&self, relay_id: &KeyId) -> Result<u64> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| StorageError::Internal(format!("Failed to acquire database lock: {e}")))?;

        let relay_id_bytes = relay_id.as_bytes();

        let total_size: Option<i64> = conn.query_row(
            "SELECT SUM(blob_size) FROM blob_upload_status WHERE relay_id = ?1",
            params![&relay_id_bytes[..]],
            |row| row.get(0),
        )?;

        Ok(total_size.unwrap_or(0) as u64)
    }
}

// ============================================================================
// ExecutorStore Implementation
// ============================================================================

#[async_trait]
impl ExecutorStore for SqliteMessageStorage {
    type Error = crate::error::StorageError;

    /// Save any serializable data to storage using postcard serialization
    async fn save<K, T>(
        &self,
        id: K,
        data: &T,
    ) -> std::result::Result<(), <Self as ExecutorStore>::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::Serialize + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&id)?;
        let data_bytes = postcard::to_stdvec(data)?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO executor_models (model_id, model_data, updated_at) 
             VALUES (?1, ?2, strftime('%s', 'now'))",
            params![&id_bytes[..], &data_bytes[..]],
        )?;

        Ok(())
    }

    /// Load any deserializable data by ID using postcard deserialization
    async fn load<K, T>(
        &self,
        id: K,
    ) -> std::result::Result<Option<T>, <Self as ExecutorStore>::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&id)?;

        let conn = self.conn.lock().unwrap();
        let data_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT model_data FROM executor_models WHERE model_id = ?1",
                params![&id_bytes[..]],
                |row| row.get(0),
            )
            .optional()?;

        match data_bytes {
            Some(bytes) => {
                let data = postcard::from_bytes(&bytes)?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Load multiple items by their IDs
    async fn load_many<K, T>(
        &self,
        ids: &[K],
    ) -> std::result::Result<Vec<Option<T>>, <Self as ExecutorStore>::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        let mut results = Vec::with_capacity(ids.len());

        // Load each ID individually (could be optimized with a single query later)
        for id in ids {
            let result = self.load(id).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Load index data by list ID using postcard deserialization
    async fn load_index<K, D>(
        &self,
        list_id: K,
    ) -> std::result::Result<Option<D>, <Self as ExecutorStore>::Error>
    where
        K: serde::Serialize + Send + Sync,
        D: serde::de::DeserializeOwned + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&list_id)?;

        let conn = self.conn.lock().unwrap();
        let data_bytes: Option<Vec<u8>> = conn
            .query_row(
                "SELECT index_data FROM executor_indexes WHERE index_id = ?1",
                params![&id_bytes[..]],
                |row| row.get(0),
            )
            .optional()?;

        match data_bytes {
            Some(bytes) => {
                let data = postcard::from_bytes(&bytes)?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Store index data by list ID using postcard serialization
    async fn store_index<K, D>(
        &self,
        list_id: K,
        index_data: &D,
    ) -> std::result::Result<(), <Self as ExecutorStore>::Error>
    where
        K: serde::Serialize + Send + Sync,
        D: serde::Serialize + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&list_id)?;
        let data_bytes = postcard::to_stdvec(index_data)?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO executor_indexes (index_id, index_data, updated_at) 
             VALUES (?1, ?2, strftime('%s', 'now'))",
            params![&id_bytes[..], &data_bytes[..]],
        )?;

        Ok(())
    }
}

// Implement Into<ExecutorError> for StorageError to enable seamless error conversion
impl From<crate::error::StorageError> for ExecutorError {
    fn from(val: crate::error::StorageError) -> Self {
        ExecutorError::StorageError(val.to_string())
    }
}
