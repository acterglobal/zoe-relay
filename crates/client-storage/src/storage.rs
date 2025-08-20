use async_trait::async_trait;
use std::path::PathBuf;
use zoe_wire_protocol::{Hash, MessageFull, Tag, VerifyingKey};

/// Configuration for storage implementations
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Path to the database file (SQLite) or database name (IndexedDB)
    pub database_path: PathBuf,
    /// Maximum number of messages to return in queries (default: 1000)
    pub max_query_limit: Option<usize>,
    /// Enable WAL mode for SQLite (default: true)
    pub enable_wal_mode: bool,
    /// Cache size in KB for SQLite (default: 64MB)
    pub cache_size_kb: Option<i32>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("messages.db"),
            max_query_limit: Some(1000),
            enable_wal_mode: true,
            cache_size_kb: Some(64 * 1024), // 64MB
        }
    }
}

/// Query parameters for message retrieval
#[derive(Debug, Clone, Default)]
pub struct MessageQuery {
    /// Filter by message author
    pub author: Option<VerifyingKey>,
    /// Filter by specific tag
    pub tag: Option<Tag>,
    /// Messages after this timestamp (inclusive)
    pub after_timestamp: Option<u64>,
    /// Messages before this timestamp (inclusive)
    pub before_timestamp: Option<u64>,
    /// Maximum number of results to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Sort order (true = ascending, false = descending by timestamp)
    pub ascending: bool,
}

/// Statistics about the storage
#[derive(Debug, Clone)]
pub struct StorageStats {
    /// Total number of messages stored
    pub message_count: u64,
    /// Total storage size in bytes
    pub storage_size_bytes: u64,
    /// Number of unique authors
    pub unique_authors: u64,
    /// Oldest message timestamp
    pub oldest_message_timestamp: Option<u64>,
    /// Newest message timestamp
    pub newest_message_timestamp: Option<u64>,
}

/// Sync status for a message on a specific relay
#[derive(Debug, Clone)]
pub struct RelaySyncStatus {
    /// Ed25519 public key of the relay server
    pub relay_pubkey: VerifyingKey,
    /// Global stream ID where the message was confirmed
    pub global_stream_id: String,
    /// Unix timestamp when sync was confirmed
    pub synced_at: u64,
}

/// Trait defining the storage interface for messages
#[async_trait]
pub trait MessageStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Store a new message or update an existing one
    async fn store_message(&self, message: &MessageFull) -> Result<(), Self::Error>;

    /// Retrieve a message by its ID
    async fn get_message(&self, id: &Hash) -> Result<Option<MessageFull>, Self::Error>;

    /// Delete a message by its ID
    async fn delete_message(&self, id: &Hash) -> Result<bool, Self::Error>;

    /// Query messages with various filters
    async fn query_messages(&self, query: &MessageQuery) -> Result<Vec<MessageFull>, Self::Error>;

    /// Mark a message as synced to a relay with its global stream ID
    async fn mark_message_synced(
        &self,
        message_id: &Hash,
        relay_pubkey: &VerifyingKey,
        global_stream_id: &str,
    ) -> Result<(), Self::Error>;

    /// Get all messages that are not yet synced to a specific relay
    async fn get_unsynced_messages_for_relay(
        &self,
        relay_pubkey: &VerifyingKey,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>, Self::Error>;

    /// Get sync status for a specific message across all relays
    async fn get_message_sync_status(
        &self,
        message_id: &Hash,
    ) -> Result<Vec<RelaySyncStatus>, Self::Error>;

    /// Get messages by author with optional limit
    async fn get_messages_by_author(
        &self,
        author: &VerifyingKey,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>, Self::Error> {
        let query = MessageQuery {
            author: Some(author.clone()),
            limit,
            ..Default::default()
        };
        self.query_messages(&query).await
    }

    /// Get messages by tag with optional limit
    async fn get_messages_by_tag(
        &self,
        tag: &Tag,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>, Self::Error> {
        let query = MessageQuery {
            tag: Some(tag.clone()),
            limit,
            ..Default::default()
        };
        self.query_messages(&query).await
    }

    /// Get messages since a specific timestamp
    async fn get_messages_since(
        &self,
        timestamp: u64,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>, Self::Error> {
        let query = MessageQuery {
            after_timestamp: Some(timestamp),
            limit,
            ..Default::default()
        };
        self.query_messages(&query).await
    }

    /// Get the total number of stored messages
    async fn get_message_count(&self) -> Result<u64, Self::Error>;

    /// Get storage statistics
    async fn get_storage_stats(&self) -> Result<StorageStats, Self::Error>;

    /// Clear all messages from storage
    async fn clear_all_messages(&self) -> Result<(), Self::Error>;

    /// Get the storage size in bytes
    async fn get_storage_size(&self) -> Result<u64, Self::Error>;

    /// Perform storage maintenance (e.g., VACUUM for SQLite)
    async fn maintenance(&self) -> Result<(), Self::Error>;

    /// Check if storage is healthy and accessible
    async fn health_check(&self) -> Result<bool, Self::Error>;
}
