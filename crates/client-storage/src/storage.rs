use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zoe_wire_protocol::{Hash, MessageFilters, MessageFull, Tag, VerifyingKey};

#[cfg(any(feature = "mock", test))]
use mockall::{automock, predicate::*};

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

/// Serializable subscription state that can be persisted and restored.
///
/// This state contains all the information needed to restore a MessagesManager
/// to its previous subscription state after a connection restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SubscriptionState {
    /// The latest stream height we've received
    /// Used to resume from the correct position after reconnection
    pub latest_stream_height: Option<String>,

    /// Combined subscription filters accumulated over time
    /// This represents the union of all active subscriptions
    pub current_filters: MessageFilters,
}

impl SubscriptionState {
    /// Create a new empty subscription state
    pub fn new() -> Self {
        Self::default()
    }

    /// Create subscription state with initial filters
    pub fn with_filters(filters: MessageFilters) -> Self {
        Self {
            latest_stream_height: None,
            current_filters: filters,
        }
    }

    /// Add filters to the combined state
    pub fn add_filters(&mut self, new_filters: &[zoe_wire_protocol::Filter]) {
        let current_filters = self.current_filters.filters.get_or_insert_with(Vec::new);
        for filter in new_filters {
            if !current_filters.contains(filter) {
                current_filters.push(filter.clone());
            }
        }
    }

    /// Remove filters from the combined state
    pub fn remove_filters(&mut self, filters_to_remove: &[zoe_wire_protocol::Filter]) {
        if let Some(current_filters) = self.current_filters.filters.as_mut() {
            current_filters.retain(|f| !filters_to_remove.contains(f));
            if current_filters.is_empty() {
                self.current_filters.filters = None;
            }
        }
    }

    /// Update the latest stream height
    pub fn set_stream_height(&mut self, height: String) {
        self.latest_stream_height = Some(height);
    }

    /// Check if we have any active filters
    pub fn has_active_filters(&self) -> bool {
        !self.current_filters.is_empty()
    }
}

/// Sync status for a message on a specific relay
#[derive(Debug, Clone)]
pub struct RelaySyncStatus {
    /// Hash of the relay server's Ed25519 public key (using VerifyingKey.id())
    pub relay_id: Hash,
    /// Global stream ID where the message was confirmed
    pub global_stream_id: String,
    /// Unix timestamp when sync was confirmed
    pub synced_at: u64,
}

/// Trait defining the storage interface for messages
#[cfg_attr(any(feature = "mock", test), automock(type Error = crate::StorageError;))]
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
        relay_id: &Hash,
        global_stream_id: &str,
    ) -> Result<(), Self::Error>;

    /// Get all messages that are not yet synced to a specific relay
    async fn get_unsynced_messages_for_relay(
        &self,
        relay_id: &Hash,
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

    // Subscription state management

    /// Store the subscription state for a specific relay
    async fn store_subscription_state(
        &self,
        relay_id: &Hash,
        state: &SubscriptionState,
    ) -> Result<(), Self::Error>;

    /// Get the subscription state for a specific relay
    async fn get_subscription_state(
        &self,
        relay_id: &Hash,
    ) -> Result<Option<SubscriptionState>, Self::Error>;

    /// Get all stored subscription states (for all relays)
    async fn get_all_subscription_states(
        &self,
    ) -> Result<std::collections::HashMap<Hash, SubscriptionState>, Self::Error>;

    /// Delete subscription state for a specific relay
    async fn delete_subscription_state(&self, relay_id: &Hash) -> Result<bool, Self::Error>;
}

/// Trait defining a key-value storage interface for arbitrary state data.
///
/// This trait provides a generic key-value store for persisting application state
/// using postcard serialization. Keys are byte slices and values are postcard-serialized blobs.
///
/// # Examples
///
/// ```rust,no_run
/// use zoe_client_storage::StateStorage;
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyState {
///     counter: u64,
///     name: String,
/// }
///
/// async fn example(storage: &impl StateStorage) -> Result<(), Box<dyn std::error::Error>> {
///     let state = MyState { counter: 42, name: "test".to_string() };
///     
///     // Store state
///     storage.store(b"my_key", &state).await?;
///     
///     // Retrieve state
///     let retrieved: Option<MyState> = storage.get(b"my_key").await?;
///     assert_eq!(retrieved.unwrap().counter, 42);
///     
///     Ok(())
/// }
/// ```
#[cfg_attr(any(feature = "mock", test), automock(type Error = crate::StorageError;))]
#[async_trait]
pub trait StateStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Store a value under the given key.
    ///
    /// The value will be serialized using postcard before storage.
    /// If a value already exists for the key, it will be overwritten.
    ///
    /// # Arguments
    /// * `key` - The key to store the value under (byte slice)
    /// * `value` - The value to store (must implement Serialize)
    ///
    /// # Errors
    /// Returns an error if serialization fails or storage operation fails.
    async fn store<T>(&self, key: &[u8], value: &T) -> Result<(), Self::Error>
    where
        T: Serialize + Send + Sync + 'static;

    /// Retrieve a value by key.
    ///
    /// The stored blob will be deserialized using postcard.
    ///
    /// # Arguments
    /// * `key` - The key to retrieve the value for (byte slice)
    ///
    /// # Returns
    /// * `Ok(Some(value))` if the key exists and deserialization succeeds
    /// * `Ok(None)` if the key doesn't exist
    /// * `Err(...)` if deserialization fails or storage operation fails
    ///
    /// # Errors
    /// Returns an error if deserialization fails or storage operation fails.
    async fn get<T>(&self, key: &[u8]) -> Result<Option<T>, Self::Error>
    where
        T: for<'de> Deserialize<'de> + Send + Sync + 'static;

    /// Delete a value by key.
    ///
    /// # Arguments
    /// * `key` - The key to delete (byte slice)
    ///
    /// # Returns
    /// * `Ok(true)` if the key existed and was deleted
    /// * `Ok(false)` if the key didn't exist
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn delete(&self, key: &[u8]) -> Result<bool, Self::Error>;

    /// Check if a key exists in storage.
    ///
    /// # Arguments
    /// * `key` - The key to check for existence (byte slice)
    ///
    /// # Returns
    /// * `Ok(true)` if the key exists
    /// * `Ok(false)` if the key doesn't exist
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn has(&self, key: &[u8]) -> Result<bool, Self::Error>;

    /// Get all keys in storage.
    ///
    /// # Returns
    /// A vector of all keys currently stored (as byte vectors).
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn list_keys(&self) -> Result<Vec<Vec<u8>>, Self::Error>;

    /// Clear all data from storage.
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn clear(&self) -> Result<(), Self::Error>;

    /// Get the number of entries in storage.
    ///
    /// # Returns
    /// The total number of key-value pairs stored.
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn count(&self) -> Result<u64, Self::Error>;
}
