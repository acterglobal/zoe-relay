use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zoe_state_machine::messages::SubscriptionState;
use zoe_wire_protocol::{Hash, KeyId, MessageFull, MessageId, Tag, VerifyingKey};

#[cfg(any(feature = "mock", test))]
use mockall::{automock, predicate::*};

/// Namespace for organizing different types of state data in storage.
///
/// This enum provides a type-safe way to categorize and query state data
/// by namespace, enabling efficient retrieval of related data without
/// scanning all keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateNamespace {
    /// PQXDH protocol session states for a specific verification key
    PqxdhSession(zoe_wire_protocol::KeyId),
    /// Group encryption session states for a specific client key
    GroupSession(zoe_wire_protocol::KeyId),
    // Any other namespace
    Custom(Vec<u8>),
}

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
    /// ID of the relay server (using VerifyingKey.id())
    pub relay_id: KeyId,
    /// Global stream ID where the message was confirmed
    pub global_stream_id: String,
    /// Unix timestamp when sync was confirmed
    pub synced_at: u64,
}

/// Upload status for a blob on a specific relay
#[derive(Debug, Clone)]
pub struct BlobUploadStatus {
    /// Hash of the blob content
    pub blob_hash: Hash,
    /// ID of the relay server (using VerifyingKey.id())
    pub relay_id: KeyId,
    /// Unix timestamp when upload was confirmed
    pub uploaded_at: u64,
    /// Size of the blob in bytes
    pub blob_size: u64,
}

/// Trait defining the storage interface for messages
#[cfg_attr(any(feature = "mock", test), automock())]
#[async_trait]
pub trait MessageStorage: Send + Sync {
    /// Store a new message or update an existing one
    async fn store_message(&self, message: &MessageFull) -> Result<(), crate::StorageError>;

    /// Retrieve a message by its ID
    async fn get_message(&self, id: &MessageId)
    -> Result<Option<MessageFull>, crate::StorageError>;

    /// Delete a message by its ID
    async fn delete_message(&self, id: &MessageId) -> Result<bool, crate::StorageError>;

    /// Query messages with various filters
    async fn query_messages(
        &self,
        query: &MessageQuery,
    ) -> Result<Vec<MessageFull>, crate::StorageError>;

    /// Mark a message as synced to a relay with its global stream ID
    async fn mark_message_synced(
        &self,
        message_id: &MessageId,
        relay_id: &KeyId,
        global_stream_id: &str,
    ) -> Result<(), crate::StorageError>;

    /// Get all messages that are not yet synced to a specific relay
    async fn get_unsynced_messages_for_relay(
        &self,
        relay_id: &KeyId,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>, crate::StorageError>;

    /// Get sync status for a specific message across all relays
    async fn get_message_sync_status(
        &self,
        message_id: &MessageId,
    ) -> Result<Vec<RelaySyncStatus>, crate::StorageError>;

    /// Get messages by author with optional limit
    async fn get_messages_by_author(
        &self,
        author: &VerifyingKey,
        limit: Option<usize>,
    ) -> Result<Vec<MessageFull>, crate::StorageError> {
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
    ) -> Result<Vec<MessageFull>, crate::StorageError> {
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
    ) -> Result<Vec<MessageFull>, crate::StorageError> {
        let query = MessageQuery {
            after_timestamp: Some(timestamp),
            limit,
            ..Default::default()
        };
        self.query_messages(&query).await
    }

    /// Get the total number of stored messages
    async fn get_message_count(&self) -> Result<u64, crate::StorageError>;

    /// Get storage statistics
    async fn get_storage_stats(&self) -> Result<StorageStats, crate::StorageError>;

    /// Clear all messages from storage
    async fn clear_all_messages(&self) -> Result<(), crate::StorageError>;

    /// Get the storage size in bytes
    async fn get_storage_size(&self) -> Result<u64, crate::StorageError>;

    /// Perform storage maintenance (e.g., VACUUM for SQLite)
    async fn maintenance(&self) -> Result<(), crate::StorageError>;

    /// Check if storage is healthy and accessible
    async fn health_check(&self) -> Result<bool, crate::StorageError>;

    // Subscription state management

    /// Store the subscription state for a specific relay
    async fn store_subscription_state(
        &self,
        relay_id: &KeyId,
        state: &SubscriptionState,
    ) -> Result<(), crate::StorageError>;

    /// Get the subscription state for a specific relay
    async fn get_subscription_state(
        &self,
        relay_id: &KeyId,
    ) -> Result<Option<SubscriptionState>, crate::StorageError>;

    /// Get all stored subscription states (for all relays)
    async fn get_all_subscription_states(
        &self,
    ) -> Result<std::collections::HashMap<KeyId, SubscriptionState>, crate::StorageError>;

    /// Delete subscription state for a specific relay
    async fn delete_subscription_state(
        &self,
        relay_id: &KeyId,
    ) -> Result<bool, crate::StorageError>;
}

/// Trait defining the storage interface for blob upload tracking
#[cfg_attr(any(feature = "mock", test), automock())]
#[async_trait]
pub trait BlobStorage: Send + Sync {
    /// Mark a blob as uploaded to a specific relay
    async fn mark_blob_uploaded(
        &self,
        blob_hash: &Hash,
        relay_id: &KeyId,
        blob_size: u64,
    ) -> Result<(), crate::StorageError>;

    /// Check if a blob has been uploaded to a specific relay
    async fn is_blob_uploaded(
        &self,
        blob_hash: &Hash,
        relay_id: &KeyId,
    ) -> Result<bool, crate::StorageError>;

    /// Get all blobs that have not been uploaded to a specific relay
    async fn get_unuploaded_blobs_for_relay(
        &self,
        relay_id: &KeyId,
        limit: Option<usize>,
    ) -> Result<Vec<Hash>, crate::StorageError>;

    /// Get upload status for a specific blob across all relays
    async fn get_blob_upload_status(
        &self,
        blob_hash: &Hash,
    ) -> Result<Vec<BlobUploadStatus>, crate::StorageError>;

    /// Get all blobs uploaded to a specific relay
    async fn get_uploaded_blobs_for_relay(
        &self,
        relay_id: &Hash,
        limit: Option<usize>,
    ) -> Result<Vec<BlobUploadStatus>, crate::StorageError>;

    /// Remove blob upload record (when blob is deleted)
    async fn remove_blob_upload_record(
        &self,
        blob_hash: &Hash,
        relay_id: Option<KeyId>, // If None, remove from all relays
    ) -> Result<u64, crate::StorageError>; // Returns number of records removed

    /// Get total number of blobs uploaded to a specific relay
    async fn get_uploaded_blob_count_for_relay(
        &self,
        relay_id: &KeyId,
    ) -> Result<u64, crate::StorageError>;

    /// Get total storage size of blobs uploaded to a specific relay
    async fn get_uploaded_blob_size_for_relay(
        &self,
        relay_id: &KeyId,
    ) -> Result<u64, crate::StorageError>;
}

/// Trait defining a key-value storage interface for arbitrary state data.
///
/// This trait provides a generic key-value store for persisting application state
/// using postcard serialization. Keys are byte slices and values are postcard-serialized blobs.
///
/// # Examples
///
/// ```rust,no_run
/// use zoe_client_storage::{StateStorage, StateNamespace};
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
///     let namespace = StateNamespace::Custom(b"example".to_vec());
///     
///     // Store state
///     storage.store(&namespace, b"my_key", &state).await?;
///     
///     // Retrieve state
///     let retrieved: Option<MyState> = storage.get(&namespace, b"my_key").await?;
///     assert_eq!(retrieved.unwrap().counter, 42);
///     
///     Ok(())
/// }
/// ```
#[cfg_attr(any(feature = "mock", test), automock(type Error = crate::StorageError;))]
#[async_trait]
pub trait StateStorage: Send + Sync {
    /// Store a value under the given key within a namespace.
    ///
    /// The value will be serialized using postcard before storage.
    /// If a value already exists for the key, it will be overwritten.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to store the value in
    /// * `key` - The key to store the value under (byte slice)
    /// * `value` - The value to store (must implement Serialize)
    ///
    /// # Errors
    /// Returns an error if serialization fails or storage operation fails.
    async fn store<T>(
        &self,
        namespace: &StateNamespace,
        key: &[u8],
        value: &T,
    ) -> Result<(), crate::StorageError>
    where
        T: Serialize + Send + Sync + 'static;

    /// Retrieve a value by key within a namespace.
    ///
    /// The stored blob will be deserialized using postcard.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to retrieve the value from
    /// * `key` - The key to retrieve the value for (byte slice)
    ///
    /// # Returns
    /// * `Ok(Some(value))` if the key exists and deserialization succeeds
    /// * `Ok(None)` if the key doesn't exist
    /// * `Err(...)` if deserialization fails or storage operation fails
    ///
    /// # Errors
    /// Returns an error if deserialization fails or storage operation fails.
    async fn get<T>(
        &self,
        namespace: &StateNamespace,
        key: &[u8],
    ) -> Result<Option<T>, crate::StorageError>
    where
        T: for<'de> Deserialize<'de> + Send + Sync + 'static;

    /// Delete a value by key within a namespace.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to delete the value from
    /// * `key` - The key to delete (byte slice)
    ///
    /// # Returns
    /// * `Ok(true)` if the key existed and was deleted
    /// * `Ok(false)` if the key didn't exist
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn delete(
        &self,
        namespace: &StateNamespace,
        key: &[u8],
    ) -> Result<bool, crate::StorageError>;

    /// Check if a key exists in storage within a namespace.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to check in
    /// * `key` - The key to check for existence (byte slice)
    ///
    /// # Returns
    /// * `Ok(true)` if the key exists
    /// * `Ok(false)` if the key doesn't exist
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn has(
        &self,
        namespace: &StateNamespace,
        key: &[u8],
    ) -> Result<bool, crate::StorageError>;

    /// Get all keys in storage.
    ///
    /// # Returns
    /// A vector of all keys currently stored (as byte vectors).
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn list_keys(&self) -> Result<Vec<Vec<u8>>, crate::StorageError>;

    /// Get all keys within a specific namespace.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to list keys from
    ///
    /// # Returns
    /// A vector of all keys in the given namespace (as byte vectors).
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn list_keys_in_namespace(
        &self,
        namespace: &StateNamespace,
    ) -> Result<Vec<Vec<u8>>, crate::StorageError>;

    /// Get all key-value pairs within a specific namespace.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to retrieve data from
    ///
    /// # Returns
    /// A vector of (key, value_data) tuples for all entries in the namespace.
    /// The value_data is the raw serialized bytes.
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn list_namespace_data<T>(
        &self,
        namespace: &crate::StateNamespace,
    ) -> Result<Vec<(Vec<u8>, T)>, crate::StorageError>
    where
        T: for<'de> serde::Deserialize<'de> + Send + Sync + 'static;

    /// Clear all data from storage.
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn clear(&self) -> Result<(), crate::StorageError>;

    /// Get the number of entries in storage.
    ///
    /// # Returns
    /// The total number of key-value pairs stored.
    ///
    /// # Errors
    /// Returns an error if the storage operation fails.
    async fn count(&self) -> Result<u64, crate::StorageError>;
}
