use serde::{Deserialize, Serialize};
use std::hash::Hash as StdHash;
use tarpc::{ClientMessage, Response};

use crate::{ChannelId, KeyId, MessageFull, MessageId, StoreKey, Tag};

/// Unified filter type for different kinds of message filtering
#[derive(Clone, PartialEq, Eq, StdHash, Serialize, Deserialize)]
pub enum Filter {
    /// Filter by message author
    Author(KeyId),
    /// Filter by channel ID
    Channel(ChannelId),
    /// Filter by event ID
    Event(MessageId),
    /// Filter by user key (for user-targeted messages)
    User(KeyId),
}

impl std::fmt::Debug for Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Filter::Author(id) => write!(f, "Author(#{})", hex::encode(id)),
            Filter::Channel(id) => write!(f, "Channel(#{})", hex::encode(id)),
            Filter::Event(id) => write!(f, "Event(#{})", hex::encode(id.as_bytes())),
            Filter::User(id) => write!(f, "User(#{})", hex::encode(id)),
        }
    }
}

impl Filter {
    pub fn matches(&self, message: &MessageFull) -> bool {
        if let Filter::Author(author) = self {
            return message.author().id() == *author;
        }
        for t in message.tags() {
            match (t, &self) {
                (Tag::Channel { id, .. }, Filter::Channel(channel)) => {
                    if id == channel {
                        return true;
                    }
                }
                (Tag::Event { id, .. }, Filter::Event(event)) => {
                    if id == event {
                        return true;
                    }
                }
                (Tag::User { id, .. }, Filter::User(user)) => {
                    if id == user {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

impl From<&Tag> for Filter {
    fn from(tag: &Tag) -> Self {
        match tag {
            Tag::Channel { id, .. } => Filter::Channel(id.clone()),
            Tag::Event { id, .. } => Filter::Event(*id),
            Tag::User { id, .. } => Filter::User(*id),
            Tag::Protected => {
                unreachable!("There is no filtering for protected tags. Programmer Error.")
            }
        }
    }
}

impl From<Tag> for Filter {
    fn from(tag: Tag) -> Self {
        Filter::from(&tag)
    }
}

/// Message filtering criteria for querying stored messages
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MessageFilters {
    pub filters: Option<Vec<Filter>>,
}

/// Type-safe filter operations using unified Filter type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FilterOperation {
    /// Add filters to the active set
    Add(Vec<Filter>),
    /// Remove specific filters from the active set
    Remove(Vec<Filter>),
    /// Replace all filters (forces restart - use sparingly)
    ReplaceAll(Vec<Filter>),
    /// Clear all filters
    Clear,
}

impl FilterOperation {
    /// Add channels to the filter
    pub fn add_channels(channels: Vec<ChannelId>) -> Self {
        Self::Add(channels.into_iter().map(Filter::Channel).collect())
    }

    /// Remove channels from the filter
    pub fn remove_channels(channels: Vec<ChannelId>) -> Self {
        Self::Remove(channels.into_iter().map(Filter::Channel).collect())
    }

    /// Add authors to the filter
    pub fn add_authors(authors: Vec<KeyId>) -> Self {
        Self::Add(authors.into_iter().map(Filter::Author).collect())
    }

    /// Remove authors from the filter
    pub fn remove_authors(authors: Vec<KeyId>) -> Self {
        Self::Remove(authors.into_iter().map(Filter::Author).collect())
    }

    /// Add events to the filter
    pub fn add_events(events: Vec<MessageId>) -> Self {
        Self::Add(events.into_iter().map(Filter::Event).collect())
    }

    /// Remove events from the filter
    pub fn remove_events(events: Vec<MessageId>) -> Self {
        Self::Remove(events.into_iter().map(Filter::Event).collect())
    }

    /// Add users to the filter
    pub fn add_users(users: Vec<KeyId>) -> Self {
        Self::Add(users.into_iter().map(Filter::User).collect())
    }

    /// Remove users from the filter
    pub fn remove_users(users: Vec<KeyId>) -> Self {
        Self::Remove(users.into_iter().map(Filter::User).collect())
    }

    /// Replace all filters
    pub fn replace_all(filters: Vec<Filter>) -> Self {
        Self::ReplaceAll(filters)
    }

    /// Clear all filters
    pub fn clear() -> Self {
        Self::Clear
    }
}

impl MessageFilters {
    pub fn is_empty(&self) -> bool {
        self.filters.as_ref().is_none_or(|f| f.is_empty())
    }

    /// Apply a type-safe filter operation to this filter set
    pub fn apply_operation(&mut self, operation: &FilterOperation) {
        match operation {
            FilterOperation::Add(new_filters) => {
                let filter_vec = self.filters.get_or_insert_with(Vec::new);
                for filter in new_filters {
                    if !filter_vec.contains(filter) {
                        filter_vec.push(filter.clone());
                    }
                }
            }
            FilterOperation::Remove(filters_to_remove) => {
                if let Some(filter_vec) = self.filters.as_mut() {
                    filter_vec.retain(|existing| !filters_to_remove.contains(existing));
                    if filter_vec.is_empty() {
                        self.filters = None;
                    }
                }
            }
            FilterOperation::ReplaceAll(new_filters) => {
                if new_filters.is_empty() {
                    self.filters = None;
                } else {
                    self.filters = Some(new_filters.clone());
                }
            }
            FilterOperation::Clear => {
                self.filters = None;
            }
        }
    }
}

/// Messages sent over the streaming protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamMessage {
    /// A new message received that matches our filter
    MessageReceived {
        /// Blake3 hash of the message
        message: Box<MessageFull>,
        /// Redis stream position
        stream_height: String,
    },
    /// We have just received a stream height update
    /// but our filter didn't apply here
    /// Indicator that we are live now and we have
    /// received all messages up to this point this
    /// server knows about
    StreamHeightUpdate(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub filters: MessageFilters,
    pub since: Option<String>,
    pub limit: Option<usize>,
}

/// Message store service for message interaction operations
#[tarpc::service]
pub trait MessageService {
    // Core message operations
    async fn publish(message: MessageFull) -> Result<PublishResult, MessageError>;

    /// Retrieve a specific message by its ID
    async fn message(id: MessageId) -> Result<Option<MessageFull>, MessageError>;

    /// Retrieve a specific user's data by their key and storage key
    async fn user_data(
        author: KeyId,
        storage_key: StoreKey,
    ) -> Result<Option<MessageFull>, MessageError>;

    // Bulk operations for sync
    /// Check which messages the server already has and return their global stream IDs.
    /// Returns a vec of `Option<String>` in the same order as the input, where:
    /// - `Some(stream_id)` means the server has the message with that global stream ID
    /// - `None` means the server doesn't have this message yet
    async fn check_messages(
        message_ids: Vec<MessageId>,
    ) -> Result<Vec<Option<String>>, MessageError>;

    /// Start the subscription
    async fn subscribe(config: SubscriptionConfig) -> Result<(), MessageError>; // Returns nothing

    /// Update the running subscription filters with the actions. Returns the now final subscription config.
    async fn update_filters(
        request: FilterUpdateRequest,
    ) -> Result<SubscriptionConfig, MessageError>;

    /// Update the internal subscription and catch up to the latest stream height for the given filter
    async fn catch_up(request: CatchUpRequest) -> Result<SubscriptionConfig, MessageError>; // Returns catch_up_id for tracking
}

/// Result type for message operations
pub type MessageResult<T> = Result<T, MessageError>;

/// Result of publishing a message to the relay
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublishResult {
    /// Message was newly stored with this global stream ID
    StoredNew { global_stream_id: String },
    /// Message already existed at this global stream ID
    AlreadyExists { global_stream_id: String },
    /// Message was expired and not stored
    Expired,
}

impl PublishResult {
    /// Get the global stream ID if available (None for expired messages)
    pub fn global_stream_id(&self) -> Option<String> {
        match self {
            PublishResult::StoredNew { global_stream_id } => Some(global_stream_id.clone()),
            PublishResult::AlreadyExists { global_stream_id } => Some(global_stream_id.clone()),
            PublishResult::Expired => None,
        }
    }

    /// Check if the message was stored (either new or already existed)
    pub fn was_stored(&self) -> bool {
        !matches!(self, PublishResult::Expired)
    }
}

/// Error types for message operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum MessageError {
    #[error("Message not found: {hash}")]
    NotFound { hash: String },

    #[error("Invalid message hash: {hash}")]
    InvalidHash { hash: String },

    #[error("Storage error: {message}")]
    StorageError { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("IO error: {message}")]
    IoError { message: String },

    #[error("Internal server error: {message}")]
    InternalError { message: String },
}

/// Generic filter update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterUpdateRequest {
    pub operations: Vec<FilterOperation>,
}

/// Type-safe catch-up request for historical messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchUpRequest {
    pub filter: Filter,
    pub since: Option<String>,
    pub max_messages: Option<usize>,
    pub request_id: u32,
}

impl CatchUpRequest {
    /// Convenience constructor for channel catch-up
    pub fn for_channel(
        channel_id: ChannelId,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: u32,
    ) -> Self {
        Self {
            filter: Filter::Channel(channel_id),
            since,
            max_messages,
            request_id,
        }
    }

    /// Convenience constructor for author catch-up
    pub fn for_author(
        author_key: KeyId,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: u32,
    ) -> Self {
        Self {
            filter: Filter::Author(author_key),
            since,
            max_messages,
            request_id,
        }
    }

    /// Convenience constructor for event catch-up
    pub fn for_event(
        event_id: MessageId,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: u32,
    ) -> Self {
        Self {
            filter: Filter::Event(event_id),
            since,
            max_messages,
            request_id,
        }
    }

    /// Convenience constructor for user catch-up
    pub fn for_user(
        user_key: KeyId,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: u32,
    ) -> Self {
        Self {
            filter: Filter::User(user_key),
            since,
            max_messages,
            request_id,
        }
    }
}

/// Catch-up response with historical messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchUpResponse {
    pub request_id: u32,
    pub filter: Filter, // What filter was requested
    pub messages: Vec<MessageFull>,
    pub is_complete: bool,          // False if more batches coming
    pub next_since: Option<String>, // For pagination
}

/// Simplified request wrapper - now just RPC requests
/// All subscription, filter updates, and catch-up requests are now handled as RPC calls
pub type MessagesServiceRequestWrap = ClientMessage<MessageServiceRequest>;

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageServiceResponseWrap {
    /// Streaming messages from background listener tasks
    StreamMessage(StreamMessage),

    /// Catch-up response with batched historical messages from background catch-up tasks
    CatchUpResponse(CatchUpResponse),

    /// RPC response (includes subscription/filter update acknowledgments)
    RpcResponse(Box<Response<MessageServiceResponse>>),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create test KeyIds from byte arrays
    fn create_test_verifying_key_id(bytes: &[u8]) -> KeyId {
        // Generate a proper Ed25519 keypair and use the public key
        use rand::SeedableRng;

        // Create a simple hash from the input bytes for deterministic generation
        let mut seed = [0u8; 32];
        let len = std::cmp::min(bytes.len(), 32);
        seed[..len].copy_from_slice(&bytes[..len]);

        let mut seed_rng = rand_chacha::ChaCha20Rng::from_seed(seed);
        let signing_key = ed25519_dalek::SigningKey::generate(&mut seed_rng);
        let verifying_key = signing_key.verifying_key();

        crate::keys::VerifyingKey::Ed25519(Box::new(verifying_key)).id()
    }

    #[test]
    fn test_filter_enum() {
        // Test that Filter variants work correctly
        let author = Filter::Author(create_test_verifying_key_id(b"alice"));
        let channel = Filter::Channel(b"general".to_vec().into());
        let event = Filter::Event(MessageId::from_content(b"important"));
        let user = Filter::User(create_test_verifying_key_id(b"bob"));

        // Test Debug formatting works
        assert!(format!("{author:?}").contains("Author"));
        assert!(format!("{channel:?}").contains("Channel"));
        assert!(format!("{event:?}").contains("Event"));
        assert!(format!("{user:?}").contains("User"));

        // Test PartialEq
        assert_eq!(
            author,
            Filter::Author(create_test_verifying_key_id(b"alice"))
        );
        assert_ne!(author, channel);
    }

    #[test]
    fn test_message_filters_default() {
        let filters = MessageFilters::default();
        assert!(filters.is_empty());
        assert!(filters.filters.is_none());
    }

    #[test]
    fn test_message_filters_is_empty() {
        let mut filters = MessageFilters::default();
        assert!(filters.is_empty());

        // Add some filters
        filters.filters = Some(vec![Filter::Channel(b"general".to_vec().into())]);
        assert!(!filters.is_empty());

        // Clear filters but add authors
        filters.filters = Some(vec![Filter::Author(create_test_verifying_key_id(b"alice"))]);
        assert!(!filters.is_empty());

        // Clear all
        filters.filters = None;
        assert!(filters.is_empty());
    }

    #[test]
    fn test_filter_operations() {
        // Test convenience constructors
        let channels = vec![b"general".to_vec().into(), b"tech".to_vec().into()];
        let authors = vec![create_test_verifying_key_id(b"alice")];

        // Test add operations
        let add_channels = FilterOperation::add_channels(channels.clone());
        match add_channels {
            FilterOperation::Add(filters) => {
                assert_eq!(filters.len(), 2);
                assert!(filters.contains(&Filter::Channel(b"general".to_vec().into())));
                assert!(filters.contains(&Filter::Channel(b"tech".to_vec().into())));
            }
            _ => panic!("Expected Add operation"),
        }

        let add_authors = FilterOperation::add_authors(authors.clone());
        match add_authors {
            FilterOperation::Add(filters) => {
                assert_eq!(filters.len(), 1);
                assert!(filters.contains(&Filter::Author(create_test_verifying_key_id(b"alice"))));
            }
            _ => panic!("Expected Add operation"),
        }

        // Test remove operations
        let remove_channels = FilterOperation::remove_channels(channels.clone().into());
        match remove_channels {
            FilterOperation::Remove(filters) => {
                assert_eq!(filters.len(), 2);
                assert!(filters.contains(&Filter::Channel(b"general".to_vec().into())));
                assert!(filters.contains(&Filter::Channel(b"tech".to_vec().into())));
            }
            _ => panic!("Expected Remove operation"),
        }

        // Test clear operation
        let clear_op = FilterOperation::clear();
        assert_eq!(clear_op, FilterOperation::Clear);
    }

    #[test]
    fn test_filter_operation_apply() {
        let mut filters = MessageFilters::default();
        assert!(filters.is_empty());

        // Add some filters
        let add_op = FilterOperation::add_channels(vec![b"general".to_vec().into()]);
        filters.apply_operation(&add_op);
        assert!(!filters.is_empty());
        assert_eq!(filters.filters.as_ref().unwrap().len(), 1);

        // Add more filters
        let add_author_op =
            FilterOperation::add_authors(vec![create_test_verifying_key_id(b"alice")]);
        filters.apply_operation(&add_author_op);
        assert_eq!(filters.filters.as_ref().unwrap().len(), 2);

        // Remove a filter
        let remove_op = FilterOperation::remove_channels(vec![b"general".to_vec().into()]);
        filters.apply_operation(&remove_op);
        assert_eq!(filters.filters.as_ref().unwrap().len(), 1);

        // Clear all
        let clear_op = FilterOperation::clear();
        filters.apply_operation(&clear_op);
        assert!(filters.is_empty());
    }

    #[test]
    fn test_catchup_request_constructors() {
        // Test channel catch-up request
        let channel_request = CatchUpRequest::for_channel(
            b"general".to_vec().into(),
            Some("0-0".to_string()),
            Some(100),
            123,
        );
        assert_eq!(
            channel_request.filter,
            Filter::Channel(b"general".to_vec().into())
        );
        assert_eq!(channel_request.request_id, 123);

        // Test author catch-up request
        let author_key = create_test_verifying_key_id(b"alice");
        let author_request = CatchUpRequest::for_author(author_key, None, None, 456);
        assert_eq!(author_request.filter, Filter::Author(author_key));
        assert_eq!(author_request.request_id, 456);
    }
}
