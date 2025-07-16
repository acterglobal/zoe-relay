use serde::{Deserialize, Serialize};
// Note: MessageFull and ProtocolMessage may be used by generated code

/// Message filters for querying relay storage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageFilters {
    pub authors: Option<Vec<Vec<u8>>>,
    pub channels: Option<Vec<Vec<u8>>>,
    pub events: Option<Vec<Vec<u8>>>,
    pub users: Option<Vec<Vec<u8>>>,
}

impl MessageFilters {
    pub fn new() -> Self {
        Self {
            authors: None,
            channels: None,
            events: None,
            users: None,
        }
    }

    pub fn with_authors(mut self, authors: Vec<Vec<u8>>) -> Self {
        self.authors = Some(authors);
        self
    }

    pub fn with_channels(mut self, channels: Vec<Vec<u8>>) -> Self {
        self.channels = Some(channels);
        self
    }

    pub fn with_events(mut self, events: Vec<Vec<u8>>) -> Self {
        self.events = Some(events);
        self
    }

    pub fn with_users(mut self, users: Vec<Vec<u8>>) -> Self {
        self.users = Some(users);
        self
    }

    pub fn is_empty(&self) -> bool {
        self.authors.is_none()
            && self.channels.is_none()
            && self.events.is_none()
            && self.users.is_none()
    }
}

impl Default for MessageFilters {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming message response containing both message data and stream metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamMessage {
    /// The actual message data (serialized MessageFull)
    pub message_data: Option<Vec<u8>>,
    /// Redis stream ID for this message
    pub stream_id: String,
    /// Whether this is the end of initial batch (switching to live mode)
    pub end_of_batch: bool,
}

/// Configuration for message streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Start listening from this message ID
    pub since: Option<String>,
    /// Maximum number of messages to receive per batch
    pub limit: Option<usize>,
    /// Message filters to apply
    pub filters: MessageFilters,
}

impl StreamConfig {
    pub fn new(filters: MessageFilters) -> Self {
        Self {
            since: None,
            limit: None,
            filters,
        }
    }

    pub fn with_since(mut self, since: String) -> Self {
        self.since = Some(since);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Error types for relay operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayError {
    MessageNotFound,
    InvalidMessageId,
    EmptyFilters,
    StorageError(String),
    SerializationError(String),
    UnauthorizedAccess,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::MessageNotFound => write!(f, "Message not found"),
            RelayError::InvalidMessageId => write!(f, "Invalid message ID"),
            RelayError::EmptyFilters => write!(f, "Message filters cannot be empty"),
            RelayError::StorageError(msg) => write!(f, "Storage error: {msg}"),
            RelayError::SerializationError(msg) => write!(f, "Serialization error: {msg}"),
            RelayError::UnauthorizedAccess => write!(f, "Unauthorized access"),
        }
    }
}

impl std::error::Error for RelayError {}

/// Result type for relay operations
pub type RelayResult<T> = Result<T, RelayError>;

/// Tarpc service trait for relay message operations
/// Authentication is handled by QUIC ed25519 mutual TLS - no additional auth needed
#[tarpc::service]
pub trait RelayService {
    /// Retrieve a specific message by its ID
    async fn get_message(message_id: Vec<u8>) -> RelayResult<Option<Vec<u8>>>;

    /// Store a message in the relay
    async fn store_message(message_data: Vec<u8>) -> RelayResult<String>;

    /// Start listening for messages and return a stream session ID
    async fn start_message_stream(config: StreamConfig) -> RelayResult<String>;

    /// Get the next batch of messages from an active stream
    async fn get_stream_batch(
        session_id: String,
        max_messages: Option<usize>,
    ) -> RelayResult<Vec<StreamMessage>>;

    /// Stop a message stream
    async fn stop_message_stream(session_id: String) -> RelayResult<bool>;
}
