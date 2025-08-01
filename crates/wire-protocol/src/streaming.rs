use blake3::Hash;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use tarpc::{ClientMessage, Response};

use crate::{MessageFull, StoreKey};

/// Message filtering criteria for querying stored messages
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Messages sent over the streaming protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamMessage {
    /// A new message received that matches our filter
    MessageReceived {
        /// Blake3 hash of the message
        message: MessageFull,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub filters: MessageFilters,
    pub since: Option<String>,
    pub limit: Option<usize>,
}
/// Message store service for message interaction operations
#[tarpc::service]
pub trait MessageService {
    // async fn subscribe(config: SubscriptionConfig) -> Result<(), MessageError>;
    async fn publish(message: MessageFull) -> Result<Option<String>, MessageError>;
    async fn message(id: Hash) -> Result<Option<MessageFull>, MessageError>;
    async fn user_data(
        author: VerifyingKey,
        storage_key: StoreKey,
    ) -> Result<Option<MessageFull>, MessageError>;
}

/// Result type for message operations
pub type MessageResult<T> = Result<T, MessageError>;

/// Error types for blob operations
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

#[derive(Debug, Serialize, Deserialize)]
pub enum MessagesServiceRequestWrap {
    Subscribe(SubscriptionConfig),
    RpcRequest(ClientMessage<MessageServiceRequest>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageServiceResponseWrap {
    StreamMessage(StreamMessage),
    RpcResponse(Response<MessageServiceResponse>),
}
