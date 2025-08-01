use thiserror::Error;
use zoe_wire_protocol::MessageError;

#[derive(Error, Debug)]
pub enum MessageStoreError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Empty filters")]
    EmptyFilters,
}

impl From<std::io::Error> for MessageStoreError {
    fn from(err: std::io::Error) -> Self {
        MessageStoreError::Internal(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for MessageStoreError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        MessageStoreError::Internal(err.to_string())
    }
}

impl From<hex::FromHexError> for MessageStoreError {
    fn from(err: hex::FromHexError) -> Self {
        MessageStoreError::Serialization(err.to_string())
    }
}

impl From<std::time::SystemTimeError> for MessageStoreError {
    fn from(err: std::time::SystemTimeError) -> Self {
        MessageStoreError::Internal(err.to_string())
    }
}

impl From<MessageStoreError> for MessageError {
    fn from(err: MessageStoreError) -> Self {
        match err {
            MessageStoreError::Redis(e) => MessageError::StorageError {
                message: e.to_string(),
            },
            MessageStoreError::Serialization(e) => MessageError::InternalError { message: e },
            MessageStoreError::EmptyFilters => MessageError::InternalError {
                message: "Empty filters".to_string(),
            },
            MessageStoreError::Internal(e) => MessageError::InternalError { message: e },
        }
    }
}

pub type Result<T> = std::result::Result<T, MessageStoreError>;
