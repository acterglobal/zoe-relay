use thiserror::Error;

#[derive(Error, Debug)]
pub enum MessageStoreError {
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Message not found")]
    MessageNotFound,

    #[error("Invalid message format")]
    InvalidMessage,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

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

pub type Result<T> = std::result::Result<T, MessageStoreError>;
