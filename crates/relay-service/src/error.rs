use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayError {
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
}

impl From<std::io::Error> for RelayError {
    fn from(err: std::io::Error) -> Self {
        RelayError::Internal(err.to_string())
    }
}

impl From<Box<dyn std::error::Error>> for RelayError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        RelayError::Internal(err.to_string())
    }
}

impl From<hex::FromHexError> for RelayError {
    fn from(err: hex::FromHexError) -> Self {
        RelayError::Serialization(err.to_string())
    }
}

impl From<std::time::SystemTimeError> for RelayError {
    fn from(err: std::time::SystemTimeError) -> Self {
        RelayError::Internal(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, RelayError>; 