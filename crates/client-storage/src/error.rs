use thiserror::Error;

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Message not found: {0}")]
    MessageNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<refinery::Error> for StorageError {
    fn from(err: refinery::Error) -> Self {
        StorageError::Migration(err.to_string())
    }
}