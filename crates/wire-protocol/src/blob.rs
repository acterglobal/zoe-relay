use serde::{Deserialize, Serialize};

/// Blob store service for file upload/download operations
#[tarpc::service]
pub trait BlobService {
    /// Check if the blob store is healthy
    async fn health_check() -> BlobResult<BlobHealth>;

    /// Upload a blob and return its hash
    async fn upload(data: Vec<u8>) -> BlobResult<String>;

    /// Download a blob by its hash
    async fn download(hash: String) -> BlobResult<Option<Vec<u8>>>;

    /// Get information about a blob
    async fn get_info(hash: String) -> BlobResult<Option<BlobInfo>>;

    // Bulk operations for sync
    /// Check which blobs the server already has stored.
    /// Returns a vec of `bool` in the same order as the input, where:
    /// - `true` means the server has the blob stored
    /// - `false` means the server doesn't have this blob yet
    async fn check_blobs(hashes: Vec<String>) -> BlobResult<Vec<bool>>;
}

/// Result type for blob operations
pub type BlobResult<T> = Result<T, BlobError>;

/// Health status of the blob store
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobHealth {
    pub status: String,
    pub total_blobs: u64,
    pub total_size_bytes: u64,
}

/// Information about a stored blob
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobInfo {
    pub hash: String,
    pub size_bytes: u64,
    pub created_at: String,
}

/// Error types for blob operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum BlobError {
    #[error("Blob not found: {hash}")]
    NotFound { hash: String },

    #[error("Invalid blob hash: {hash}")]
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
