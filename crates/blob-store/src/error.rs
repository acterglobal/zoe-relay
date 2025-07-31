use thiserror::Error;

/// Error type for blob store operations
#[derive(Error, Debug)]
pub enum BlobStoreError {
    #[error("Blob not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hash parsing error: {0}")]
    HashParse(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Request error: {0}")]
    Request(String),
}

impl From<anyhow::Error> for BlobStoreError {
    fn from(err: anyhow::Error) -> Self {
        BlobStoreError::Internal(err.to_string())
    }
}

impl From<irpc::Error> for BlobStoreError {
    fn from(err: irpc::Error) -> Self {
        BlobStoreError::Request(err.to_string())
    }
}

impl From<iroh_blobs::api::RequestError> for BlobStoreError {
    fn from(err: iroh_blobs::api::RequestError) -> Self {
        BlobStoreError::Request(err.to_string())
    }
}