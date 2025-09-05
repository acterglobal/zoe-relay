mod blob_service;
mod multi_relay_blob_service;

pub use blob_service::BlobService;
pub use multi_relay_blob_service::MultiRelayBlobService;

use async_trait::async_trait;
use zoe_wire_protocol::{BlobError as WireError, BlobId};

#[cfg(any(feature = "mock", test))]
use mockall::{automock, predicate::*};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Blob not found: {hash}")]
    NotFound { hash: BlobId },

    #[error("IO error: {0}")]
    IoError(std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("RPC error: {0}")]
    RpcError(tarpc::client::RpcError),

    #[error("Wire blob error: {0}")]
    WireError(WireError),
}

pub type Result<T> = std::result::Result<T, BlobError>;

/// Trait for blob storage operations, enabling mocking in tests
#[cfg_attr(any(feature = "mock", test), automock(type Error = BlobError;))]
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Download a blob by its ID
    async fn get_blob(&self, blob_id: &BlobId) -> std::result::Result<Vec<u8>, BlobError>;

    /// Upload a blob and return its hash
    async fn upload_blob(&self, blob: &[u8]) -> std::result::Result<BlobId, BlobError>;
}
