use crate::error::{ClientError, Result as ClientResult};
use async_trait::async_trait;
use quinn::Connection;
use tarpc::{context, serde_transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::LengthDelimitedCodec;
use zoe_wire_protocol::{
    BlobError as WireError, BlobServiceClient, PostcardFormat, StreamPair, ZoeServices,
};

#[cfg(any(feature = "mock", test))]
use mockall::{automock, predicate::*};

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("Blob not found: {hash}")]
    NotFound { hash: String },

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
    type Error: std::error::Error + Send + Sync + 'static;

    /// Download a blob by its ID
    async fn get_blob(&self, blob_id: &str) -> std::result::Result<Vec<u8>, Self::Error>;

    /// Upload a blob and return its hash
    async fn upload_blob(&self, blob: &[u8]) -> std::result::Result<String, Self::Error>;
}

#[derive(Clone)]
pub struct BlobService {
    client: BlobServiceClient,
}

impl BlobService {
    pub async fn connect(connection: &Connection) -> ClientResult<Self> {
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_u8(ZoeServices::Blob as u8).await?;
        let service_ok = recv.read_u8().await?;
        if service_ok != 1 {
            return Err(ClientError::Generic(
                "Service ID not acknowledged".to_string(),
            ));
        }

        let streams = StreamPair::new(recv, send);

        let framed = tokio_util::codec::Framed::new(streams, LengthDelimitedCodec::new());
        let transport = serde_transport::new(framed, PostcardFormat);
        let client = BlobServiceClient::new(Default::default(), transport).spawn();
        Ok(Self { client })
    }
}

#[async_trait]
impl BlobStore for BlobService {
    type Error = BlobError;

    async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let Some(blob) = self
            .client
            .download(context::current(), blob_id.to_string())
            .await
            .map_err(BlobError::RpcError)?
            .map_err(BlobError::WireError)?
        else {
            return Err(BlobError::NotFound {
                hash: blob_id.to_string(),
            });
        };
        Ok(blob)
    }

    async fn upload_blob(&self, blob: &[u8]) -> Result<String> {
        let hash = self
            .client
            .upload(context::current(), blob.to_vec())
            .await
            .map_err(BlobError::RpcError)?
            .map_err(BlobError::WireError)?;
        Ok(hash)
    }
}

impl BlobService {
    /// Get a blob by its ID (convenience method)
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        <Self as BlobStore>::get_blob(self, blob_id).await
    }

    /// Upload a blob and return its hash (convenience method)
    pub async fn upload_blob(&self, blob: &[u8]) -> Result<String> {
        <Self as BlobStore>::upload_blob(self, blob).await
    }
}
