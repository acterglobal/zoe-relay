use crate::error::{ClientError, Result as ClientResult};
use async_trait::async_trait;
use quinn::Connection;
use tarpc::{context, serde_transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::LengthDelimitedCodec;
use zoe_wire_protocol::{BlobId, BlobServiceClient, PostcardFormat, StreamPair, ZoeServices};

use super::{BlobError, BlobStore};

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
    async fn get_blob(&self, blob_id: &BlobId) -> Result<Vec<u8>, BlobError> {
        let Some(blob) = self
            .client
            .download(context::current(), *blob_id)
            .await
            .map_err(BlobError::RpcError)?
            .map_err(BlobError::WireError)?
        else {
            return Err(BlobError::NotFound { hash: *blob_id });
        };
        Ok(blob)
    }

    async fn upload_blob(&self, blob: &[u8]) -> Result<BlobId, BlobError> {
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
    pub async fn get_blob(&self, blob_id: &BlobId) -> Result<Vec<u8>, BlobError> {
        <Self as BlobStore>::get_blob(self, blob_id).await
    }

    /// Upload a blob and return its hash (convenience method)
    pub async fn upload_blob(&self, blob: &[u8]) -> Result<BlobId, BlobError> {
        <Self as BlobStore>::upload_blob(self, blob).await
    }
}
