use crate::error::{ClientError, Result as ClientResult};
use quinn::Connection;
use tarpc::{context, serde_transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::codec::LengthDelimitedCodec;
use zoe_wire_protocol::{
    BlobError as WireError, BlobServiceClient, PostcardFormat, StreamPair, ZoeServices,
};

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

type Result<T> = std::result::Result<T, BlobError>;

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

impl BlobService {
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
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

    pub async fn upload_blob(&self, blob: &[u8]) -> Result<String> {
        let hash = self
            .client
            .upload(context::current(), blob.to_vec())
            .await
            .map_err(BlobError::RpcError)?
            .map_err(BlobError::WireError)?;
        Ok(hash)
    }
}
