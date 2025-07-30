use crate::{create_postcard_transport, Service, StreamPair};
use async_trait::async_trait;
use futures::StreamExt;
use tarpc::server::{BaseChannel, Channel};
use zoe_blob_store::BlobServiceImpl;
use zoe_wire_protocol::{BlobError, BlobService as _};

#[derive(Debug, thiserror::Error)]
pub enum BlobServiceError {
    #[error("Blob error: {0}")]
    BlobError(BlobError),

    #[error("IO error: {0}")]
    IoError(std::io::Error),

    #[error("Join error: {0}")]
    JoinError(tokio::task::JoinError),
}

pub struct BlobService {
    streams: StreamPair,
    service: BlobServiceImpl,
}

impl BlobService {
    pub fn new(streams: StreamPair, blob_service: BlobServiceImpl) -> Self {
        Self {
            streams,
            service: blob_service,
        }
    }
}

#[async_trait]
impl Service for BlobService {
    type Error = BlobServiceError;
    async fn run(mut self) -> Result<(), Self::Error> {
        self.streams.send_ack().await.map_err(BlobServiceError::IoError)?;
        let s = self.service.serve();
        let transport = create_postcard_transport::<_, _>(self.streams);
        let channel = BaseChannel::with_defaults(transport);

        tokio::spawn(async move {
            channel
                .execute(s)
                .for_each(|response| async move {
                    tokio::spawn(response);
                })
                .await;
        })
        .await
        .map_err(BlobServiceError::JoinError)?;
        Ok(())
    }
}
