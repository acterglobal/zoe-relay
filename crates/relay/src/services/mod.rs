pub mod blob;
pub mod messages;

use crate::{Service, ServiceError, ServiceRouter};
use async_trait::async_trait;
pub use blob::{BlobService, BlobServiceError};
pub use messages::{MessagesService, MessagesServiceError};
use zoe_blob_store::BlobServiceImpl;
use zoe_message_store::RedisMessageStorage;
use zoe_wire_protocol::ConnectionInfo;
use zoe_wire_protocol::StreamPair;
pub use zoe_wire_protocol::ZoeServices;

#[derive(Debug, thiserror::Error)]
pub enum AllServiceError {
    #[error("Blob service error: {0}")]
    Blob(BlobServiceError),

    #[error("Messages service error: {0}")]
    Messages(MessagesServiceError),
}

pub enum Services {
    Blob(BlobService),
    Messages(MessagesService),
}

#[async_trait]
impl Service for Services {
    type Error = AllServiceError;

    async fn run(self) -> Result<(), Self::Error> {
        match self {
            Services::Blob(service) => service.run().await.map_err(AllServiceError::Blob),
            Services::Messages(service) => service.run().await.map_err(AllServiceError::Messages),
        }
    }
}

pub struct RelayServiceRouter {
    blob_service: BlobServiceImpl,
    message_service: RedisMessageStorage,
}

impl RelayServiceRouter {
    pub fn new(blob_service: BlobServiceImpl, message_service: RedisMessageStorage) -> Self {
        Self {
            blob_service,
            message_service,
        }
    }
}

#[async_trait]
impl ServiceRouter for RelayServiceRouter {
    type ServiceId = ZoeServices;
    type Error = ServiceError;
    type Service = Services;

    async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> {
        ZoeServices::try_from(service_id).map_err(|_| ServiceError::InvalidServiceId(service_id))
    }

    async fn create_service(
        &self,
        service_id: &Self::ServiceId,
        _connection_info: &ConnectionInfo,
        streams: StreamPair,
    ) -> Result<Self::Service, Self::Error> {
        match service_id {
            ZoeServices::Blob => Ok(Services::Blob(BlobService::new(
                streams,
                self.blob_service.clone(),
            ))),
            ZoeServices::Messages => Ok(Services::Messages(MessagesService::new(
                streams,
                self.message_service.clone(),
            ))),
        }
    }
}
