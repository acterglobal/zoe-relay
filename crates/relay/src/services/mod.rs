pub mod blob;
pub mod rpc;

use crate::{Service, ServiceRouter};
use async_trait::async_trait;
pub use blob::{BlobService, BlobServiceError};
pub use zoeyr_wire_protocol::ZoeServices;

#[derive(Debug, thiserror::Error)]
enum AllServiceError {
    Blob(BlobServiceError),
}

enum Services {
    Blob(BlobService),
}

#[async_trait]
impl Service for Services {
    type Error = AllServiceError;

    async fn run(self) -> Result<(), Self::Error> {
        match self {
            Services::Blob(service) => service.run().await.map_err(ServiceError::Blob),
        }
    }
}

struct RelayServiceRouter {
    blob_service: BlobServiceImpl,
}

impl RelayServiceRouter {
    pub fn new(blob_service: BlobServiceImpl) -> Self {
        Self { blob_service }
    }
}

#[async_trait]
impl ServiceRouter for RelayServiceRouter {
    type ServiceId = ZoeServices;
    type Error = ServiceError;

    #[doc = " The service type that handles connections"]
    type Service = Services;

    async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> {
        ZoeServices::try_from(service_id).map_err(|_| ServiceError::InvalidServiceId(service_id))
    }

    async fn create_service(
        &self,
        service_id: &Self::ServiceId,
        connection_info: &ConnectionInfo,
        streams: StreamPair,
    ) -> Result<Self::Service, Self::Error> {
        match service_id {
            ZoeServices::Blob => Ok(Services::Blob(BlobService::new(
                streams,
                self.blob_service.clone(),
            ))),
            _ => Err(ServiceError::InvalidServiceId(service_id)),
        }
    }
}
