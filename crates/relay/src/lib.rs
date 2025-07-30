pub mod config;
pub mod error;
pub mod relay;
pub mod router;
pub mod services;

pub use config::{BlobConfig, RelayConfig};
pub use error::ServiceError;
pub use relay::{ConnectionInfo, RelayServer, StreamPair};
pub use router::{Service, ServiceRouter};
pub use services::{
    rpc::create_postcard_transport, BlobService, BlobServiceError, RelayServiceRouter,
};

pub type ZoeRelayServer = RelayServer<RelayServiceRouter>;
