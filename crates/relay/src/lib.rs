pub mod error;
pub mod relay;
pub mod router;
pub mod services;
pub mod config;

pub use error::ServiceError;
pub use relay::{ConnectionInfo, RelayServer, StreamPair};
pub use router::{Service, ServiceRouter};
pub use services::{RelayServiceRouter, BlobService, BlobServiceError, rpc::create_postcard_transport};
pub use config::{RelayConfig, BlobConfig};

pub type ZoeRelayServer = RelayServer<RelayServiceRouter>;