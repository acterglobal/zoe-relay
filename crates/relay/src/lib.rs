pub mod challenge;
pub mod config;
pub mod error;
pub mod relay;
pub mod router;
pub mod services;
pub use config::{BlobConfig, RelayConfig};
pub use error::ServiceError;
pub use relay::{ConnectionInfo, RelayServer};
pub use router::{Service, ServiceRouter};
pub use services::{BlobService, BlobServiceError, RelayServiceRouter};

// Re-export challenge types for testing
pub use zoe_wire_protocol::KeyResult;

pub type ZoeRelayServer = RelayServer<RelayServiceRouter>;
