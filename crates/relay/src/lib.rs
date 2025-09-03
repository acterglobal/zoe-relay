pub mod challenge;
pub mod config;
pub mod error;
pub mod relay;
pub mod router;
pub mod services;
pub use config::BlobConfig;
pub use error::ServiceError;
pub use relay::RelayServer;
pub use router::{Service, ServiceRouter};
pub use services::{BlobService, BlobServiceError, RelayServiceRouter};
pub use zoe_wire_protocol::ConnectionInfo;

// Re-export challenge types for testing
pub use zoe_wire_protocol::KeyResult;

pub type ZoeRelayServer = RelayServer<RelayServiceRouter>;
