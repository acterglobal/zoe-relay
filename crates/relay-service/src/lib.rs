pub mod config;
pub mod dynamic_auth_server;
pub mod error;
pub mod storage;

// Re-export commonly used types
pub use storage::{RedisStorage, MessageFilters};
pub use error::RelayError;
pub use config::RelayConfig;

// Export connection utilities for examples and clients
pub mod connection;
pub use connection::*;

/// Re-export common types for convenience
pub use zoeyr_wire_protocol::{Kind, Message, MessageFull, StoreKey, Tag};

/// Re-export protocol types for dynamic authentication
pub use zoeyr_wire_protocol::{
    ProtocolMessage, FileContent,
    AuthChallenge,
    MessageHandler, SessionConfig, TransportConfig,
    generate_deterministic_cert_from_ed25519, extract_ed25519_from_cert,
    InsecureCertVerifier
};
