pub mod challenge;
pub mod client;
pub mod error;
pub mod file_storage;
#[cfg(feature = "frb-api")]
pub mod frb_api;
pub mod pqxdh;
pub mod relay_client;
pub mod rpc_transport;
pub mod services;
pub mod session_manager;
pub mod util;

#[cfg(feature = "frb-api")]
pub use frb_api::*;

pub use client::{
    Client, ClientBuilder, OverallConnectionStatus, RelayConnectionInfo, RelayConnectionStatus,
    RelayInfo, RelayStatusUpdate,
};
pub use error::ClientError;
pub use file_storage::FileStorage;
pub use pqxdh::PqxdhProtocolHandler;
pub use relay_client::{RelayClient, RelayClientBuilder};
pub use rpc_transport::{RpcMessageListener, TarpcOverMessagesClient, TarpcOverMessagesServer};
pub use services::{BlobService, MessagesService, MessagesStream};
pub use session_manager::{SessionManager, SessionManagerError, SessionManagerResult};

// Re-export FileRef and Image from app-primitives for convenience
pub use zoe_app_primitives::{FileRef, Image};
pub use zoe_wire_protocol::{SigningKey, VerifyingKey};
