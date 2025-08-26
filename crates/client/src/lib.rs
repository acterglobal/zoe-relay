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
#[cfg(feature = "frb-api")]
pub use frb_api::*;

pub use client::{Client, ClientBuilder};
pub use error::ClientError;
pub use file_storage::FileStorage;
pub use pqxdh::{
    PqxdhProtocolHandler, PqxdhSession, create_pqxdh_prekey_bundle_with_private_keys,
    fetch_pqxdh_inbox, publish_pqxdh_inbox, send_pqxdh_initial_message,
};
pub use relay_client::RelayClient;
pub use rpc_transport::{RpcMessageListener, TarpcOverMessagesClient, TarpcOverMessagesServer};
pub use services::{BlobService, MessagesService, MessagesStream};

// Re-export FileRef and Image from app-primitives for convenience
pub use zoe_app_primitives::{FileRef, Image};
pub use zoe_wire_protocol::{SigningKey, VerifyingKey};
