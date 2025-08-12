pub mod client;
pub mod error;
pub mod file_storage;
pub mod rpc_transport;
pub mod services;

pub use client::RelayClient;
pub use error::ClientError;
pub use file_storage::FileStorage;
pub use rpc_transport::{RpcMessageListener, TarpcOverMessagesClient, TarpcOverMessagesServer};
pub use services::{BlobService, MessagesService, MessagesStream};

// Re-export FileRef and Image from app-primitives for convenience
pub use zoe_app_primitives::{FileRef, Image};
