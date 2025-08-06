pub mod client;
pub mod error;
pub mod file_storage;
pub mod services;

pub use client::RelayClient;
pub use error::ClientError;
pub use file_storage::FileStorage;
pub use services::{BlobService, MessagesService, MessagesStream};

// Re-export StoredFileInfo from app-primitives for convenience
pub use zoe_app_primitives::StoredFileInfo;
