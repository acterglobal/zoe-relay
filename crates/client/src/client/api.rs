use super::{
    ZoeClientBlobService, ZoeClientMessageManager, ZoeClientSessionManager, ZoeClientStorage,
};
use crate::error::Result;
use std::sync::Arc;
use zoe_blob_store::BlobClient;
use zoe_wire_protocol::{KeyPair, VerifyingKey};

#[cfg(not(feature = "frb-api"))]
mod file_storage;
#[cfg(not(feature = "frb-api"))]
mod relay;
#[cfg(not(feature = "frb-api"))]
mod secret;

// need to be public for flutter rust bridge
#[cfg(feature = "frb-api")]
pub mod file_storage;
#[cfg(feature = "frb-api")]
pub mod relay;
#[cfg(feature = "frb-api")]
pub mod secret;

pub use super::Client;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb)]
// File Storage
impl Client {
    pub fn client_secret_hex(&self) -> Result<String> {
        self.client_secret.to_hex()
    }

    pub fn id_hex(&self) -> String {
        hex::encode(self.client_secret.inner_keypair.id())
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl Client {
    /// Get access to the multi-relay message manager
    pub fn message_manager(&self) -> &Arc<ZoeClientMessageManager> {
        &self.message_manager
    }

    /// Get access to the multi-relay blob service
    pub fn blob_service(&self) -> &Arc<ZoeClientBlobService> {
        &self.blob_service
    }

    /// Get access to storage
    pub fn storage(&self) -> &Arc<ZoeClientStorage> {
        &self.storage
    }

    /// Get the client's public key
    pub fn public_key(&self) -> VerifyingKey {
        self.client_secret.inner_keypair.public_key()
    }

    /// Get the client's keypair
    pub fn keypair(&self) -> &Arc<KeyPair> {
        &self.client_secret.inner_keypair
    }

    /// Close the client and clean up all resources
    /// Get access to the session manager for PQXDH operations
    ///
    /// This provides access to the underlying session manager which handles
    /// PQXDH protocol handlers and state management.
    ///
    /// # Returns
    ///
    /// A reference to the `SessionManager`
    pub async fn session_manager(&self) -> &Arc<ZoeClientSessionManager> {
        &self.session_manager
    }
    /// Get a reference to the blob client for advanced operations
    ///
    /// This provides direct access to the underlying blob storage client
    /// for operations not covered by the high-level file storage API.
    ///
    /// # Returns
    ///
    /// A reference to the `BlobClient`
    pub fn blob_client(&self) -> &BlobClient {
        self.fs.blob_client()
    }
}
