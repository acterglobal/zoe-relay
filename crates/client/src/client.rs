use crate::error::Result;
use crate::{ClientError, FileStorage, RelayClient};
use zoe_wire_protocol::prelude::*;
// Note: serde imports removed since ML-DSA types don't support serde
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use zoe_app_primitives::FileRef;
use zoe_blob_store::BlobClient;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

// Note: ML-DSA types don't have simple serde serialization, so we'll handle this differently
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct ClientSecret {
    inner_keypair: KeyPair, // ML-DSA-65 for inner protocol
    server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>, // TLS server key
    server_addr: SocketAddr,
}

// Note: Serialization removed due to ML-DSA types not supporting serde
// TODO: Implement custom serialization if needed for ClientSecret

impl ClientSecret {
    // Add this constructor method
    pub fn new(
        inner_keypair: KeyPair,
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        server_addr: SocketAddr,
    ) -> Self {
        Self {
            inner_keypair,
            server_public_key,
            server_addr,
        }
    }

    /// Get the inner keypair (ML-DSA-65)
    pub fn inner_keypair(&self) -> &KeyPair {
        &self.inner_keypair
    }

    /// Get the server public key (ML-DSA-44)
    pub fn server_public_key(&self) -> &ml_dsa::VerifyingKey<ml_dsa::MlDsa44> {
        &self.server_public_key
    }

    // Note: as_hex() method removed due to ML-DSA serialization complexity
    // TODO: Implement custom serialization if needed

    // Note: from_hex() method removed due to ML-DSA serialization complexity
    // TODO: Implement custom serialization if needed
}

pub struct ClientInner {
    fs: FileStorage,
    #[allow(dead_code)]
    relay_client: RelayClient,
}

#[derive(Default)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct ClientBuilder {
    media_storage_path: Option<PathBuf>,
    inner_keypair: Option<KeyPair>,
    server_public_key: Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>>,
    server_addr: Option<SocketAddr>,
}

impl ClientBuilder {
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn client_secret(&mut self, secret: ClientSecret) {
        self.server_addr = Some(secret.server_addr);
        self.server_public_key = Some(secret.server_public_key);
        self.inner_keypair = Some(secret.inner_keypair);
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub fn media_storage_path(&mut self, media_storage_path: String) {
        self.media_storage_path = Some(PathBuf::from(media_storage_path));
    }

    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn inner_keypair(&mut self, inner_keypair: KeyPair) {
        self.inner_keypair = Some(inner_keypair);
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub fn server_info(
        &mut self,
        server_public_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        server_addr: SocketAddr,
    ) {
        self.server_public_key = Some(server_public_key);
        self.server_addr = Some(server_addr);
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub async fn build(self) -> Result<Client> {
        let Some(media_storage_path) = self.media_storage_path else {
            return Err(ClientError::BuildError(
                "Media storage path is required".to_string(),
            ));
        };

        let Some(server_public_key) = self.server_public_key else {
            return Err(ClientError::BuildError(
                "Server public key is required".to_string(),
            ));
        };

        let Some(server_addr) = self.server_addr else {
            return Err(ClientError::BuildError(
                "Server address is required".to_string(),
            ));
        };

        let relay_client = if let Some(inner_keypair) = self.inner_keypair {
            RelayClient::new(inner_keypair, server_public_key, server_addr).await?
        } else {
            RelayClient::new_with_random_key(server_public_key, server_addr).await?
        };

        // Create blob service for remote blob operations
        let blob_service = relay_client.connect_blob_service().await?;

        // Create file storage with remote blob service support
        let fs = FileStorage::new_with_remote(media_storage_path.as_path(), blob_service).await?;

        Ok(Client {
            inner: Arc::new(ClientInner { fs, relay_client }),
        })
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// Create a new ClientBuilder for constructing a Client
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }
}

// File Storage
impl Client {
    /// Store a file by reading from disk, encrypting, and storing in blob storage
    ///
    /// This method:
    /// 1. Reads the file from the provided path
    /// 2. Encrypts the content using convergent encryption
    /// 3. Stores the encrypted data in the blob store
    /// 4. Returns metadata needed to retrieve the file later
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to store
    ///
    /// # Returns
    ///
    /// A `FileRef` containing the metadata needed to retrieve the file
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read
    /// - Encryption fails
    /// - Blob storage operation fails
    pub async fn store_file(&self, file_path: PathBuf) -> Result<FileRef> {
        self.inner.fs.store_file(&file_path).await
    }

    /// Store raw data (not from a file) with encryption and blob storage
    ///
    /// This method allows storing arbitrary data without reading from disk.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw data to store
    /// * `reference_name` - A reference name for the data (used in metadata)
    /// * `content_type` - Optional content type for metadata
    ///
    /// # Returns
    ///
    /// `FileRef` containing the blob hash, encryption info, and metadata
    pub async fn store_data(
        &self,
        data: &[u8],
        reference_name: &str,
        content_type: Option<String>,
    ) -> Result<FileRef> {
        self.inner
            .fs
            .store_data(data, reference_name, content_type)
            .await
    }

    /// Check if a file exists in storage
    ///
    /// # Arguments
    ///
    /// * `stored_info` - Metadata from when the file was stored
    ///
    /// # Returns
    ///
    /// `true` if the file exists in storage, `false` otherwise
    pub async fn has_file(&self, stored_info: &FileRef) -> Result<bool> {
        self.inner.fs.has_file(stored_info).await
    }

    /// Retrieve a file from storage and save it to disk
    ///
    /// This method:
    /// 1. Retrieves the encrypted data from blob storage using the FileRef
    /// 2. Decrypts the content
    /// 3. Writes the decrypted content to the specified path
    ///
    /// # Arguments
    ///
    /// * `file_ref` - Metadata for the file to retrieve
    /// * `output_path` - Path where the decrypted file should be saved
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be found in storage
    /// - Decryption fails
    /// - Writing to disk fails
    pub async fn retrieve_file(&self, file_ref: &FileRef, output_path: PathBuf) -> Result<()> {
        // Get the file content from storage
        let content = self.inner.fs.retrieve_file(file_ref).await?;

        // Write the content to the specified path
        fs::write(&output_path, content)
            .await
            .map_err(ClientError::Io)?;

        Ok(())
    }

    /// Retrieve a file from storage as bytes
    ///
    /// This method:
    /// 1. Retrieves the encrypted data from blob storage using the FileRef
    /// 2. Decrypts the content
    /// 3. Returns the decrypted content as bytes
    ///
    /// # Arguments
    ///
    /// * `file_ref` - Metadata for the file to retrieve
    ///
    /// # Returns
    ///
    /// The decrypted file content as `Vec<u8>`
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be found in storage
    /// - Decryption fails
    pub async fn retrieve_file_bytes(&self, file_ref: &FileRef) -> Result<Vec<u8>> {
        self.inner.fs.retrieve_file(file_ref).await
    }

    /// Get a reference to the blob client for advanced operations
    ///
    /// This provides direct access to the underlying blob storage client
    /// for operations not covered by the high-level file storage API.
    ///
    /// # Returns
    ///
    /// A reference to the `BlobClient`
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn blob_client(&self) -> &BlobClient {
        self.inner.fs.blob_client()
    }
}
