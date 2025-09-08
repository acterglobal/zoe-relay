use crate::error::Result;
use crate::{ClientError, FileStorage, RelayClient, RelayClientBuilder, SessionManager};
use rand::Rng;
use zoe_client_storage::{SqliteMessageStorage, StorageConfig};
use zoe_wire_protocol::{KeyPair, VerifyingKey};
// Note: serde imports removed since ML-DSA types don't support serde
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use zoe_app_primitives::{CompressionConfig, FileRef};
use zoe_blob_store::BlobClient;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

// Note: ML-DSA types don't have simple serde serialization, so we'll handle this differently
#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Serialize, Deserialize)]
pub struct ClientSecret {
    #[serde(
        serialize_with = "serialize_key_pair",
        deserialize_with = "deserialize_key_pair"
    )]
    inner_keypair: Arc<KeyPair>, // inner protocol
    server_public_key: VerifyingKey, // TLS server key
    server_addr: SocketAddr,
    encryption_key: [u8; 32],
}

fn serialize_key_pair<S>(
    key_pair: &Arc<KeyPair>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&key_pair.to_pem().map_err(serde::ser::Error::custom)?)
}
fn deserialize_key_pair<'de, D>(deserializer: D) -> std::result::Result<Arc<KeyPair>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Arc::new(
        KeyPair::from_pem(&s).map_err(serde::de::Error::custom)?,
    ))
}

impl ClientSecret {
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex).map_err(|e| {
            ClientError::BuildError(format!("Failed to decode hex for client secret: {}", e))
        })?;
        let secret = postcard::from_bytes(&bytes).map_err(|e| {
            ClientError::BuildError(format!("Failed to deserialize client secret: {}", e))
        })?;
        Ok(secret)
    }

    pub fn to_hex(&self) -> Result<String> {
        let bytes = postcard::to_stdvec(&self).map_err(|e| {
            ClientError::BuildError(format!("Failed to serialize client secret: {}", e))
        })?;
        Ok(hex::encode(bytes))
    }
}

#[derive(Default)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct ClientBuilder {
    media_storage_dir: Option<PathBuf>,
    inner_keypair: Option<Arc<KeyPair>>,
    server_public_key: Option<VerifyingKey>,
    server_addr: Option<SocketAddr>,
    db_storage_dir: Option<PathBuf>,
    encryption_key: Option<[u8; 32]>,
}

impl ClientBuilder {
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn client_secret(&mut self, secret: ClientSecret) {
        self.server_addr = Some(secret.server_addr);
        self.server_public_key = Some(secret.server_public_key);
        self.inner_keypair = Some(secret.inner_keypair);
        self.encryption_key = Some(secret.encryption_key);
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub fn media_storage_dir(&mut self, media_storage_dir: String) {
        self.media_storage_dir_pathbuf(PathBuf::from(media_storage_dir));
    }

    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn media_storage_dir_pathbuf(&mut self, media_storage_dir: PathBuf) {
        self.media_storage_dir = Some(PathBuf::from(media_storage_dir));
    }

    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn inner_keypair(&mut self, inner_keypair: KeyPair) {
        self.inner_keypair = Some(Arc::new(inner_keypair));
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub fn server_info(&mut self, server_public_key: VerifyingKey, server_addr: SocketAddr) {
        self.server_public_key = Some(server_public_key);
        self.server_addr = Some(server_addr);
    }

    /// Set the storage database path (convenience method)
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn db_storage_dir(&mut self, path: String) {
        self.db_storage_dir_pathbuf(PathBuf::from(path));
    }

    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn db_storage_dir_pathbuf(&mut self, path: PathBuf) {
        self.db_storage_dir = Some(path);
    }

    /// Set the encryption key for storage
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn encryption_key(&mut self, key: [u8; 32]) {
        self.encryption_key = Some(key);
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub async fn build(self) -> Result<Client> {
        let Some(media_storage_dir) = self.media_storage_dir else {
            return Err(ClientError::BuildError(
                "Media storage dir is required".to_string(),
            ));
        };

        let Some(db_storage_dir) = self.db_storage_dir else {
            return Err(ClientError::BuildError(
                "DB storage dir is required".to_string(),
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

        let encryption_key = match self.encryption_key {
            Some(encryption_key) => encryption_key,
            None => rand::rngs::OsRng::default().r#gen(),
        };

        let key_pair = if let Some(key_pair) = self.inner_keypair {
            key_pair
        } else {
            Arc::new(KeyPair::generate(&mut rand::rngs::OsRng))
        };

        let user_id = key_pair.id();
        let user_id_hex = hex::encode(user_id);

        // Strategy: Use tokio::task::spawn to run on separate stack
        // This completely avoids stack overflow by using a new task with fresh stack

        // Run all operations on separate tasks to avoid stack buildup
        let fs_path = media_storage_dir.to_path_buf().join(&user_id_hex);
        let storage_config = StorageConfig {
            database_path: db_storage_dir.join(&user_id_hex).join("db.sqlite"),
            max_query_limit: None,
            enable_wal_mode: false,
            cache_size_kb: None,
        };

        // Create storage instance in the ClientBuilder
        let storage = Arc::new(
            SqliteMessageStorage::new(storage_config, &encryption_key)
                .await
                .map_err(|e| ClientError::BuildError(format!("Failed to create storage: {}", e)))?,
        );

        let relay_client = RelayClientBuilder::new()
            .server_public_key(server_public_key.clone())
            .server_address(server_addr)
            .storage(storage)
            .client_keypair(key_pair.clone())
            .build()
            .await?;

        let fs = FileStorage::new(
            &fs_path,
            relay_client.blob_service().await?.clone(),
            CompressionConfig::default(),
        )
        .await?;

        Ok(Client {
            client_secret: Arc::new(ClientSecret {
                inner_keypair: key_pair,
                server_public_key: server_public_key,
                server_addr: server_addr,
                encryption_key: encryption_key,
            }),
            fs: Arc::new(fs),
            relay_client,
        })
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct Client {
    client_secret: Arc<ClientSecret>,
    fs: Arc<FileStorage>,
    relay_client: RelayClient,
}

impl Client {
    /// Create a new ClientBuilder for constructing a Client
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }
}

#[cfg_attr(feature = "frb-api", frb)]
// File Storage
impl Client {
    pub fn client_secret_hex(&self) -> Result<String> {
        self.client_secret.to_hex()
    }

    pub fn id_hex(&self) -> String {
        hex::encode(self.client_secret.inner_keypair.id())
    }

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
        self.fs.store_file(&file_path).await
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
        self.fs.store_data(data, reference_name, content_type).await
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
        self.fs.has_file(stored_info).await
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
        let content = self.fs.retrieve_file(file_ref).await?;

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
        self.fs.retrieve_file(file_ref).await
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
        self.fs.blob_client()
    }

    /// Get access to the session manager for PQXDH operations
    ///
    /// This provides access to the underlying session manager which handles
    /// PQXDH protocol handlers and state management.
    ///
    /// # Returns
    ///
    /// A reference to the `SessionManager`
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub async fn session_manager(
        &self,
    ) -> &SessionManager<
        zoe_client_storage::SqliteMessageStorage,
        crate::services::MessagePersistenceManager,
    > {
        self.relay_client.session_manager().await
    }

    /// Get the client's public key for PQXDH connections
    ///
    /// This returns the public key that other clients can use to establish
    /// PQXDH connections with this client.
    ///
    /// # Returns
    ///
    /// The client's public `VerifyingKey`
    pub fn public_key(&self) -> zoe_wire_protocol::VerifyingKey {
        self.relay_client.public_key()
    }

    pub async fn close(&self) {
        self.relay_client.close().await;
    }
}
