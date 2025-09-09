use crate::error::Result;
use crate::services::MultiRelayMessageManager;
use crate::services::blob_store::MultiRelayBlobService;
use crate::util::DEFAULT_PORT;
use crate::{ClientError, FileStorage, RelayClient, RelayClientBuilder, SessionManager};
use eyeball::{SharedObservable, Subscriber};
use rand::Rng;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use zoe_app_primitives::{CompressionConfig, FileRef, RelayAddress};
use zoe_blob_store::BlobClient;
use zoe_client_storage::{SqliteMessageStorage, StorageConfig};
use zoe_wire_protocol::{KeyId, KeyPair, VerifyingKey};
// Note: serde imports removed since ML-DSA types don't support serde
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

// Note: ML-DSA types don't have simple serde serialization, so we'll handle this differently
#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSecret {
    #[serde(
        serialize_with = "serialize_key_pair",
        deserialize_with = "deserialize_key_pair"
    )]
    inner_keypair: Arc<KeyPair>, // inner protocol
    servers: Vec<RelayAddress>,
    encryption_key: [u8; 32],
}

impl PartialEq for ClientSecret {
    fn eq(&self, other: &Self) -> bool {
        // Compare servers and encryption key, but not keypair (since KeyPair doesn't implement Eq)
        self.servers == other.servers && self.encryption_key == other.encryption_key
    }
}

impl Eq for ClientSecret {}

impl ClientSecret {
    /// Get the list of configured servers
    pub fn servers(&self) -> &[RelayAddress] {
        &self.servers
    }
}

// Note: ML-DSA types don't have simple serde serialization, so we'll handle this differently
#[cfg_attr(feature = "frb-api", frb(ignore))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyClientSecret {
    #[serde(
        serialize_with = "serialize_key_pair",
        deserialize_with = "deserialize_key_pair"
    )]
    inner_keypair: Arc<KeyPair>, // inner protocol
    server_public_key: VerifyingKey, // TLS server key
    server_addr: SocketAddr,
    encryption_key: [u8; 32],
}

impl PartialEq for LegacyClientSecret {
    fn eq(&self, other: &Self) -> bool {
        // Compare all fields except keypair (since KeyPair doesn't implement Eq)
        self.server_public_key == other.server_public_key
            && self.server_addr == other.server_addr
            && self.encryption_key == other.encryption_key
    }
}

impl Eq for LegacyClientSecret {}

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
        let secret = match postcard::from_bytes(&bytes) {
            Ok(secret) => secret,
            Err(e) => {
                tracing::warn!(
                    "Failed to deserialize client secret: {}. Trying with legacy format.",
                    e
                );
                let legacy_secret: LegacyClientSecret =
                    postcard::from_bytes(&bytes).map_err(|e| {
                        ClientError::BuildError(format!(
                            "Failed to deserialize legacy client secret: {}",
                            e
                        ))
                    })?;
                ClientSecret {
                    inner_keypair: legacy_secret.inner_keypair,
                    servers: vec![
                        RelayAddress::new(legacy_secret.server_public_key)
                            .with_address(legacy_secret.server_addr.into()),
                    ],
                    encryption_key: legacy_secret.encryption_key,
                }
            }
        };
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
    servers: Option<Vec<RelayAddress>>,
    db_storage_dir: Option<PathBuf>,
    encryption_key: Option<[u8; 32]>,
    autoconnect: bool,
}

impl ClientBuilder {
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn client_secret(&mut self, secret: ClientSecret) {
        self.servers = Some(secret.servers);
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
    pub fn servers(&mut self, servers: Vec<RelayAddress>) {
        self.servers = Some(servers);
    }

    #[cfg_attr(feature = "frb-api", frb)]
    pub fn server_info(&mut self, server_public_key: VerifyingKey, server_addr: SocketAddr) {
        self.servers = Some(vec![
            RelayAddress::new(server_public_key)
                .with_address(server_addr.into())
                .with_name("Legacy Server".to_string()),
        ]);
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

    /// Enable or disable automatic connection to server during build
    ///
    /// When autoconnect is true (default for backward compatibility), the client
    /// will require server information and connect immediately during build().
    /// When autoconnect is false, the client starts in offline mode and can
    /// connect to relays later using add_relay().
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn autoconnect(&mut self, autoconnect: bool) {
        self.autoconnect = autoconnect;
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

        // Server info is only required when autoconnect is true (default behavior)
        if self.autoconnect {
            if self.servers.is_none() || self.servers.as_ref().unwrap().is_empty() {
                return Err(ClientError::BuildError(
                    "At least one server is required when autoconnect is enabled".to_string(),
                ));
            }
        }

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

        // Create storage
        let fs_path = media_storage_dir.to_path_buf().join(&user_id_hex);
        let storage_config = StorageConfig {
            database_path: db_storage_dir.join(&user_id_hex).join("db.sqlite"),
            max_query_limit: None,
            enable_wal_mode: false,
            cache_size_kb: None,
        };

        let storage = Arc::new(
            SqliteMessageStorage::new(storage_config, &encryption_key)
                .await
                .map_err(|e| ClientError::BuildError(format!("Failed to create storage: {}", e)))?,
        );

        // Initialize broadcast channel for relay status updates
        let (relay_status_sender, _) = broadcast::channel(100);
        // Offline mode: use multi-relay services
        let message_manager = Arc::new(MultiRelayMessageManager::new(Arc::clone(&storage)));
        let blob_service = Arc::new(MultiRelayBlobService::new(Arc::clone(&storage)));
        let session_manager = Arc::new(
            SessionManager::builder(Arc::clone(&storage), message_manager.clone())
                .client_keypair(key_pair.clone())
                .build()
                .await
                .map_err(|e| {
                    ClientError::BuildError(format!("Failed to create session manager: {}", e))
                })?,
        );

        let fs =
            FileStorage::new(&fs_path, blob_service.clone(), CompressionConfig::default()).await?;

        let servers = self.servers.clone().unwrap_or_default();
        let client_secret = ClientSecret {
            inner_keypair: key_pair,
            servers: servers.clone(),
            encryption_key: encryption_key,
        };

        // Initialize observable state for client secret
        let client_secret_observable = SharedObservable::new(client_secret.clone());

        let client = Client {
            client_secret: Arc::new(client_secret),
            fs: Arc::new(fs),
            storage: Arc::clone(&storage),
            message_manager,
            blob_service,
            relay_connections: Arc::new(RwLock::new(BTreeMap::new())),
            relay_info: Arc::new(RwLock::new(BTreeMap::new())),
            encryption_key,
            client_secret_observable,
            relay_status_sender,
            connection_monitors: Arc::new(RwLock::new(BTreeMap::new())),
            session_manager,
        };

        // If autoconnect is enabled, add the first server immediately
        if self.autoconnect && !servers.is_empty() {
            let first_server = &servers[0];
            let relay_address = first_server.clone();

            // Add the relay (this will attempt to connect)
            if let Err(e) = client.add_relay(relay_address).await {
                tracing::warn!(
                    "Failed to connect to initial relay in autoconnect mode: {}",
                    e
                );
                // Don't fail the build, just log the warning
            }
        }

        Ok(client)
    }
}

/// Connection information for a relay server
///
/// Stores the full RelayAddress configuration so we can attempt reconnection
/// to all available addresses, not just the last successful one.
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub relay_id: KeyId,
    pub relay_address: RelayAddress,
}

/// Connection status for a relay
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConnectionStatus {
    /// Not connected
    Disconnected {
        /// Optional connection error that caused the disconnection
        error: Option<String>,
    },
    /// Currently connecting
    Connecting,
    /// Connected and operational to a specific address
    Connected {
        /// The specific address that the connection succeeded on
        connected_address: SocketAddr,
    },
    /// Connection failed
    Failed { error: String },
}

/// Represents a relay connection with its status
#[derive(Debug, Clone)]
pub struct RelayConnectionInfo {
    pub info: RelayInfo,
    pub status: RelayConnectionStatus,
}

// ClientSecret is used directly - no wrapper needed

/// Per-relay connection status update
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatusUpdate {
    /// The relay ID
    pub relay_id: KeyId,
    /// The relay address information
    pub relay_address: RelayAddress,
    /// Current connection status
    pub status: RelayConnectionStatus,
}

/// Overall connection status for the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverallConnectionStatus {
    /// True if connected to at least one relay
    pub is_connected: bool,
    /// Number of connected relays
    pub connected_count: usize,
    /// Total number of configured relays
    pub total_count: usize,
}

pub type ZoeClientStorage = SqliteMessageStorage;
pub type ZoeClientSessionManager = SessionManager<ZoeClientStorage, ZoeClientMessageManager>;
pub type ZoeClientMessageManager = MultiRelayMessageManager<ZoeClientStorage>;
pub type ZoeClientBlobService = MultiRelayBlobService<ZoeClientStorage>;
pub type ZoeClientFileStorage = FileStorage<ZoeClientBlobService>;

#[derive(Clone)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct Client {
    client_secret: Arc<ClientSecret>,
    fs: Arc<ZoeClientFileStorage>,
    // All clients now use multi-relay architecture
    storage: Arc<ZoeClientStorage>,
    message_manager: Arc<ZoeClientMessageManager>,
    blob_service: Arc<ZoeClientBlobService>,
    relay_connections: Arc<RwLock<BTreeMap<KeyId, RelayClient>>>,
    relay_info: Arc<RwLock<BTreeMap<KeyId, RelayConnectionInfo>>>,
    encryption_key: [u8; 32],
    /// Observable state for client secret updates - third parties can subscribe to changes
    client_secret_observable: SharedObservable<ClientSecret>,
    /// Broadcast channel for per-relay connection status updates
    relay_status_sender: broadcast::Sender<RelayStatusUpdate>,
    /// Connection monitoring tasks for each relay
    connection_monitors: Arc<RwLock<BTreeMap<KeyId, JoinHandle<()>>>>,
    /// Session manager for the client
    session_manager: Arc<ZoeClientSessionManager>,
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
}

// Relay management methods (only available in offline mode)
#[cfg_attr(feature = "frb-api", frb)]
impl Client {
    /// Add a relay server to the client
    ///
    /// This will attempt to connect to all addresses in the RelayAddress in random order
    /// with a 10-second timeout per attempt. Only adds the relay to local state if a
    /// connection succeeds.
    pub async fn add_relay(&self, address: RelayAddress) -> Result<()> {
        let relay_id = address.id();

        // Notify about connecting status
        self.notify_relay_status_change(
            relay_id,
            address.clone(),
            RelayConnectionStatus::Connecting,
        )
        .await;

        // Try to connect to any of the addresses
        match self.try_connect_to_relay_addresses(&address).await {
            Ok((successful_addr, relay_client)) => {
                let relay_info = RelayInfo {
                    relay_id,
                    relay_address: address.clone(),
                };

                // Update relay info with successful connection
                {
                    let mut info_map = self.relay_info.write().await;
                    info_map.insert(
                        relay_id,
                        RelayConnectionInfo {
                            info: relay_info.clone(),
                            status: RelayConnectionStatus::Connected {
                                connected_address: successful_addr,
                            },
                        },
                    );
                }

                // Add to connections
                {
                    let mut connections = self.relay_connections.write().await;
                    connections.insert(relay_id, relay_client.clone());
                }

                // Add services to multi-relay managers
                let messages_manager = relay_client
                    .persistence_manager()
                    .await
                    .messages_manager()
                    .clone();
                let blob_service = Arc::clone(relay_client.blob_service().await?);

                self.message_manager
                    .add_relay(relay_id, messages_manager, true)
                    .await?;
                self.blob_service.add_relay(relay_id, blob_service).await;

                tracing::info!(
                    "Successfully connected to relay {} at address: {}",
                    hex::encode(relay_id.as_bytes()),
                    successful_addr
                );

                // Start connection monitoring for this relay
                self.start_connection_monitoring(relay_id, relay_client.clone());

                // Update observable states
                self.update_client_secret_state().await;
                self.notify_relay_status_change(
                    relay_id,
                    address,
                    RelayConnectionStatus::Connected {
                        connected_address: successful_addr,
                    },
                )
                .await;

                Ok(())
            }
            Err(connection_errors) => {
                tracing::warn!(
                    "Failed to connect to relay {} at any address. Errors: {:?}",
                    hex::encode(relay_id.as_bytes()),
                    connection_errors
                );

                // Add to relay info with failed status so we can track and retry later
                let error_summary = connection_errors
                    .iter()
                    .map(|(addr, err)| format!("{}: {}", addr, err))
                    .collect::<Vec<_>>()
                    .join("; ");

                let relay_info = RelayInfo {
                    relay_id,
                    relay_address: address.clone(),
                };

                let failed_status = RelayConnectionStatus::Failed {
                    error: format!("All connection attempts failed: {}", error_summary),
                };

                // Store the failed relay info for future reconnection attempts
                {
                    let mut info_map = self.relay_info.write().await;
                    info_map.insert(
                        relay_id,
                        RelayConnectionInfo {
                            info: relay_info,
                            status: failed_status.clone(),
                        },
                    );
                }

                // Don't update client secret for failed connections
                // (only successful connections should be persisted)

                self.notify_relay_status_change(relay_id, address, failed_status)
                    .await;

                Err(ClientError::Generic(format!(
                    "Failed to connect to relay at any address: {}",
                    error_summary
                )))
            }
        }
    }

    /// Try to connect to a relay using all its addresses in random order
    ///
    /// Returns the successful address and relay client, or all connection errors
    async fn try_connect_to_relay_addresses(
        &self,
        address: &RelayAddress,
    ) -> std::result::Result<(SocketAddr, RelayClient), Vec<(String, ClientError)>> {
        use rand::seq::SliceRandom;

        let network_addresses: Vec<_> = address.all_addresses().iter().cloned().collect();
        if network_addresses.is_empty() {
            return Err(vec![(
                "no addresses".to_string(),
                ClientError::Generic("No addresses provided".to_string()),
            )]);
        }

        // Randomize the order of connection attempts
        let mut shuffled_addresses = network_addresses;
        shuffled_addresses.shuffle(&mut rand::thread_rng());

        let mut connection_errors = Vec::new();

        for network_addr in shuffled_addresses {
            let addr_display = network_addr.to_connection_string(Some(DEFAULT_PORT));
            tracing::debug!("Attempting to connect to relay at: {}", addr_display);

            // Resolve address with timeout
            let socket_addr = match tokio::time::timeout(
                Duration::from_secs(5), // 5s for DNS resolution
                network_addr.resolve_to_socket_addr(DEFAULT_PORT),
            )
            .await
            {
                Ok(Ok(addr)) => addr,
                Ok(Err(e)) => {
                    connection_errors.push((
                        addr_display,
                        ClientError::Generic(format!("DNS resolution failed: {}", e)),
                    ));
                    continue;
                }
                Err(_) => {
                    connection_errors.push((
                        addr_display,
                        ClientError::Generic("DNS resolution timeout".to_string()),
                    ));
                    continue;
                }
            };

            // Attempt connection with timeout
            match tokio::time::timeout(
                Duration::from_secs(10), // 10s for connection attempt
                self.connect_to_relay(address.public_key.clone(), socket_addr),
            )
            .await
            {
                Ok(Ok(relay_client)) => {
                    tracing::info!("Successfully connected to relay at: {}", socket_addr);
                    return Ok((socket_addr, relay_client));
                }
                Ok(Err(e)) => {
                    connection_errors.push((addr_display, e));
                }
                Err(_) => {
                    connection_errors.push((
                        addr_display,
                        ClientError::Generic("Connection timeout".to_string()),
                    ));
                }
            }
        }

        Err(connection_errors)
    }

    /// Remove a relay connection (offline mode only)
    pub async fn remove_relay(&self, server_public_key: VerifyingKey) -> Result<bool> {
        let relay_id = server_public_key.id();

        // Get relay info before removing
        let relay_info = {
            let info_map = self.relay_info.read().await;
            info_map.get(&relay_id).map(|info| info.info.clone())
        };

        // Stop connection monitoring
        self.stop_connection_monitoring(relay_id).await;

        // Remove from multi-relay managers
        self.message_manager.remove_relay(&relay_id).await;
        self.blob_service.remove_relay(&relay_id).await;

        // Close and remove connection
        let removed = {
            let mut connections = self.relay_connections.write().await;
            connections.remove(&relay_id)
        };

        let had_active_connection = removed.is_some();
        if let Some(relay_client) = removed {
            relay_client.close().await;
        }

        // Update relay info (or remove if it exists)
        let had_relay_info = {
            let mut info_map = self.relay_info.write().await;
            if let Some(info) = info_map.get_mut(&relay_id) {
                info.status = RelayConnectionStatus::Disconnected {
                    error: None, // Manual removal, no error
                };
                true
            } else {
                false
            }
        };

        let was_removed = had_active_connection || had_relay_info;

        tracing::info!(
            "Removed relay connection: {}",
            hex::encode(relay_id.as_bytes())
        );

        // Update observable states
        self.update_client_secret_state().await;

        // Notify about disconnection if we had the relay info
        if let Some(info) = relay_info {
            self.notify_relay_status_change(
                relay_id,
                info.relay_address,
                RelayConnectionStatus::Disconnected {
                    error: None, // Manual removal, no error
                },
            )
            .await;
        }

        Ok(was_removed)
    }

    /// Get list of all configured relays with their connection status
    pub async fn get_relay_status(&self) -> Result<Vec<RelayConnectionInfo>> {
        let info_map = self.relay_info.read().await;
        Ok(info_map.values().cloned().collect())
    }

    /// Check if any relays are currently connected
    pub async fn has_connected_relays(&self) -> bool {
        self.overall_status().await.is_connected
    }

    /// Attempt to reconnect to all failed relays
    pub async fn reconnect_failed_relays(&self) -> Result<usize> {
        let failed_relays: Vec<RelayInfo> = {
            let info_map = self.relay_info.read().await;
            info_map
                .values()
                .filter(|info| matches!(info.status, RelayConnectionStatus::Failed { .. }))
                .map(|info| info.info.clone())
                .collect()
        };

        let mut reconnected = 0;
        for relay_info in failed_relays {
            // Use the full RelayAddress which contains all configured addresses
            if self.add_relay(relay_info.relay_address).await.is_ok() {
                reconnected += 1;
            }
        }

        Ok(reconnected)
    }

    /// Connect to a specific relay (internal method)
    async fn connect_to_relay(
        &self,
        server_public_key: VerifyingKey,
        server_addr: SocketAddr,
    ) -> Result<RelayClient> {
        let relay_client = RelayClientBuilder::new()
            .server_public_key(server_public_key)
            .server_address(server_addr)
            .storage(Arc::clone(&self.storage))
            .client_keypair(Arc::clone(&self.client_secret.inner_keypair))
            .autosubscribe(true)
            .build()
            .await?;

        Ok(relay_client)
    }

    /// Get access to the multi-relay message manager
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn message_manager(&self) -> &Arc<MultiRelayMessageManager<SqliteMessageStorage>> {
        &self.message_manager
    }

    /// Get access to the multi-relay blob service
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn blob_service(&self) -> &Arc<MultiRelayBlobService<SqliteMessageStorage>> {
        &self.blob_service
    }

    /// Get access to storage
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn storage(&self) -> &Arc<SqliteMessageStorage> {
        &self.storage
    }

    /// Get the client's public key
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub fn public_key(&self) -> VerifyingKey {
        self.client_secret.inner_keypair.public_key()
    }

    /// Get the client's keypair
    #[cfg_attr(feature = "frb-api", frb(ignore))]
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
    #[cfg_attr(feature = "frb-api", frb(ignore))]
    pub async fn session_manager(&self) -> &Arc<ZoeClientSessionManager> {
        &self.session_manager
    }

    pub async fn close(&self) {
        // Stop all connection monitors
        {
            let mut monitors = self.connection_monitors.write().await;
            for (relay_id, monitor_task) in monitors.iter() {
                tracing::debug!(
                    "Stopping connection monitor for relay: {}",
                    hex::encode(relay_id.as_bytes())
                );
                monitor_task.abort();
            }
            monitors.clear();
        }

        // Close all relay connections
        let relay_clients = {
            let mut connections = self.relay_connections.write().await;
            let clients: Vec<_> = connections.values().cloned().collect();
            connections.clear();
            clients
        };

        for relay_client in relay_clients {
            relay_client.close().await;
        }
    }

    /// Subscribe to client secret updates
    ///
    /// Third parties can use this to be notified when the client secret changes,
    /// allowing them to store updated client secrets with the current server configuration.
    pub fn subscribe_to_client_secret(&self) -> Subscriber<ClientSecret> {
        self.client_secret_observable.subscribe()
    }

    /// Subscribe to per-relay connection status updates
    ///
    /// This provides real-time updates about individual relay connection status changes.
    /// Each relay reports its status independently via this broadcast channel.
    pub fn subscribe_to_relay_status(&self) -> broadcast::Receiver<RelayStatusUpdate> {
        self.relay_status_sender.subscribe()
    }

    /// Create a stream of overall connection status computed from relay status updates
    ///
    /// This is a computed stream that automatically updates when any relay status changes.
    /// It maintains local state and only locks once for initial state, then updates based on
    /// incoming relay status changes without additional locking.
    pub fn overall_status_stream(
        &self,
    ) -> impl futures::Stream<Item = OverallConnectionStatus> + '_ {
        let client = self.clone();
        let relay_receiver = self.subscribe_to_relay_status();

        async_stream::stream! {
            let mut relay_receiver = relay_receiver;

            // Get initial status using existing function (only lock once)
            let mut current_status = client.overall_status().await;
            yield current_status.clone();

            // Keep track of relay states locally to avoid locking
            let mut relay_states = std::collections::BTreeMap::new();

            // Update local state based on relay status changes
            while let Ok(update) = relay_receiver.recv().await {
                // Update our local tracking of this relay's status
                let was_connected = relay_states.get(&update.relay_id)
                    .map(|status| matches!(status, RelayConnectionStatus::Connected { .. }))
                    .unwrap_or(false);

                let is_now_connected = matches!(update.status, RelayConnectionStatus::Connected { .. });

                // Update local relay state
                relay_states.insert(update.relay_id, update.status);

                // Update overall status based on the change
                if was_connected && !is_now_connected {
                    // A relay disconnected
                    current_status.connected_count = current_status.connected_count.saturating_sub(1);
                } else if !was_connected && is_now_connected {
                    // A relay connected
                    current_status.connected_count += 1;
                }

                // Update total count (relay was added to our tracking)
                current_status.total_count = relay_states.len();

                // Update is_connected flag
                current_status.is_connected = current_status.connected_count > 0;

                yield current_status.clone();
            }
        }
    }

    /// Get the current client secret
    pub fn client_secret(&self) -> ClientSecret {
        self.client_secret_observable.get()
    }

    /// Calculate the current overall connection status
    ///
    /// This is computed from the current relay states, ensuring it's always accurate but makes it
    /// a bit more expensive to compute. For live updates it is recommended to use `overall_status_stream`
    /// instead.
    pub async fn overall_status(&self) -> OverallConnectionStatus {
        let (connected_count, total_count) = {
            let info_map = self.relay_info.read().await;
            let connected = info_map
                .values()
                .filter(|info| matches!(info.status, RelayConnectionStatus::Connected { .. }))
                .count();
            // Only count successfully connected or disconnected relays, not failed ones
            let total = info_map
                .values()
                .filter(|info| !matches!(info.status, RelayConnectionStatus::Failed { .. }))
                .count();
            (connected, total)
        };

        OverallConnectionStatus {
            is_connected: connected_count > 0,
            connected_count,
            total_count,
        }
    }

    /// Update the client secret observable state with current server configuration
    async fn update_client_secret_state(&self) {
        // Get only successfully connected servers for persistence in client secret
        let connected_servers = {
            let info_map = self.relay_info.read().await;
            info_map
                .values()
                .filter(|info| matches!(info.status, RelayConnectionStatus::Connected { .. }))
                .map(|info| info.info.relay_address.clone())
                .collect::<Vec<_>>()
        };

        // Update client secret with current server configuration
        let mut updated_client_secret = (*self.client_secret).clone();
        updated_client_secret.servers = connected_servers;

        self.client_secret_observable.set(updated_client_secret);
    }

    /// Start monitoring a relay connection for disconnections
    fn start_connection_monitoring(&self, relay_id: KeyId, relay_client: RelayClient) {
        let client = self.clone();
        let connection = relay_client.connection().clone();
        let monitors = Arc::clone(&self.connection_monitors);

        let monitor_task = tokio::spawn(async move {
            // Monitor the connection for closure
            let closed_future = connection.closed();
            let connection_error = closed_future.await;

            let error_msg = connection_error.to_string();
            tracing::warn!(
                "Relay connection lost for relay {}: {}",
                hex::encode(relay_id.as_bytes()),
                error_msg
            );

            // Get relay info for status update
            let relay_address = {
                let info_map = client.relay_info.read().await;
                info_map
                    .get(&relay_id)
                    .map(|info| info.info.relay_address.clone())
            };

            if let Some(relay_address) = relay_address {
                // Update relay status to disconnected with error details
                {
                    let mut info_map = client.relay_info.write().await;
                    if let Some(info) = info_map.get_mut(&relay_id) {
                        info.status = RelayConnectionStatus::Disconnected {
                            error: Some(error_msg.clone()),
                        };
                    }
                }

                // Remove from active connections
                {
                    let mut connections = client.relay_connections.write().await;
                    connections.remove(&relay_id);
                }

                // Remove from multi-relay managers
                client.message_manager.remove_relay(&relay_id).await;
                client.blob_service.remove_relay(&relay_id).await;

                // Update observable states
                client.update_client_secret_state().await;

                // Notify about disconnection
                client
                    .notify_relay_status_change(
                        relay_id,
                        relay_address.clone(),
                        RelayConnectionStatus::Disconnected {
                            error: Some(error_msg),
                        },
                    )
                    .await;

                // Attempt automatic reconnection after a delay
                let reconnect_client = client.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;

                    tracing::info!(
                        "Attempting automatic reconnection to relay: {}",
                        hex::encode(relay_id.as_bytes())
                    );

                    if let Err(e) = reconnect_client.add_relay(relay_address).await {
                        tracing::warn!(
                            "Automatic reconnection failed for relay {}: {}",
                            hex::encode(relay_id.as_bytes()),
                            e
                        );
                    }
                });
            }
        });

        // Store the monitor task
        tokio::spawn(async move {
            let mut monitor_map = monitors.write().await;
            monitor_map.insert(relay_id, monitor_task);
        });
    }

    /// Stop monitoring a relay connection
    async fn stop_connection_monitoring(&self, relay_id: KeyId) {
        let mut monitors = self.connection_monitors.write().await;
        if let Some(monitor_task) = monitors.remove(&relay_id) {
            monitor_task.abort();
        }
    }

    /// Notify about relay status change
    async fn notify_relay_status_change(
        &self,
        relay_id: KeyId,
        relay_address: RelayAddress,
        status: RelayConnectionStatus,
    ) {
        let status_update = RelayStatusUpdate {
            relay_id,
            relay_address,
            status,
        };

        // Send to broadcast channel - ignore if no receivers
        let _ = self.relay_status_sender.send(status_update);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;
    use tokio::fs;

    async fn create_test_client_offline() -> (Client, TempDir, TempDir) {
        let media_temp_dir = TempDir::new().unwrap();
        let db_temp_dir = TempDir::new().unwrap();

        let mut builder = ClientBuilder::default();
        builder.media_storage_dir_pathbuf(media_temp_dir.path().to_path_buf());
        builder.db_storage_dir_pathbuf(db_temp_dir.path().to_path_buf());
        builder.encryption_key([42u8; 32]);
        builder.autoconnect(false); // Offline mode

        let client = builder.build().await.unwrap();
        (client, media_temp_dir, db_temp_dir)
    }

    #[tokio::test]
    async fn test_client_file_storage_offline() {
        let (client, media_temp_dir, _db_temp_dir) = create_test_client_offline().await;

        // Create a test file
        let test_file_path = media_temp_dir.path().join("test_file.txt");
        let test_content = b"Hello, offline world!";
        fs::write(&test_file_path, test_content).await.unwrap();

        // Store the file
        let file_ref = client.store_file(test_file_path.clone()).await.unwrap();
        assert!(!file_ref.blob_hash.is_empty());

        // Check if file exists
        assert!(client.has_file(&file_ref).await.unwrap());

        // Retrieve file as bytes
        let retrieved_content = client.retrieve_file_bytes(&file_ref).await.unwrap();
        assert_eq!(retrieved_content, test_content);

        // Retrieve file to disk
        let output_path = media_temp_dir.path().join("retrieved_file.txt");
        client
            .retrieve_file(&file_ref, output_path.clone())
            .await
            .unwrap();

        let disk_content = fs::read(&output_path).await.unwrap();
        assert_eq!(disk_content, test_content);
    }

    #[tokio::test]
    async fn test_client_relay_management_offline() {
        let (client, _media_temp_dir, _db_temp_dir) = create_test_client_offline().await;

        // Initially no relays
        assert!(client.get_relay_status().await.unwrap().is_empty());
        assert!(!client.has_connected_relays().await);

        // Adding a relay should fail (no actual server running)
        let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
        let relay_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let relay_address =
            RelayAddress::new(relay_keypair.public_key()).with_address(relay_addr.into());

        let result = client.add_relay(relay_address).await;
        assert!(result.is_err());

        // Relay should be tracked as failed
        let status = client.get_relay_status().await.unwrap();
        assert_eq!(status.len(), 1);
        assert!(matches!(
            status[0].status,
            RelayConnectionStatus::Failed { .. }
        ));
    }

    #[tokio::test]
    async fn test_client_builder_validation() {
        // Missing media storage dir
        let mut builder = ClientBuilder::default();
        builder.db_storage_dir_pathbuf(TempDir::new().unwrap().path().to_path_buf());
        let result = builder.build().await;
        assert!(result.is_err());

        // Missing db storage dir
        let mut builder = ClientBuilder::default();
        builder.media_storage_dir_pathbuf(TempDir::new().unwrap().path().to_path_buf());
        let result = builder.build().await;
        assert!(result.is_err());

        // Missing server info in autoconnect mode
        let mut builder = ClientBuilder::default();
        builder.media_storage_dir_pathbuf(TempDir::new().unwrap().path().to_path_buf());
        builder.db_storage_dir_pathbuf(TempDir::new().unwrap().path().to_path_buf());
        builder.autoconnect(true);
        let result = builder.build().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_client_public_key_access() {
        let (client, _media_temp_dir, _db_temp_dir) = create_test_client_offline().await;

        let public_key = client.public_key();
        let keypair = client.keypair();

        // Public key from keypair should match direct access
        assert_eq!(public_key, keypair.public_key());
        assert_eq!(client.id_hex(), hex::encode(public_key.id()));
    }

    #[tokio::test]
    async fn test_client_close() {
        let (client, _media_temp_dir, _db_temp_dir) = create_test_client_offline().await;

        // Close should complete without error
        client.close().await;
    }
}
