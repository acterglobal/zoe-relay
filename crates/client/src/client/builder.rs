use super::ClientSecret;
use crate::error::Result;
use crate::services::MultiRelayMessageManager;
use crate::services::blob_store::MultiRelayBlobService;
use crate::{Client, ClientError, FileStorage, SessionManager};
use eyeball::SharedObservable;
use rand::Rng;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use zoe_app_primitives::{CompressionConfig, RelayAddress};
use zoe_client_storage::{SqliteMessageStorage, StorageConfig};
use zoe_wire_protocol::{KeyPair, VerifyingKey};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

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

impl Client {
    /// Create a new ClientBuilder for constructing a Client
    #[cfg_attr(feature = "frb-api", frb)]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }
}

#[cfg_attr(feature = "frb-api", frb)]
impl ClientBuilder {
    pub fn client_secret(&mut self, secret: ClientSecret) {
        self.servers.get_or_insert_default().extend(secret.servers);
        self.inner_keypair = Some(secret.inner_keypair);
        self.encryption_key = Some(secret.encryption_key);
    }

    pub fn media_storage_dir(&mut self, media_storage_dir: String) {
        self.media_storage_dir_pathbuf(PathBuf::from(media_storage_dir));
    }

    pub fn servers(&mut self, servers: Vec<RelayAddress>) {
        self.servers = Some(servers);
    }

    pub fn server_info(&mut self, server_public_key: VerifyingKey, server_addr: SocketAddr) {
        self.servers.get_or_insert_default().push(
            RelayAddress::new(server_public_key)
                .with_address(server_addr.into())
                .with_name("Legacy Server".to_string()),
        );
    }

    /// Set the storage database path (convenience method)
    pub fn db_storage_dir(&mut self, path: String) {
        self.db_storage_dir_pathbuf(PathBuf::from(path));
    }

    /// Set the encryption key for storage
    pub fn encryption_key(&mut self, key: [u8; 32]) {
        self.encryption_key = Some(key);
    }

    /// Enable or disable automatic connection to server during build
    ///
    /// When autoconnect is true (default for backward compatibility), the client
    /// will require server information and connect immediately during build().
    /// When autoconnect is false, the client starts in offline mode and can
    /// connect to relays later using add_relay().
    pub fn autoconnect(&mut self, autoconnect: bool) {
        self.autoconnect = autoconnect;
    }

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
            enable_wal_mode: true, // Enable WAL mode for better concurrent access
            cache_size_kb: Some(32 * 1024), // 32MB cache for better performance
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
        if self.autoconnect {
            for server in servers {
                // add all servers in background
                let relay_address = server.clone();
                let _handle = client.add_relay_background(relay_address);
            }
        }

        Ok(client)
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
// non Flutter Rust Bridge API methods
impl ClientBuilder {
    pub fn media_storage_dir_pathbuf(&mut self, media_storage_dir: PathBuf) {
        self.media_storage_dir = Some(PathBuf::from(media_storage_dir));
    }

    pub fn inner_keypair(&mut self, inner_keypair: KeyPair) {
        self.inner_keypair = Some(Arc::new(inner_keypair));
    }

    pub fn db_storage_dir_pathbuf(&mut self, path: PathBuf) {
        self.db_storage_dir = Some(path);
    }
}
