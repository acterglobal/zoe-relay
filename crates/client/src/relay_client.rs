use crate::SessionManager;
use crate::challenge::perform_client_challenge_handshake;
use crate::error::{ClientError, Result};
use crate::services::{BlobService, MessagePersistenceManager, MessagePersistenceManagerBuilder};
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use zoe_client_storage::{SqliteMessageStorage, StorageConfig as DbConfig};
use zoe_wire_protocol::{KeyPair, VerifyingKey, connection::client::create_client_endpoint};

struct RelayClientInner {
    client_keypair_tls: KeyPair, // For TLS certificates (Ed25519 or ML-DSA-44)
    client_keypair_inner: Arc<KeyPair>, // For inner protocol
    connection: Connection,
    blob_service: Arc<BlobService>,
    persistence_manager: Arc<MessagePersistenceManager>,
    session_manager: SessionManager<SqliteMessageStorage, MessagePersistenceManager>,
    storage: Arc<SqliteMessageStorage>,
    endpoint: Endpoint,
}

/// Builder for creating RelayClient instances with configurable options.
///
/// This builder allows configuring storage, connection parameters, and message persistence
/// before creating a RelayClient instance. All RelayClients have message persistence enabled
/// by default and require storage configuration.
///
/// # Example
///
/// ```rust,no_run
/// # use zoe_client::RelayClientBuilder;
/// # use std::net::SocketAddr;
/// # use zoe_wire_protocol::{KeyPair, VerifyingKey};
/// # async fn example() -> zoe_client::error::Result<()> {
/// let server_key = VerifyingKey::from([0u8; 32]); // Replace with actual key
/// let server_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
/// let encryption_key = [42u8; 32]; // Use a proper encryption key
///
/// let client = RelayClientBuilder::new()
///     .server_public_key(server_key)
///     .server_address(server_addr)
///     .db_storage_path("client_messages.db")
///     .encryption_key(encryption_key)
///     .autosubscribe(true)
///     .build()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct RelayClientBuilder {
    client_keypair_inner: Option<KeyPair>,
    server_public_key: Option<VerifyingKey>,
    server_address: Option<SocketAddr>,
    db_config: Option<DbConfig>,
    encryption_key: Option<[u8; 32]>,
    storage: Option<Arc<SqliteMessageStorage>>,
    autosubscribe: bool,
    buffer_size: Option<usize>,
}

impl RelayClientBuilder {
    /// Create a new RelayClientBuilder with default settings
    pub fn new() -> Self {
        Self {
            client_keypair_inner: None,
            server_public_key: None,
            server_address: None,
            db_config: None,
            encryption_key: None,
            storage: None,
            autosubscribe: false,
            buffer_size: None,
        }
    }

    /// Set the client's inner protocol keypair (for message signing/verification)
    /// If not set, a random keypair will be generated
    pub fn client_keypair(mut self, keypair: KeyPair) -> Self {
        self.client_keypair_inner = Some(keypair);
        self
    }

    /// Set the server's public key for TLS verification
    pub fn server_public_key(mut self, key: VerifyingKey) -> Self {
        self.server_public_key = Some(key);
        self
    }

    /// Set the server address to connect to
    pub fn server_address(mut self, addr: SocketAddr) -> Self {
        self.server_address = Some(addr);
        self
    }

    /// Set the storage configuration
    pub fn db_config(mut self, config: DbConfig) -> Self {
        self.db_config = Some(config);
        self
    }

    /// Set the storage database path (convenience method)
    pub fn db_storage_path<P: Into<PathBuf>>(mut self, path: P) -> Self {
        let mut config = self.db_config.unwrap_or_default();
        config.database_path = path.into();
        self.db_config = Some(config);
        self
    }

    /// Set the encryption key for storage
    pub fn encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Set a pre-created storage instance
    ///
    /// When this is set, the builder will use this storage instead of creating one
    /// from db_config and encryption_key.
    pub fn storage(mut self, storage: Arc<SqliteMessageStorage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Enable or disable automatic subscription to messages
    pub fn autosubscribe(mut self, enable: bool) -> Self {
        self.autosubscribe = enable;
        self
    }

    /// Set the buffer size for message processing
    pub fn buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = Some(size);
        self
    }

    /// Build the RelayClient with the configured options
    ///
    /// Storage and encryption key are required for message persistence.
    pub async fn build(self) -> Result<RelayClient> {
        let server_public_key = self
            .server_public_key
            .ok_or_else(|| ClientError::Generic("Server public key is required".to_string()))?;

        let server_address = self
            .server_address
            .ok_or_else(|| ClientError::Generic("Server address is required".to_string()))?;

        // Encryption key is only required if no pre-created storage is provided
        let encryption_key = if self.storage.is_some() {
            self.encryption_key.unwrap_or([0u8; 32]) // Default if storage is pre-created
        } else {
            self.encryption_key.ok_or_else(|| {
                ClientError::Generic(
                    "Encryption key is required when no storage is provided".to_string(),
                )
            })?
        };

        let client_keypair_inner = Arc::new(
            self.client_keypair_inner
                .unwrap_or_else(|| KeyPair::generate(&mut rand::thread_rng())),
        );

        // Generate TLS keypair for certificates (default to Ed25519)
        let client_keypair_tls = KeyPair::generate_ed25519(&mut rand::thread_rng());

        // Establish connection
        let (endpoint, connection) = RelayClientInner::connect_with_transport_keys(
            &client_keypair_tls,
            &client_keypair_inner,
            server_address,
            &server_public_key,
        )
        .await?;

        // Use pre-created storage or create new one
        let storage = if let Some(storage) = self.storage {
            storage
        } else {
            let db_config = self.db_config.unwrap_or_default();
            Arc::new(
                SqliteMessageStorage::new(db_config, &encryption_key)
                    .await
                    .map_err(|e| {
                        ClientError::Generic(format!("Failed to create storage: {}", e))
                    })?,
            )
        };

        let blob_service = Arc::new(BlobService::connect(&connection).await?);

        // Create persistence manager (always required now)
        let persistence_manager = Arc::new(
            MessagePersistenceManagerBuilder::new()
                .storage(storage.clone())
                .relay_pubkey(server_public_key)
                .autosubscribe(self.autosubscribe)
                .buffer_size(self.buffer_size.unwrap_or(1000))
                .build(&connection)
                .await?,
        );

        let session_manager = SessionManager::builder(storage.clone(), persistence_manager.clone())
            .client_keypair(client_keypair_inner.clone())
            .build()
            .await?;

        Ok(RelayClient {
            inner: Arc::new(RelayClientInner {
                client_keypair_tls,
                client_keypair_inner,
                storage,
                connection,
                persistence_manager,
                blob_service,
                session_manager,
                endpoint,
            }),
        })
    }
}

impl Default for RelayClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A Zoe Relay Client with integrated message persistence
#[derive(Clone)]
pub struct RelayClient {
    inner: Arc<RelayClientInner>,
}

impl RelayClientInner {
    async fn close(&self) {
        self.connection.close(0u32.into(), b"Client closed");
        self.endpoint.wait_idle().await;
    }
    /// Connect to relay server with transport keys and return the connection
    async fn connect_with_transport_keys(
        client_keypair_tls: &KeyPair, // For TLS certificates (Ed25519 or ML-DSA-44)
        client_keypair_inner: &KeyPair, // For inner protocol
        server_addr: SocketAddr,
        server_public_key: &VerifyingKey,
    ) -> Result<(Endpoint, Connection)> {
        info!("🚀 Starting relay client with transport keys");
        info!(
            "🔑 Client TLS key: {} ({})",
            client_keypair_tls.public_key(),
            client_keypair_tls.algorithm()
        );
        info!(
            "🔑 Client inner public key id: {}",
            hex::encode(client_keypair_inner.public_key().id())
        );
        info!("🌐 Connecting to server: {}", server_addr);
        info!(
            "🔐 Server public key: {} ({})",
            hex::encode(server_public_key.id()),
            server_public_key.algorithm()
        );

        // Create client endpoint and establish QUIC connection
        let client_endpoint = create_client_endpoint(server_public_key)?;
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;

        // Validate that the server supports our protocol
        let client_protocol_config = zoe_wire_protocol::version::ClientProtocolConfig::default();
        match zoe_wire_protocol::version::validate_server_protocol_support(
            &connection,
            &client_protocol_config,
        ) {
            Ok(negotiated_version) => {
                info!(
                    "✅ Connected to relay server with protocol: {}",
                    negotiated_version
                );
            }
            Err(e) => {
                return Err(ClientError::ProtocolError(format!(
                    "Server protocol validation failed: {}",
                    e
                )));
            }
        }

        // No conversion needed - server_public_key is already a VerifyingKey

        // Perform ML-DSA challenge-response handshake
        let (send, recv) = connection.accept_bi().await?;
        let Ok((verified_count, _)) = perform_client_challenge_handshake(
            send,
            recv,
            server_public_key,
            &[client_keypair_inner],
        )
        .await
        else {
            connection.close(0u32.into(), b"ML-DSA handshake failed");
            client_endpoint.wait_idle().await;
            return Err(anyhow::anyhow!("ML-DSA handshake failed").into());
        };

        info!(
            "🔐 ML-DSA handshake completed: {} out of {} keys verified",
            verified_count, 1
        );

        Ok((client_endpoint, connection))
    }
}

// public methods
impl RelayClient {
    /// Get the client's inner protocol public key
    pub fn public_key(&self) -> VerifyingKey {
        self.inner.client_keypair_inner.public_key()
    }

    /// Get the client's inner protocol keypair
    pub fn keypair(&self) -> &Arc<KeyPair> {
        &self.inner.client_keypair_inner
    }

    /// Get the client's TLS public key (Ed25519 or ML-DSA-44)
    pub fn tls_public_key(&self) -> VerifyingKey {
        self.inner.client_keypair_tls.public_key()
    }

    pub fn connection(&self) -> &Connection {
        &self.inner.connection
    }

    /// Get access to the message persistence manager
    pub fn persistence_manager(&self) -> &MessagePersistenceManager {
        &self.inner.persistence_manager
    }

    pub fn session_manager(
        &self,
    ) -> &SessionManager<SqliteMessageStorage, MessagePersistenceManager> {
        &self.inner.session_manager
    }

    pub fn blob_service(&self) -> &Arc<BlobService> {
        &self.inner.blob_service
    }

    pub fn storage(&self) -> &Arc<SqliteMessageStorage> {
        &self.inner.storage
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}
