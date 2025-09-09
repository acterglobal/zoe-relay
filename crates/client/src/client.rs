use crate::services::MultiRelayMessageManager;
use crate::services::blob_store::MultiRelayBlobService;
use crate::{FileStorage, RelayClient, SessionManager};
use eyeball::SharedObservable;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use zoe_client_storage::SqliteMessageStorage;
use zoe_wire_protocol::KeyId;

mod api;
mod builder;
mod info;
mod secret;

pub use builder::ClientBuilder;
pub use info::{
    OverallConnectionStatus, RelayConnectionInfo, RelayConnectionStatus, RelayInfo,
    RelayStatusUpdate,
};
pub use secret::ClientSecret;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

pub type ZoeClientStorage = SqliteMessageStorage;
pub type ZoeClientSessionManager = SessionManager<ZoeClientStorage, ZoeClientMessageManager>;
pub type ZoeClientMessageManager = MultiRelayMessageManager<ZoeClientStorage>;
pub type ZoeClientBlobService = MultiRelayBlobService<ZoeClientStorage>;
pub type ZoeClientFileStorage = FileStorage<ZoeClientBlobService>;
#[derive(Clone)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct Client {
    pub(crate) client_secret: Arc<ClientSecret>,
    pub(crate) fs: Arc<ZoeClientFileStorage>,
    // All clients now use multi-relay architecture
    pub(crate) storage: Arc<ZoeClientStorage>,
    pub(crate) message_manager: Arc<ZoeClientMessageManager>,
    pub(crate) blob_service: Arc<ZoeClientBlobService>,
    pub(crate) relay_connections: Arc<RwLock<BTreeMap<KeyId, RelayClient>>>,
    pub(crate) relay_info: Arc<RwLock<BTreeMap<KeyId, RelayConnectionInfo>>>,
    pub(crate) encryption_key: [u8; 32],
    /// Observable state for client secret updates - third parties can subscribe to changes
    pub(crate) client_secret_observable: SharedObservable<ClientSecret>,
    /// Broadcast channel for per-relay connection status updates
    pub(crate) relay_status_sender: broadcast::Sender<RelayStatusUpdate>,
    /// Connection monitoring tasks for each relay
    pub(crate) connection_monitors: Arc<RwLock<BTreeMap<KeyId, JoinHandle<()>>>>,
    /// Session manager for the client
    pub(crate) session_manager: Arc<ZoeClientSessionManager>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tempfile::TempDir;
    use tokio::fs;
    use zoe_app_primitives::RelayAddress;
    use zoe_wire_protocol::KeyPair;

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
