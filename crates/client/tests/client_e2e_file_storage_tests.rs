//! End-to-end tests for Client file storage with real relay server
//!
//! These tests verify that the Client API works correctly for file storage
//! operations across multiple clients connected to a real relay server.

use anyhow::{Context, Result};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

use tracing::info;
use zoe_app_primitives::connection::{NetworkAddress, RelayAddress};
use zoe_blob_store::BlobServiceImpl;
use zoe_client::Client;
use zoe_message_store::RedisMessageStorage;
use zoe_relay::{RelayServer, RelayServiceRouter};
use zoe_wire_protocol::{KeyPair, VerifyingKey};

// Initialize crypto provider for Rustls
fn init_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install crypto provider");
    });
}

/// Test infrastructure for managing relay server and clients
struct TestInfrastructure {
    server_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    server_addr: SocketAddr,
    server_public_key: VerifyingKey,
    temp_dirs: Vec<TempDir>,
}

impl TestInfrastructure {
    /// Set up test infrastructure with relay server
    async fn setup() -> Result<Self> {
        // Generate server key (default to Ed25519)
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng()); // Ed25519 for transport
        let server_public_key = server_keypair.public_key();

        info!(
            "🔑 Server public key: {}",
            hex::encode(server_public_key.encode())
        );

        // Create temporary directory for blob storage
        let blob_temp_dir = TempDir::new().context("Failed to create blob temp directory")?;

        // Create blob service
        let blob_service = BlobServiceImpl::new(blob_temp_dir.path().to_path_buf())
            .await
            .context("Failed to create blob service")?;

        info!("💾 Blob storage created at: {:?}", blob_temp_dir.path());

        // Use Redis for message store
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        // Connect to Redis
        let message_service = RedisMessageStorage::new(redis_url.clone())
            .await
            .context("Failed to connect to Redis - make sure Redis server is running")?;

        info!("✅ Connected to Redis message store");

        // Create service router
        let router = RelayServiceRouter::new(blob_service, message_service);

        // Create relay server
        let relay_server = RelayServer::new(
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)),
            server_keypair,
            router,
        )
        .context("Failed to create relay server")?;
        let server_addr = relay_server
            .local_addr()
            .context("Failed to get relay server address")?;

        // Spawn server in background
        info!("🌐 Starting relay server on {}", server_addr);
        let server_handle = tokio::spawn(async move { relay_server.run().await });

        // Wait a bit for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        info!("✅ Test infrastructure setup complete");

        Ok(Self {
            server_handle,
            server_addr,
            server_public_key,
            temp_dirs: vec![blob_temp_dir],
        })
    }

    /// Create a new Client connected to the test server
    async fn create_client(&self, media_storage_path: &std::path::Path) -> Result<Client> {
        info!(
            "👤 Creating client with storage at: {:?}",
            media_storage_path
        );

        let mut builder = Client::builder();
        builder.media_storage_dir_pathbuf(media_storage_path.to_path_buf());
        builder.db_storage_dir_pathbuf(media_storage_path.to_path_buf());
        builder.server_info(self.server_public_key.clone(), self.server_addr);
        // Add encryption key for storage
        builder.encryption_key([42u8; 32]);

        info!("🔧 Building client...");

        // Add timeout to client creation to debug hanging
        let client = tokio::time::timeout(Duration::from_secs(10), builder.build())
            .await
            .context("Client creation timed out after 10 seconds")?
            .context("Failed to create client")?;

        // Connect to the relay server for blob storage
        info!("🔗 Connecting client to relay server...");
        let network_address = match self.server_addr {
            SocketAddr::V4(addr) => NetworkAddress::ipv4_with_port(*addr.ip(), addr.port()),
            SocketAddr::V6(addr) => NetworkAddress::ipv6_with_port(*addr.ip(), addr.port()),
        };
        let relay_address =
            RelayAddress::new(self.server_public_key.clone()).with_address(network_address);
        client
            .add_relay(relay_address)
            .await
            .context("Failed to connect client to relay server")?;

        info!("✅ Client connected successfully");
        Ok(client)
    }

    /// Clean up the test infrastructure
    async fn cleanup(self) -> Result<()> {
        info!("🧹 Cleaning up test infrastructure");

        // Abort the server
        self.server_handle.abort();
        let _ = self.server_handle.await;

        // Temp directories are automatically cleaned up when dropped
        drop(self.temp_dirs);

        info!("✅ Cleanup complete");
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_client_e2e_file_storage_with_relay() -> Result<()> {
    // Add timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        // Initialize crypto provider for Rustls
        init_crypto_provider();

        // Initialize logging for the test
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

        info!("🚀 Starting Client E2E File Storage with Relay Test");

        // Set up test infrastructure
        let infra = TestInfrastructure::setup().await?;

        // Create temporary directories for each client's local storage
        let temp_dir1 = TempDir::new().context("Failed to create temp dir for client 1")?;
        let temp_dir2 = TempDir::new().context("Failed to create temp dir for client 2")?;

        // Create two clients connected to the relay
        let client1 = infra.create_client(temp_dir1.path()).await?;
        let client2 = infra.create_client(temp_dir2.path()).await?;

        info!("👥 Created two clients connected to relay server");

        // Create test file content
        let test_content = format!(
            "🚀 Client E2E File Storage with Relay Test\n\
         📅 Timestamp: {}\n\
         📄 This file demonstrates remote file storage between clients via relay!\n\
         🌟 Client 1 stores → Relay Server → Client 2 fetches = ✨ Magic! ✨\n\
         🎯 Testing the full Client API with real relay server infrastructure.\n",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        );
        let test_bytes = test_content.as_bytes();

        info!("📝 Created test content ({} bytes)", test_bytes.len());
        info!(
            "📄 Content preview: {}",
            &test_content[..100.min(test_content.len())]
        );

        // Step 1: Client 1 stores the file
        info!("📤 Client 1 storing file...");
        let stored_file_ref = client1
            .store_data(test_bytes, "relay_test.txt", Some("text/plain".to_string()))
            .await
            .context("Client 1 failed to store file")?;

        info!("✅ Client 1 stored file with:");
        info!("   📋 Blob hash: {}", stored_file_ref.blob_hash);
        info!("   📁 Filename: {:?}", stored_file_ref.filename());
        info!(
            "   📊 Original size: {} bytes",
            stored_file_ref.original_size()
        );
        info!(
            "   🗜️ Was compressed: {}",
            stored_file_ref.encryption_info.was_compressed
        );

        // Step 2: Verify Client 1 can retrieve its own file
        info!("🔍 Client 1 verifying local retrieval...");
        let client1_retrieved = client1
            .retrieve_file_bytes(&stored_file_ref)
            .await
            .context("Client 1 failed to retrieve its own file")?;

        assert_eq!(
            client1_retrieved, test_bytes,
            "Client 1 local retrieval should match original"
        );
        info!("✅ Client 1 local retrieval verified");

        // Step 3: Give some time for remote synchronization to complete
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 4: Client 2 checks if it has the file locally (should be false initially)
        info!("🔍 Client 2 checking local storage...");
        let has_local_before = client2
            .has_file(&stored_file_ref)
            .await
            .context("Failed to check if Client 2 has file locally")?;
        info!(
            "   💾 Client 2 local storage has file: {}",
            has_local_before
        );

        // Step 5: Client 2 retrieves the file (should fetch from relay server)
        info!("📥 Client 2 attempting remote retrieval via relay...");
        info!("   📋 Looking for blob hash: {}", stored_file_ref.blob_hash);

        let client2_retrieved = client2
            .retrieve_file_bytes(&stored_file_ref)
            .await
            .context("Client 2 failed to retrieve file from relay server")?;

        info!("✅ Client 2 successfully retrieved file from relay server");
        info!("   📊 Retrieved {} bytes", client2_retrieved.len());

        // Step 6: Verify content integrity across clients
        assert_eq!(
            client2_retrieved, test_bytes,
            "Client 2 remote retrieval should match original content"
        );
        info!("✅ Content integrity verified across clients via relay server");

        // Verify the retrieved content as string
        let retrieved_content = String::from_utf8(client2_retrieved.clone())
            .context("Retrieved content should be valid UTF-8")?;
        assert_eq!(
            retrieved_content, test_content,
            "String content should match exactly"
        );

        // Step 7: Verify Client 2 now has it cached locally
        let has_local_after = client2
            .has_file(&stored_file_ref)
            .await
            .context("Failed to check if Client 2 has file locally after retrieval")?;
        info!(
            "   💾 Client 2 local cache after retrieval: {}",
            has_local_after
        );

        // Step 8: Test retrieving again from Client 2 (should use local cache)
        info!("🔍 Client 2 testing local cache retrieval...");
        let client2_cached = client2
            .retrieve_file_bytes(&stored_file_ref)
            .await
            .context("Client 2 failed to retrieve file from local cache")?;

        assert_eq!(
            client2_cached, test_bytes,
            "Client 2 cached retrieval should match original"
        );
        info!("✅ Client 2 local cache retrieval verified");

        // Step 9: Test convergent encryption property
        info!("🔒 Testing convergent encryption property...");
        let duplicate_ref = client2
            .store_data(
                test_bytes,
                "duplicate_file.txt",
                Some("text/plain".to_string()),
            )
            .await
            .context("Failed to store duplicate content")?;

        assert_eq!(
            stored_file_ref.blob_hash, duplicate_ref.blob_hash,
            "Convergent encryption should produce same hash for same content"
        );
        info!("✅ Convergent encryption property verified");

        // Step 10: Test file-to-disk operations
        info!("💾 Testing file-to-disk operations...");
        let output_path = temp_dir2.path().join("retrieved_file.txt");
        client2
            .retrieve_file(&stored_file_ref, output_path.clone())
            .await
            .context("Failed to retrieve file to disk")?;

        let disk_content = tokio::fs::read(&output_path)
            .await
            .context("Failed to read file from disk")?;

        assert_eq!(
            disk_content, test_bytes,
            "File saved to disk should match original content"
        );
        info!("✅ File-to-disk operation verified");

        info!("🎉 All Client E2E file storage tests with relay server passed!");

        // Clean up
        infra.cleanup().await?;

        Ok(())
    })
    .await;

    match result {
        Ok(r) => r,
        Err(_) => anyhow::bail!("Test timed out after 30 seconds"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_client_e2e_file_from_disk_with_relay() -> Result<()> {
    // Add timeout to prevent hanging
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        // Initialize crypto provider for Rustls
        init_crypto_provider();

        // Initialize logging for the test
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

        info!("🚀 Starting Client E2E File-from-Disk with Relay Test");

        // Set up test infrastructure
        let infra = TestInfrastructure::setup().await?;

        // Create temporary directories for each client's local storage
        let temp_dir1 = TempDir::new().context("Failed to create temp dir for client 1")?;
        let temp_dir2 = TempDir::new().context("Failed to create temp dir for client 2")?;

        // Create two clients connected to the relay
        let client1 = infra.create_client(temp_dir1.path()).await?;
        let client2 = infra.create_client(temp_dir2.path()).await?;

        info!("👥 Created two clients connected to relay server for file-from-disk test");

        // Create a test file on disk for Client 1
        let test_content = format!(
            "🚀 Client E2E File-from-Disk with Relay Test\n\
         📅 Timestamp: {}\n\
         📄 This file was read from disk, stored via Client 1, and retrieved by Client 2!\n\
         🌟 Disk → Client 1 → Relay Server → Client 2 → Disk = ✨ Full Circle! ✨\n",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
        );

        let input_file_path = temp_dir1.path().join("input_test_file.txt");
        tokio::fs::write(&input_file_path, &test_content)
            .await
            .context("Failed to write test file to disk")?;

        info!("📝 Created test file on disk: {:?}", input_file_path);
        info!("📊 File size: {} bytes", test_content.len());

        // Step 1: Client 1 stores the file from disk
        info!("📤 Client 1 storing file from disk...");
        let stored_file_ref = client1
            .store_file(input_file_path)
            .await
            .context("Client 1 failed to store file from disk")?;

        info!("✅ Client 1 stored file with:");
        info!("   📋 Blob hash: {}", stored_file_ref.blob_hash);
        info!("   📁 Filename: {:?}", stored_file_ref.filename());
        info!(
            "   📊 Original size: {} bytes",
            stored_file_ref.original_size()
        );

        // Step 2: Give some time for remote synchronization
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Step 3: Client 2 retrieves and saves to disk
        info!("📥 Client 2 retrieving file from relay and saving to disk...");
        let output_file_path = temp_dir2.path().join("output_test_file.txt");
        client2
            .retrieve_file(&stored_file_ref, output_file_path.clone())
            .await
            .context("Client 2 failed to retrieve file from relay to disk")?;

        // Step 4: Verify the file content matches
        let output_content = tokio::fs::read_to_string(&output_file_path)
            .await
            .context("Failed to read output file")?;

        assert_eq!(
            output_content, test_content,
            "Output file content should match input file content"
        );

        info!("✅ File content verified across disk → Client 1 → Relay → Client 2 → disk");
        info!("🎉 Client E2E file-from-disk with relay test passed!");

        // Clean up
        infra.cleanup().await?;

        Ok(())
    })
    .await;

    match result {
        Ok(r) => r,
        Err(_) => anyhow::bail!("Test timed out after 30 seconds"),
    }
}
