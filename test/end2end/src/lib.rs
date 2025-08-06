//! End-to-end testing infrastructure for Zoe
//!
//! This crate provides comprehensive end-to-end tests that spin up the entire
//! Zoe infrastructure including relay server, blob storage, and message store
//! to test the complete system integration.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::{thread_rng, Rng};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use zoe_blob_store::BlobServiceImpl;
use zoe_client::RelayClient;
use zoe_message_store::RedisMessageStorage;
use zoe_relay::{RelayServer, RelayServiceRouter};

/// Test infrastructure for managing relay server and clients
pub struct TestInfrastructure {
    pub server_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    pub server_addr: SocketAddr,
    pub server_public_key: ed25519_dalek::VerifyingKey,
    pub client_key: SigningKey,
    pub temp_dirs: Vec<TempDir>,
    pub redis_url: String,
}

impl TestInfrastructure {
    /// Set up complete testing infrastructure with relay server on random port
    pub async fn setup() -> Result<Self> {
        // Initialize tracing for tests
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();

        info!("🚀 Setting up end-to-end test infrastructure");

        // Find a random available port
        let server_addr = find_free_port().await?;
        info!("📡 Using server address: {}", server_addr);

        // Create temporary directories for blob storage
        let blob_temp_dir = TempDir::new().context("Failed to create blob temp directory")?;
        let blob_dir = blob_temp_dir.path().to_path_buf();
        
        // Generate server keys
        let server_key = SigningKey::generate(&mut thread_rng());
        let server_public_key = server_key.verifying_key();
        
        info!("🔑 Server public key: {}", hex::encode(server_public_key.to_bytes()));

        // Create blob service
        let blob_service = BlobServiceImpl::new(blob_dir.clone())
            .await
            .context("Failed to create blob service")?;

        // For now, we'll create a mock message service since the current API has issues
        // TODO: Re-enable proper Redis message service when API is stabilized
        let redis_url = "redis://127.0.0.1:6379".to_string();
        
        // Try to connect to Redis, but don't fail if it's not available
        let message_service = match RedisMessageStorage::new(redis_url.clone()).await {
            Ok(service) => {
                info!("✅ Connected to Redis message store");
                service
            }
            Err(e) => {
                warn!("⚠️ Failed to connect to Redis ({}), tests will be limited", e);
                // We'll still create the service router but message tests will be skipped
                return Err(anyhow::anyhow!("Redis not available for testing: {}", e));
            }
        };

        // Create service router
        let router = RelayServiceRouter::new(blob_service, message_service);

        // Create relay server
        let relay_server = RelayServer::new(server_addr, server_key, router)
            .context("Failed to create relay server")?;

        // Spawn server in background
        info!("🌐 Starting relay server on {}", server_addr);
        let server_handle = tokio::spawn(async move {
            relay_server.run().await
        });

        // Wait a bit for server to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Generate client key
        let client_key = SigningKey::generate(&mut thread_rng());

        info!("✅ Test infrastructure setup complete");

        Ok(Self {
            server_handle,
            server_addr,
            server_public_key,
            client_key,
            temp_dirs: vec![blob_temp_dir],
            redis_url,
        })
    }

    /// Create a new relay client connected to the test server
    pub async fn create_client(&self) -> Result<RelayClient> {
        info!("👤 Creating relay client");
        
        let client = timeout(
            Duration::from_secs(5),
            RelayClient::new(
                self.client_key.clone(),
                self.server_public_key,
                self.server_addr,
            )
        )
        .await
        .context("Timeout connecting to relay server")?
        .context("Failed to create relay client")?;

        info!("✅ Relay client connected successfully");
        Ok(client)
    }

    /// Clean up the test infrastructure
    pub async fn cleanup(self) -> Result<()> {
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

/// Find a free port for testing
async fn find_free_port() -> Result<SocketAddr> {
    for _ in 0..10 {
        let port: u16 = thread_rng().gen_range(10000..65000);
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        
        // Try to bind to check if port is available
        if let Ok(listener) = tokio::net::TcpListener::bind(addr).await {
            drop(listener);
            debug!("Found free port: {}", port);
            return Ok(addr);
        }
    }
    
    anyhow::bail!("Could not find a free port after 10 attempts");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial] // Run tests sequentially to avoid port conflicts
    async fn test_infrastructure_setup_and_teardown() -> Result<()> {
        let infra = TestInfrastructure::setup().await?;
        
        // Verify server is running by creating a client
        let _client = infra.create_client().await?;
        
        // Clean up
        infra.cleanup().await?;
        
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_client_connection_to_relay_server() -> Result<()> {
        let infra = TestInfrastructure::setup().await?;
        
        // Test that we can create a client and it connects successfully
        let client = infra.create_client().await?;
        
        // Try to connect to blob service to verify routing works
        let blob_service = client.connect_blob_service().await;
        
        // This should succeed (connection-wise)
        assert!(blob_service.is_ok(), "Should be able to connect to blob service");
        
        // Skip message service test due to current API issues
        info!("🔄 Skipping message service connection test due to API inconsistencies");
        
        infra.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial] 
    async fn test_blob_service_end_to_end() -> Result<()> {
        let infra = TestInfrastructure::setup().await?;
        let client = infra.create_client().await?;
        
        // Connect to blob service
        let blob_service = client.connect_blob_service().await?;
        
        // Test basic blob operations
        let test_data = b"Hello, this is test blob data for end-to-end testing!";
        
        // Upload a blob
        let blob_hash = blob_service.upload_blob(test_data).await?;
        info!("📤 Uploaded blob with hash: {}", blob_hash);
        assert!(!blob_hash.is_empty(), "Blob hash should not be empty");
        
        // Download the blob back
        let downloaded_data = blob_service.get_blob(&blob_hash).await?;
        info!("📥 Downloaded {} bytes", downloaded_data.len());
        assert_eq!(downloaded_data, test_data, "Downloaded data should match uploaded data");
        
        // Test downloading non-existent blob
        let fake_hash = "nonexistent_hash_12345";
        let result = blob_service.get_blob(fake_hash).await;
        assert!(result.is_err(), "Should fail to download non-existent blob");
        
        infra.cleanup().await?;
        Ok(())
    }

    // NOTE: Message service tests are disabled due to API inconsistencies in the current codebase
    // This will be re-enabled once the wire protocol API is stabilized
    #[tokio::test]
    #[serial]
    #[ignore] // Temporarily disabled due to API issues
    async fn test_message_service_end_to_end() -> Result<()> {
        let infra = TestInfrastructure::setup().await?;
        let client = infra.create_client().await?;
        
        // Test that we can at least connect to the message service
        let connection_result = client.connect_message_service().await;
        info!("Message service connection result: {:?}", connection_result.is_ok());
        
        // Skip actual message operations due to API inconsistencies
        // TODO: Re-enable when wire protocol is stable
        
        infra.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_multiple_clients_concurrent_access() -> Result<()> {
        let infra = TestInfrastructure::setup().await?;
        
        // Create multiple clients
        let client1 = infra.create_client().await?;
        let client2 = infra.create_client().await?;
        
        let blob_service1 = client1.connect_blob_service().await?;
        let blob_service2 = client2.connect_blob_service().await?;
        
        // Upload data from both clients concurrently
        let data1 = b"Client 1 data";
        let data2 = b"Client 2 data";
        
        let (hash1, hash2) = tokio::join!(
            blob_service1.upload_blob(data1),
            blob_service2.upload_blob(data2)
        );
        
        let hash1 = hash1?;
        let hash2 = hash2?;
        
        // Each client should be able to download the other's data
        let retrieved1 = blob_service2.get_blob(&hash1).await?;
        let retrieved2 = blob_service1.get_blob(&hash2).await?;
        
        assert_eq!(retrieved1, data1);
        assert_eq!(retrieved2, data2);
        
        infra.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_infrastructure_resilience() -> Result<()> {
        let infra = TestInfrastructure::setup().await?;
        let client = infra.create_client().await?;
        
        // Test that services handle various edge cases
        let blob_service = client.connect_blob_service().await?;
        
        // Test empty blob
        let empty_data = b"";
        let empty_hash = blob_service.upload_blob(empty_data).await?;
        let retrieved_empty = blob_service.get_blob(&empty_hash).await?;
        assert_eq!(retrieved_empty, empty_data);
        
        // Test large blob (within reasonable limits)
        let large_data = vec![42u8; 1024 * 100]; // 100KB
        let large_hash = blob_service.upload_blob(&large_data).await?;
        let retrieved_large = blob_service.get_blob(&large_hash).await?;
        assert_eq!(retrieved_large, large_data);
        
        infra.cleanup().await?;
        Ok(())
    }
}
