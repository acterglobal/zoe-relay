//! Comprehensive tests for the system check functionality
//!
//! These tests verify the system check API works correctly with real relay servers
//! and covers all test categories including offline, online, and synchronization tests.

use anyhow::{Context, Result};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tracing::info;

use zoe_app_primitives::{NetworkAddress, RelayAddress};
use zoe_blob_store::BlobServiceImpl;
use zoe_message_store::RedisMessageStorage;
use zoe_relay::{RelayServer, RelayServiceRouter};
use zoe_wire_protocol::{KeyPair, VerifyingKey};

use super::{
    DiagnosticCollector, DiagnosticLevel, DiagnosticMessage, ExtractableDiagnosticCollector,
    SystemCheck, SystemCheckConfig, SystemCheckResults, TestCategory, TestResult,
    run_system_check_with_diagnostics,
};
use crate::Client;

// Initialize crypto provider for Rustls
fn init_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
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
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
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

    /// Create a new Client for system check testing
    async fn create_client(&mut self) -> Result<Client> {
        let temp_dir = TempDir::new().context("Failed to create temp dir for client")?;

        info!("👤 Creating client with storage at: {:?}", temp_dir.path());

        let mut builder = Client::builder();
        builder.media_storage_dir_pathbuf(temp_dir.path().to_path_buf());
        builder.db_storage_dir_pathbuf(temp_dir.path().to_path_buf());
        builder.autoconnect(false); // Manual connection for system check
        // Add encryption key for storage
        builder.encryption_key([42u8; 32]);

        info!("🔧 Building client...");

        // Add timeout to client creation
        let client = tokio::time::timeout(Duration::from_secs(10), builder.build())
            .await
            .context("Client creation timed out after 10 seconds")?
            .context("Failed to create client")?;

        // Store temp dir to keep it alive
        self.temp_dirs.push(temp_dir);

        info!("✅ Client created successfully");
        Ok(client)
    }

    /// Get relay address for connecting clients
    fn get_relay_address(&self) -> RelayAddress {
        let network_address = match self.server_addr {
            SocketAddr::V4(addr) => NetworkAddress::ipv4_with_port(*addr.ip(), addr.port()),
            SocketAddr::V6(addr) => NetworkAddress::ipv6_with_port(*addr.ip(), addr.port()),
        };
        RelayAddress::new(self.server_public_key.clone())
            .with_address(network_address)
            .with_name("System Check Test Server".to_string())
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

/// Test diagnostic collector for capturing system check diagnostics
#[derive(Debug, Default)]
struct TestDiagnosticCollector {
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl TestDiagnosticCollector {
    fn new() -> Self {
        Self::default()
    }
}

impl DiagnosticCollector for TestDiagnosticCollector {
    fn add_error(&mut self, message: String) {
        self.errors.push(message);
    }

    fn add_warning(&mut self, message: String) {
        self.warnings.push(message);
    }
}

impl ExtractableDiagnosticCollector for TestDiagnosticCollector {
    fn extract_messages(&self) -> (Vec<DiagnosticMessage>, bool, bool) {
        let mut messages = Vec::new();

        for error in &self.errors {
            messages.push(DiagnosticMessage {
                level: DiagnosticLevel::Error,
                message: error.clone(),
            });
        }

        for warning in &self.warnings {
            messages.push(DiagnosticMessage {
                level: DiagnosticLevel::Warning,
                message: warning.clone(),
            });
        }

        (messages, !self.errors.is_empty(), !self.warnings.is_empty())
    }
}

/// Unit tests for SystemCheckResults
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_system_check_results_creation() {
        let config = SystemCheckConfig::default();
        let results = SystemCheckResults::new(config);

        assert_eq!(results.passed_count(), 0);
        assert_eq!(results.failed_count(), 0);
        assert_eq!(results.skipped_count(), 0);
        assert_eq!(results.total_count(), 0);
        assert!(results.is_success()); // Empty results are considered successful
    }

    #[test]
    fn test_system_check_results_with_tests() {
        let config = SystemCheckConfig::default();
        let mut results = SystemCheckResults::new(config);

        // Add a passed test
        let passed_test = crate::system_check::TestInfo {
            name: "test_connectivity".to_string(),
            result: TestResult::Passed,
            duration: Duration::from_millis(100),
            details: vec!["Connection established".to_string()],
            started_at: std::time::Instant::now(),
        };
        results.add_test(TestCategory::Connectivity, passed_test);

        // Add a failed test
        let failed_test = crate::system_check::TestInfo {
            name: "test_storage".to_string(),
            result: TestResult::Failed {
                error: "Database connection failed".to_string(),
            },
            duration: Duration::from_millis(50),
            details: vec!["Timeout occurred".to_string()],
            started_at: std::time::Instant::now(),
        };
        results.add_test(TestCategory::Storage, failed_test);

        // Add a skipped test
        let skipped_test = crate::system_check::TestInfo {
            name: "test_blob".to_string(),
            result: TestResult::Skipped,
            duration: Duration::from_millis(0),
            details: vec!["Test disabled".to_string()],
            started_at: std::time::Instant::now(),
        };
        results.add_test(TestCategory::BlobService, skipped_test);

        results.finalize();

        assert_eq!(results.passed_count(), 1);
        assert_eq!(results.failed_count(), 1);
        assert_eq!(results.skipped_count(), 1);
        assert_eq!(results.total_count(), 3);
        assert!(!results.is_success()); // Has failures

        // Test category-specific queries
        assert!(!results.category_has_failures(TestCategory::Connectivity));
        assert!(results.category_has_failures(TestCategory::Storage));
        assert!(!results.category_has_failures(TestCategory::BlobService));

        // Test first failure
        let first_failure = results.first_failure().unwrap();
        assert_eq!(first_failure.name, "test_storage");
        assert!(matches!(first_failure.result, TestResult::Failed { .. }));
    }

    #[test]
    fn test_diagnostic_collector() {
        let mut collector = TestDiagnosticCollector::new();

        collector.add_error("Database connection failed".to_string());
        collector.add_warning("Slow response time detected".to_string());
        collector.add_error("Network timeout".to_string());

        let (messages, has_errors, has_warnings) = collector.extract_messages();

        assert!(has_errors);
        assert!(has_warnings);
        assert_eq!(messages.len(), 3);

        // Check message types
        let error_count = messages
            .iter()
            .filter(|m| m.level == DiagnosticLevel::Error)
            .count();
        let warning_count = messages
            .iter()
            .filter(|m| m.level == DiagnosticLevel::Warning)
            .count();

        assert_eq!(error_count, 2);
        assert_eq!(warning_count, 1);
    }

    #[test]
    fn test_system_check_config_builder() {
        let config = SystemCheckConfig::default()
            .with_timeout_secs(30)
            .with_blob_test_size(1024)
            .with_storage_test_count(5)
            .skip_blob_tests()
            .with_offline_tests(true)
            .with_sync_verification(true)
            .with_offline_message_count(3)
            .with_offline_blob_size(2048);

        assert_eq!(config.operation_timeout, Duration::from_secs(30));
        assert_eq!(config.blob_test_size, 1024);
        assert_eq!(config.storage_test_count, 5);
        assert!(config.skip_blob_tests);
        assert!(config.run_offline_tests);
        assert!(config.verify_sync);
        assert_eq!(config.offline_message_count, 3);
        assert_eq!(config.offline_blob_size, 2048);
    }
}

/// Integration tests with real relay server
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_system_check_comprehensive_with_relay() -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(60), async {
            // Initialize crypto provider and logging
            init_crypto_provider();
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            info!("🚀 Starting comprehensive system check test with relay");

            // Set up test infrastructure
            let mut infra = TestInfrastructure::setup().await?;

            // Create client for system check
            let client = infra.create_client().await?;

            // Add relay connection
            client.add_relay(infra.get_relay_address()).await?;

            // Wait for connection to be established
            let mut attempts = 0;
            while attempts < 50 && !client.has_connected_relays().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                attempts += 1;
            }
            assert!(
                client.has_connected_relays().await,
                "Failed to establish relay connection"
            );

            // Configure comprehensive system check
            let config = SystemCheckConfig::default()
                .with_timeout_secs(10)
                .with_blob_test_size(1024)
                .with_storage_test_count(2)
                .with_offline_tests(true)
                .with_sync_verification(true)
                .with_offline_message_count(2)
                .with_offline_blob_size(512);

            // Run system check
            let system_check = SystemCheck::new(client, config);
            let results = system_check.run_all().await?;

            // Verify results
            assert!(
                results.is_success(),
                "System check should pass with working relay"
            );
            assert!(results.total_count() > 0, "Should have run some tests");

            // Verify all expected categories were tested
            let categories = [
                TestCategory::OfflineStorage,
                TestCategory::OfflineBlob,
                TestCategory::Connectivity,
                TestCategory::Storage,
                TestCategory::BlobService,
                TestCategory::Synchronization,
            ];

            for category in categories {
                let tests = results.get_category_results(category);
                assert!(tests.is_some(), "Category {:?} should have tests", category);
                let tests = tests.unwrap();
                assert!(
                    !tests.is_empty(),
                    "Category {:?} should have non-empty tests",
                    category
                );

                // All tests should pass
                for test in tests {
                    assert!(
                        test.result.is_passed(),
                        "Test {} in category {:?} should pass: {:?}",
                        test.name,
                        category,
                        test.result
                    );
                }
            }

            info!("✅ Comprehensive system check test passed");

            // Clean up
            infra.cleanup().await?;
            Ok(())
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => anyhow::bail!("Test timed out after 60 seconds"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_system_check_connectivity_only() -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            init_crypto_provider();
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            info!("🚀 Starting connectivity-only system check test");

            let mut infra = TestInfrastructure::setup().await?;
            let client = infra.create_client().await?;
            client.add_relay(infra.get_relay_address()).await?;

            // Wait for connection
            let mut attempts = 0;
            while attempts < 50 && !client.has_connected_relays().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                attempts += 1;
            }

            // Configure connectivity-only test
            let config = SystemCheckConfig::default()
                .with_timeout_secs(5)
                .with_offline_tests(false)
                .with_sync_verification(false)
                .skip_storage_tests()
                .skip_blob_tests();

            let system_check = SystemCheck::new(client, config);
            let results = system_check.run_connectivity_tests().await?;

            assert!(!results.is_empty(), "Should have connectivity tests");
            for test in &results {
                assert!(
                    test.result.is_passed(),
                    "Connectivity test should pass: {:?}",
                    test.result
                );
            }

            info!("✅ Connectivity-only test passed");
            infra.cleanup().await?;
            Ok(())
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => anyhow::bail!("Test timed out after 30 seconds"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_system_check_offline_tests_only() -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            init_crypto_provider();
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            info!("🚀 Starting offline-only system check test");

            let mut infra = TestInfrastructure::setup().await?;
            let client = infra.create_client().await?;
            // Note: No relay connection for offline tests

            // Configure offline-only tests
            let config = SystemCheckConfig::default()
                .with_timeout_secs(5)
                .with_offline_tests(true)
                .with_sync_verification(false)
                .skip_connectivity_tests()
                .with_offline_message_count(1)
                .with_offline_blob_size(256);

            let system_check = SystemCheck::new(client, config);

            // Test offline storage
            let storage_results = system_check.run_offline_storage_tests().await?;
            assert!(
                !storage_results.is_empty(),
                "Should have offline storage tests"
            );

            // Test offline blob
            let blob_results = system_check.run_offline_blob_tests().await?;
            assert!(!blob_results.is_empty(), "Should have offline blob tests");

            // All offline tests should pass
            for test in storage_results.iter().chain(blob_results.iter()) {
                assert!(
                    test.result.is_passed(),
                    "Offline test should pass: {:?}",
                    test.result
                );
            }

            info!("✅ Offline-only tests passed");
            infra.cleanup().await?;
            Ok(())
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => anyhow::bail!("Test timed out after 30 seconds"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_system_check_with_diagnostics_api() -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(45), async {
            init_crypto_provider();
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            info!("🚀 Starting system check with diagnostics API test");

            let mut infra = TestInfrastructure::setup().await?;
            let client = infra.create_client().await?;
            client.add_relay(infra.get_relay_address()).await?;

            // Wait for connection
            let mut attempts = 0;
            while attempts < 50 && !client.has_connected_relays().await {
                tokio::time::sleep(Duration::from_millis(100)).await;
                attempts += 1;
            }

            // Create diagnostic collector
            let diagnostic_collector = Arc::new(Mutex::new(TestDiagnosticCollector::new()));

            // Configure system check
            let config = SystemCheckConfig::default()
                .with_timeout_secs(10)
                .with_blob_test_size(512)
                .with_storage_test_count(1);

            // Setup tracing function (simplified for test)
            let setup_tracing = |_collector: Arc<Mutex<TestDiagnosticCollector>>| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                // In a real implementation, this would set up tracing with the collector
                // For this test, we'll just return Ok
                Ok(())
            };

            // Run system check with diagnostics
            let outcome = run_system_check_with_diagnostics(
                client,
                config,
                diagnostic_collector.clone(),
                setup_tracing,
            ).await?;

            // Verify outcome
            assert!(outcome.success, "System check should succeed");
            assert!(outcome.test_results.is_success(), "Test results should be successful");
            assert!(outcome.test_results.total_count() > 0, "Should have run tests");

            // Check diagnostics (may be empty in successful run)
            info!("Diagnostics: {} errors, {} warnings", 
                outcome.diagnostics.iter().filter(|d| d.level == DiagnosticLevel::Error).count(),
                outcome.diagnostics.iter().filter(|d| d.level == DiagnosticLevel::Warning).count()
            );

            info!("✅ System check with diagnostics API test passed");
            infra.cleanup().await?;
            Ok(())
        }).await;

        match result {
            Ok(r) => r,
            Err(_) => anyhow::bail!("Test timed out after 45 seconds"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_system_check_failure_scenarios() -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            init_crypto_provider();
            let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

            info!("🚀 Starting system check failure scenarios test");

            // Create client without relay connection to test failures
            let mut infra = TestInfrastructure::setup().await?;
            let client = infra.create_client().await?;
            // Note: No relay connection - this should cause connectivity tests to fail

            // Configure system check with very short timeout to force failures
            let config = SystemCheckConfig::default()
                .with_timeout_secs(1) // Very short timeout
                .with_offline_tests(false) // Skip offline tests
                .with_sync_verification(false); // Skip sync tests

            let system_check = SystemCheck::new(client, config);

            // Run connectivity tests - should fail without relay connection
            let connectivity_results = system_check.run_connectivity_tests().await?;
            assert!(
                !connectivity_results.is_empty(),
                "Should have connectivity tests"
            );

            // At least some connectivity tests should fail
            let has_failures = connectivity_results
                .iter()
                .any(|test| test.result.is_failed());
            assert!(
                has_failures,
                "Should have connectivity failures without relay connection"
            );

            info!("✅ Failure scenarios test passed");
            infra.cleanup().await?;
            Ok(())
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => anyhow::bail!("Test timed out after 30 seconds"),
        }
    }
}
