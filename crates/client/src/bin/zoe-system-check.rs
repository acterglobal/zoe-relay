//! # Zoe System Check Binary
//!
//! A comprehensive system check tool that verifies all aspects of the Zoe client functionality
//! including offline operations, server connectivity, storage operations, blob service functionality,
//! and synchronization between offline and online data.
//!
//! ## Usage
//!
//! Basic comprehensive check:
//! ```bash
//! cargo run --bin zoe-system-check -- --relay-address "127.0.0.1:8080" --server-key "abc123..." --ephemeral
//! ```
//!
//! Individual test categories:
//! ```bash
//! cargo run --bin zoe-system-check -- -r server:port -s key -e connectivity
//! cargo run --bin zoe-system-check -- -r server:port -s key -e offline-storage
//! cargo run --bin zoe-system-check -- -r server:port -s key -e storage --count 5
//! cargo run --bin zoe-system-check -- -r server:port -s key -e blob-service --size 2048
//! ```
//!
//! ## What This Tool Tests
//!
//! ### Phase 1: Offline Tests (without relay connection)
//! 1. **Offline Storage**: Local message storage and retrieval
//! 2. **Offline Blob Service**: Local blob data handling and integrity
//!
//! ### Phase 2: Connectivity Tests
//! 3. **Server Connectivity**: QUIC connection, protocol negotiation, ML-DSA handshake
//!
//! ### Phase 3: Online Tests (with relay connection)
//! 4. **Online Storage**: Store and retrieve messages through relay
//! 5. **Online Blob Service**: Upload and download data through relay
//!
//! ### Phase 4: Synchronization Tests
//! 6. **Sync Verification**: Verify offline data syncs with server
//!
//! ## Exit Codes
//!
//! - `0`: All tests passed successfully
//! - `1`: Errors or warnings detected (with --fail-on-warnings)
//! - `2`: Test failures detected
//! - `4`: Configuration or setup error

use clap::{Parser, Subcommand};
use std::process;
use std::sync::{Arc, Mutex};
use tracing::{error, info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::prelude::*;
use zoe_client::cli::RelayClientArgs;
use zoe_client::system_check::DiagnosticLayer;
use zoe_client::util::resolve_to_socket_addr;
use zoe_client::{
    Client, DiagnosticCollector, SystemCheck, SystemCheckConfig, TestCategory, TestResult,
};

fn print_summary(diagnostic_collector: &DiagnosticCollector) {
    if diagnostic_collector.has_errors() {
        eprintln!("\n❌ ERRORS DETECTED:");
        eprintln!("═══════════════════");
        for (i, error) in diagnostic_collector.errors().iter().enumerate() {
            eprintln!("{}. {}", i + 1, error);
        }
    }

    if diagnostic_collector.has_warnings() {
        eprintln!("\n⚠️  WARNINGS DETECTED:");
        eprintln!("═════════════════════");
        for (i, warning) in diagnostic_collector.warnings().iter().enumerate() {
            eprintln!("{}. {}", i + 1, warning);
        }
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about = "Comprehensive Zoe system check tool", long_about = None)]
struct SystemCheckArgs {
    #[command(flatten)]
    client_args: RelayClientArgs,

    /// Run in quiet mode (only show summary)
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Fail with non-zero exit code if any warnings are detected
    #[arg(long, global = true)]
    fail_on_warnings: bool,

    /// Timeout for operations in seconds
    #[arg(short, long, default_value = "30", global = true)]
    timeout: u64,

    /// Skip offline tests
    #[arg(long, global = true)]
    skip_offline: bool,

    /// Skip sync verification
    #[arg(long, global = true)]
    skip_sync: bool,

    /// Test command to run
    #[command(subcommand)]
    command: Option<TestCommand>,
}

#[derive(Subcommand, Debug)]
enum TestCommand {
    /// Test offline storage functionality
    OfflineStorage {
        /// Number of test messages
        #[arg(long, default_value = "2")]
        count: u32,
    },
    /// Test offline blob service functionality
    OfflineBlob {
        /// Size of test data in bytes
        #[arg(long, default_value = "65536")]
        size: usize,
    },
    /// Test server connectivity
    Connectivity,
    /// Test online storage operations
    Storage {
        /// Number of test messages
        #[arg(long, default_value = "3")]
        count: u32,
    },
    /// Test online blob service operations
    BlobService {
        /// Size of test data in bytes
        #[arg(long, default_value = "1048576")]
        size: usize,
    },
    /// Test synchronization between offline and online data
    Synchronization,
    /// Run all tests in comprehensive flow
    All,
}

#[tokio::main]
async fn main() {
    let args = SystemCheckArgs::parse();

    // Initialize crypto provider for Rustls
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Create diagnostic collector
    let diagnostic_collector = Arc::new(Mutex::new(DiagnosticCollector::new()));
    let diagnostic_layer = DiagnosticLayer::new(diagnostic_collector.clone());
    let fmt_layer = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            tracing_subscriber::EnvFilter::new(if args.quiet {
                "warn"
            } else {
                "zoe_system_check=info,warn"
            })
        }),
    );
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(diagnostic_layer)
        .init();

    info!("🚀 Starting Zoe System Check");

    // Create client configuration
    let mut config = SystemCheckConfig::default().with_timeout_secs(args.timeout);

    // Apply global flags
    if args.skip_offline {
        config = config.with_offline_tests(false);
    }
    if args.skip_sync {
        config = config.with_sync_verification(false);
    }

    // Determine what tests to run and configure accordingly
    let (run_specific_test, specific_category) = match &args.command {
        Some(TestCommand::OfflineStorage { count }) => {
            config = config
                .with_offline_message_count(*count)
                .skip_blob_tests()
                .skip_connectivity_tests();
            (true, Some(TestCategory::OfflineStorage))
        }
        Some(TestCommand::OfflineBlob { size }) => {
            config = config
                .with_offline_blob_size(*size)
                .skip_storage_tests()
                .skip_connectivity_tests();
            (true, Some(TestCategory::OfflineBlob))
        }
        Some(TestCommand::Connectivity) => {
            config = config
                .with_offline_tests(false)
                .with_sync_verification(false)
                .skip_storage_tests()
                .skip_blob_tests();
            (true, Some(TestCategory::Connectivity))
        }
        Some(TestCommand::Storage { count }) => {
            config = config
                .with_storage_test_count(*count)
                .with_offline_tests(false)
                .with_sync_verification(false)
                .skip_blob_tests();
            (true, Some(TestCategory::Storage))
        }
        Some(TestCommand::BlobService { size }) => {
            config = config
                .with_blob_test_size(*size)
                .with_offline_tests(false)
                .with_sync_verification(false)
                .skip_storage_tests();
            (true, Some(TestCategory::BlobService))
        }
        Some(TestCommand::Synchronization) => {
            config = config
                .skip_storage_tests()
                .skip_blob_tests()
                .skip_connectivity_tests();
            (true, Some(TestCategory::Synchronization))
        }
        Some(TestCommand::All) | None => {
            // Run comprehensive test flow
            (false, None)
        }
    };

    // Create client
    info!("📍 Establishing client connection...");
    let client = match create_client(&args.client_args).await {
        Ok(client) => {
            info!("✅ Client connection established successfully");
            client
        }
        Err(e) => {
            error!("❌ Failed to create client: {}", e);
            process::exit(4);
        }
    };

    // Create system check instance
    let system_check = SystemCheck::new(client, config.clone());

    // Run tests
    let results = if run_specific_test {
        if let Some(category) = specific_category {
            match category {
                TestCategory::OfflineStorage => {
                    info!("🔍 Running offline storage tests only...");
                }
                TestCategory::OfflineBlob => {
                    info!("🔍 Running offline blob tests only...");
                }
                TestCategory::Connectivity => {
                    info!("🔍 Running connectivity tests only...");
                }
                TestCategory::Storage => {
                    info!("🔍 Running online storage tests only...");
                }
                TestCategory::BlobService => {
                    info!("🔍 Running blob service tests only...");
                }
                TestCategory::Synchronization => {
                    info!("🔍 Running synchronization tests only...");
                }
            }

            match system_check.run_category_tests(category).await {
                Ok(tests) => {
                    let mut results = zoe_client::SystemCheckResults::new(config);
                    for test in tests {
                        results.add_test(category, test);
                    }
                    results.finalize();
                    results
                }
                Err(e) => {
                    error!("❌ Failed to run {} tests: {}", category.name(), e);
                    process::exit(2);
                }
            }
        } else {
            unreachable!("Specific test requested but no category provided");
        }
    } else {
        info!("🔍 Running comprehensive system check...");
        match system_check.run_all().await {
            Ok(results) => results,
            Err(e) => {
                error!("❌ System check failed: {}", e);
                process::exit(4);
            }
        }
    };

    // Print results
    print_results(&results, args.quiet);

    // Print actual captured errors and warnings
    let (has_errors, has_warnings) = {
        let collector = diagnostic_collector.lock().unwrap();
        if collector.has_errors() || collector.has_warnings() {
            print_summary(&collector);
        }
        (collector.has_errors(), collector.has_warnings())
    };

    // Determine exit code (simplified)
    let exit_code = if !results.is_success() {
        error!("❌ System check failed due to test failures");
        2 // Test failures
    } else if has_errors {
        error!("❌ System check failed due to errors (see above)");
        1 // Errors detected
    } else if args.fail_on_warnings && has_warnings {
        error!("❌ System check failed due to warnings (--fail-on-warnings enabled)");
        1 // Warnings treated as errors
    } else {
        info!("🎉 All system checks completed successfully!");
        if has_warnings && !args.fail_on_warnings {
            warn!(
                "⚠️  Note: Warnings detected but not treated as failures (use --fail-on-warnings to change this)"
            );
        }
        0 // Success
    };
    process::exit(exit_code);
}

/// Create a client with the specified configuration
async fn create_client(args: &RelayClientArgs) -> Result<Client, Box<dyn std::error::Error>> {
    let mut builder = Client::builder();

    // Configure for offline-first operation
    builder.autoconnect(false); // We'll manually establish connections as needed

    if args.ephemeral {
        // Set up temporary directories
        let temp_dir = tempfile::tempdir()?;
        let media_storage_path = temp_dir.path().join("blobs");
        let db_storage_path = temp_dir.path().join("db");

        builder.media_storage_dir_pathbuf(media_storage_path);
        builder.db_storage_dir_pathbuf(db_storage_path);

        // Create the client
        let client = builder.build().await?;

        // Get server public key from either direct argument or file
        let server_public_key = if let Some(file_path) = &args.server_key_file {
            info!("📖 Reading server public key from: {}", file_path.display());
            let content = std::fs::read_to_string(file_path)?;
            zoe_wire_protocol::VerifyingKey::from_pem(&content)?
        } else if let Some(key) = &args.server_key {
            key.clone()
        } else {
            return Err("Must specify either --server-key or --server-key-file".into());
        };

        // Parse server address
        let server_addr = resolve_to_socket_addr(&args.relay_address).await?;

        info!("🔗 Establishing relay connection...");
        use zoe_app_primitives::RelayAddress;

        let relay_address = RelayAddress::new(server_public_key)
            .with_address(server_addr.into())
            .with_name("System Check Server".to_string());

        client.add_relay(relay_address).await?;

        // Wait for the connection to be established
        info!("⏳ Waiting for relay connection to be ready...");
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 50; // 5 seconds total (50 * 100ms)

        while attempts < MAX_ATTEMPTS {
            if client.has_connected_relays().await {
                info!("✅ Relay connection established successfully");
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            attempts += 1;
        }

        if attempts >= MAX_ATTEMPTS {
            return Err("Failed to establish relay connection within timeout".into());
        }

        Ok(client)
    } else {
        Err("Non-ephemeral mode not yet supported in new system check".into())
    }
}

/// Print test results in a formatted way
fn print_results(results: &zoe_client::SystemCheckResults, quiet: bool) {
    if !quiet {
        info!("📋 SYSTEM CHECK REPORT");
        info!("═══════════════════════");

        // Print results by category in logical order
        let categories = [
            TestCategory::OfflineStorage,
            TestCategory::OfflineBlob,
            TestCategory::Connectivity,
            TestCategory::Storage,
            TestCategory::BlobService,
            TestCategory::Synchronization,
        ];

        for category in categories {
            if let Some(tests) = results.get_category_results(category)
                && !tests.is_empty()
            {
                let status = if tests.iter().all(|t| t.result.is_passed()) {
                    "✅ PASSED"
                } else if tests.iter().any(|t| t.result.is_failed()) {
                    "❌ FAILED"
                } else {
                    "⏭️ SKIPPED"
                };

                info!("{} {}: {}", category.emoji(), category.name(), status);

                for test in tests {
                    let test_status = match &test.result {
                        TestResult::Passed => "PASSED",
                        TestResult::Failed { .. } => "FAILED",
                        TestResult::Skipped => "SKIPPED",
                    };
                    let status_icon = match &test.result {
                        TestResult::Passed => "✅",
                        TestResult::Failed { .. } => "❌",
                        TestResult::Skipped => "⏭️",
                    };

                    info!(
                        "  {} {}: {} ({:.2}s)",
                        status_icon,
                        test.name,
                        test_status,
                        test.duration.as_secs_f64()
                    );

                    // Show details for failed tests or in verbose mode
                    if matches!(test.result, TestResult::Failed { .. }) || !test.details.is_empty()
                    {
                        for detail in &test.details {
                            info!("    - {}", detail);
                        }
                    }

                    // Show error for failed tests
                    if let TestResult::Failed { error } = &test.result {
                        info!("    ❌ Error: {}", error);
                    }
                }
            }
        }

        info!("═══════════════════════");
    }

    // Always show summary
    info!(
        "📊 Summary: {}/{} tests passed",
        results.passed_count(),
        results.total_count()
    );
    info!(
        "⏱️ Total time: {:.2}s",
        results.total_duration.as_secs_f64()
    );

    if results.is_success() {
        info!("🎉 ALL TESTS PASSED - System is fully operational!");
    } else {
        let failed = results.failed_count();
        let skipped = results.skipped_count();

        if failed > 0 {
            error!("❌ {} test(s) FAILED", failed);
        }
        if skipped > 0 {
            info!("⏭️ {} test(s) SKIPPED", skipped);
        }

        if let Some(first_failure) = results.first_failure()
            && let TestResult::Failed { error } = &first_failure.result
        {
            error!("💥 First failure: {} - {}", first_failure.name, error);
        }
    }
}
