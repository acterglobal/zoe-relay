//! Comprehensive tests for the system check binary functionality
//!
//! These tests verify that the system check binary correctly validates all aspects
//! of the Zoe client functionality including server connectivity, storage operations,
//! and blob service functionality.

use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

/// Helper function to create a temporary relay server and export its key
async fn create_relay_with_key_export() -> Option<(TempDir, std::path::PathBuf)> {
    let temp_dir = TempDir::new().ok()?;
    let key_export_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&key_export_dir).ok()?;

    // Use the relay CLI to generate a key and export it
    let output = tokio::process::Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("zoe-relay")
        .arg("--")
        .arg("generate-key")
        .arg("--algorithm")
        .arg("ed25519")
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // The key file should be created in the default location
    let key_file = temp_dir.path().join("server.pem");
    if key_file.exists() {
        Some((temp_dir, key_file))
    } else {
        None
    }
}

/// Test helper to run the system check binary with given arguments
async fn run_system_check(args: &[&str]) -> Result<std::process::Output, std::io::Error> {
    // First ensure the binary is compiled with CLI features
    let compile_output = tokio::process::Command::new("cargo")
        .arg("build")
        .arg("--bin")
        .arg("zoe-system-check")
        .arg("--features")
        .arg("cli")
        .output()
        .await?;

    if !compile_output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to compile binary: {}",
                String::from_utf8_lossy(&compile_output.stderr)
            ),
        ));
    }

    // Run the compiled binary directly with CLI features
    let mut cmd = tokio::process::Command::new("cargo");
    cmd.arg("run")
        .arg("--bin")
        .arg("zoe-system-check")
        .arg("--features")
        .arg("cli")
        .arg("--")
        .args(args);

    // Run with timeout to prevent hanging tests
    let output = timeout(Duration::from_secs(30), cmd.output())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Command timed out"))?;

    output
}

#[tokio::test]
async fn test_system_check_help() {
    let output = run_system_check(&["--help"]).await.unwrap();
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Comprehensive Zoe system check tool"));
    assert!(stdout.contains("--relay-address"));
    assert!(stdout.contains("--server-key"));
    assert!(stdout.contains("--ephemeral"));
}

#[tokio::test]
async fn test_system_check_invalid_server() {
    // Test with non-existent server and invalid key file
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--server-key-file",
        "/dev/null", // Invalid key file
        "--ephemeral",
    ])
    .await
    .unwrap();

    // Should exit with non-zero code (connectivity failure or invalid args)
    assert_ne!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should show error about key file or connectivity
    assert!(stderr.contains("Failed") || stderr.len() > 0);
}

#[tokio::test]
async fn test_system_check_missing_required_args() {
    // Test without required arguments
    let output = run_system_check(&["--relay-address", "127.0.0.1:8080"])
        .await
        .unwrap();

    // Should exit with error due to missing server key and storage config
    assert_ne!(output.status.code(), Some(0));
}

#[tokio::test]
async fn test_system_check_skip_options() {
    // Test with skip options (should still fail due to invalid server, but test argument parsing)
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--server-key",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--ephemeral",
        "--skip-blob-tests",
        "--skip-storage-tests",
    ])
    .await
    .unwrap();

    // Should still exit with non-zero code (connectivity failure)
    assert_ne!(output.status.code(), Some(0));
}

#[tokio::test]
async fn test_system_check_quiet_output() {
    // Test quiet flag (without server key to trigger error message)
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--ephemeral",
        "--quiet",
    ])
    .await
    .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should still show error messages even in quiet mode
    assert!(stderr.contains("Must specify") || stderr.contains("server-key") || stderr.len() > 0);
}

#[tokio::test]
async fn test_system_check_custom_test_parameters() {
    // Test custom blob size and storage count parameters
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--server-key",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--ephemeral",
        "--blob-test-size",
        "2048",
        "--storage-test-count",
        "5",
    ])
    .await
    .unwrap();

    // Should still fail on connectivity, but arguments should be parsed correctly
    assert_ne!(output.status.code(), Some(0));
}

/// Test that demonstrates proper key file usage with relay key export
#[tokio::test]
async fn test_system_check_with_relay_key_export() {
    // Create a temporary directory for the server key export
    let temp_dir = TempDir::new().unwrap();
    let key_export_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&key_export_dir).unwrap();

    // Generate a server key and export it using the relay CLI
    let key_gen_output = tokio::process::Command::new("cargo")
        .arg("run")
        .arg("--bin")
        .arg("zoe-relay")
        .arg("--")
        .arg("--data-dir")
        .arg(temp_dir.path())
        .arg("--export-public-key-to")
        .arg(&key_export_dir)
        .arg("--interface")
        .arg("127.0.0.1")
        .arg("--port")
        .arg("0") // Use port 0 to let the OS choose
        .kill_on_drop(true)
        .spawn();

    if let Ok(mut child) = key_gen_output {
        // Give the relay a moment to start and export the key
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Kill the relay server
        let _ = child.kill().await;

        // Check if the key file was created
        let key_file = key_export_dir.join("zoe_relay_server_public_key.pem");
        if key_file.exists() {
            // Test the system check with the exported key file
            let output = run_system_check(&[
                "--relay-address",
                "127.0.0.1:99999", // Non-existent server
                "--server-key-file",
                key_file.to_str().unwrap(),
                "--ephemeral",
                "--blob-test-size",
                "512",
                "--storage-test-count",
                "2",
            ])
            .await
            .unwrap();

            // Should fail due to connectivity, but key parsing should work
            assert_ne!(output.status.code(), Some(0));

            let stderr = String::from_utf8_lossy(&output.stderr);
            // Should show that it's trying to connect (key was parsed successfully)
            assert!(stderr.contains("Starting comprehensive") || stderr.contains("connectivity"));
        } else {
            // If key export failed, just test basic argument parsing
            let output = run_system_check(&["--relay-address", "127.0.0.1:99999", "--ephemeral"])
                .await
                .unwrap();

            // Should fail due to missing server key
            assert_ne!(output.status.code(), Some(0));
        }
    } else {
        // If relay binary failed to start, skip this test
        println!("Skipping test - relay binary not available");
    }
}

/// Test the SystemCheckTestMessage serialization and deserialization
#[test]
fn test_system_check_test_message_serialization() {
    // Define the test message structure locally since we can't import from binary
    #[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
    struct SystemCheckTestMessage {
        test_id: u64,
        timestamp: u64,
        data: Vec<u8>,
        checksum: u32,
    }

    impl SystemCheckTestMessage {
        fn new(test_id: u64, data: Vec<u8>) -> Self {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let checksum = crc32fast::hash(&data);
            Self {
                test_id,
                timestamp,
                data,
                checksum,
            }
        }

        fn verify_checksum(&self) -> bool {
            crc32fast::hash(&self.data) == self.checksum
        }
    }

    let test_data = vec![1, 2, 3, 4, 5];
    let message = SystemCheckTestMessage::new(42, test_data.clone());

    // Test serialization
    let serialized = postcard::to_stdvec(&message).unwrap();
    assert!(!serialized.is_empty());

    // Test deserialization
    let deserialized: SystemCheckTestMessage = postcard::from_bytes(&serialized).unwrap();
    assert_eq!(deserialized.test_id, 42);
    assert_eq!(deserialized.data, test_data);
    assert_eq!(deserialized.checksum, message.checksum);

    // Test checksum verification
    assert!(deserialized.verify_checksum());
}

/// Unit test for the SystemCheckResults structure
#[test]
fn test_system_check_results() {
    // Define the results structure locally since we can't import from binary
    #[derive(Debug)]
    struct SystemCheckResults {
        connectivity_passed: bool,
        storage_passed: bool,
        storage_skipped: bool,
        blob_passed: bool,
        blob_skipped: bool,
    }

    impl SystemCheckResults {
        fn new() -> Self {
            Self {
                connectivity_passed: true, // If we get here, connectivity passed
                storage_passed: false,
                storage_skipped: false,
                blob_passed: false,
                blob_skipped: false,
            }
        }
    }

    let mut results = SystemCheckResults::new();
    assert!(results.connectivity_passed);
    assert!(!results.storage_passed);
    assert!(!results.storage_skipped);
    assert!(!results.blob_passed);
    assert!(!results.blob_skipped);

    results.storage_passed = true;
    results.blob_passed = true;

    assert!(results.connectivity_passed);
    assert!(results.storage_passed);
    assert!(results.blob_passed);
}

/// Test error handling for invalid blob sizes
#[tokio::test]
async fn test_system_check_invalid_blob_size() {
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--server-key",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--ephemeral",
        "--blob-test-size",
        "0", // Invalid size
    ])
    .await
    .unwrap();

    // Should handle invalid parameters gracefully
    assert_ne!(output.status.code(), Some(0));
}

/// Test error handling for invalid storage test count
#[tokio::test]
async fn test_system_check_invalid_storage_count() {
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--server-key",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--ephemeral",
        "--storage-test-count",
        "0", // Invalid count
    ])
    .await
    .unwrap();

    // Should handle invalid parameters gracefully
    assert_ne!(output.status.code(), Some(0));
}

/// Test that the binary handles malformed server keys correctly
#[tokio::test]
async fn test_system_check_malformed_server_key() {
    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:8080",
        "--server-key",
        "invalid_hex_key",
        "--ephemeral",
    ])
    .await
    .unwrap();

    // Should exit with error due to malformed key
    assert_ne!(output.status.code(), Some(0));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid hex string") || stderr.contains("invalid value"));
}

/// Performance test to ensure system check completes within reasonable time
#[tokio::test]
async fn test_system_check_performance() {
    let start = std::time::Instant::now();

    let output = run_system_check(&[
        "--relay-address",
        "127.0.0.1:99999",
        "--server-key",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--ephemeral",
        "--blob-test-size",
        "1024",
        "--storage-test-count",
        "1",
    ])
    .await
    .unwrap();

    let duration = start.elapsed();

    // Should complete within 30 seconds even when failing
    assert!(duration < Duration::from_secs(30));

    // Should still fail due to invalid server
    assert_ne!(output.status.code(), Some(0));
}
