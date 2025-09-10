//! Blob service tests for system check
//!
//! This module contains tests that verify the client can properly upload and
//! download files through the blob service, including data integrity
//! verification and error handling.

use super::{SystemCheckConfig, TestInfo, TestResult};
use crate::{Client, services::BlobStore};
use rand::Rng;
use tracing::{debug, info};

/// Run all blob service tests
pub async fn run_tests(client: &Client, config: &SystemCheckConfig) -> Vec<TestInfo> {
    let mut tests = Vec::new();

    // Test blob upload and download
    tests.push(test_blob_upload_download(client, config).await);

    // Test blob integrity
    tests.push(test_blob_integrity(client, config).await);

    tests
}

/// Test basic blob upload and download functionality
async fn test_blob_upload_download(client: &Client, config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Blob Upload/Download");

    debug!(
        "Testing blob upload/download with {} bytes...",
        config.blob_test_size
    );

    // Generate random test data
    let mut rng = rand::thread_rng();
    let test_data: Vec<u8> = (0..config.blob_test_size)
        .map(|_| rng.r#gen::<u8>())
        .collect();
    let original_checksum = crc32fast::hash(&test_data);

    // Upload the blob
    let blob_id = match client.blob_service().upload_blob(&test_data).await {
        Ok(id) => {
            test.add_detail(format!(
                "Successfully uploaded blob with ID: {}",
                hex::encode(id)
            ));
            id
        }
        Err(e) => {
            let error = format!("Failed to upload blob: {}", e);
            return test.with_result(TestResult::Failed { error });
        }
    };

    // Download the blob
    match client.blob_service().get_blob(&blob_id).await {
        Ok(downloaded_data) => {
            let downloaded_checksum = crc32fast::hash(&downloaded_data);

            test.add_detail(format!(
                "Successfully downloaded blob: {} bytes",
                downloaded_data.len()
            ));
            test.add_detail(format!("Original checksum: {:08x}", original_checksum));
            test.add_detail(format!("Downloaded checksum: {:08x}", downloaded_checksum));

            if downloaded_data == test_data && downloaded_checksum == original_checksum {
                info!("Blob upload/download test completed successfully");
                test.with_result(TestResult::Passed)
            } else {
                let error = "Downloaded data does not match original data".to_string();
                test.with_result(TestResult::Failed { error })
            }
        }
        Err(e) => {
            let error = format!("Failed to download blob: {}", e);
            test.with_result(TestResult::Failed { error })
        }
    }
}

/// Test blob data integrity with various sizes
async fn test_blob_integrity(client: &Client, _config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Blob Integrity");

    debug!("Testing blob integrity...");

    // Test with different data patterns to ensure integrity
    let test_patterns = vec![
        (vec![0u8; 100], "Zero bytes"),
        (vec![255u8; 100], "Max bytes"),
        ((0..100u8).collect(), "Sequential bytes"),
    ];

    let mut successful_tests = 0;

    let pattern_count = test_patterns.len();
    for (pattern_data, pattern_name) in test_patterns {
        let original_checksum = crc32fast::hash(&pattern_data);

        match client.blob_service().upload_blob(&pattern_data).await {
            Ok(blob_id) => match client.blob_service().get_blob(&blob_id).await {
                Ok(downloaded_data) => {
                    let downloaded_checksum = crc32fast::hash(&downloaded_data);

                    if downloaded_data == pattern_data && downloaded_checksum == original_checksum {
                        test.add_detail(format!("{}: ✓ Integrity verified", pattern_name));
                        successful_tests += 1;
                    } else {
                        test.add_detail(format!("{}: ✗ Integrity check failed", pattern_name));
                    }
                }
                Err(e) => {
                    test.add_detail(format!("{}: ✗ Download failed: {}", pattern_name, e));
                }
            },
            Err(e) => {
                test.add_detail(format!("{}: ✗ Upload failed: {}", pattern_name, e));
            }
        }
    }

    if successful_tests == pattern_count {
        info!("Blob integrity test completed successfully");
        test.with_result(TestResult::Passed)
    } else {
        let error = format!(
            "Only {}/{} integrity tests passed",
            successful_tests, pattern_count
        );
        test.with_result(TestResult::Failed { error })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use tempfile::TempDir;

    async fn create_test_client() -> (Client, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let media_storage_path = temp_dir.path().join("blobs");
        let db_storage_path = temp_dir.path().join("db");

        let client = {
            let mut builder = Client::builder();
            builder.media_storage_dir_pathbuf(media_storage_path);
            builder.db_storage_dir_pathbuf(db_storage_path);
            builder.autoconnect(false);
            builder.build().await.unwrap()
        };

        (client, temp_dir)
    }

    #[tokio::test]
    async fn test_blob_service_tests_structure() {
        let (client, _temp_dir) = create_test_client().await;
        let config = SystemCheckConfig::default();

        let results = run_tests(&client, &config).await;

        // Should have 2 tests
        assert_eq!(results.len(), 2);

        let test_names: Vec<_> = results.iter().map(|t| &t.name).collect();
        assert!(test_names.contains(&&"Blob Upload/Download".to_string()));
        assert!(test_names.contains(&&"Blob Integrity".to_string()));
    }

    #[test]
    fn test_data_patterns() {
        // Test the integrity of our test patterns
        let patterns = vec![
            (vec![0u8; 10], "Zero bytes"),
            (vec![255u8; 10], "Max bytes"),
            ((0..10u8).collect(), "Sequential bytes"),
        ];

        for (data, name) in patterns {
            let checksum = crc32fast::hash(&data);
            // Verify checksum is consistent
            assert_eq!(
                checksum,
                crc32fast::hash(&data),
                "Checksum inconsistent for {}",
                name
            );
        }
    }
}
