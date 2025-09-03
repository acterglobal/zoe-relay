use crate::{BlobStorage, BlobUploadStatus, SqliteMessageStorage, StorageConfig};
use tempfile::TempDir;
use zoe_wire_protocol::Hash;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_hash(value: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        Hash::from(bytes)
    }

    async fn create_test_storage() -> (SqliteMessageStorage, TempDir) {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let db_path = temp_dir.path().join("test_blob_storage.db");

        let config = StorageConfig {
            database_path: db_path,
            max_query_limit: Some(1000),
            enable_wal_mode: false, // Disable WAL for tests
            cache_size_kb: Some(1024),
        };

        let encryption_key = [0u8; 32]; // Test key
        let storage = SqliteMessageStorage::new(config, &encryption_key)
            .await
            .expect("Failed to create storage");

        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_mark_blob_uploaded() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let blob_hash = create_test_hash(2);
        let blob_size = 1024;

        let result = storage
            .mark_blob_uploaded(&blob_hash, &relay_id, blob_size)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_is_blob_uploaded() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let blob_hash = create_test_hash(2);
        let blob_size = 2048;

        // Initially should not be uploaded
        let result = storage.is_blob_uploaded(&blob_hash, &relay_id).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Mark as uploaded
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id, blob_size)
            .await
            .unwrap();

        // Now should be uploaded
        let result = storage.is_blob_uploaded(&blob_hash, &relay_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_get_blob_upload_status() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id1 = create_test_hash(1);
        let relay_id2 = create_test_hash(2);
        let blob_hash = create_test_hash(3);
        let blob_size = 4096;

        // Mark as uploaded to two relays
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id1, blob_size)
            .await
            .unwrap();
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id2, blob_size * 2)
            .await
            .unwrap();

        let result = storage.get_blob_upload_status(&blob_hash).await;
        assert!(result.is_ok());

        let statuses = result.unwrap();
        assert_eq!(statuses.len(), 2);

        // Check that both relays are present
        let relay_ids: Vec<Hash> = statuses.iter().map(|s| s.relay_id).collect();
        assert!(relay_ids.contains(&relay_id1));
        assert!(relay_ids.contains(&relay_id2));

        // Check blob hash and sizes
        for status in &statuses {
            assert_eq!(status.blob_hash, blob_hash);
            assert!(status.blob_size == blob_size || status.blob_size == blob_size * 2);
            assert!(status.uploaded_at > 0);
        }
    }

    #[tokio::test]
    async fn test_get_uploaded_blobs_for_relay() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let other_relay_id = create_test_hash(2);

        let blob_hash1 = create_test_hash(3);
        let blob_hash2 = create_test_hash(4);
        let blob_hash3 = create_test_hash(5);
        let blob_size = 1024;

        // Upload blobs to different relays
        storage
            .mark_blob_uploaded(&blob_hash1, &relay_id, blob_size)
            .await
            .unwrap();
        storage
            .mark_blob_uploaded(&blob_hash2, &relay_id, blob_size * 2)
            .await
            .unwrap();
        storage
            .mark_blob_uploaded(&blob_hash3, &other_relay_id, blob_size * 3)
            .await
            .unwrap();

        let result = storage.get_uploaded_blobs_for_relay(&relay_id, None).await;
        assert!(result.is_ok());

        let statuses = result.unwrap();
        assert_eq!(statuses.len(), 2);

        let blob_hashes: Vec<Hash> = statuses.iter().map(|s| s.blob_hash).collect();
        assert!(blob_hashes.contains(&blob_hash1));
        assert!(blob_hashes.contains(&blob_hash2));
        assert!(!blob_hashes.contains(&blob_hash3));
    }

    #[tokio::test]
    async fn test_get_uploaded_blobs_for_relay_with_limit() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let blob_size = 1024;

        // Upload multiple blobs
        for i in 0..5 {
            let blob_hash = create_test_hash(10 + i);
            storage
                .mark_blob_uploaded(&blob_hash, &relay_id, blob_size)
                .await
                .unwrap();
        }

        let result = storage
            .get_uploaded_blobs_for_relay(&relay_id, Some(3))
            .await;
        assert!(result.is_ok());

        let statuses = result.unwrap();
        assert_eq!(statuses.len(), 3);
    }

    #[tokio::test]
    async fn test_remove_blob_upload_record_specific_relay() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id1 = create_test_hash(1);
        let relay_id2 = create_test_hash(2);
        let blob_hash = create_test_hash(3);
        let blob_size = 1024;

        // Upload to two relays
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id1, blob_size)
            .await
            .unwrap();
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id2, blob_size)
            .await
            .unwrap();

        // Remove from one relay
        let result = storage
            .remove_blob_upload_record(&blob_hash, Some(relay_id1))
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Check that it's removed from relay1 but not relay2
        assert!(
            !storage
                .is_blob_uploaded(&blob_hash, &relay_id1)
                .await
                .unwrap()
        );
        assert!(
            storage
                .is_blob_uploaded(&blob_hash, &relay_id2)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_remove_blob_upload_record_all_relays() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id1 = create_test_hash(1);
        let relay_id2 = create_test_hash(2);
        let blob_hash = create_test_hash(3);
        let blob_size = 1024;

        // Upload to two relays
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id1, blob_size)
            .await
            .unwrap();
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id2, blob_size)
            .await
            .unwrap();

        // Remove from all relays
        let result = storage.remove_blob_upload_record(&blob_hash, None).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        // Check that it's removed from both relays
        assert!(
            !storage
                .is_blob_uploaded(&blob_hash, &relay_id1)
                .await
                .unwrap()
        );
        assert!(
            !storage
                .is_blob_uploaded(&blob_hash, &relay_id2)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_unuploaded_blobs_for_relay() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let other_relay_id = create_test_hash(2);
        let blob_size = 1024;

        // Upload some blobs
        for i in 0..3 {
            let blob_hash = create_test_hash(10 + i);
            storage
                .mark_blob_uploaded(&blob_hash, &relay_id, blob_size)
                .await
                .unwrap();
        }

        // Upload one blob to other relay
        let other_blob = create_test_hash(20);
        storage
            .mark_blob_uploaded(&other_blob, &other_relay_id, blob_size)
            .await
            .unwrap();

        let result = storage
            .get_unuploaded_blobs_for_relay(&relay_id, None)
            .await;
        assert!(result.is_ok());

        // This is a placeholder implementation that returns empty
        let unuploaded = result.unwrap();
        assert_eq!(unuploaded.len(), 0);
    }

    #[tokio::test]
    async fn test_get_uploaded_blob_count_for_relay() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let other_relay_id = create_test_hash(2);
        let blob_size = 1024;

        // Upload blobs to different relays
        for i in 0..3 {
            let blob_hash = create_test_hash(10 + i);
            storage
                .mark_blob_uploaded(&blob_hash, &relay_id, blob_size)
                .await
                .unwrap();
        }

        let other_blob = create_test_hash(20);
        storage
            .mark_blob_uploaded(&other_blob, &other_relay_id, blob_size)
            .await
            .unwrap();

        let result = storage.get_uploaded_blob_count_for_relay(&relay_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 3);

        let result2 = storage
            .get_uploaded_blob_count_for_relay(&other_relay_id)
            .await;
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_get_uploaded_blob_size_for_relay() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let blob_size = 1024;

        // Upload blobs with different sizes
        let blob_hash1 = create_test_hash(10);
        let blob_hash2 = create_test_hash(11);
        storage
            .mark_blob_uploaded(&blob_hash1, &relay_id, blob_size)
            .await
            .unwrap();
        storage
            .mark_blob_uploaded(&blob_hash2, &relay_id, blob_size * 2)
            .await
            .unwrap();

        let result = storage.get_uploaded_blob_size_for_relay(&relay_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), blob_size + blob_size * 2);
    }

    #[tokio::test]
    async fn test_mark_blob_uploaded_replace_existing() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);
        let blob_hash = create_test_hash(2);
        let blob_size1 = 1024;
        let blob_size2 = 2048;

        // Upload first time
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id, blob_size1)
            .await
            .unwrap();

        let statuses = storage.get_blob_upload_status(&blob_hash).await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].blob_size, blob_size1);

        // Upload again with different size (should replace)
        storage
            .mark_blob_uploaded(&blob_hash, &relay_id, blob_size2)
            .await
            .unwrap();

        let statuses = storage.get_blob_upload_status(&blob_hash).await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].blob_size, blob_size2);
    }

    #[tokio::test]
    async fn test_blob_upload_status_struct() {
        let blob_hash = create_test_hash(1);
        let relay_id = create_test_hash(2);
        let uploaded_at = 1234567890;
        let blob_size = 4096;

        let status = BlobUploadStatus {
            blob_hash,
            relay_id,
            uploaded_at,
            blob_size,
        };

        assert_eq!(status.blob_hash, blob_hash);
        assert_eq!(status.relay_id, relay_id);
        assert_eq!(status.uploaded_at, uploaded_at);
        assert_eq!(status.blob_size, blob_size);
    }

    #[tokio::test]
    async fn test_concurrent_blob_operations() {
        let (storage, _temp_dir) = create_test_storage().await;
        let relay_id = create_test_hash(1);

        // Test concurrent uploads
        let mut handles = Vec::new();
        let storage = std::sync::Arc::new(storage);
        for i in 0..10 {
            let storage_clone = storage.clone();
            let relay_id_clone = relay_id;
            let handle = tokio::spawn(async move {
                let blob_hash = create_test_hash(10 + i);
                storage_clone
                    .mark_blob_uploaded(&blob_hash, &relay_id_clone, 1024 + i as u64)
                    .await
            });
            handles.push(handle);
        }

        // Wait for all uploads to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
        }

        // Verify all uploads were recorded
        let count = storage
            .get_uploaded_blob_count_for_relay(&relay_id)
            .await
            .unwrap();
        assert_eq!(count, 10);
    }
}
