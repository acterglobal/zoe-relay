//! Client-side blob store with sync capabilities
//!
//! This module provides a client-side blob storage that maintains a local FSstore
//! and can synchronize with remote blob stores via RPC.

use futures::StreamExt;
use hex;
use iroh_blobs::{Hash, store::fs::FsStore};
use std::path::PathBuf;
use std::sync::Arc;
use tarpc::context;
use tracing::{error, info, warn};
use zoe_wire_protocol::{BlobId, BlobService};

use crate::{BlobServiceImpl, BlobStoreError};

/// Client-side blob store with sync capabilities
#[derive(Clone)]
pub struct BlobClient {
    /// Local blob storage using iroh's filesystem store
    pub store: Arc<FsStore>,
}

/// Result of a sync operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncResult {
    /// Number of blobs uploaded to remote
    pub uploaded: usize,
    /// Number of blobs downloaded from remote  
    pub downloaded: usize,
    /// Number of blobs that failed to sync
    pub failed: usize,
}

impl BlobClient {
    /// Create a new blob client with local storage
    pub async fn new(data_dir: PathBuf) -> Result<Self, BlobStoreError> {
        // Ensure data directory exists
        tokio::fs::create_dir_all(&data_dir)
            .await
            .map_err(|e| BlobStoreError::Storage(e.to_string()))?;

        let store = FsStore::load(data_dir)
            .await
            .map_err(|e| BlobStoreError::Storage(e.to_string()))?;

        Ok(Self {
            store: Arc::new(store),
        })
    }

    /// Store a blob locally
    pub async fn store_blob(&self, data: Vec<u8>) -> Result<String, BlobStoreError> {
        info!("Storing blob of {} bytes locally", data.len());

        let progress = self.store.add_bytes(data);
        let result = progress.await.map_err(|e| {
            error!("Failed to store blob locally: {}", e);
            BlobStoreError::Storage(e.to_string())
        })?;

        let hash = result.hash.to_string();
        info!("Successfully stored blob locally: {}", hash);
        Ok(hash)
    }

    /// Get a blob from local storage
    pub async fn get_blob(&self, hash: &str) -> Result<Option<Vec<u8>>, BlobStoreError> {
        let hash_obj = hash
            .parse::<Hash>()
            .map_err(|_| BlobStoreError::HashParse(hash.to_string()))?;

        match self.store.get_bytes(hash_obj).await {
            Ok(bytes) => Ok(Some(bytes.to_vec())),
            Err(_) => Ok(None), // Blob not found
        }
    }

    /// Check if a blob exists locally
    pub async fn has_blob(&self, hash: &str) -> Result<bool, BlobStoreError> {
        let hash_obj = hash
            .parse::<Hash>()
            .map_err(|_| BlobStoreError::HashParse(hash.to_string()))?;

        self.store
            .has(hash_obj)
            .await
            .map_err(|e| BlobStoreError::Storage(e.to_string()))
    }

    /// Get all local blob hashes (for sync purposes)
    pub async fn list_local_blobs(&self) -> Result<Vec<String>, BlobStoreError> {
        info!("Listing all local blobs");

        // Use iroh's blobs listing interface
        let mut blobs = Vec::new();

        // Try using the blobs().list() interface
        let list_progress = self.store.blobs().list();
        let stream = list_progress.stream().await.map_err(|e| {
            error!("Failed to create blob list stream: {}", e);
            BlobStoreError::Internal(format!("Failed to list blobs: {e}"))
        })?;

        futures::pin_mut!(stream);

        while let Some(progress_event) = stream.next().await {
            match progress_event {
                Ok(hash) => {
                    blobs.push(hash.to_string());
                }
                Err(e) => {
                    error!("Error reading blob hash: {}", e);
                    return Err(BlobStoreError::Internal(format!("Error listing blob: {e}")));
                }
            }
        }

        info!("Found {} local blobs", blobs.len());
        Ok(blobs)
    }

    /// Upload a blob to a remote server
    pub async fn upload(
        &self,
        remote: &BlobServiceImpl,
        hash: &str,
    ) -> Result<BlobId, BlobStoreError> {
        // Get the blob data locally
        let data = self
            .get_blob(hash)
            .await?
            .ok_or_else(|| BlobStoreError::NotFound(hash.to_string()))?;

        // Upload to remote
        match remote.clone().upload(context::current(), data).await {
            Ok(remote_hash) => {
                info!(
                    "Successfully uploaded blob {} to remote as {}",
                    hash, remote_hash
                );
                Ok(remote_hash)
            }
            Err(e) => {
                error!("Failed to upload blob {} to remote: {}", hash, e);
                Err(BlobStoreError::Internal(format!("Upload failed: {e}")))
            }
        }
    }

    /// Download a blob from a remote server
    pub async fn download(
        &self,
        remote: &BlobServiceImpl,
        hash: &BlobId,
    ) -> Result<bool, BlobStoreError> {
        // Download from remote
        match remote.clone().download(context::current(), *hash).await {
            Ok(Some(data)) => {
                // Store locally
                let local_hash = self.store_blob(data).await?;
                info!(
                    "Downloaded blob {} from remote and stored as {}",
                    hash, local_hash
                );
                Ok(true)
            }
            Ok(None) => {
                info!("Blob {} not found on remote", hash);
                Ok(false)
            }
            Err(e) => {
                error!("Failed to download blob {} from remote: {}", hash, e);
                Err(BlobStoreError::Internal(format!("Download failed: {e}")))
            }
        }
    }

    /// Upload multiple blobs to a remote server
    /// Only uploads blobs that the remote doesn't already have
    pub async fn upload_blobs(
        &self,
        remote: &BlobServiceImpl,
        local_hashes: &[BlobId],
    ) -> Result<SyncResult, BlobStoreError> {
        if local_hashes.is_empty() {
            return Ok(SyncResult {
                uploaded: 0,
                downloaded: 0,
                failed: 0,
            });
        }

        info!("Uploading {} blobs to remote", local_hashes.len());

        // Check which blobs the remote already has
        let remote_has = match remote
            .clone()
            .check_blobs(context::current(), local_hashes.to_vec())
            .await
        {
            Ok(results) => results,
            Err(e) => {
                error!("Failed to check remote blob existence: {}", e);
                return Err(BlobStoreError::Internal(format!(
                    "Remote check failed: {e}"
                )));
            }
        };

        let mut uploaded = 0;
        let mut failed = 0;

        // Upload blobs that the remote doesn't have
        for (hash, remote_has_blob) in local_hashes.iter().zip(remote_has.iter()) {
            if !remote_has_blob {
                match self.upload(remote, &hash.to_hex()).await {
                    Ok(_) => {
                        uploaded += 1;
                        info!("Successfully uploaded blob {} to remote", hash);
                    }
                    Err(e) => {
                        failed += 1;
                        warn!("Failed to upload blob {} to remote: {}", hash, e);
                    }
                }
            }
        }

        let result = SyncResult {
            uploaded,
            downloaded: 0, // This method only uploads
            failed,
        };

        info!(
            "Upload to remote complete: uploaded={}, failed={}",
            result.uploaded, result.failed
        );

        Ok(result)
    }

    /// Download multiple blobs from a remote server
    /// Only downloads blobs that are missing locally
    pub async fn download_blobs(
        &self,
        remote: &BlobServiceImpl,
        remote_hashes: &[BlobId],
    ) -> Result<SyncResult, BlobStoreError> {
        info!("Downloading {} blobs from remote", remote_hashes.len());

        if remote_hashes.is_empty() {
            return Ok(SyncResult {
                uploaded: 0,
                downloaded: 0,
                failed: 0,
            });
        }

        let mut downloaded = 0;
        let mut failed = 0;

        for hash in remote_hashes {
            // Check if we already have it locally
            if self.has_blob(&hash.to_hex()).await? {
                continue; // Skip if we already have it
            }

            // Download from remote
            match self.download(remote, hash).await {
                Ok(true) => {
                    downloaded += 1;
                    info!("Successfully downloaded blob {} from remote", hash);
                }
                Ok(false) => {
                    warn!("Blob {} not found on remote during download", hash);
                }
                Err(e) => {
                    failed += 1;
                    warn!("Failed to download blob {} from remote: {}", hash, e);
                }
            }
        }

        let result = SyncResult {
            uploaded: 0, // This method only downloads
            downloaded,
            failed,
        };

        info!(
            "Download from remote complete: downloaded={}, failed={}",
            result.downloaded, result.failed
        );

        Ok(result)
    }

    /// Sync local blobs to remote server
    /// If no hashes are provided, syncs all local blobs
    pub async fn sync(
        &self,
        remote: &BlobServiceImpl,
        local_hashes: Option<&[BlobId]>,
    ) -> Result<SyncResult, BlobStoreError> {
        // Get hashes to sync - either provided ones or all local blobs
        let hashes_to_sync = match local_hashes {
            Some(hashes) => hashes.to_vec(),
            None => {
                info!("No specific hashes provided, syncing all local blobs");
                // Convert string hashes to BlobId
                let string_hashes = self.list_local_blobs().await?;
                string_hashes
                    .into_iter()
                    .filter_map(|s| {
                        if let Ok(bytes) = hex::decode(&s) {
                            if bytes.len() == 32 {
                                let mut array = [0u8; 32];
                                array.copy_from_slice(&bytes);
                                Some(BlobId::from_bytes(array))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect()
            }
        };

        info!("Starting sync with {} local blobs", hashes_to_sync.len());

        // Upload local blobs to remote (only uploads blobs that remote doesn't have)
        let upload_result = self.upload_blobs(remote, &hashes_to_sync).await?;

        let result = SyncResult {
            uploaded: upload_result.uploaded,
            downloaded: 0, // Currently only supports upload direction
            failed: upload_result.failed,
        };

        info!(
            "Sync complete: uploaded={}, downloaded={}, failed={}",
            result.uploaded, result.downloaded, result.failed
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_client() -> BlobClient {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let client = BlobClient::new(data_dir).await.unwrap();

        // Prevent temp_dir from being dropped
        std::mem::forget(temp_dir);

        client
    }

    #[tokio::test]
    async fn test_client_store_and_get_blob() {
        let client = create_test_client().await;

        let test_data = b"Hello, blob client world!".to_vec();

        // Store the blob
        let hash = client.store_blob(test_data.clone()).await.unwrap();
        assert!(!hash.is_empty());

        // Get the blob back
        let retrieved = client.get_blob(&hash).await.unwrap();
        assert_eq!(retrieved, Some(test_data));

        // Check if blob exists
        assert!(client.has_blob(&hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_client_get_nonexistent_blob() {
        let client = create_test_client().await;

        let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = client.get_blob(fake_hash).await.unwrap();
        assert_eq!(result, None);

        assert!(!client.has_blob(fake_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_client_multiple_blobs() {
        let client = create_test_client().await;

        let blob1_data = b"First blob".to_vec();
        let blob2_data = b"Second blob".to_vec();

        let hash1 = client.store_blob(blob1_data.clone()).await.unwrap();
        let hash2 = client.store_blob(blob2_data.clone()).await.unwrap();

        assert_ne!(hash1, hash2);

        let retrieved1 = client.get_blob(&hash1).await.unwrap();
        let retrieved2 = client.get_blob(&hash2).await.unwrap();

        assert_eq!(retrieved1, Some(blob1_data));
        assert_eq!(retrieved2, Some(blob2_data));
    }

    #[tokio::test]
    async fn test_client_local_operations() {
        let client = create_test_client().await;

        // These operations work fine without remote (just local operations)
        // Test with non-existent but valid Blake3 hash format
        let fake_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(client.get_blob(fake_hash).await.unwrap().is_none());
        assert!(!client.has_blob(fake_hash).await.unwrap());
    }

    #[tokio::test]
    async fn test_list_local_blobs() {
        let client = create_test_client().await;

        // Initially should have no blobs
        let initial_blobs = client.list_local_blobs().await.unwrap();
        assert_eq!(initial_blobs.len(), 0);

        // Add some blobs
        let blob1_data = b"Test blob 1".to_vec();
        let blob2_data = b"Test blob 2".to_vec();
        let blob3_data = b"Test blob 3".to_vec();

        let hash1 = client.store_blob(blob1_data).await.unwrap();
        let hash2 = client.store_blob(blob2_data).await.unwrap();
        let hash3 = client.store_blob(blob3_data).await.unwrap();

        // List should now contain all 3 blobs
        let all_blobs = client.list_local_blobs().await.unwrap();
        assert_eq!(all_blobs.len(), 3);

        // Check that all our hashes are present
        assert!(all_blobs.contains(&hash1));
        assert!(all_blobs.contains(&hash2));
        assert!(all_blobs.contains(&hash3));

        println!(
            "Successfully listed {} blobs: {:?}",
            all_blobs.len(),
            all_blobs
        );
    }

    // Helper function to create an in-process remote server for testing
    async fn create_test_remote_service() -> crate::BlobServiceImpl {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        let service = crate::BlobServiceImpl::new(data_dir).await.unwrap();

        // Prevent temp_dir from being dropped
        std::mem::forget(temp_dir);

        service
    }

    #[tokio::test]
    async fn test_sync_empty_remote() {
        // Test syncing when remote has no blobs - all should be uploaded
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        // Store some blobs locally
        let blob1_data = b"Sync test blob 1".to_vec();
        let blob2_data = b"Sync test blob 2".to_vec();
        let blob3_data = b"Sync test blob 3".to_vec();

        let hash1 = client.store_blob(blob1_data.clone()).await.unwrap();
        let hash2 = client.store_blob(blob2_data.clone()).await.unwrap();
        let hash3 = client.store_blob(blob3_data.clone()).await.unwrap();

        let _local_hashes = [hash1.clone(), hash2.clone(), hash3.clone()];
        let local_blob_ids = vec![
            BlobId::from_content(&blob1_data),
            BlobId::from_content(&blob2_data),
            BlobId::from_content(&blob3_data),
        ];

        // Verify remote doesn't have these blobs initially
        let remote_has = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has, vec![false, false, false]);

        // Perform sync
        let sync_result = client.sync(&remote, Some(&local_blob_ids)).await.unwrap();

        // All blobs should have been uploaded
        assert_eq!(sync_result.uploaded, 3);
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);

        // Verify remote now has all blobs
        let remote_has_after = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has_after, vec![true, true, true]);

        // Verify data integrity
        let remote_blob1 = remote
            .clone()
            .download(tarpc::context::current(), local_blob_ids[0])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote_blob1, blob1_data);
    }

    #[tokio::test]
    async fn test_sync_partial_remote() {
        // Test syncing when remote already has some blobs - only missing ones should be uploaded
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        // Store some blobs locally
        let blob1_data = b"Partial sync blob 1".to_vec();
        let blob2_data = b"Partial sync blob 2".to_vec();
        let blob3_data = b"Partial sync blob 3".to_vec();
        let blob4_data = b"Partial sync blob 4".to_vec();

        let hash1 = client.store_blob(blob1_data.clone()).await.unwrap();
        let hash2 = client.store_blob(blob2_data.clone()).await.unwrap();
        let hash3 = client.store_blob(blob3_data.clone()).await.unwrap();
        let hash4 = client.store_blob(blob4_data.clone()).await.unwrap();

        // Pre-populate remote with some of the blobs (blob1 and blob3)
        let _ = remote
            .clone()
            .upload(tarpc::context::current(), blob1_data.clone())
            .await
            .unwrap();
        let _ = remote
            .clone()
            .upload(tarpc::context::current(), blob3_data.clone())
            .await
            .unwrap();

        let _local_hashes = [hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];
        let local_blob_ids = vec![
            BlobId::from_content(&blob1_data),
            BlobId::from_content(&blob2_data),
            BlobId::from_content(&blob3_data),
            BlobId::from_content(&blob4_data),
        ];

        // Verify remote has some but not all blobs initially
        let remote_has = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has, vec![true, false, true, false]); // has 1&3, missing 2&4

        // Perform sync
        let sync_result = client.sync(&remote, Some(&local_blob_ids)).await.unwrap();

        // Only the missing blobs should have been uploaded
        assert_eq!(sync_result.uploaded, 2); // blob2 and blob4
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);

        // Verify remote now has all blobs
        let remote_has_after = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has_after, vec![true, true, true, true]);

        // Verify data integrity of newly uploaded blobs
        let remote_blob2 = remote
            .clone()
            .download(tarpc::context::current(), local_blob_ids[1])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote_blob2, blob2_data);

        let remote_blob4 = remote
            .clone()
            .download(tarpc::context::current(), local_blob_ids[3])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote_blob4, blob4_data);
    }

    #[tokio::test]
    async fn test_sync_complete_remote() {
        // Test syncing when remote already has all blobs - nothing should be uploaded
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        // Store some blobs locally
        let blob1_data = b"Complete sync blob 1".to_vec();
        let blob2_data = b"Complete sync blob 2".to_vec();

        let hash1 = client.store_blob(blob1_data.clone()).await.unwrap();
        let hash2 = client.store_blob(blob2_data.clone()).await.unwrap();

        // Pre-populate remote with all the blobs
        let remote_hash1 = remote
            .clone()
            .upload(tarpc::context::current(), blob1_data.clone())
            .await
            .unwrap();
        let remote_hash2 = remote
            .clone()
            .upload(tarpc::context::current(), blob2_data.clone())
            .await
            .unwrap();

        // Verify hashes match (content-based addressing)
        let local_blob_id1 = BlobId::from_content(&blob1_data);
        let local_blob_id2 = BlobId::from_content(&blob2_data);
        assert_eq!(local_blob_id1, remote_hash1);
        assert_eq!(local_blob_id2, remote_hash2);

        let _local_hashes = [hash1.clone(), hash2.clone()];
        let local_blob_ids = vec![local_blob_id1, local_blob_id2];

        // Verify remote has all blobs initially
        let remote_has = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has, vec![true, true]);

        // Perform sync
        let sync_result = client.sync(&remote, Some(&local_blob_ids)).await.unwrap();

        // No blobs should have been uploaded
        assert_eq!(sync_result.uploaded, 0);
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);

        // Verify remote still has all blobs
        let remote_has_after = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids)
            .await
            .unwrap();
        assert_eq!(remote_has_after, vec![true, true]);
    }

    #[tokio::test]
    async fn test_sync_empty_input() {
        // Test syncing with empty blob list
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        let empty_hashes: Vec<BlobId> = vec![];

        // Perform sync with empty input
        let sync_result = client.sync(&remote, Some(&empty_hashes)).await.unwrap();

        // Nothing should happen
        assert_eq!(sync_result.uploaded, 0);
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);
    }

    #[tokio::test]
    async fn test_sync_large_batch() {
        // Test syncing with a larger number of blobs to verify check_blobs chunking works
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        let mut local_hashes = Vec::new();
        let mut local_blob_ids = Vec::new();
        let mut blob_data = Vec::new();

        // Create 10 blobs
        for i in 0..10 {
            let data = format!("Large batch blob {i}").into_bytes();
            blob_data.push(data.clone());
            let hash = client.store_blob(data.clone()).await.unwrap();
            local_hashes.push(hash);
            local_blob_ids.push(BlobId::from_content(&data));
        }

        // Pre-populate remote with every other blob (0, 2, 4, 6, 8)
        for i in (0..10).step_by(2) {
            let _ = remote
                .clone()
                .upload(tarpc::context::current(), blob_data[i].clone())
                .await
                .unwrap();
        }

        // Perform sync
        let sync_result = client.sync(&remote, Some(&local_blob_ids)).await.unwrap();

        // Should upload 5 blobs (the odd-numbered ones: 1, 3, 5, 7, 9)
        assert_eq!(sync_result.uploaded, 5);
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);

        // Verify remote now has all blobs
        let remote_has_after = remote
            .clone()
            .check_blobs(tarpc::context::current(), local_blob_ids)
            .await
            .unwrap();
        assert_eq!(remote_has_after, vec![true; 10]);
    }

    #[tokio::test]
    async fn test_sync_all_local_blobs() {
        // Test syncing all local blobs automatically when None is passed
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        // Store some blobs locally
        let blob1_data = b"Auto sync blob 1".to_vec();
        let blob2_data = b"Auto sync blob 2".to_vec();
        let blob3_data = b"Auto sync blob 3".to_vec();

        let hash1 = client.store_blob(blob1_data.clone()).await.unwrap();
        let hash2 = client.store_blob(blob2_data.clone()).await.unwrap();
        let hash3 = client.store_blob(blob3_data.clone()).await.unwrap();

        // Verify remote doesn't have these blobs initially
        let _all_local_hashes = [hash1.clone(), hash2.clone(), hash3.clone()];
        let all_local_blob_ids = vec![
            BlobId::from_content(&blob1_data),
            BlobId::from_content(&blob2_data),
            BlobId::from_content(&blob3_data),
        ];
        let remote_has = remote
            .clone()
            .check_blobs(tarpc::context::current(), all_local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has, vec![false, false, false]);

        // Perform sync with None (should sync all local blobs automatically)
        let sync_result = client.sync(&remote, None).await.unwrap();

        // All blobs should have been uploaded
        assert_eq!(sync_result.uploaded, 3);
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);

        // Verify remote now has all blobs
        let remote_has_after = remote
            .clone()
            .check_blobs(tarpc::context::current(), all_local_blob_ids.clone())
            .await
            .unwrap();
        assert_eq!(remote_has_after, vec![true, true, true]);

        // Verify data integrity
        let remote_blob2 = remote
            .clone()
            .download(tarpc::context::current(), all_local_blob_ids[1])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote_blob2, blob2_data);
    }

    #[tokio::test]
    async fn test_sync_all_with_partial_remote() {
        // Test syncing all local blobs when remote already has some
        let client = create_test_client().await;
        let remote = create_test_remote_service().await;

        // Store some blobs locally
        let blob1_data = b"Auto partial sync blob 1".to_vec();
        let blob2_data = b"Auto partial sync blob 2".to_vec();

        let hash1 = client.store_blob(blob1_data.clone()).await.unwrap();
        let hash2 = client.store_blob(blob2_data.clone()).await.unwrap();

        // Pre-populate remote with one of the blobs
        let _ = remote
            .clone()
            .upload(tarpc::context::current(), blob1_data.clone())
            .await
            .unwrap();

        // Perform sync with None (should sync all local blobs, but only upload missing ones)
        let sync_result = client.sync(&remote, None).await.unwrap();

        // Only the missing blob should have been uploaded
        assert_eq!(sync_result.uploaded, 1); // blob2
        assert_eq!(sync_result.downloaded, 0);
        assert_eq!(sync_result.failed, 0);

        // Verify remote now has both blobs
        let _all_hashes = [hash1.clone(), hash2.clone()];
        let all_blob_ids = vec![
            BlobId::from_content(&blob1_data),
            BlobId::from_content(&blob2_data),
        ];
        let remote_has_after = remote
            .clone()
            .check_blobs(tarpc::context::current(), all_blob_ids)
            .await
            .unwrap();
        assert_eq!(remote_has_after, vec![true, true]);
    }
}
