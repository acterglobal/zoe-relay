//! Client-side blob store with sync capabilities
//!
//! This module provides a client-side blob storage that maintains a local FSstore
//! and can synchronize with remote blob stores via RPC.

use futures::StreamExt;
use iroh_blobs::{Hash, store::fs::FsStore};
use std::path::PathBuf;
use std::sync::Arc;
use tarpc::context;
use tracing::{error, info, warn};
use zoe_wire_protocol::BlobService;

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
    ) -> Result<String, BlobStoreError> {
        // Get the blob data locally
        let data = self
            .get_blob(hash)
            .await?
            .ok_or_else(|| BlobStoreError::NotFound(hash.to_string()))?;

        // Upload to remote
        match remote.clone().upload_blob(context::current(), data).await {
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
        hash: &str,
    ) -> Result<bool, BlobStoreError> {
        // Download from remote
        match remote
            .clone()
            .download_blob(context::current(), hash.to_string())
            .await
        {
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
        local_hashes: &[String],
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
                match self.upload(remote, hash).await {
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
        remote_hashes: &[String],
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
            if self.has_blob(hash).await? {
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

    /// Full bidirectional sync with remote server
    /// This is a simplified version - in practice, you'd want more sophisticated sync logic
    pub async fn full_sync(
        &self,
        remote: &BlobServiceImpl,
        local_hashes: &[String],
    ) -> Result<SyncResult, BlobStoreError> {
        info!(
            "Starting full bidirectional sync with {} local blobs",
            local_hashes.len()
        );

        // Step 1: Upload local blobs to remote
        let upload_result = self.upload_blobs(remote, local_hashes).await?;

        // Step 2: For this simple implementation, we don't have a way to list remote blobs
        // In a real implementation, you'd add a list_blobs RPC method to get remote hashes
        // then call download_blobs with those hashes

        let result = SyncResult {
            uploaded: upload_result.uploaded,
            downloaded: 0, // Would be implemented with remote blob listing
            failed: upload_result.failed,
        };

        info!(
            "Full sync complete: uploaded={}, downloaded={}, failed={}",
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
}
