use iroh_blobs::{Hash, store::fs::FsStore};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

use zoeyr_wire_protocol::{BlobError, BlobHealth, BlobInfo, BlobResult, BlobService};

use crate::BlobStoreError;

/// Implementation of the blob service using Iroh's filesystem store
#[derive(Clone)]
pub struct BlobServiceImpl {
    pub store: Arc<FsStore>,
}

impl BlobServiceImpl {
    /// Create a new blob service with the given data directory
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
}

impl BlobService for BlobServiceImpl {
    async fn health_check(self, _context: tarpc::context::Context) -> BlobResult<BlobHealth> {
        info!("Health check requested");

        // Count total blobs and calculate size
        let total_blobs = 0u64;
        let total_size_bytes = 0u64;

        // Note: Iroh doesn't provide a direct way to list all blobs,
        // so we'll return basic health status
        // In a real implementation, you might want to maintain metadata

        Ok(BlobHealth {
            status: "healthy".to_string(),
            total_blobs,
            total_size_bytes,
        })
    }

    async fn upload_blob(
        self,
        _context: tarpc::context::Context,
        data: Vec<u8>,
    ) -> BlobResult<String> {
        info!("Uploading blob of {} bytes", data.len());

        // Store the blob using add_bytes
        let progress = self.store.add_bytes(data.clone());
        let result = progress.await.map_err(|e| {
            error!("Failed to store blob: {}", e);
            BlobError::StorageError {
                message: e.to_string(),
            }
        })?;

        let hash = result.hash;
        info!("Successfully stored blob {}", hash);
        Ok(hash.to_string())
    }

    async fn download_blob(
        self,
        _context: tarpc::context::Context,
        hash: String,
    ) -> BlobResult<Option<Vec<u8>>> {
        info!("Downloading blob: {}", hash);

        let hash = hash
            .parse::<Hash>()
            .map_err(|_| BlobError::InvalidHash { hash: hash.clone() })?;

        // Try to get the blob data
        let data = match self.store.get_bytes(hash).await {
            Ok(bytes) => bytes,
            Err(_) => return Ok(None), // Blob not found
        };

        info!(
            "Successfully retrieved blob {} ({} bytes)",
            hash,
            data.len()
        );
        Ok(Some(data.to_vec()))
    }

    async fn get_blob_info(
        self,
        _context: tarpc::context::Context,
        hash: String,
    ) -> BlobResult<Option<BlobInfo>> {
        info!("Getting blob info: {}", hash);

        let hash_obj = hash
            .parse::<Hash>()
            .map_err(|_| BlobError::InvalidHash { hash: hash.clone() })?;

        // Check if blob exists and get its size
        let exists = self
            .store
            .has(hash_obj)
            .await
            .map_err(|e| BlobError::StorageError {
                message: e.to_string(),
            })?;

        if !exists {
            return Ok(None);
        }

        // Get the blob size by retrieving the bytes
        let size_bytes = match self.store.get_bytes(hash_obj).await {
            Ok(bytes) => bytes.len() as u64,
            Err(e) => {
                error!("Failed to retrieve blob {} for size info: {}", hash, e);
                return Err(BlobError::StorageError {
                    message: e.to_string(),
                });
            }
        };

        let info = BlobInfo {
            hash,
            size_bytes,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        Ok(Some(info))
    }
}
