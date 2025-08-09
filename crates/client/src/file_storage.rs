//! High-level file storage that encrypts files and stores them in blob storage
//!
//! This module provides a higher-level abstraction for storing files that:
//! 1. Reads files from disk
//! 2. Encrypts them using convergent encryption
//! 3. Stores encrypted data in blob storage  
//! 4. Returns metadata for later retrieval
//!
//! ## Usage
//!
//! ```rust,no_run
//! use zoe_client::FileStorage;
//! use std::path::Path;
//! use tempfile::tempdir;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let temp_dir = tempdir()?;
//! let storage = FileStorage::new(temp_dir.path()).await?;
//!
//! // Store a file
//! let file_path = Path::new("/path/to/my/file.txt");
//! let stored_info = storage.store_file(file_path).await?;
//!
//! // Later, retrieve the file
//! let retrieved_data = storage.retrieve_file(&stored_info).await?;
//! # Ok(())
//! # }
//! ```

use crate::error::{ClientError, Result};
use crate::services::BlobService;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};
use zoe_app_primitives::FileRef;
use zoe_blob_store::BlobClient;
use zoe_encrypted_storage::{CompressionConfig, ConvergentEncryption};

// FileRef is now defined in zoe-app-primitives and imported above

/// High-level file storage client that encrypts files and stores them as blobs
#[derive(Clone)]
pub struct FileStorage {
    blob_client: BlobClient,
    remote_blob_service: Option<BlobService>,
    compression_config: CompressionConfig,
}

impl FileStorage {
    /// Create a new file storage client with default compression settings
    pub async fn new(blob_storage_path: &Path) -> Result<Self> {
        let blob_client = BlobClient::new(blob_storage_path.to_path_buf()).await?;

        Ok(Self {
            blob_client,
            remote_blob_service: None,
            compression_config: CompressionConfig::default(),
        })
    }

    /// Create a new file storage client with custom compression settings
    pub async fn new_with_compression(
        blob_storage_path: &Path,
        compression_config: CompressionConfig,
    ) -> Result<Self> {
        let blob_client = BlobClient::new(blob_storage_path.to_path_buf()).await?;

        Ok(Self {
            blob_client,
            remote_blob_service: None,
            compression_config,
        })
    }

    /// Create a new file storage client with remote blob service support
    pub async fn new_with_remote(
        blob_storage_path: &Path,
        remote_blob_service: BlobService,
    ) -> Result<Self> {
        let blob_client = BlobClient::new(blob_storage_path.to_path_buf()).await?;

        Ok(Self {
            blob_client,
            remote_blob_service: Some(remote_blob_service),
            compression_config: CompressionConfig::default(),
        })
    }

    /// Create a new file storage client with remote blob service and custom compression
    pub async fn new_with_remote_and_compression(
        blob_storage_path: &Path,
        remote_blob_service: BlobService,
        compression_config: CompressionConfig,
    ) -> Result<Self> {
        let blob_client = BlobClient::new(blob_storage_path.to_path_buf()).await?;

        Ok(Self {
            blob_client,
            remote_blob_service: Some(remote_blob_service),
            compression_config,
        })
    }

    /// Store a file by reading from disk, encrypting, and storing in blob storage
    ///
    /// This method:
    /// 1. Reads the file from the provided path
    /// 2. Encrypts the content using convergent encryption
    /// 3. Stores the encrypted data in the blob store
    /// 4. Returns metadata needed to retrieve the file later
    ///
    /// # Arguments
    ///
    /// * `file_path` - Path to the file to store
    ///
    /// # Returns
    ///
    /// `FileRef` containing the blob hash, encryption info, and metadata
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use zoe_client::FileStorage;
    /// # use std::path::Path;
    /// # use tempfile::tempdir;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let temp_dir = tempdir()?;
    /// let storage = FileStorage::new(temp_dir.path()).await?;
    ///
    /// let file_path = Path::new("/path/to/document.pdf");
    /// let stored_info = storage.store_file(file_path).await?;
    ///
    /// println!("File stored with blob hash: {}", stored_info.blob_hash);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn store_file(&self, file_path: &Path) -> Result<FileRef> {
        info!("Storing file: {}", file_path.display());

        // Read file content
        let file_content = fs::read(file_path).await.map_err(|e| {
            ClientError::FileStorage(format!(
                "Failed to read file {}: {}",
                file_path.display(),
                e
            ))
        })?;

        let original_size = file_content.len() as u64;
        debug!("File size: {} bytes", original_size);

        // Encrypt the file content using convergent encryption
        let (encrypted_data, encryption_info) =
            ConvergentEncryption::encrypt_with_compression_config(
                &file_content,
                self.compression_config.clone(),
            )?;

        debug!(
            "File encrypted, compressed: {}",
            encryption_info.was_compressed
        );

        // Store encrypted data in blob storage
        let blob_hash = self.blob_client.store_blob(encrypted_data.clone()).await?;

        info!("File stored successfully with blob hash: {}", blob_hash);

        // Push to remote blob service if available
        if let Some(remote_service) = &self.remote_blob_service {
            match remote_service.upload_blob(&encrypted_data).await {
                Ok(remote_hash) => {
                    if remote_hash == blob_hash {
                        info!("File successfully pushed to remote storage: {}", blob_hash);
                    } else {
                        warn!(
                            "Remote hash mismatch: local={}, remote={}",
                            blob_hash, remote_hash
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to push file to remote storage: {}", e);
                    // Don't fail the operation since local storage succeeded
                }
            }
        }

        // Determine content type from file extension
        let content_type = file_path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| format!("application/{ext}"));

        // Extract filename from path
        let filename = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut stored_info = FileRef::new(blob_hash, encryption_info, Some(filename));

        if let Some(content_type) = content_type {
            stored_info = stored_info.with_content_type(content_type);
        }

        Ok(stored_info)
    }

    /// Store raw data (not from a file) with encryption and blob storage
    ///
    /// This method allows storing arbitrary data without reading from disk.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw data to store
    /// * `reference_name` - A reference name for the data (used in metadata)
    /// * `content_type` - Optional content type for metadata
    ///
    /// # Returns
    ///
    /// `FileRef` containing the blob hash, encryption info, and metadata
    pub async fn store_data(
        &self,
        data: &[u8],
        reference_name: &str,
        content_type: Option<String>,
    ) -> Result<FileRef> {
        info!(
            "Storing raw data: {} ({} bytes)",
            reference_name,
            data.len()
        );

        let _original_size = data.len() as u64; // Size is tracked in encryption_info

        // Encrypt the data using convergent encryption
        let (encrypted_data, encryption_info) =
            ConvergentEncryption::encrypt_with_compression_config(
                data,
                self.compression_config.clone(),
            )?;

        debug!(
            "Data encrypted, compressed: {}",
            encryption_info.was_compressed
        );

        // Store encrypted data in blob storage
        let blob_hash = self.blob_client.store_blob(encrypted_data.clone()).await?;

        info!("Data stored successfully with blob hash: {}", blob_hash);

        // Push to remote blob service if available
        if let Some(remote_service) = &self.remote_blob_service {
            match remote_service.upload_blob(&encrypted_data).await {
                Ok(remote_hash) => {
                    if remote_hash == blob_hash {
                        info!("Data successfully pushed to remote storage: {}", blob_hash);
                    } else {
                        warn!(
                            "Remote hash mismatch: local={}, remote={}",
                            blob_hash, remote_hash
                        );
                    }
                }
                Err(e) => {
                    warn!("Failed to push data to remote storage: {}", e);
                    // Don't fail the operation since local storage succeeded
                }
            }
        }

        let mut stored_info =
            FileRef::new(blob_hash, encryption_info, Some(reference_name.to_string()));

        if let Some(content_type) = content_type {
            stored_info = stored_info.with_content_type(content_type);
        }

        Ok(stored_info)
    }

    /// Retrieve a file from storage and decrypt it
    ///
    /// This method:
    /// 1. Retrieves the encrypted data from blob storage using the hash
    /// 2. Decrypts the data using the provided encryption info
    /// 3. Returns the original file content
    ///
    /// # Arguments
    ///
    /// * `stored_info` - Metadata from when the file was stored
    ///
    /// # Returns
    ///
    /// The original file content as bytes
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use zoe_client::FileStorage;
    /// # use std::path::Path;
    /// # use tempfile::tempdir;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let temp_dir = tempdir()?;
    /// let storage = FileStorage::new(temp_dir.path()).await?;
    ///
    /// // Assume we have stored_info from a previous store_file call
    /// # let stored_info = zoe_client::FileRef {
    /// #     blob_hash: "example".to_string(),
    /// #     encryption_info: zoe_encrypted_storage::ConvergentEncryptionInfo {
    /// #         key: [0; 32],
    /// #         was_compressed: false,
    /// #         source_size: 100,
    /// #     },
    /// #     filename: Some("example.txt".to_string()),
    /// #     content_type: None,
    /// #     metadata: vec![],
    /// # };
    ///
    /// let file_content = storage.retrieve_file(&stored_info).await?;
    /// println!("Retrieved {} bytes", file_content.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn retrieve_file(&self, stored_info: &FileRef) -> Result<Vec<u8>> {
        info!("Retrieving file with blob hash: {}", stored_info.blob_hash);

        // Get encrypted data from blob storage
        let encrypted_data = match self.blob_client.get_blob(&stored_info.blob_hash).await? {
            Some(data) => {
                debug!("Retrieved blob from local storage");
                data
            }
            None => {
                // Try to fetch from remote if available
                if let Some(remote_service) = &self.remote_blob_service {
                    info!(
                        "Blob not found locally, attempting remote fetch for hash: {}",
                        stored_info.blob_hash
                    );
                    match remote_service.get_blob(&stored_info.blob_hash).await {
                        Ok(remote_data) => {
                            info!("Successfully retrieved blob from remote storage");
                            // Store the fetched data locally for future use
                            if let Err(e) = self.blob_client.store_blob(remote_data.clone()).await {
                                warn!("Failed to cache remotely fetched blob locally: {}", e);
                            } else {
                                debug!("Cached remotely fetched blob to local storage");
                            }
                            remote_data
                        }
                        Err(e) => {
                            return Err(ClientError::FileStorage(format!(
                                "Blob not found locally or remotely with hash {}: {}",
                                stored_info.blob_hash, e
                            )));
                        }
                    }
                } else {
                    return Err(ClientError::FileStorage(format!(
                        "Blob not found with hash: {}",
                        stored_info.blob_hash
                    )));
                }
            }
        };

        debug!("Retrieved encrypted data: {} bytes", encrypted_data.len());

        // Decrypt the data
        let decrypted_data =
            ConvergentEncryption::decrypt(&encrypted_data, &stored_info.encryption_info)?;

        info!(
            "File decrypted successfully: {} bytes",
            decrypted_data.len()
        );

        // Verify the size matches expectations
        if decrypted_data.len() != stored_info.original_size() {
            return Err(ClientError::FileStorage(format!(
                "Decrypted file size mismatch: expected {}, got {}",
                stored_info.original_size(),
                decrypted_data.len()
            )));
        }

        Ok(decrypted_data)
    }

    /// Check if a file exists in storage
    ///
    /// # Arguments
    ///
    /// * `stored_info` - Metadata from when the file was stored
    ///
    /// # Returns
    ///
    /// `true` if the file exists in storage, `false` otherwise
    pub async fn has_file(&self, stored_info: &FileRef) -> Result<bool> {
        self.blob_client
            .has_blob(&stored_info.blob_hash)
            .await
            .map_err(Into::into)
    }

    /// Save retrieved file content to disk
    ///
    /// This is a convenience method that combines `retrieve_file` with writing to disk.
    ///
    /// # Arguments
    ///
    /// * `stored_info` - Metadata from when the file was stored
    /// * `output_path` - Path where to write the retrieved file
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use zoe_client::FileStorage;
    /// # use std::path::Path;
    /// # use tempfile::tempdir;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let temp_dir = tempdir()?;
    /// let storage = FileStorage::new(temp_dir.path()).await?;
    ///
    /// # let stored_info = zoe_client::FileRef {
    /// #     blob_hash: "example".to_string(),
    /// #     encryption_info: zoe_encrypted_storage::ConvergentEncryptionInfo {
    /// #         key: [0; 32],
    /// #         was_compressed: false,
    /// #         source_size: 100,
    /// #     },
    /// #     filename: Some("example.txt".to_string()),
    /// #     content_type: None,
    /// #     metadata: vec![],
    /// # };
    ///
    /// let output_path = Path::new("/tmp/retrieved_file.txt");
    /// storage.retrieve_file_to_disk(&stored_info, output_path).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn retrieve_file_to_disk(
        &self,
        stored_info: &FileRef,
        output_path: &Path,
    ) -> Result<()> {
        let file_content = self.retrieve_file(stored_info).await?;

        // Ensure parent directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                ClientError::FileStorage(format!(
                    "Failed to create parent directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        fs::write(output_path, file_content).await.map_err(|e| {
            ClientError::FileStorage(format!(
                "Failed to write file {}: {}",
                output_path.display(),
                e
            ))
        })?;

        info!("File retrieved and saved to: {}", output_path.display());
        Ok(())
    }

    /// Get the underlying blob client for advanced operations
    pub fn blob_client(&self) -> &BlobClient {
        &self.blob_client
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn test_store_and_retrieve_file() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path()).await.unwrap();

        // Create a temporary file with test content
        let test_content = b"Hello, this is a test file for storage!";
        let file_path = temp_dir.path().join("test_file.txt");
        let mut file = File::create(&file_path).await.unwrap();
        file.write_all(test_content).await.unwrap();
        file.flush().await.unwrap();

        // Store the file
        let stored_info = storage.store_file(&file_path).await.unwrap();

        // Verify metadata
        assert_eq!(stored_info.original_size(), test_content.len());
        assert_eq!(stored_info.filename(), Some("test_file.txt"));
        assert!(stored_info.content_type.is_some());

        // Retrieve the file
        let retrieved_content = storage.retrieve_file(&stored_info).await.unwrap();

        // Verify content matches
        assert_eq!(retrieved_content, test_content);
    }

    #[tokio::test]
    async fn test_store_and_retrieve_data() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path()).await.unwrap();

        let test_data = b"This is raw data without a file";
        let reference_name = "test_data";
        let content_type = Some("text/plain".to_string());

        // Store raw data
        let stored_info = storage
            .store_data(test_data, reference_name, content_type.clone())
            .await
            .unwrap();

        // Verify metadata
        assert_eq!(stored_info.original_size(), test_data.len());
        assert_eq!(stored_info.filename(), Some(reference_name));
        assert_eq!(stored_info.content_type, content_type);

        // Retrieve the data
        let retrieved_data = storage.retrieve_file(&stored_info).await.unwrap();

        // Verify content matches
        assert_eq!(retrieved_data, test_data);
    }

    #[tokio::test]
    async fn test_has_file() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path()).await.unwrap();

        let test_data = b"Test data for existence check";
        let stored_info = storage
            .store_data(test_data, "existence_test", None)
            .await
            .unwrap();

        // Check that file exists
        assert!(storage.has_file(&stored_info).await.unwrap());

        // Create a fake stored info that doesn't exist in the current storage
        // Use a different temp directory to generate a hash that won't exist in the main storage
        let fake_temp_dir = tempdir().unwrap();
        let fake_storage = FileStorage::new(fake_temp_dir.path()).await.unwrap();
        let fake_data = b"different fake data for different hash";
        let fake_info_temp = fake_storage
            .store_data(fake_data, "fake_test", None)
            .await
            .unwrap();

        let fake_info = FileRef::new(
            fake_info_temp.blob_hash, // This hash exists in fake_storage, but not in main storage
            fake_info_temp.encryption_info,
            Some("fake_file.txt".to_string()),
        );

        // Check that fake file doesn't exist
        assert!(!storage.has_file(&fake_info).await.unwrap());
    }

    #[tokio::test]
    async fn test_retrieve_file_to_disk() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path()).await.unwrap();

        let test_content = b"Content to save to disk";
        let stored_info = storage
            .store_data(test_content, "disk_test", None)
            .await
            .unwrap();

        // Retrieve to a new file
        let output_path = temp_dir.path().join("output_file.txt");
        storage
            .retrieve_file_to_disk(&stored_info, &output_path)
            .await
            .unwrap();

        // Verify the file was written correctly
        let saved_content = fs::read(&output_path).await.unwrap();
        assert_eq!(saved_content, test_content);
    }

    #[tokio::test]
    async fn test_convergent_encryption_property() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path()).await.unwrap();

        let test_data = b"Same content for convergent test";

        // Store the same data twice
        let stored_info1 = storage
            .store_data(test_data, "convergent1", None)
            .await
            .unwrap();
        let stored_info2 = storage
            .store_data(test_data, "convergent2", None)
            .await
            .unwrap();

        // Should produce the same blob hash (convergent property)
        assert_eq!(stored_info1.blob_hash, stored_info2.blob_hash);
        assert_eq!(
            stored_info1.encryption_info.key,
            stored_info2.encryption_info.key
        );
    }

    // We can't easily test with real BlobService due to connection dependencies,
    // so these tests focus on the logic flow and error handling
    #[tokio::test]
    async fn test_file_storage_without_remote() {
        let temp_dir = tempdir().unwrap();
        let storage = FileStorage::new(temp_dir.path()).await.unwrap();

        // Test that normal operations work without remote service
        let test_data = b"Test data without remote";
        let stored_info = storage
            .store_data(test_data, "no_remote_test", None)
            .await
            .unwrap();

        let retrieved_data = storage.retrieve_file(&stored_info).await.unwrap();
        assert_eq!(retrieved_data, test_data);
    }

    #[tokio::test]
    async fn test_remote_push_simulation() {
        let temp_dir1 = tempdir().unwrap();
        let temp_dir2 = tempdir().unwrap();

        // Create two separate storages to simulate local and remote
        let local_storage = FileStorage::new(temp_dir1.path()).await.unwrap();
        let remote_storage = FileStorage::new(temp_dir2.path()).await.unwrap();

        let test_data = b"Test data for remote push simulation";

        // Store in local
        let stored_info = local_storage
            .store_data(test_data, "remote_push_test", None)
            .await
            .unwrap();

        // Simulate remote push by storing the same encrypted data
        let encrypted_data = {
            let (encrypted, _) =
                zoe_encrypted_storage::ConvergentEncryption::encrypt_with_compression_config(
                    test_data,
                    zoe_encrypted_storage::CompressionConfig::default(),
                )
                .unwrap();
            encrypted
        };

        let remote_hash = remote_storage
            .blob_client
            .store_blob(encrypted_data)
            .await
            .unwrap();

        // Verify the hashes should match (convergent encryption)
        assert_eq!(stored_info.blob_hash, remote_hash);
    }

    #[tokio::test]
    async fn test_remote_fetch_simulation() {
        let temp_dir1 = tempdir().unwrap();
        let temp_dir2 = tempdir().unwrap();

        // Create storages
        let storage1 = FileStorage::new(temp_dir1.path()).await.unwrap();
        let storage2 = FileStorage::new(temp_dir2.path()).await.unwrap();

        let test_data = b"Test data for remote fetch simulation";

        // Store data in storage2 (simulating remote)
        let stored_info = storage2
            .store_data(test_data, "remote_fetch_test", None)
            .await
            .unwrap();

        // Verify storage1 doesn't have it
        assert!(!storage1.has_file(&stored_info).await.unwrap());

        // Manually transfer blob (simulating remote fetch)
        let encrypted_data = storage2
            .blob_client
            .get_blob(&stored_info.blob_hash)
            .await
            .unwrap()
            .unwrap();
        storage1
            .blob_client
            .store_blob(encrypted_data)
            .await
            .unwrap();

        // Now storage1 should have it and be able to retrieve
        assert!(storage1.has_file(&stored_info).await.unwrap());
        let retrieved_data = storage1.retrieve_file(&stored_info).await.unwrap();
        assert_eq!(retrieved_data, test_data);
    }
}
