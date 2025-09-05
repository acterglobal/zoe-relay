use super::BlobStore;
use crate::services::BlobError;
use async_trait::async_trait;
use std::collections::HashMap;
use zoe_client_storage::{BlobStorage, BlobUploadStatus};
use zoe_wire_protocol::{BlobId, KeyId};
/// Multi-relay blob service that manages blob uploads across multiple relays
/// and tracks upload status using persistent storage
pub struct MultiRelayBlobService<S: BlobStorage> {
    /// Map of relay ID to blob service for that relay
    relay_services: HashMap<KeyId, Box<dyn BlobStore>>,
    /// Storage for tracking blob upload status
    storage: S,
}

impl<S: BlobStorage> MultiRelayBlobService<S> {
    /// Create a new multi-relay blob service
    pub fn new(storage: S) -> Self {
        Self {
            relay_services: HashMap::new(),
            storage,
        }
    }

    /// Add a relay blob service
    pub fn add_relay(&mut self, relay_id: KeyId, service: Box<dyn BlobStore>) {
        self.relay_services.insert(relay_id, service);
        tracing::info!(
            "Added blob service for relay: {}",
            hex::encode(relay_id.as_bytes())
        );
    }

    /// Remove a relay blob service
    pub fn remove_relay(&mut self, relay_id: &KeyId) -> Option<Box<dyn BlobStore>> {
        let removed = self.relay_services.remove(relay_id);
        if removed.is_some() {
            tracing::info!(
                "Removed blob service for relay: {}",
                hex::encode(relay_id.as_bytes())
            );
        }
        removed
    }

    /// Get all configured relay IDs
    pub fn get_relay_ids(&self) -> Vec<KeyId> {
        self.relay_services.keys().cloned().collect()
    }

    /// Check if a blob has been uploaded to a specific relay
    pub async fn is_blob_uploaded_to_relay(
        &self,
        blob_hash: &BlobId,
        relay_id: &KeyId,
    ) -> Result<bool, BlobError> {
        self.storage
            .is_blob_uploaded(blob_hash, relay_id)
            .await
            .map_err(|e| BlobError::SerializationError(format!("Storage error: {e}")))
    }

    /// Get upload status for a blob across all relays
    pub async fn get_blob_upload_status(
        &self,
        blob_hash: &BlobId,
    ) -> Result<Vec<BlobUploadStatus>, BlobError> {
        self.storage
            .get_blob_upload_status(blob_hash)
            .await
            .map_err(|e| BlobError::SerializationError(format!("Storage error: {e}")))
    }

    /// Upload a blob to a specific relay and track the upload
    pub async fn upload_blob_to_relay(
        &self,
        blob: &[u8],
        relay_id: &KeyId,
    ) -> Result<BlobId, BlobError> {
        let service = self.relay_services.get(relay_id).ok_or_else(|| {
            BlobError::SerializationError(format!(
                "No service for relay: {}",
                hex::encode(relay_id.as_bytes())
            ))
        })?;

        // Upload the blob
        let blob_hash = service.upload_blob(blob).await?;

        // Mark as uploaded in storage
        self.storage
            .mark_blob_uploaded(&blob_hash, relay_id, blob.len() as u64)
            .await
            .map_err(|e| BlobError::SerializationError(format!("Storage error: {e}")))?;

        tracing::info!(
            "Successfully uploaded blob {} to relay {} (size: {} bytes)",
            blob_hash,
            hex::encode(relay_id.as_bytes()),
            blob.len()
        );

        Ok(blob_hash)
    }

    /// Upload a blob to all configured relays
    pub async fn upload_blob_to_all_relays(
        &self,
        blob: &[u8],
    ) -> Result<HashMap<KeyId, Result<BlobId, BlobError>>, BlobError> {
        let mut results = HashMap::new();

        for (relay_id, service) in &self.relay_services {
            let result = match service.upload_blob(blob).await {
                Ok(blob_hash) => {
                    // Mark as uploaded in storage
                    match self
                        .storage
                        .mark_blob_uploaded(&blob_hash, relay_id, blob.len() as u64)
                        .await
                    {
                        Ok(()) => {
                            tracing::info!(
                                "Successfully uploaded blob {} to relay {} (size: {} bytes)",
                                blob_hash,
                                hex::encode(relay_id.as_bytes()),
                                blob.len()
                            );
                            Ok(blob_hash)
                        }
                        Err(e) => {
                            tracing::error!("Failed to mark blob as uploaded in storage: {}", e);
                            Err(BlobError::SerializationError(format!("Storage error: {e}")))
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to upload blob to relay {}: {}",
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                    Err(e)
                }
            };

            results.insert(*relay_id, result);
        }

        Ok(results)
    }

    /// Upload a blob to relays where it hasn't been uploaded yet
    pub async fn upload_blob_to_missing_relays(
        &self,
        blob: &[u8],
    ) -> Result<HashMap<KeyId, Result<BlobId, BlobError>>, BlobError> {
        let mut results = HashMap::new();

        // Calculate blob hash first to check existing uploads
        // We'll use the first successful upload to get the hash, or calculate it ourselves
        let mut blob_hash_opt: Option<BlobId> = None;

        for (relay_id, service) in &self.relay_services {
            // Check if already uploaded
            if let Some(blob_hash) = blob_hash_opt {
                match self.storage.is_blob_uploaded(&blob_hash, relay_id).await {
                    Ok(true) => {
                        tracing::debug!(
                            "Blob {} already uploaded to relay {}",
                            blob_hash,
                            hex::encode(relay_id.as_bytes())
                        );
                        results.insert(*relay_id, Ok(blob_hash));
                        continue;
                    }
                    Ok(false) => {
                        // Need to upload
                    }
                    Err(e) => {
                        tracing::error!("Storage error checking upload status: {}", e);
                        results.insert(
                            *relay_id,
                            Err(BlobError::SerializationError(format!("Storage error: {e}"))),
                        );
                        continue;
                    }
                }
            }

            // Upload the blob
            let result = match service.upload_blob(blob).await {
                Ok(blob_hash) => {
                    blob_hash_opt = Some(blob_hash);

                    // Mark as uploaded in storage
                    match self
                        .storage
                        .mark_blob_uploaded(&blob_hash, relay_id, blob.len() as u64)
                        .await
                    {
                        Ok(()) => {
                            tracing::info!(
                                "Successfully uploaded blob {} to relay {} (size: {} bytes)",
                                blob_hash,
                                hex::encode(relay_id.as_bytes()),
                                blob.len()
                            );
                            Ok(blob_hash)
                        }
                        Err(e) => {
                            tracing::error!("Failed to mark blob as uploaded in storage: {}", e);
                            Err(BlobError::SerializationError(format!("Storage error: {e}")))
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to upload blob to relay {}: {}",
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                    Err(e)
                }
            };

            results.insert(*relay_id, result);
        }

        Ok(results)
    }

    /// Download a blob from any available relay (tries relays in order)
    pub async fn download_blob_from_any_relay(
        &self,
        blob_hash: &BlobId,
    ) -> Result<Vec<u8>, BlobError> {
        let mut last_error = BlobError::NotFound { hash: *blob_hash };

        for (relay_id, service) in &self.relay_services {
            match service.get_blob(blob_hash).await {
                Ok(blob_data) => {
                    tracing::debug!(
                        "Successfully downloaded blob {} from relay {} (size: {} bytes)",
                        blob_hash,
                        hex::encode(relay_id.as_bytes()),
                        blob_data.len()
                    );
                    return Ok(blob_data);
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to download blob {} from relay {}: {}",
                        blob_hash,
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Get statistics about blob uploads for a specific relay
    pub async fn get_relay_blob_stats(&self, relay_id: &KeyId) -> Result<(u64, u64), BlobError> {
        let count = self
            .storage
            .get_uploaded_blob_count_for_relay(relay_id)
            .await
            .map_err(|e| BlobError::SerializationError(format!("Storage error: {e}")))?;

        let size = self
            .storage
            .get_uploaded_blob_size_for_relay(relay_id)
            .await
            .map_err(|e| BlobError::SerializationError(format!("Storage error: {e}")))?;

        Ok((count, size))
    }

    /// Remove blob upload records (when blob is deleted)
    pub async fn remove_blob_records(&self, blob_hash: &BlobId) -> Result<u64, BlobError> {
        self.storage
            .remove_blob_upload_record(blob_hash, None)
            .await
            .map_err(|e| BlobError::SerializationError(format!("Storage error: {e}")))
    }
}

#[async_trait]
impl<S: BlobStorage> BlobStore for MultiRelayBlobService<S> {
    /// Download a blob from any available relay
    async fn get_blob(&self, blob_id: &BlobId) -> Result<Vec<u8>, BlobError> {
        self.download_blob_from_any_relay(blob_id).await
    }

    /// Upload a blob to all configured relays
    async fn upload_blob(&self, blob: &[u8]) -> Result<BlobId, BlobError> {
        let results = self.upload_blob_to_all_relays(blob).await?;

        // Return the hash from the first successful upload
        for (relay_id, result) in results {
            match result {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    tracing::warn!(
                        "Upload to relay {} failed: {}",
                        hex::encode(relay_id.as_bytes()),
                        e
                    );
                }
            }
        }

        Err(BlobError::SerializationError(
            "Failed to upload to any relay".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use zoe_client_storage::{StorageError, storage::MockBlobStorage};
    use zoe_wire_protocol::Hash;

    /// Mock blob store implementation for testing
    #[derive(Clone)]
    struct MockBlobStoreImpl {
        blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        should_fail: Arc<Mutex<bool>>,
    }

    impl MockBlobStoreImpl {
        fn new() -> Self {
            Self {
                blobs: Arc::new(Mutex::new(HashMap::new())),
                should_fail: Arc::new(Mutex::new(false)),
            }
        }

        async fn set_should_fail(&self, should_fail: bool) {
            *self.should_fail.lock().await = should_fail;
        }

        #[allow(dead_code)]
        async fn get_stored_blobs(&self) -> HashMap<String, Vec<u8>> {
            self.blobs.lock().await.clone()
        }
    }

    #[async_trait]
    impl BlobStore for MockBlobStoreImpl {
        async fn get_blob(&self, blob_id: &BlobId) -> Result<Vec<u8>, BlobError> {
            if *self.should_fail.lock().await {
                return Err(BlobError::NotFound { hash: *blob_id });
            }

            let blobs = self.blobs.lock().await;
            blobs
                .get(&blob_id.to_hex())
                .cloned()
                .ok_or_else(|| BlobError::NotFound { hash: *blob_id })
        }

        async fn upload_blob(&self, blob: &[u8]) -> Result<BlobId, BlobError> {
            if *self.should_fail.lock().await {
                return Err(BlobError::IoError(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "Mock upload failure",
                )));
            }

            // Simple hash calculation for testing (not cryptographically secure)
            let blob_id = BlobId::from_content(blob);
            let hash_string = blob_id.to_hex();

            let mut blobs = self.blobs.lock().await;
            blobs.insert(hash_string, blob.to_vec());

            Ok(blob_id)
        }
    }

    fn create_test_hash(value: u8) -> Hash {
        let mut bytes = [0u8; 32];
        bytes[0] = value;
        Hash::from(bytes)
    }

    fn create_test_key_id(value: u8) -> KeyId {
        KeyId(create_test_hash(value))
    }

    #[tokio::test]
    async fn test_multi_relay_blob_service_creation() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_is_blob_uploaded()
            .returning(|_, _| Ok(false));

        let service = MultiRelayBlobService::new(mock_storage);
        assert_eq!(service.get_relay_ids().len(), 0);
    }

    #[tokio::test]
    async fn test_add_remove_relay() {
        let mock_storage = MockBlobStorage::new();
        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        // Add relay
        service.add_relay(relay_id, Box::new(mock_blob_store));
        assert_eq!(service.get_relay_ids().len(), 1);
        assert!(service.get_relay_ids().contains(&relay_id));

        // Remove relay
        let removed = service.remove_relay(&relay_id);
        assert!(removed.is_some());
        assert_eq!(service.get_relay_ids().len(), 0);
    }

    #[tokio::test]
    async fn test_upload_blob_to_relay() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_mark_blob_uploaded()
            .withf(|_hash, _relay_id, size| *size == 11)
            .times(1)
            .returning(|_, _, _| Ok(()));

        let mut service = MultiRelayBlobService::new(mock_storage);
        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        service.add_relay(relay_id, Box::new(mock_blob_store));

        let test_data = b"hello world";
        let result = service.upload_blob_to_relay(test_data, &relay_id).await;

        assert!(result.is_ok());
        let blob_hash = result.unwrap();
        // BlobId doesn't have starts_with, just verify it's not empty
        assert!(!blob_hash.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn test_upload_blob_to_relay_storage_failure() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_mark_blob_uploaded()
            .times(1)
            .returning(|_, _, _| Err(StorageError::Internal("Storage failure".to_string())));

        let mut service = MultiRelayBlobService::new(mock_storage);
        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        service.add_relay(relay_id, Box::new(mock_blob_store));

        let test_data = b"hello world";
        let result = service.upload_blob_to_relay(test_data, &relay_id).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BlobError::SerializationError(msg) => assert!(msg.contains("Storage error")),
            _ => panic!("Expected SerializationError"),
        }
    }

    #[tokio::test]
    async fn test_upload_blob_to_all_relays() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_mark_blob_uploaded()
            .times(2)
            .returning(|_, _, _| Ok(()));

        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id1 = create_test_key_id(1);
        let relay_id2 = create_test_key_id(2);
        let mock_blob_store1 = MockBlobStoreImpl::new();
        let mock_blob_store2 = MockBlobStoreImpl::new();

        service.add_relay(relay_id1, Box::new(mock_blob_store1));
        service.add_relay(relay_id2, Box::new(mock_blob_store2));

        let test_data = b"hello world";
        let results = service.upload_blob_to_all_relays(test_data).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.get(&relay_id1).unwrap().is_ok());
        assert!(results.get(&relay_id2).unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_upload_blob_to_all_relays_partial_failure() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_mark_blob_uploaded()
            .times(1) // Only one successful upload
            .returning(|_, _, _| Ok(()));

        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id1 = create_test_key_id(1);
        let relay_id2 = create_test_key_id(2);
        let mock_blob_store1 = MockBlobStoreImpl::new();
        let mock_blob_store2 = MockBlobStoreImpl::new();

        // Make the second store fail
        mock_blob_store2.set_should_fail(true).await;

        service.add_relay(relay_id1, Box::new(mock_blob_store1));
        service.add_relay(relay_id2, Box::new(mock_blob_store2));

        let test_data = b"hello world";
        let results = service.upload_blob_to_all_relays(test_data).await.unwrap();

        assert_eq!(results.len(), 2);
        assert!(results.get(&relay_id1).unwrap().is_ok());
        assert!(results.get(&relay_id2).unwrap().is_err());
    }

    #[tokio::test]
    async fn test_upload_blob_to_missing_relays() {
        let mut mock_storage = MockBlobStorage::new();

        // Only expect mark_blob_uploaded since is_blob_uploaded is only called
        // when we already have a blob hash from a previous upload
        mock_storage
            .expect_mark_blob_uploaded()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        service.add_relay(relay_id, Box::new(mock_blob_store));

        let test_data = b"hello world";
        let results = service
            .upload_blob_to_missing_relays(test_data)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert!(results.get(&relay_id).unwrap().is_ok());
    }

    #[tokio::test]
    async fn test_download_blob_from_any_relay() {
        let mock_storage = MockBlobStorage::new();
        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        // Pre-populate the mock store with test data
        let test_data = b"hello world";
        let blob_hash = mock_blob_store.upload_blob(test_data).await.unwrap();

        service.add_relay(relay_id, Box::new(mock_blob_store));

        let result = service.download_blob_from_any_relay(&blob_hash).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_data);
    }

    #[tokio::test]
    async fn test_download_blob_not_found() {
        let mock_storage = MockBlobStorage::new();
        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        service.add_relay(relay_id, Box::new(mock_blob_store));

        let nonexistent_hash = BlobId::from_content(b"nonexistent");
        let result = service
            .download_blob_from_any_relay(&nonexistent_hash)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            BlobError::NotFound { hash } => assert_eq!(hash, nonexistent_hash),
            _ => panic!("Expected NotFound error"),
        }
    }

    #[tokio::test]
    async fn test_is_blob_uploaded_to_relay() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_is_blob_uploaded()
            .withf(|_hash, _| true)
            .times(1)
            .returning(|_, _| Ok(true));

        let service = MultiRelayBlobService::new(mock_storage);
        let relay_id = create_test_key_id(1);

        // Create a proper hex-encoded hash string
        let test_hash = create_test_hash(2);
        let _hash_string = hex::encode(test_hash.as_bytes());
        let blob_id = BlobId::from(test_hash);
        let result = service.is_blob_uploaded_to_relay(&blob_id, &relay_id).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_get_blob_upload_status() {
        let mut mock_storage = MockBlobStorage::new();
        let relay_id = create_test_key_id(1);
        let expected_status = vec![BlobUploadStatus {
            blob_hash: create_test_hash(2),
            relay_id,
            uploaded_at: 1234567890,
            blob_size: 100,
        }];

        mock_storage
            .expect_get_blob_upload_status()
            .withf(|_hash| true)
            .times(1)
            .returning(move |_| Ok(expected_status.clone()));

        let service = MultiRelayBlobService::new(mock_storage);

        let test_hash = create_test_hash(2);
        let blob_id = BlobId::from(test_hash);
        let result = service.get_blob_upload_status(&blob_id).await;

        assert!(result.is_ok());
        let statuses = result.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].blob_hash, test_hash);
        assert_eq!(statuses[0].relay_id, relay_id);
    }

    #[tokio::test]
    async fn test_get_relay_blob_stats() {
        let mut mock_storage = MockBlobStorage::new();
        let relay_id = create_test_key_id(1);

        mock_storage
            .expect_get_uploaded_blob_count_for_relay()
            .times(1)
            .returning(|_| Ok(5));
        mock_storage
            .expect_get_uploaded_blob_size_for_relay()
            .times(1)
            .returning(|_| Ok(1024));

        let service = MultiRelayBlobService::new(mock_storage);

        let result = service.get_relay_blob_stats(&relay_id).await;

        assert!(result.is_ok());
        let (count, size) = result.unwrap();
        assert_eq!(count, 5);
        assert_eq!(size, 1024);
    }

    #[tokio::test]
    async fn test_remove_blob_records() {
        let mut mock_storage = MockBlobStorage::new();

        mock_storage
            .expect_remove_blob_upload_record()
            .withf(|_hash, relay_id| relay_id.is_none())
            .times(1)
            .returning(|_, _| Ok(2));

        let service = MultiRelayBlobService::new(mock_storage);

        // Create a proper hex-encoded hash string
        let test_hash = create_test_hash(2);
        let _hash_string = hex::encode(test_hash.as_bytes());
        let blob_id = BlobId::from(test_hash);
        let result = service.remove_blob_records(&blob_id).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_blob_store_trait_implementation() {
        let mut mock_storage = MockBlobStorage::new();
        mock_storage
            .expect_mark_blob_uploaded()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let mut service = MultiRelayBlobService::new(mock_storage);

        let relay_id = create_test_key_id(1);
        let mock_blob_store = MockBlobStoreImpl::new();

        service.add_relay(relay_id, Box::new(mock_blob_store));

        let test_data = b"hello world";

        // Test upload through BlobStore trait
        let upload_result =
            <MultiRelayBlobService<_> as BlobStore>::upload_blob(&service, test_data).await;
        assert!(upload_result.is_ok());

        let blob_hash = upload_result.unwrap();

        // Test download through BlobStore trait
        let download_result =
            <MultiRelayBlobService<_> as BlobStore>::get_blob(&service, &blob_hash).await;
        assert!(download_result.is_ok());
        assert_eq!(download_result.unwrap(), test_data);
    }

    #[tokio::test]
    async fn test_blob_store_trait_upload_failure() {
        let mock_storage = MockBlobStorage::new();
        let service = MultiRelayBlobService::new(mock_storage);
        // No relays added, so upload should fail

        let test_data = b"hello world";

        let result =
            <MultiRelayBlobService<_> as BlobStore>::upload_blob(&service, test_data).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BlobError::SerializationError(msg) => {
                assert!(msg.contains("Failed to upload to any relay"))
            }
            _ => panic!("Expected SerializationError"),
        }
    }

    #[tokio::test]
    async fn test_upload_to_nonexistent_relay() {
        let mock_storage = MockBlobStorage::new();
        let service = MultiRelayBlobService::new(mock_storage);

        let relay_id = create_test_key_id(1);
        let test_data = b"hello world";

        let result = service.upload_blob_to_relay(test_data, &relay_id).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BlobError::SerializationError(msg) => assert!(msg.contains("No service for relay")),
            _ => panic!("Expected SerializationError"),
        }
    }
}
