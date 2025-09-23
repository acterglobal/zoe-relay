use super::error::ExecutorError;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Storage trait for the unified generic executor
///
/// This trait defines a completely generic storage interface that works with
/// any serializable data type. The store doesn't need to know about specific
/// model types - it just stores and retrieves serializable data.
#[async_trait]
pub trait ExecutorStore: Clone + Send + Sync {
    /// Associated error type for storage operations
    type Error: std::error::Error + Send + Sync + Into<ExecutorError>;

    /// Save any serializable data to storage
    ///
    /// Returns the execute references that should be broadcast for updates.
    async fn save<K, T>(&self, id: K, data: &T) -> Result<(), Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::Serialize + Send + Sync;

    /// Load any deserializable data by ID
    ///
    /// Returns None if the data doesn't exist.
    async fn load<K, T>(&self, id: K) -> Result<Option<T>, Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::de::DeserializeOwned + Send + Sync;

    /// Load multiple items by their IDs
    ///
    /// Returns a map of ID -> data for items that exist.
    /// Missing items are simply not included in the result.
    async fn load_many<K, T>(&self, ids: &[K]) -> Result<Vec<Option<T>>, Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::de::DeserializeOwned + Send + Sync;

    /// Load index data by list ID - returns serialized index information
    async fn load_index<K, D>(&self, list_id: K) -> Result<Option<D>, Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        D: serde::de::DeserializeOwned + Send + Sync;

    /// Store index data by list ID - stores serialized index information
    async fn store_index<K, D>(&self, list_id: K, index_data: &D) -> Result<(), Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        D: serde::Serialize + Send + Sync;
}

/// Simple in-memory store for testing and development
#[derive(Debug, Clone, Default)]
pub struct InMemoryStore {
    models: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
    indexes: Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ExecutorStore for InMemoryStore {
    type Error = InMemoryStoreError;

    async fn save<K, T>(&self, id: K, data: &T) -> Result<(), Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::Serialize + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&id)?;
        let data_bytes = postcard::to_stdvec(data)?;

        let mut models = self.models.write().await;
        models.insert(id_bytes, data_bytes);
        Ok(())
    }

    async fn load<K, T>(&self, id: K) -> Result<Option<T>, Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&id)?;

        let models = self.models.read().await;
        match models.get(&id_bytes) {
            Some(data_bytes) => {
                let data = postcard::from_bytes(data_bytes)?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    async fn load_many<K, T>(&self, ids: &[K]) -> Result<Vec<Option<T>>, Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        T: serde::de::DeserializeOwned + Send + Sync,
    {
        let mut results = Vec::with_capacity(ids.len());
        for id in ids {
            let result = self.load(id).await?;
            results.push(result);
        }
        Ok(results)
    }

    async fn load_index<K, D>(&self, list_id: K) -> Result<Option<D>, Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        D: serde::de::DeserializeOwned + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&list_id)?;

        let indexes = self.indexes.read().await;
        match indexes.get(&id_bytes) {
            Some(data_bytes) => {
                let data = postcard::from_bytes(data_bytes)?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    async fn store_index<K, D>(&self, list_id: K, index_data: &D) -> Result<(), Self::Error>
    where
        K: serde::Serialize + Send + Sync,
        D: serde::Serialize + Send + Sync,
    {
        let id_bytes = postcard::to_stdvec(&list_id)?;
        let data_bytes = postcard::to_stdvec(index_data)?;

        let mut indexes = self.indexes.write().await;
        indexes.insert(id_bytes, data_bytes);
        Ok(())
    }
}

/// Errors for the in-memory store
#[derive(Debug, Error)]
pub enum InMemoryStoreError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),
}

impl From<InMemoryStoreError> for ExecutorError {
    fn from(val: InMemoryStoreError) -> Self {
        ExecutorError::StorageError(format!("{}", val))
    }
}
