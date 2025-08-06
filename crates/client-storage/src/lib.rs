pub mod error;
pub mod storage;
pub mod sqlite;

#[cfg(test)]
mod tests;

pub use error::{StorageError, Result};
pub use storage::{MessageStorage, StorageConfig, MessageQuery, StorageStats};
pub use sqlite::SqliteMessageStorage;

// Storage factory for creating appropriate storage implementations
pub struct StorageFactory;

impl StorageFactory {
    /// Create a new storage instance based on the configuration
    pub async fn create_sqlite(
        config: StorageConfig,
        encryption_key: &[u8; 32],
    ) -> Result<Box<dyn MessageStorage<Error = StorageError>>> {
        let storage = SqliteMessageStorage::new(config, encryption_key).await?;
        Ok(Box::new(storage))
    }
}