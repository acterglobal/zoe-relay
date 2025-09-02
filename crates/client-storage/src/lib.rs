pub mod error;
pub mod sqlite;
pub mod storage;

#[cfg(test)]
mod tests;

pub use error::{Result, StorageError};
pub use sqlite::SqliteMessageStorage;
pub use storage::{
    MessageQuery, MessageStorage, RelaySyncStatus, StateNamespace, StateStorage, StorageConfig,
    StorageStats, SubscriptionState,
};

// Storage factory for creating appropriate storage implementations
pub struct StorageFactory;

impl StorageFactory {
    /// Create a new storage instance based on the configuration
    pub async fn create_sqlite(
        config: StorageConfig,
        encryption_key: &[u8; 32],
    ) -> Result<Box<dyn MessageStorage>> {
        let storage = SqliteMessageStorage::new(config, encryption_key).await?;
        Ok(Box::new(storage))
    }
}
