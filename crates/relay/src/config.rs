use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use ed25519_dalek::SigningKey;
use rand::thread_rng;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RelayConfig {
    pub server_key: SigningKey,
    pub blob_config: BlobConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobConfig {
    pub data_dir: PathBuf,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server_key: SigningKey::generate(&mut thread_rng()),
            blob_config: BlobConfig::default(),
        }
    }
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./blob-store-data"),
        }
    }
}