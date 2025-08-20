use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zoe_wire_protocol::ServerKeypair;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    pub server_keypair: ServerKeypair,
    pub blob_config: BlobConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobConfig {
    pub data_dir: PathBuf,
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./blob-store-data"),
        }
    }
}
