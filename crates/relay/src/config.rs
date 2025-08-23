use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zoe_wire_protocol::KeyPair;

#[derive(Debug)]
pub struct RelayConfig {
    pub server_keypair: KeyPair,
    pub blob_config: BlobConfig,
}

impl RelayConfig {
    /// Create a new RelayConfig with Ed25519 keypair for transport security
    pub fn new_with_new_ed25519_tls_key() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            server_keypair: KeyPair::generate_ed25519(&mut rng),
            blob_config: BlobConfig::default(),
        }
    }
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
