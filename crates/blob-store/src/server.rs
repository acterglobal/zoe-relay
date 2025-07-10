use std::path::PathBuf;

use clap::Parser;
use tracing::info;

use crate::{BlobStoreConfig, BlobStoreError};

/// Command line arguments for the blob store server
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Data directory for storing blobs
    #[arg(short, long, default_value = "./blob-store-data")]
    data_dir: PathBuf,

    /// Port to bind the server to
    #[arg(short, long, default_value_t = 9091)]
    port: u16,

    /// Host address to bind to
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
}

impl From<Args> for BlobStoreConfig {
    fn from(args: Args) -> Self {
        Self {
            data_dir: args.data_dir,
            port: args.port,
            host: args.host,
        }
    }
}

/// Run the blob store server with command line arguments
pub async fn run_with_args() -> Result<(), BlobStoreError> {
    let args = Args::parse();
    let config: BlobStoreConfig = args.into();

    info!("Starting blob store with config: {:?}", config);

    crate::start_server(config).await
}

/// Run the blob store server with default configuration
pub async fn run_default() -> Result<(), BlobStoreError> {
    let config = BlobStoreConfig::default();
    info!("Starting blob store with default config: {:?}", config);

    crate::start_server(config).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_args_to_config_conversion() {
        let temp_dir = TempDir::new().unwrap();
        let args = Args {
            data_dir: temp_dir.path().to_path_buf(),
            port: 9090,
            host: "0.0.0.0".to_string(),
        };

        let config: BlobStoreConfig = args.into();
        assert_eq!(config.port, 9090);
        assert_eq!(config.host, "0.0.0.0");
    }
}
