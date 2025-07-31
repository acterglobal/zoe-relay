use anyhow::Result;
use clap::{Arg, Command};
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use zoe_blob_store::BlobServiceImpl;
use zoe_message_store::RedisMessageStorage;

use zoe_relay::{RelayConfig, RelayServer, RelayServiceRouter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with default info level if RUST_LOG is not set
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let app = Command::new("zoe-relay")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Zoe Relay Server - QUIC relay with ed25519 authentication")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Server bind address")
                .default_value("127.0.0.1:4433"),
        )
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path"),
        )
        .arg(
            Arg::new("blob-dir")
                .short('b')
                .long("blob-dir")
                .value_name("DIRECTORY")
                .help("Blob storage directory")
                .default_value("./blob-store-data"),
        )
        .arg(
            Arg::new("private-key")
                .short('k')
                .long("private-key")
                .value_name("PRIVATE_KEY")
                .help("Private key for the server"),
        )
        .arg(
            Arg::new("generate-key")
                .long("generate-key")
                .help("Generate a new server key and exit")
                .action(clap::ArgAction::SetTrue),
        );

    let matches = app.get_matches();

    // Handle key generation
    if matches.get_flag("generate-key") {
        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let hex_key = hex::encode(server_key.to_bytes());
        println!("Generated server key: {hex_key}");
        println!(
            "You can use this key in your configuration file or set it via environment variable."
        );
        return Ok(());
    }

    // Parse address
    let address: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

    // Load or create configuration
    let config = if let Some(config_path) = matches.get_one::<String>("config") {
        load_config(config_path)?
    } else {
        // Create default config with CLI overrides
        let mut config = RelayConfig::default();

        // Override blob directory if provided
        if let Some(blob_dir) = matches.get_one::<String>("blob-dir") {
            config.blob_config.data_dir = PathBuf::from(blob_dir);
        }

        if let Some(private_key) = matches.get_one::<String>("private-key") {
            let private_key_bytes: [u8; 32] = hex::decode(private_key).unwrap().try_into().unwrap();
            config.server_key = SigningKey::from(private_key_bytes);
        }

        config
    };

    info!("Starting Zoe Relay Server");
    info!("Server address: {}", address);
    info!(
        "Server public key: {}",
        hex::encode(config.server_key.verifying_key().to_bytes())
    );
    info!("Blob storage directory: {:?}", config.blob_config.data_dir);

    // Create blob service implementation
    let blob_service = BlobServiceImpl::new(config.blob_config.data_dir.clone()).await?;

    // Create message service implementation (assumes Redis at localhost:6379 for now)
    let message_service = RedisMessageStorage::new("redis://127.0.0.1:6379".to_string())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;

    // Create service router
    let router = RelayServiceRouter::new(blob_service, message_service);

    // Create and start relay server
    let server = RelayServer::new(address, config.server_key, router)?;

    info!("🚀 Zoe Relay Server running on {}", address);
    info!("Press Ctrl+C to stop the server");

    // Handle graceful shutdown
    let shutdown_signal = tokio::signal::ctrl_c();

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            info!("Received shutdown signal, stopping server...");
        }
    }

    info!("Server shutdown complete");
    Ok(())
}

fn load_config(config_path: &str) -> Result<RelayConfig> {
    let config_content = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read config file '{}': {}", config_path, e))?;

    let config: RelayConfig = toml::from_str(&config_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", config_path, e))?;

    info!("Loaded configuration from: {}", config_path);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_load_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");

        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let test_config = RelayConfig {
            server_key,
            blob_config: zoe_relay::BlobConfig {
                data_dir: PathBuf::from("/test/path"),
            },
        };

        let config_toml = toml::to_string(&test_config).unwrap();
        fs::write(&config_path, config_toml).unwrap();

        let loaded_config = load_config(config_path.to_str().unwrap()).unwrap();
        assert_eq!(
            loaded_config.blob_config.data_dir,
            PathBuf::from("/test/path")
        );
    }

    #[test]
    fn test_default_config() {
        let config = RelayConfig::default();
        assert_eq!(
            config.blob_config.data_dir,
            PathBuf::from("./blob-store-data")
        );
    }
}
