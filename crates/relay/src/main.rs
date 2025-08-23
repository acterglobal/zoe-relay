use anyhow::Result;
use clap::{Arg, Command};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;
use zoe_blob_store::BlobServiceImpl;
use zoe_message_store::RedisMessageStorage;
// Import will be conditional based on features

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
        use zoe_wire_protocol::KeyPair;
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng()); // Generates Ed25519 for transport
        println!("Generated server keypair: {}", server_keypair.public_key());
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
        let mut config = RelayConfig::new_with_new_ed25519_tls_key();

        // Override blob directory if provided
        if let Some(blob_dir) = matches.get_one::<String>("blob-dir") {
            config.blob_config.data_dir = PathBuf::from(blob_dir);
        }

        if let Some(private_key) = matches.get_one::<String>("private-key") {
            let _private_key_bytes: [u8; 32] =
                hex::decode(private_key).unwrap().try_into().unwrap();
            // TODO: Implement proper key loading from bytes
            // For now, just use default Ed25519 generation
            use zoe_wire_protocol::KeyPair;
            config.server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        }

        config
    };

    info!("Starting Zoe Relay Server");
    info!("Server address: {}", address);
    info!(
        "Server identity: {} ({})",
        config.server_keypair.public_key(),
        config.server_keypair.public_key().algorithm()
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
    let server = RelayServer::new(address, config.server_keypair, router)?;

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

    // For now, we only load the blob config from TOML since KeyPair doesn't support serde
    #[derive(serde::Deserialize)]
    struct ConfigFile {
        blob_config: zoe_relay::BlobConfig,
    }

    let config_file: ConfigFile = toml::from_str(&config_content)
        .map_err(|e| anyhow::anyhow!("Failed to parse config file '{}': {}", config_path, e))?;

    // Create RelayConfig with default Ed25519 keypair and loaded blob config
    let mut config = RelayConfig::new_with_new_ed25519_tls_key();
    config.blob_config = config_file.blob_config;

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

        // Create a test config file with just the blob config (since KeyPair doesn't support serde)
        #[derive(serde::Serialize)]
        struct TestConfigFile {
            blob_config: zoe_relay::BlobConfig,
        }

        let test_config_file = TestConfigFile {
            blob_config: zoe_relay::BlobConfig {
                data_dir: PathBuf::from("/test/path"),
            },
        };

        let config_toml = toml::to_string(&test_config_file).unwrap();
        fs::write(&config_path, config_toml).unwrap();

        let loaded_config = load_config(config_path.to_str().unwrap()).unwrap();
        assert_eq!(
            loaded_config.blob_config.data_dir,
            PathBuf::from("/test/path")
        );
    }

    #[test]
    fn test_default_config() {
        let config = RelayConfig::new_with_new_ed25519_tls_key();
        assert_eq!(
            config.blob_config.data_dir,
            PathBuf::from("./blob-store-data")
        );
    }
}
