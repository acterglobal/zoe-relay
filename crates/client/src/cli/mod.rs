use crate::{Client, ClientError, util::resolve_to_socket_addr};
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
use tempfile::TempDir;
use tracing::{error, info};
use zoe_wire_protocol::VerifyingKey;

#[derive(Parser, Debug)]
pub struct RelayClientArgs {
    /// Relay server address (e.g., "127.0.0.1:8080")
    #[arg(
        short,
        long,
        env = "ZOE_RELAY_ADDRESS",
        default_value = "127.0.0.1:13908"
    )]
    pub relay_address: String,

    /// Server public key in hex format
    #[arg(short, long, value_parser = parse_verifying_key, conflicts_with = "server_key_file")]
    pub server_key: Option<VerifyingKey>,

    /// Path to file containing server public key in hex format
    #[arg(long, env = "ZOE_SERVER_KEY_FILE", conflicts_with = "server_key")]
    pub server_key_file: Option<PathBuf>,

    #[arg(short, long, conflicts_with = "ephemeral")]
    pub persist_path: Option<PathBuf>,

    #[arg(short, long, env = "ZOE_EPHEMERAL", conflicts_with = "persist_path")]
    pub ephemeral: bool,
}

/// Helper function to parse hex string to VerifyingKey (simplified for demo)
fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let hex = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {}", e))?;
    let key: VerifyingKey =
        postcard::from_bytes(&hex).map_err(|e| format!("Invalid key: {}", e))?;
    Ok(key)
}

/// Common setup to be done in a client cli
pub async fn main_setup() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Rustls crypto provider before any TLS operations
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("full=info")),
        )
        .init();

    Ok(())
}

pub async fn full_cli_client(args: RelayClientArgs) -> Result<Client, ClientError> {
    info!("🚀 Starting Zoe Client Connection Test");
    info!("📍 Target server: {}", args.relay_address);

    let server_addr: SocketAddr = match resolve_to_socket_addr(&args.relay_address).await {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid server address or failed to resolve: {e}");
            std::process::exit(1);
        }
    };

    // Get server public key from either direct argument or file
    let server_public_key = if let Some(file_path) = args.server_key_file {
        info!("📖 Reading server public key from: {}", file_path.display());
        let content = std::fs::read_to_string(&file_path).map_err(|e| {
            ClientError::BuildError(format!(
                "Failed to read key file {}: {e}",
                file_path.display()
            ))
        })?;
        VerifyingKey::from_pem(&content).map_err(|e| {
            ClientError::BuildError(format!(
                "Failed to parse key file {}: {e}",
                file_path.display()
            ))
        })?
    } else if let Some(key) = args.server_key {
        key
    } else {
        error!("Must specify either --server-key or --server-key-file");
        std::process::exit(1);
    };

    let mut builder = Client::builder();
    builder.server_info(server_public_key, server_addr);
    if let Some(persist_path) = args.persist_path {
        info!("💾 Using persistent storage at: {}", persist_path.display());
        error!("persistence not yet implemented");
    } else if !args.ephemeral {
        error!("💾 Must specify either --persist-path or --ephemeral");
        std::process::exit(1);
    } else {
        // ephemeral mode

        let temp_dir = TempDir::new()?;
        // Create temporary directories for storage

        info!(
            "💾 Using temporary storage at: {}",
            temp_dir.path().display()
        );
        let media_storage_path = temp_dir.path().join("blobs");
        let db_storage_path = temp_dir.path().join("db");

        info!("🔧 Building client...");

        // Build the clien
        builder.media_storage_dir_pathbuf(media_storage_path);
        builder.db_storage_dir_pathbuf(db_storage_path);
    }

    builder.build().await
}
