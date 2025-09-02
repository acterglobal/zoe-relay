//! # Zoe Client Connection Test Example
//!
//! This example demonstrates how to use the Zoe client builder to connect to a relay server
//! and verify that the server is responding properly.
//!
//! ## Usage
//!
//! Basic usage with random keys (for testing):
//! ```bash
//! cargo run --example full -- --relay-address "127.0.0.1:8080"
//! ```
//!
//! With specific server key:
//! ```bash
//! cargo run --example full -- --relay-address "127.0.0.1:8080" --server-key "abc123..."
//! ```
//!
//! With both server and client keys:
//! ```bash
//! cargo run --example full -- --relay-address "127.0.0.1:8080" --server-key "abc123..." --client-key "def456..."
//! ```
//!
//! ## What This Example Tests
//!
//! When the client is successfully built, it means:
//! - QUIC connection to the server was established
//! - Protocol version negotiation succeeded
//! - ML-DSA challenge-response handshake completed
//! - Blob service is connected and responding
//! - Storage (SQLite) is initialized and accessible
//!
//! If any of these steps fail, the example will exit with an error message
//! explaining what might be wrong.

use clap::{Parser, arg, command};
use rand::rngs::OsRng;
use std::{net::SocketAddr, path::PathBuf};
use tempfile::TempDir;
use tracing::{error, info};
use zoe_client::{Client, client::ClientSecret};
use zoe_wire_protocol::{KeyPair, VerifyingKey};

#[cfg(debug_assertions)]
const IS_DEBUG: bool = true;
#[cfg(not(debug_assertions))]
const IS_DEBUG: bool = false;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct FullClientArgs {
    /// Relay server address (e.g., "127.0.0.1:8080")
    #[arg(short, long, default_value = "127.0.0.1:13908")]
    relay_address: String,

    /// Server public key in hex format (optional - will generate random for demo)
    #[arg(short, long, value_parser = parse_verifying_key)]
    server_key: VerifyingKey,

    #[arg(short, long, conflicts_with = "ephemeral")]
    persist_path: Option<PathBuf>,

    #[arg(short, long, conflicts_with = "persist_path")]
    ephemeral: bool,
}

/// Helper function to parse hex string to VerifyingKey (simplified for demo)
fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let hex = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {}", e))?;
    let key: VerifyingKey =
        postcard::from_bytes(&hex).map_err(|e| format!("Invalid key: {}", e))?;
    Ok(key)
}

/// Generate a random encryption key for storage
fn generate_encryption_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut key);
    key
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !IS_DEBUG {
        error!("This is a debug only app for now. Release mode isn't supported yet.");
        std::process::exit(1);
    }

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

    let args = FullClientArgs::parse();

    info!("🚀 Starting Zoe Client Connection Test");
    info!("📍 Target server: {}", args.relay_address);

    // Parse server address
    let server_addr: SocketAddr = args
        .relay_address
        .parse()
        .map_err(|e| format!("Invalid server address '{}': {}", args.relay_address, e))?;

    let server_public_key = args.server_key;

    let mut builder = Client::builder();
    if let Some(persist_path) = args.persist_path {
        info!("💾 Using persistent storage at: {}", persist_path.display());
        error!("persistence not yet implemented");
    } else if !args.ephemeral {
        error!("💾 Must specify either --persist-path or --ephemeral");
        std::process::exit(1);
    } else {
        // ephemeral mode

        let client_keypair = KeyPair::generate(&mut OsRng);
        let temp_dir = TempDir::new()?;
        // Create temporary directories for storage

        info!(
            "💾 Using temporary storage at: {}",
            temp_dir.path().display()
        );
        let media_storage_path = temp_dir.path().join("media");
        let db_storage_path = temp_dir.path().join("client.db");
        // Create client secret
        let client_secret = ClientSecret::new(client_keypair, server_public_key, server_addr);

        // Generate encryption key for storage
        let encryption_key = generate_encryption_key();

        info!("🔧 Building client...");

        // Build the client
        builder.client_secret(client_secret);
        builder.media_storage_path(media_storage_path.to_string_lossy().to_string());
        builder.storage_path(db_storage_path.to_string_lossy().to_string());
        builder.encryption_key(encryption_key);
    }

    let client_result = builder.build().await;

    match client_result {
        Ok(client) => {
            info!("✅ Successfully connected to server!");
            info!("🎉 Server is responding and all handshakes completed");

            // The fact that we got here means:
            // 1. QUIC connection established
            // 2. Protocol version negotiated
            // 3. ML-DSA challenge-response handshake completed
            // 4. Blob service connected
            // 5. Storage initialized

            info!("📊 Connection details:");
            info!("  - Protocol: QUIC with ML-DSA authentication");
            info!("  - Storage: SQLite with encryption");
            info!("  - Blob service: Connected");

            info!("✅ All tests passed! Client is ready for use.");
            client.close().await;
        }
        Err(e) => {
            error!("❌ Failed to connect to server: {}", e);
            error!("🔍 This could mean:");
            error!("  - Server is not running at {}", server_addr);
            error!("  - Wrong server public key provided");
            error!("  - Network connectivity issues");
            error!("  - Server doesn't support our protocol version");

            std::process::exit(1);
        }
    }

    info!("🏁 Connection test completed successfully!");
    Ok(())
}
