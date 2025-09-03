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

use clap::{Parser, command};
use tracing::{error, info};
use zoe_client::cli::{RelayClientArgs, full_cli_client, main_setup};

#[cfg(debug_assertions)]
const IS_DEBUG: bool = true;
#[cfg(not(debug_assertions))]
const IS_DEBUG: bool = false;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct FullClientArgs {
    #[command(flatten)]
    args: RelayClientArgs,
}

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !IS_DEBUG {
        error!("This is a debug only app for now. Release mode isn't supported yet.");
        std::process::exit(1);
    }

    main_setup().await?;

    let args = FullClientArgs::parse().args;
    let server_addr = args.relay_address.clone();
    let client_result = full_cli_client(args).await;

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
