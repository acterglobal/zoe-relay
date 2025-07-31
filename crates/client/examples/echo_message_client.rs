//! # Echo Message Client Example
//!
//! Demonstrates connecting to a Zoe Relay Server and using the Messages service
//! to subscribe to messages, publish a message, and verify it's received via the stream.
//!
//! ## Usage
//!
//! ```bash
//! # Start the relay server first
//! cargo run --bin zoe-relay
//!
//! # In another terminal, run the client
//! cargo run --example echo_message_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY>
//! ```

use anyhow::Result;
use clap::{Arg, Command};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::SocketAddr;
use zoe_client::Client;

// Message client logic is now handled by the Client struct in the library

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse command line arguments
    let matches = Command::new("echo_message_client")
        .about("Echo message client for testing Zoe Relay Messages service")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Server address to connect to")
                .default_value("127.0.0.1:4433"),
        )
        .arg(
            Arg::new("server-key")
                .short('k')
                .long("server-key")
                .value_name("HEX_PUBLIC_KEY")
                .help("Server's ed25519 public key (hex encoded)")
                .required(true),
        )
        .arg(
            Arg::new("client-key")
                .short('c')
                .long("client-key")
                .value_name("HEX_PRIVATE_KEY")
                .help("Client's ed25519 private key (hex encoded, optional - generates random if not provided)"),
        )
        .get_matches();

    // Parse server address
    let address: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

    // Parse server public key
    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes = hex::decode(server_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid server key hex: {}", e))?;

    if server_key_bytes.len() != 32 {
        anyhow::bail!("Server key must be 32 bytes (64 hex characters)");
    }

    let server_public_key = VerifyingKey::from_bytes(&server_key_bytes.try_into().unwrap())
        .map_err(|e| anyhow::anyhow!("Invalid ed25519 public key: {}", e))?;

    // Create client (with optional private key)
    let client = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let client_key_bytes = hex::decode(client_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid client key hex: {}", e))?;

        if client_key_bytes.len() != 32 {
            anyhow::bail!("Client key must be 32 bytes (64 hex characters)");
        }

        let client_key = SigningKey::from_bytes(&client_key_bytes.try_into().unwrap());
        Client::from_key(client_key)
    } else {
        Client::new()
    };

    // Run the echo test
    client
        .run_echo_test(address, server_public_key)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))
}
