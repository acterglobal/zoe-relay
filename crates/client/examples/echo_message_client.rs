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
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tarpc::context;
use tokio::time::timeout;
use tracing::{error, info, warn};
use zoe_client::{ClientError, MessagesService, MessagesStream, RelayClient};
use zoe_wire_protocol::{
    KeyPair, Kind, Message, MessageFilters, MessageFull, StreamMessage, SubscriptionConfig,
    VerifyingKey, generate_keypair,
};

/// Run the complete message echo test
async fn run_echo_test(
    client_public_key: VerifyingKey,
    client_keypair: &KeyPair,
    messages_service: MessagesService,
    mut messages_stream: MessagesStream,
) -> Result<()> {
    // Step 1: Subscribe to messages from our own key
    let subscription_config = SubscriptionConfig {
        filters: MessageFilters {
            authors: Some(vec![client_public_key.encode().to_vec()]),
            channels: None,
            events: None,
            users: None,
        },
        since: None,
        limit: None,
    };

    messages_service.subscribe(subscription_config).await?;
    info!("📬 Sent subscription request for our own messages");

    // Step 2: Create and publish an echo message
    let echo_content = "Hello from message client! 🚀".as_bytes().to_vec();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ClientError::Generic(e.to_string()))?
        .as_secs();

    let message = Message::new_v0(
        echo_content.clone(),
        client_public_key.clone(),
        timestamp,
        Kind::Regular,
        vec![], // no tags
    );

    let message_full = MessageFull::new(message, client_keypair)
        .map_err(|e| ClientError::Generic(format!("Failed to create MessageFull: {e}")))?;
    info!(
        "📝 Created message with ID: {}",
        hex::encode(message_full.id().as_bytes())
    );

    let message_id = *message_full.id().as_bytes();

    if let Err(e) = messages_service
        .publish(context::current(), message_full)
        .await
    {
        error!("❌ Failed to send message: {}", e);
    }
    info!("📤 Published echo message to relay server");

    // Give a small delay to ensure the message is fully processed by the server
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Step 3: Wait for the message to come back via the stream
    info!("👂 Listening for messages...");

    let receive_timeout = Duration::from_secs(1);
    let mut message_received = false;
    let max_attempts = 15;
    let mut count = 0;

    loop {
        if count >= max_attempts || message_received {
            break;
        }
        count += 1;

        match timeout(receive_timeout, messages_stream.recv()).await {
            Ok(Some(stream_message)) => {
                match stream_message {
                    StreamMessage::MessageReceived {
                        message,
                        stream_height,
                    } => {
                        info!("🎉 Received message via stream!");
                        info!("   Stream height: {}", stream_height);
                        info!("   Message ID: {}", hex::encode(message.id().as_bytes()));
                        info!("   Author: {}", hex::encode(message.author().encode()));
                        info!(
                            "   Content: {:?}",
                            String::from_utf8_lossy(
                                message.raw_content().expect("Expected raw content")
                            )
                        );

                        // Verify it's our message
                        if message.id() == &message_id {
                            info!("✅ SUCCESS: Received our own echo message!");
                            info!(
                                "   Original content: {:?}",
                                String::from_utf8_lossy(&echo_content)
                            );
                            info!(
                                "   Received content: {:?}",
                                String::from_utf8_lossy(
                                    message.raw_content().expect("Expected raw content")
                                )
                            );
                            message_received = true;
                        } else {
                            warn!("⚠️  Received different message than expected");
                        }
                    }
                    StreamMessage::StreamHeightUpdate(height) => {
                        info!("📊 Stream height update: {}", height);
                        // Continue listening
                    }
                }
            }
            Ok(None) => {
                warn!("🔚 Stream ended without receiving message");
            }
            Err(_) => {
                warn!(
                    "⏰ Timeout waiting for message ({}s) - attempt {}/{}",
                    receive_timeout.as_secs(),
                    count,
                    max_attempts
                );
            }
        }
    }

    // Give the server a moment to process any remaining messages before closing
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Clean shutdowns
    info!("🔌 Disconnected from server");

    if message_received {
        info!("🎊 Message client test completed successfully!");
        Ok(())
    } else {
        Err(anyhow::anyhow!("Message was not received via stream"))
    }
}

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

    // Parse server public key (ML-DSA-44 for TLS)
    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes = hex::decode(server_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid server key hex: {}", e))?;

    // Try to decode as Ed25519 first (default), then ML-DSA-44
    let server_public_key = if server_key_bytes.len() == 32 {
        // Ed25519 public key (32 bytes)
        let ed25519_key = ed25519_dalek::VerifyingKey::from_bytes(
            server_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?,
        )
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;
        zoe_wire_protocol::TransportPublicKey::from_ed25519(ed25519_key)
    } else {
        // ML-DSA-44 public key (1312 bytes)
        let ml_dsa_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(
            server_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid ML-DSA-44 public key length"))?,
        );
        zoe_wire_protocol::TransportPublicKey::from_ml_dsa_44(&ml_dsa_key)
    };

    // Create client (with optional private key)
    let client = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let _client_key_bytes = hex::decode(client_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid client key hex: {}", e))?;

        let client_keypair = generate_keypair(&mut rand::thread_rng()); // TODO: Implement proper key loading
        RelayClient::new(client_keypair, server_public_key, address).await?
    } else {
        RelayClient::new_with_random_key(server_public_key, address).await?
    };

    // Run the echo test
    let (messages_service, messages_stream) = client.connect_message_service().await?;
    let client_public_key = client.public_key();
    let client_keypair = client.keypair();
    run_echo_test(
        client_public_key,
        client_keypair,
        messages_service,
        messages_stream,
    )
    .await
}
