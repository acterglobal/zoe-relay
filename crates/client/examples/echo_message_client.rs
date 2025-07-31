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
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::timeout;
use tracing::{info, warn};
use zoe_client::{ClientError, MessagesService, MessagesStream, RelayClient};
use zoe_wire_protocol::{
    Kind, Message, MessageFilters, MessageFull, MessagesServiceRequest, StreamMessage,
    SubscriptionConfig,
};

/// Run the complete message echo test
async fn run_echo_test(
    client_key: &SigningKey,
    messages_service: MessagesService,
    mut messages_stream: MessagesStream,
) -> Result<()> {
    // Step 1: Subscribe to messages from our own key
    let subscription_config = SubscriptionConfig {
        filters: MessageFilters {
            authors: Some(vec![client_key.verifying_key().to_bytes().to_vec()]),
            channels: None,
            events: None,
            users: None,
        },
        since: None,
        limit: None,
    };

    let subscribe_request = MessagesServiceRequest::Subscribe(subscription_config);
    messages_service.send_raw(subscribe_request).await?;
    info!("📬 Sent subscription request for our own messages");

    // Step 2: Create and publish an echo message
    let echo_content = "Hello from message client! 🚀".as_bytes().to_vec();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ClientError::Generic(e.to_string()))?
        .as_secs();

    let message = Message::new_v0(
        echo_content.clone(),
        client_key.verifying_key(),
        timestamp,
        Kind::Regular,
        vec![], // no tags
    );

    let message_full = MessageFull::new(message, &client_key)
        .map_err(|e| ClientError::Generic(format!("Failed to create MessageFull: {}", e)))?;
    info!(
        "📝 Created message with ID: {}",
        hex::encode(message_full.id.as_bytes())
    );

    let message_id = message_full.id.as_bytes().clone();

    messages_service.publish(message_full).await?;
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
                        info!("   Message ID: {}", hex::encode(message.id.as_bytes()));
                        info!("   Author: {}", hex::encode(message.author().to_bytes()));
                        info!(
                            "   Content: {:?}",
                            String::from_utf8_lossy(message.content())
                        );

                        // Verify it's our message
                        if message.id.as_bytes() == &message_id {
                            info!("✅ SUCCESS: Received our own echo message!");
                            info!(
                                "   Original content: {:?}",
                                String::from_utf8_lossy(&echo_content)
                            );
                            info!(
                                "   Received content: {:?}",
                                String::from_utf8_lossy(message.content())
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
        RelayClient::new(client_key, server_public_key, address).await?
    } else {
        RelayClient::new_with_random_key(server_public_key, address).await?
    };

    // Run the echo test
    let (messages_service, messages_stream) = client.connect_message_service().await?;
    let client_key = client.signing_key();
    run_echo_test(&client_key, messages_service, messages_stream).await
}
