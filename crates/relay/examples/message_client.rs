//! # Message Client Example
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
//! cargo run --example message_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY>
//! ```

use anyhow::Result;
use clap::{Arg, Command};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::{SinkExt, StreamExt};
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
use rustls::ClientConfig as RustlsClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tarpc::serde_transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use tokio_util::codec::LengthDelimitedCodec;
use tracing::{error, info, warn};
use zoe_relay::services::rpc::PostcardFormat;
use zoe_wire_protocol::{
    generate_deterministic_cert_from_ed25519, AcceptSpecificServerCertVerifier, Kind, Message,
    MessageFilters, MessageFull, MessagesServiceRequest, StreamMessage, SubscriptionConfig,
};

/// Message client that connects to the relay server and tests message streaming
struct MessageClient {
    client_key: SigningKey,
}

impl MessageClient {
    fn new() -> Self {
        Self {
            client_key: SigningKey::generate(&mut rand::thread_rng()),
        }
    }

    fn from_key(key: SigningKey) -> Self {
        Self { client_key: key }
    }

    /// Connect to relay server and test message streaming
    async fn run(&self, server_addr: SocketAddr, server_public_key: VerifyingKey) -> Result<()> {
        info!("🚀 Starting message client");
        info!(
            "🔑 Client public key: {}",
            hex::encode(self.client_key.verifying_key().to_bytes())
        );
        info!("🌐 Connecting to server: {}", server_addr);
        info!(
            "🔐 Server public key: {}",
            hex::encode(server_public_key.to_bytes())
        );

        // Create client endpoint
        let client_endpoint = self.create_client_endpoint(&server_public_key)?;

        // Connect to server
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        info!("✅ Connected to relay server");

        // Open bidirectional stream
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send service ID (10 for Messages service)
        const MESSAGES_SERVICE_ID: u8 = 10;
        send.write_u8(MESSAGES_SERVICE_ID).await?;
        info!("📡 Selected Messages service (ID: {})", MESSAGES_SERVICE_ID);

        let service_ok = recv.read_u8().await?;
        assert_eq!(service_ok, 1, "Service ID not acknowledged");

        // Set up postcard transport for message communication
        let streams = zoe_relay::StreamPair { recv, send };
        let framed = tokio_util::codec::Framed::new(streams, LengthDelimitedCodec::new());
        let transport = serde_transport::new(framed, PostcardFormat::default());
        let (mut sink, mut stream) = transport.split();

        info!("🔄 Transport established, starting message flow");

        // Step 1: Subscribe to messages from our own key
        let subscription_config = SubscriptionConfig {
            filters: MessageFilters {
                authors: Some(vec![self.client_key.verifying_key().to_bytes().to_vec()]),
                channels: None,
                events: None,
                users: None,
            },
            since: None,
            limit: None,
        };

        let subscribe_request = MessagesServiceRequest::Subscribe(subscription_config);
        sink.send(subscribe_request).await?;
        sink.flush().await?;
        info!("📬 Sent subscription request for our own messages");

        // Step 2: Create and publish an echo message
        let echo_content = "Hello from message client! 🚀".as_bytes().to_vec();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let message = Message::new_v0(
            echo_content.clone(),
            self.client_key.verifying_key(),
            timestamp,
            Kind::Regular,
            vec![], // no tags
        );

        let message_full = MessageFull::new(message, &self.client_key)
            .map_err(|e| anyhow::anyhow!("Failed to create MessageFull: {}", e))?;
        info!(
            "📝 Created message withnm, ID: {}",
            hex::encode(message_full.id.as_bytes())
        );

        let publish_request = MessagesServiceRequest::Publish(message_full.clone());
        sink.send(publish_request).await?;
        sink.flush().await?;
        info!("📤 Published echo message to relay server");

        // Give a small delay to ensure the message is fully processed by the server
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 3: Wait for the message to come back via the stream
        info!("👂 Listening for messages...");

        let receive_timeout = Duration::from_secs(2);
        let mut message_received = false;
        let max_attempts = 15;
        let mut count = 0;

        loop {
            if count >= max_attempts || message_received {
                break;
            }
            count += 1;

            match timeout(receive_timeout, stream.next()).await {
                Ok(Some(Ok(stream_message))) => {
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
                            if message.id.as_bytes() == message_full.id.as_bytes() {
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
                Ok(Some(Err(e))) => {
                    error!("❌ Error receiving stream message: {}", e);
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

        // Clean shutdown
        connection.close(0u32.into(), b"test complete");
        info!("🔌 Disconnected from server");

        if message_received {
            info!("🎊 Message client test completed successfully!");
            Ok(())
        } else {
            anyhow::bail!("❌ Message was not received via stream");
        }
    }

    fn create_client_endpoint(&self, server_public_key: &VerifyingKey) -> Result<Endpoint> {
        // Generate client certificate for mutual TLS
        let (client_certs, client_key) =
            generate_deterministic_cert_from_ed25519(&self.client_key, "client")?;

        // Create custom certificate verifier that accepts our server
        let verifier = AcceptSpecificServerCertVerifier::new(*server_public_key);

        // Create client config with client certificate for mutual TLS
        let crypto = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(client_certs, client_key)?;

        let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(endpoint)
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
    let matches = Command::new("message_client")
        .about("Message client for testing Zoe Relay Messages service")
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
        MessageClient::from_key(client_key)
    } else {
        MessageClient::new()
    };

    // Run the client
    client.run(address, server_public_key).await
}
