//! # Chat Client Example
//!
//! A simple chat client that connects to a Zoe Relay Server and provides
//! a basic chat interface with live message updates.
//!
//! ## Features
//!
//! - Real-time chat with live message updates
//! - Channel-based messaging using topics
//! - Simple CLI interface
//! - Abbreviated author IDs for readability
//! - Message history and live updates
//!
//! ## Usage
//!
//! ```bash
//! # Start the relay server first
//! cargo run --bin zoe-relay
//!
//! # In another terminal, run the chat client
//! cargo run --example chat_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY> --channel general
//! ```

use anyhow::Result;
use clap::{Arg, Command};
use std::{
    collections::VecDeque,
    io::{self, Write},
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};
use tarpc::context;
use tokio::{
    io::{AsyncBufReadExt, BufReader, stdin},
    select,
};
use tracing::{error, info, warn};
use zoe_client::{ClientError, MessagesService, RelayClient};
use zoe_wire_protocol::{
    Content, Hash, KeyPair, Kind, Message, MessageFilters, MessageFull, StreamMessage,
    SubscriptionConfig, Tag, VerifyingKey, generate_keypair,
};

/// Configuration for the chat client
struct ChatConfig {
    server_addr: SocketAddr,
    server_key: zoe_wire_protocol::TransportPublicKey,
    channel: String,
    client_keypair: KeyPair,
}

/// A chat message for display
#[derive(Debug, Clone)]
struct ChatMessage {
    author_id: String,
    content: String,
    timestamp: u64,
}

impl ChatMessage {
    fn from_stream_message(stream_msg: &StreamMessage) -> Result<Self> {
        match stream_msg {
            StreamMessage::MessageReceived {
                message: msg_full,
                stream_height: _,
            } => {
                let author_bytes = msg_full.author().encode();
                let author_id = hex::encode(&author_bytes[..4]); // First 4 bytes as hex

                let content =
                    String::from_utf8_lossy(msg_full.raw_content().expect("Expected raw content"))
                        .to_string();
                let timestamp = *msg_full.when();

                Ok(ChatMessage {
                    author_id,
                    content,
                    timestamp,
                })
            }
            StreamMessage::StreamHeightUpdate(_) => Err(anyhow::anyhow!(
                "Cannot create chat message from stream height update"
            )),
        }
    }

    fn format_for_display(&self) -> String {
        let time = format!(
            "{:02}:{:02}:{:02}",
            (self.timestamp / 3600) % 24,
            (self.timestamp / 60) % 60,
            self.timestamp % 60
        );
        format!("[{}] {}: {}", time, self.author_id, self.content)
    }
}

/// Simple chat client with live updates
struct ChatClient {
    config: ChatConfig,
    messages: VecDeque<ChatMessage>,
    max_messages: usize,
}

impl ChatClient {
    fn new(config: ChatConfig) -> Self {
        Self {
            config,
            messages: VecDeque::new(),
            max_messages: 50, // Keep last 50 messages
        }
    }

    /// Connect to the relay server and start the chat session
    async fn run(self) -> Result<()> {
        info!("🚀 Starting chat client");

        // Destructure self to avoid partial move issues
        let ChatClient {
            config,
            mut messages,
            max_messages,
        } = self;
        let channel = config.channel.clone();

        info!("📱 Channel: {}", channel);
        info!(
            "🔑 Your ID: {}",
            hex::encode(&config.client_keypair.public_key().encode()[..4])
        );

        // Connect to relay server
        let relay_client =
            RelayClient::new(config.client_keypair, config.server_key, config.server_addr).await?;

        // Connect to message service
        let (mut messages_service, mut messages_stream) =
            relay_client.connect_message_service().await?;

        // Subscribe to the channel
        Self::subscribe_to_channel(&messages_service, channel.clone()).await?;

        // Set up async stdin reader
        let mut stdin_reader = BufReader::new(stdin());
        let mut input_line = String::new();

        // Clear screen and show initial interface
        // Clear screen and move cursor to top
        print!("\x1b[2J\x1b[H");

        // Display header
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");
        println!(
            "│                          Zoe Chat - Channel: {}                          │",
            channel
        );
        println!("├─────────────────────────────────────────────────────────────────────────────┤");

        // Display messages
        if messages.is_empty() {
            println!(
                "│ No messages yet. Be the first to say something! 💬                        │"
            );
        } else {
            for message in &messages {
                let formatted = message.format_for_display();
                println!("│ {formatted:<75} │");
            }
        }

        // Display input prompt
        println!("├─────────────────────────────────────────────────────────────────────────────┤");
        println!("│ Type your message and press Enter to send. Type '/quit' to exit.           │");
        print!(
            "└─────────────────────────────────────────────────────────────────────────────┘\n> "
        );

        // Flush output
        io::stdout().flush().unwrap();

        info!("💬 Chat ready! Type messages and press Enter to send.");
        info!("💡 Type '/quit' to exit the chat.");

        loop {
            select! {
                // Handle incoming messages
                stream_result = messages_stream.recv() => {
                    match stream_result {
                        Some(stream_message) => {
                            // Handle incoming message
                            match &stream_message {
                                StreamMessage::MessageReceived { .. } => {
                                    if let Ok(chat_message) = ChatMessage::from_stream_message(&stream_message) {
                                        // Add message to buffer
                                        messages.push_back(chat_message);
                                        // Keep only the last N messages
                                        while messages.len() > max_messages {
                                            messages.pop_front();
                                        }
                                        // Update display
                                        // Clear screen and move cursor to top
                                        print!("\x1b[2J\x1b[H");

                                        // Display header
                                        println!("┌─────────────────────────────────────────────────────────────────────────────┐");
                                        println!(
                                            "│                          Zoe Chat - Channel: {}                          │",
                                            channel
                                        );
                                        println!("├─────────────────────────────────────────────────────────────────────────────┤");

                                        // Display messages
                                        if messages.is_empty() {
                                            println!(
                                                "│ No messages yet. Be the first to say something! 💬                        │"
                                            );
                                        } else {
                                            for message in &messages {
                                                let formatted = message.format_for_display();
                                                println!("│ {formatted:<75} │");
                                            }
                                        }

                                        // Display input prompt
                                        println!("├─────────────────────────────────────────────────────────────────────────────┤");
                                        println!("│ Type your message and press Enter to send. Type '/quit' to exit.           │");
                                        print!(
                                            "└─────────────────────────────────────────────────────────────────────────────┘\n> "
                                        );

                                        // Flush output
                                        io::stdout().flush().unwrap();
                                    }
                                }
                                StreamMessage::StreamHeightUpdate(_) => {
                                    // Just a height update, no action needed
                                }
                            }
                        }
                        None => {
                            warn!("📡 Message stream ended. Restarting...");
                            (messages_service, messages_stream) = relay_client.connect_message_service().await?;
                            Self::subscribe_to_channel(&messages_service, channel.clone()).await?;
                            continue;
                        }
                    }
                }
                // Handle user input
                input_result = stdin_reader.read_line(&mut input_line) => {
                    match input_result {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            let trimmed = input_line.trim().to_string();
                            input_line.clear();

                            if trimmed == "/quit" {
                                info!("👋 Goodbye!");
                                break;
                            }

                            if !trimmed.is_empty() {
                                // Send message
                                let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                                let channel_tag = Tag::Channel {
                                    id: channel.as_bytes().to_vec(),
                                    relays: vec![],
                                };
                                let message = Message::new_v0(
                                    trimmed.as_bytes().to_vec(),
                                    relay_client.public_key(),
                                    timestamp,
                                    Kind::Regular,
                                    vec![channel_tag],
                                );
                                if let Ok(message_full) = MessageFull::new(message, relay_client.keypair()) {
                                    if let Err(e) = messages_service.publish(context::current(), message_full).await {
                                        error!("❌ Failed to send message: {}", e);
                                    }
                                } else {
                                    error!("❌ Failed to create MessageFull");
                                }
                            }
                        }
                        Err(e) => {
                            error!("❌ Failed to read input: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Subscribe to messages in the specified channel
    async fn subscribe_to_channel(service: &MessagesService, channel: String) -> Result<()> {
        let channel_bytes = channel.as_bytes().to_vec();

        let subscription_config = SubscriptionConfig {
            filters: MessageFilters {
                authors: None,
                channels: Some(vec![channel_bytes]),
                events: None,
                users: None,
            },
            since: None,
            limit: Some(20), // Get last 20 messages
        };

        service.subscribe(subscription_config).await?;

        info!("📡 Subscribed to channel: {}", channel);
        Ok(())
    }

    /// Handle an incoming message from the stream
    async fn handle_incoming_message(&mut self, stream_message: StreamMessage) -> Result<()> {
        match &stream_message {
            StreamMessage::MessageReceived { .. } => {
                if let Ok(chat_message) = ChatMessage::from_stream_message(&stream_message) {
                    self.add_message(chat_message);
                    self.display_interface().await;
                }
            }
            StreamMessage::StreamHeightUpdate(_) => {
                // Just a height update, no action needed
            }
        }
        Ok(())
    }

    /// Send a chat message to the channel
    async fn send_message(
        &self,
        service: &MessagesService,
        relay_client: &RelayClient,
        channel: &str,
        content: &str,
    ) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let channel_tag = Tag::Channel {
            id: channel.as_bytes().to_vec(),
            relays: vec![],
        };

        let message = Message::new_v0(
            content.as_bytes().to_vec(),
            relay_client.public_key(),
            timestamp,
            Kind::Regular,
            vec![channel_tag],
        );

        let message_full = MessageFull::new(message, relay_client.keypair())
            .map_err(|e| ClientError::Generic(format!("Failed to create MessageFull: {e}")))?;

        if let Err(e) = service.publish(context::current(), message_full).await {
            error!("❌ Failed to send message: {}", e);
        }
        Ok(())
    }

    /// Add a message to the display buffer
    fn add_message(&mut self, message: ChatMessage) {
        self.messages.push_back(message);

        // Keep only the last N messages
        while self.messages.len() > self.max_messages {
            self.messages.pop_front();
        }
    }

    /// Display the chat interface
    async fn display_interface(&self) {
        // Clear screen and move cursor to top
        print!("\x1b[2J\x1b[H");

        // Display header
        println!("┌─────────────────────────────────────────────────────────────────────────────┐");
        println!(
            "│                          Zoe Chat - Channel: {}                          │",
            self.config.channel
        );
        println!("├─────────────────────────────────────────────────────────────────────────────┤");

        // Display messages
        if self.messages.is_empty() {
            println!(
                "│ No messages yet. Be the first to say something! 💬                        │"
            );
        } else {
            for message in &self.messages {
                let formatted = message.format_for_display();
                println!("│ {formatted:<75} │");
            }
        }

        // Display input prompt
        println!("├─────────────────────────────────────────────────────────────────────────────┤");
        println!("│ Type your message and press Enter to send. Type '/quit' to exit.           │");
        print!(
            "└─────────────────────────────────────────────────────────────────────────────┘\n> "
        );

        // Flush output
        io::stdout().flush().unwrap();
    }
}

/// Parse command line arguments
fn parse_args() -> Result<ChatConfig> {
    let matches = Command::new("Chat Client")
        .about("A simple chat client for Zoe Relay")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Relay server address")
                .default_value("127.0.0.1:4433"),
        )
        .arg(
            Arg::new("server-key")
                .short('s')
                .long("server-key")
                .value_name("HEX_KEY")
                .help("Server's ed25519 public key (32 bytes in hex)")
                .required(true),
        )
        .arg(
            Arg::new("channel")
                .short('c')
                .long("channel")
                .value_name("CHANNEL")
                .help("Chat channel name")
                .default_value("general"),
        )
        .arg(
            Arg::new("client-key")
                .long("client-key")
                .value_name("HEX_KEY")
                .help("Client's ed25519 private key (32 bytes in hex). If not provided, a random key will be generated."),
        )
        .get_matches();

    let server_addr: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid server address: {}", e))?;

    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes = hex::decode(server_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid server key hex: {}", e))?;

    // Try to decode as Ed25519 first (default), then ML-DSA-44
    let server_key = if server_key_bytes.len() == 32 {
        // Ed25519 public key (32 bytes)
        let ed25519_key = ed25519_dalek::VerifyingKey::from_bytes(
            server_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?,
        )
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;
        zoe_wire_protocol::TransportPublicKey::from_ed25519(ed25519_key)
    } else if server_key_bytes.len() == 1312 {
        // ML-DSA-44 public key (1312 bytes)
        let ml_dsa_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(
            server_key_bytes
                .as_slice()
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-44 public key length: {}", e))?,
        );
        zoe_wire_protocol::TransportPublicKey::from_ml_dsa_44(&ml_dsa_key)
    } else {
        anyhow::bail!("Server key must be either 32 bytes (Ed25519) or 1312 bytes (ML-DSA-44)");
    };

    let channel = matches.get_one::<String>("channel").unwrap().clone();

    let client_keypair = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let _client_key_bytes = hex::decode(client_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid client key hex: {}", e))?;
        // TODO: Implement proper ML-DSA key loading from bytes
        generate_keypair(&mut rand::thread_rng())
    } else {
        generate_keypair(&mut rand::thread_rng())
    };

    Ok(ChatConfig {
        server_addr,
        server_key,
        channel,
        client_keypair,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse command line arguments
    let config = parse_args()?;

    // Create and run chat client
    let chat_client = ChatClient::new(config);

    match chat_client.run().await {
        Ok(()) => {
            info!("Chat session ended successfully");
        }
        Err(e) => {
            error!("Chat session failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
