use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use std::sync::Arc;
use tracing::{error, info, warn};

use zoeyr_relay_service::{storage::RedisStorage, config::RelayConfig, storage::MessageFilters};
use zoeyr_wire_protocol::{
    MessageFull, generate_ed25519_keypair, load_ed25519_key_from_hex
};

#[derive(Parser)]
#[command(name = "relay-listen-client")]
#[command(about = "Zoeyr relay client that listens for messages from the server")]
struct Cli {
    /// Redis URL for message storage
    #[arg(short, long, default_value = "redis://127.0.0.1:6379")]
    redis_url: String,
    
    /// Client private key (hex) - if not provided, generates new key
    #[arg(short, long)]
    private_key: Option<String>,
    
    /// Filter by specific authors (comma-separated hex public keys)
    #[arg(short, long)]
    authors: Option<String>,
    
    /// Filter by specific users (comma-separated hex IDs)
    #[arg(short, long)]
    users: Option<String>,
    
    /// Filter by specific channels (comma-separated hex IDs)
    #[arg(short, long)]
    channels: Option<String>,
    
    /// Start listening from this message ID (hex)
    #[arg(short, long)]
    since: Option<String>,
    
    /// Maximum number of messages to retrieve per batch
    #[arg(short = 'l', long, default_value = "10")]
    limit: usize,
    
    /// Listen for new messages indefinitely
    #[arg(long)]
    follow: bool,
}

pub struct RelayListenClient {
    storage: Arc<RedisStorage>,
    client_key: SigningKey,
}

impl RelayListenClient {
    pub async fn new(redis_url: String, client_key: SigningKey) -> Result<Self> {
        let config = RelayConfig {
            redis: zoeyr_relay_service::config::RedisConfig {
                url: redis_url,
                pool_size: 10,
            },
            ..Default::default()
        };
        
        let storage = Arc::new(RedisStorage::new(config).await?);
        
        Ok(Self {
            storage,
            client_key,
        })
    }
    
    pub async fn listen_for_messages(
        &self,
        filters: MessageFilters,
        since: Option<String>,
        limit: usize,
        follow: bool,
    ) -> Result<()> {
        info!("🎧 Starting to listen for messages...");
        info!("📋 Client public key: {}", hex::encode(self.client_key.verifying_key().to_bytes()));
        
        if filters.is_empty() {
            info!("📡 Listening for ALL messages (no filters applied)");
        } else {
            info!("🔍 Listening with filters applied:");
            if let Some(authors) = &filters.authors {
                info!("   👥 Authors: {} keys", authors.len());
            }
            if let Some(users) = &filters.users {
                info!("   👤 Users: {} IDs", users.len());
            }
            if let Some(channels) = &filters.channels {
                info!("   📢 Channels: {} IDs", channels.len());
            }
        }
        
        if let Some(since_id) = &since {
            info!("⏰ Starting from message ID: {}", since_id);
        }
        
        let mut stream = Box::pin(
            self.storage
                .listen_for_messages::<String>(&filters, since, Some(limit))
                .await?
        );
        
        let mut message_count = 0;
        
        while let Some(msg) = stream.as_mut().next().await {
            match msg {
                Ok((Some(msg_id), height)) => {
                    message_count += 1;
                    let hx_id = hex::encode(&msg_id);
                    info!("📨 Received message: {} at height: {}", hx_id, &height);
                    
                    // Try to fetch the full message
                    match self.storage.get_message::<String>(&msg_id).await {
                        Ok(Some(message)) => {
                            self.display_message(&message, &hx_id, &height).await?;
                        }
                        Ok(None) => {
                            warn!("⚠️ Message {} not found in storage", hx_id);
                        }
                        Err(e) => {
                            error!("❌ Error fetching message {} content: {}", hx_id, e);
                        }
                    }
                }
                Ok((None, height)) => {
                    if message_count == 0 {
                        info!("📭 No messages found at height: {}", &height);
                    }
                    
                    if !follow {
                        info!("🏁 Reached end of available messages");
                        break;
                    } else {
                        info!("⏳ Waiting for new messages... (height: {})", &height);
                    }
                }
                Err(e) => {
                    error!("❌ Error receiving message: {}", e);
                    if !follow {
                        break;
                    }
                }
            }
        }
        
        if follow {
            warn!("🔚 Stream ended unexpectedly");
        } else {
            info!("✅ Finished listening - received {} messages", message_count);
        }
        
        Ok(())
    }
    
    async fn display_message(
        &self,
        message: &MessageFull<String>,
        message_id: &str,
        height: &str,
    ) -> Result<()> {
        println!("┌─────────────────────────────────────────────────────");
        println!("│ 📨 Message ID: {}", message_id);
        println!("│ 👤 Author: {}", hex::encode(message.author().to_bytes()));
        println!("│ ⏰ Timestamp: {}", message.when());
        println!("│ 📍 Stream Position: {}", height);
        println!("│ 🏷️  Kind: {:?}", message.kind());
        
        if !message.tags().is_empty() {
            println!("│ 🔖 Tags: {} items", message.tags().len());
            for (i, tag) in message.tags().iter().enumerate() {
                println!("│   {}: {:?}", i + 1, tag);
            }
        }
        
        println!("│");
        println!("│ 💬 Content: {}", message.content());
        println!("└─────────────────────────────────────────────────────");
        println!();
        
        Ok(())
    }
}

/// Parse hex-encoded filter values
fn parse_hex_list(input: &str) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    for hex_str in input.split(',') {
        let hex_str = hex_str.trim();
        if !hex_str.is_empty() {
            let bytes = hex::decode(hex_str)
                .with_context(|| format!("Invalid hex format: {}", hex_str))?;
            result.push(bytes);
        }
    }
    Ok(result)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(
            if std::env::var("RUST_LOG").is_ok() {
                "info".parse().unwrap()
            } else {
                "relay_listen_client=info".parse().unwrap()
            }
        ))
        .init();
    
    let cli = Cli::parse();
    
    // Load or generate client key
    let client_key = match &cli.private_key {
        Some(hex_key) => {
            info!("🔑 Loading private key from hex...");
            load_ed25519_key_from_hex(hex_key)
                .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?
        }
        None => {
            info!("🔑 Generating new client key...");
            let key = generate_ed25519_keypair();
            info!("🔑 Client public key: {}", hex::encode(key.verifying_key().to_bytes()));
            key
        }
    };
    
    // Create message filters
    let mut filters = MessageFilters::default();
    
    if let Some(authors_str) = &cli.authors {
        let authors = parse_hex_list(authors_str)?;
        filters.authors = Some(authors);
    }
    
    if let Some(users_str) = &cli.users {
        let users = parse_hex_list(users_str)?;
        filters.users = Some(users);
    }
    
    if let Some(channels_str) = &cli.channels {
        let channels = parse_hex_list(channels_str)?;
        filters.channels = Some(channels);
    }
    
    // If no filters specified, we need to handle this case properly
    // The Redis storage requires at least one filter, so let's listen for all authors
    if filters.is_empty() {
        info!("📡 No filters specified - listening for all messages");
        // We'll need to get all authors from Redis or listen differently
        // For now, we'll just note this limitation
        warn!("⚠️ At least one filter is required. Consider using --authors with server public key");
        return Err(anyhow::anyhow!("At least one filter (authors, users, or channels) is required"));
    }
    
    // Create and run the listener client
    let client = RelayListenClient::new(cli.redis_url, client_key).await?;
    
    if cli.follow {
        info!("🔄 Following mode enabled - will listen indefinitely");
    } else {
        info!("📋 Batch mode - will retrieve existing messages and exit");
    }
    
    client.listen_for_messages(filters, cli.since, cli.limit, cli.follow).await?;
    
    Ok(())
} 