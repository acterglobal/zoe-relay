// use tracing::{error, info};
// use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use tracing::{error, info, warn};
use tracing_subscriber::prelude::*;
use zoeyr_relay_service::storage::{MessageFilters, RedisStorage};
use zoeyr_wire_protocol::{Kind, Message, MessageFull, Tag};

#[derive(Parser)]
#[command(name = "relay-test")]
#[command(about = "Test tool for Zoeyr relay service storage")]
struct Cli {
    #[arg(long, default_value = "redis://127.0.0.1:6379")]
    redis_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Listen for messages matching the given filters
    Listen {
        /// Author IDs to filter by (hex strings)
        #[arg(long, value_delimiter = ',')]
        authors: Option<Vec<String>>,

        /// Channel IDs to filter by (hex strings)
        #[arg(long, value_delimiter = ',')]
        channels: Option<Vec<String>>,

        /// Event IDs to filter by (hex strings)
        #[arg(long, value_delimiter = ',')]
        events: Option<Vec<String>>,

        /// Event index to filter by
        #[arg(long, value_delimiter = ',')]
        event_index: Option<Vec<u8>>,

        /// User IDs to filter by (hex strings)
        #[arg(long, value_delimiter = ',')]
        users: Option<Vec<String>>,

        /// Start listening from this message ID
        #[arg(long)]
        since: Option<String>,

        /// Maximum number of messages to receive per batch
        #[arg(long, default_value = "10")]
        limit: usize,
    },

    /// Send test messages to Redis
    Send {
        /// Number of test messages to send
        #[arg(long, default_value = "1")]
        count: usize,

        /// Author ID for the test messages (hex string)
        #[arg(long, default_value = "test_author_123")]
        author: String,

        /// Include event tag in test messages
        #[arg(long)]
        with_event: bool,

        /// Include user tag in test messages
        #[arg(long)]
        with_user: bool,

        /// Include channel tag in test messages
        #[arg(long)]
        with_channel: bool,

        /// Make messages ephemeral with given timeout (seconds)
        #[arg(long)]
        ephemeral: Option<u64>,
    },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestContent {
    text: String,
    timestamp: u64,
    value: u32,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    // Create Redis storage
    let config = zoeyr_relay_service::config::RelayConfig {
        redis: zoeyr_relay_service::config::RedisConfig {
            url: cli.redis_url,
            pool_size: 10,
        },
        ..Default::default()
    };

    let storage = RedisStorage::new(config).await?;
    info!("Connected to Redis");

    match cli.command {
        Commands::Listen {
            authors,
            channels,
            events,
            event_index,
            users,
            since,
            limit,
        } => {
            let events = event_index.map(|e| {
                e.into_iter()
                    .map(|s| {
                        let mut bytes = [0u8; 32];
                        bytes[0] = s;
                        bytes.to_vec()
                    })
                    .collect()
            });
            let filters = MessageFilters {
                authors: authors.map(|a| {
                    a.into_iter()
                        .map(|s| hex::decode(s).unwrap_or_default())
                        .collect()
                }),
                channels: channels.map(|c| {
                    c.into_iter()
                        .map(|s| hex::decode(s).unwrap_or_default())
                        .collect()
                }),
                events: events,
                users: users.map(|u| {
                    u.into_iter()
                        .map(|s| hex::decode(s).unwrap_or_default())
                        .collect()
                }),
            };

            info!(
                "Starting to listen for messages with filters: {:?}",
                filters
            );

            listen_for_messages::<TestContent>(&storage, &filters, since, limit).await?;
        }

        Commands::Send {
            count,
            author: _author,
            with_event,
            with_user,
            with_channel,
            ephemeral,
        } => {
            info!("Sending {} test messages", count);

            // Create a signing key for testing
            let mut rng = rand::rngs::OsRng;
            let mut secret_bytes = [0u8; 32];
            use rand::RngCore;
            rng.fill_bytes(&mut secret_bytes);
            let signing_key = SigningKey::from_bytes(&secret_bytes);
            let verifying_key = signing_key.verifying_key();

            for i in 0..count {
                let content = TestContent {
                    text: format!("Test message {}", i + 1),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    value: i as u32,
                };

                let mut tags = Vec::new();

                if with_event {
                    // Create a fake event ID (32 bytes)
                    let mut event_id_bytes = [0u8; 32];
                    event_id_bytes[0] = i as u8;
                    let event_id = blake3::Hash::from(event_id_bytes);
                    tags.push(Tag::Event {
                        id: event_id,
                        relays: Vec::new(),
                    });
                }

                if with_user {
                    tags.push(Tag::User {
                        id: format!("user_{}", i).into_bytes(),
                        relays: Vec::new(),
                    });
                }

                if with_channel {
                    tags.push(Tag::Channel {
                        id: format!("channel_{}", i).into_bytes(),
                        relays: Vec::new(),
                    });
                }

                let message = Message::new_v0(
                    content,
                    verifying_key.clone(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    ephemeral
                        .map(|t| Kind::Emphemeral(Some(t as u8)))
                        .unwrap_or(Kind::Regular),
                    tags,
                );

                let message_full = MessageFull::new(message, &signing_key)?;

                match storage.store_message(&message_full).await {
                    Ok(true) => {
                        info!("Stored new message {}: {}", i + 1, message_full.id);
                    }
                    Ok(false) => {
                        warn!("Message {} already existed: {}", i + 1, message_full.id);
                    }
                    Err(e) => {
                        error!("Failed to store message {}: {}", i + 1, e);
                    }
                }
            }

            info!("Finished sending test messages");
        }
    }

    Ok(())
}

async fn listen_for_messages<T>(
    storage: &RedisStorage,
    filters: &MessageFilters,
    since: Option<String>,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + std::fmt::Debug,
{
    let mut stream = Box::pin(
        storage
            .listen_for_messages::<T>(filters, since, Some(limit))
            .await?,
    );

    while let Some(msg) = stream.as_mut().next().await {
        match msg {
            Ok((Some(msg_id), height)) => {
                let hx_id = hex::encode(&msg_id);
                info!("Received message: {} at height: {}", hx_id, height);

                // Try to fetch the full message
                match storage.get_message::<T>(&msg_id).await {
                    Ok(Some(message)) => {
                        println!("Message content: {:?}", message.content());
                        println!("Stream position: {}", height);
                    }
                    Ok(None) => {
                        println!("404: Message {} not found ", hx_id);
                        continue;
                    }
                    Err(e) => {
                        error!("Error fetching message {} content: {}", hx_id, e);
                    }
                }
            }

            Ok((None, height)) => {
                info!(
                    "No message found at height: {}, switching to blocking mode",
                    height
                );
            }
            Err(e) => {
                error!("Error receiving message: {}", e);
            }
        }
    }

    warn!("Stream ended");
    Ok(())
}
