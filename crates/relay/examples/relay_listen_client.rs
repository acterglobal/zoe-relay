use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};

use zoeyr_relay::RelayClientBuilder;
use zoeyr_wire_protocol::{MessageFilters, StreamConfig};

#[derive(Parser)]
#[command(name = "relay-listen-client")]
#[command(about = "Zoeyr relay client that listens for messages via QUIC+tarpc")]
struct Cli {
    /// Server address to connect to
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    server: String,

    /// Expected server ed25519 public key (hex format)
    #[arg(short = 'S', long)]
    server_public_key: String,

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
    #[arg(short = 'f', long)]
    since: Option<String>,

    /// Maximum number of messages to retrieve per batch
    #[arg(short = 'l', long, default_value = "10")]
    limit: usize,

    /// Test server statistics instead of listening
    #[arg(long)]
    stats: bool,
}

async fn get_stats(client: &zoeyr_relay::QuicTarpcClient) -> Result<()> {
    info!("📊 Requesting server statistics via QUIC+tarpc");

    // Create tarpc client and send request
    let relay_service = client.relay_service().await?;

    match relay_service.get_stats(tarpc::context::current()).await? {
        Ok(stats) => {
            println!("📊 Server Statistics:");
            println!("   Total Messages: {}", stats.total_messages);
            println!("   Active Streams: {}", stats.active_streams);
            println!("   Storage Size: {} bytes", stats.storage_size_bytes);
            println!("   Connected Clients: {}", stats.connected_clients);
            Ok(())
        }
        Err(error) => {
            error!("❌ Server error: {:?}", error);
            Err(anyhow::anyhow!("Server error: {:?}", error))
        }
    }
}

async fn test_stream_messages(
    client: &zoeyr_relay::QuicTarpcClient,
    filters: MessageFilters,
    since: Option<String>,
    limit: usize,
) -> Result<()> {
    info!("🎧 Testing message streaming via QUIC+tarpc");
    info!(
        "📋 Client public key: {}",
        hex::encode(client.client_public_key())
    );

    if filters.is_empty() {
        warn!("⚠️ No filters specified - this may not work as expected");
        info!("📡 Would attempt to listen for ALL messages");
    } else {
        info!("🔍 Would listen with filters applied:");
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

    // Create stream config
    let stream_config = StreamConfig {
        since,
        limit: Some(limit),
        filters,
    };

    // Create tarpc client and send stream start request
    let relay_service = client.relay_service().await?;

    match relay_service
        .start_message_stream(tarpc::context::current(), stream_config)
        .await?
    {
        Ok(session_id) => {
            info!("🎧 Stream started successfully: {}", session_id);

            // In a full implementation, we would:
            // 1. Use the session ID to repeatedly call get_stream_batch
            // 2. Display messages as they arrive
            // 3. Handle stream termination properly

            info!("ℹ️ Stream testing completed - full streaming implementation pending");
            Ok(())
        }
        Err(error) => {
            error!("❌ Failed to start stream: {:?}", error);
            Err(anyhow::anyhow!("Failed to start stream: {:?}", error))
        }
    }
}

/// Parse hex-encoded filter values
fn parse_hex_list(input: &str) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    for hex_str in input.split(',') {
        let hex_str = hex_str.trim();
        if !hex_str.is_empty() {
            let bytes =
                hex::decode(hex_str).with_context(|| format!("Invalid hex format: {}", hex_str))?;
            result.push(bytes);
        }
    }
    Ok(result)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with INFO level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    info!("🚀 Zoeyr QUIC+Tarpc Listen Client");
    info!("📋 Server: {}", cli.server);
    info!("🔑 Expected server public key: {}", cli.server_public_key);

    let server_addr: std::net::SocketAddr = cli.server.parse().context("Invalid server address")?;

    // Build client using the reusable builder
    let mut builder = RelayClientBuilder::new(server_addr, cli.server_public_key);

    if let Some(private_key) = cli.private_key {
        builder = builder.with_private_key(private_key);
    }

    let client = builder.build().await?;

    if cli.stats {
        match get_stats(&client).await {
            Ok(_) => {
                info!("✅ Stats request completed successfully!");
            }
            Err(e) => {
                error!("❌ Stats request failed: {}", e);
                return Err(e);
            }
        }
    } else {
        // Parse filters
        let mut filters = MessageFilters::new();

        if let Some(authors_str) = cli.authors {
            let authors = parse_hex_list(&authors_str)?;
            filters = filters.with_authors(authors);
        }

        if let Some(users_str) = cli.users {
            let users = parse_hex_list(&users_str)?;
            filters = filters.with_users(users);
        }

        if let Some(channels_str) = cli.channels {
            let channels = parse_hex_list(&channels_str)?;
            filters = filters.with_channels(channels);
        }

        match test_stream_messages(&client, filters, cli.since, cli.limit).await {
            Ok(_) => {
                info!("✅ Stream test completed successfully!");
            }
            Err(e) => {
                error!("❌ Stream test failed: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}
