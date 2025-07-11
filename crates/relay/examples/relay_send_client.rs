use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use tracing::{error, info};

use zoeyr_relay::RelayClientBuilder;
use zoeyr_wire_protocol::{Kind, Message, MessageFull, Tag};

#[derive(Parser)]
#[command(name = "relay-send-client")]
#[command(about = "Zoeyr relay client that sends messages via QUIC+tarpc")]
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

    /// Message to send
    #[arg(short, long)]
    message: String,

    /// Get server stats instead of sending message
    #[arg(long)]
    stats: bool,
}

async fn send_message(client: &zoeyr_relay::QuicTarpcClient, message: String) -> Result<String> {
    info!("📤 Sending message via QUIC+tarpc: {}", message);

    // Create a proper MessageFull<String> message
    let message_content = Message::new_v0(
        message,
        client.client_signing_key().verifying_key(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Kind::Regular,
        vec![Tag::User {
            id: client.client_public_key().to_vec(),
            relays: vec![],
        }],
    );

    let message_full = MessageFull::new(message_content, client.client_signing_key())
        .map_err(|e| anyhow::anyhow!("Failed to create MessageFull: {}", e))?;

    // Serialize the message
    let message_data = message_full
        .storage_value()
        .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?
        .to_vec();

    info!("📤 Sending store_message request via tarpc");

    // Create tarpc client and send request
    let relay_service = client.relay_service().await?;

    match relay_service
        .store_message(tarpc::context::current(), message_data)
        .await?
    {
        Ok(storage_id) => {
            info!("✅ Message sent to server successfully!");
            info!("   Storage/Stream ID: {}", storage_id);
            info!(
                "   Message Hash: {}",
                hex::encode(message_full.id.as_bytes())
            );
            println!("\n🎉 SUCCESS: Message stored on relay server!");
            println!("   📦 Storage ID: {}", storage_id);
            println!(
                "   🆔 Message ID: {}",
                hex::encode(message_full.id.as_bytes())
            );
            println!("   📝 Content: \"{}\"", message_full.content());
            println!(
                "   👤 Author: {}",
                hex::encode(message_full.author().to_bytes())
            );
            Ok(storage_id)
        }
        Err(error) => {
            error!("❌ Failed to store message: {:?}", error);
            println!("\n💥 FAILED: Could not store message on server!");
            println!("   Error: {:?}", error);
            Err(anyhow::anyhow!("Failed to store message: {:?}", error))
        }
    }
}

async fn get_stats(client: &zoeyr_relay::QuicTarpcClient) -> Result<()> {
    info!("📊 Requesting server statistics via tarpc");

    // Create tarpc client and send request
    let relay_service = client.relay_service().await?;

    match relay_service.get_stats(tarpc::context::current()).await? {
        Ok(stats) => {
            info!("✅ Server statistics retrieved");
            println!("📊 Server Statistics:");
            println!("   Total Messages: {}", stats.total_messages);
            println!("   Active Streams: {}", stats.active_streams);
            println!("   Storage Size: {} bytes", stats.storage_size_bytes);
            println!("   Connected Clients: {}", stats.connected_clients);
            Ok(())
        }
        Err(error) => {
            error!("❌ Failed to get stats: {:?}", error);
            Err(anyhow::anyhow!("Failed to get stats: {:?}", error))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with INFO level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    info!("🚀 Zoeyr QUIC+Tarpc Send Client");
    info!("📋 Server: {}", cli.server);
    info!("🔑 Expected server public key: {}", cli.server_public_key);

    let server_addr: SocketAddr = cli.server.parse().context("Invalid server address")?;

    // Build client using the reusable builder
    let mut builder = RelayClientBuilder::new(server_addr, cli.server_public_key);

    if let Some(private_key) = cli.private_key {
        builder = builder.with_private_key(private_key);
    }

    let client = builder.build().await?;

    if cli.stats {
        get_stats(&client).await?;
    } else {
        match send_message(&client, cli.message).await {
            Ok(_storage_id) => {
                info!("🚀 Client completed successfully!");
                println!("\n✨ Message relay operation completed!");
                println!("   Check the server logs to see storage confirmation.");
            }
            Err(e) => {
                error!("❌ Failed to send message: {}", e);
                return Err(e);
            }
        }
    }

    Ok(())
}
