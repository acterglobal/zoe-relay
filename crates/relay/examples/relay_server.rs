use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use tracing::info;

use zoeyr_relay::RelayServerBuilder;

#[derive(Parser)]
#[command(name = "relay-server")]
#[command(about = "Zoeyr relay server with QUIC transport and tarpc services")]
struct Cli {
    /// Server bind address
    #[arg(short, long, default_value = "127.0.0.1:4433")]
    addr: String,

    /// Server private key (hex) - if not provided, generates new key
    #[arg(short, long)]
    private_key: Option<String>,

    /// Redis URL for message storage
    #[arg(short, long, default_value = "redis://127.0.0.1:6379")]
    redis_url: String,

    /// Path to save generated key to
    #[arg(long, default_value = "relay_server.key")]
    key_output: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with INFO level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    info!("🚀 Zoeyr QUIC+Tarpc Relay Server");
    info!("📋 Server: {}", cli.addr);

    let server_addr: SocketAddr = cli.addr.parse().context("Invalid server address")?;

    // Build server using the reusable builder
    let mut builder = RelayServerBuilder::new(server_addr)
        .with_redis_url(cli.redis_url)
        .with_key_output(cli.key_output);

    if let Some(private_key) = cli.private_key {
        builder = builder.with_private_key(private_key);
    }

    let (server, _storage) = builder.build().await?;

    info!("🎯 Relay server ready to accept messages!");
    println!("\n🚀 Zoeyr Relay Server is now running!");
    println!("   📡 Server will show detailed logs when messages are stored");
    println!("   💾 Redis storage backend connected");
    println!("   🔄 Ready to process client connections\n");

    // Run the server
    server.run().await
}
