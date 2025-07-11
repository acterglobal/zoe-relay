use anyhow::{Context, Result};
use clap::Parser;
use tokio::time::Duration;
use tracing::{error, info};

use ed25519_dalek::SigningKey;
use std::sync::Arc;
use zoeyr_relay::RelayClientBuilder;
use zoeyr_wire_protocol::{
    Kind, Message, MessageFilters, MessageFull, RelayError, StreamRequest, Tag,
};

#[derive(Parser)]
#[command(name = "relay-dual-client")]
#[command(about = "Zoeyr relay client that can both send and listen for messages")]
struct Cli {
    /// Server address to connect to
    #[arg(short = 'S', long, default_value = "127.0.0.1:4433")]
    server: String,

    /// Expected server ed25519 public key (hex format)
    #[arg(short = 'P', long)]
    server_public_key: String,

    /// Client private key (hex) - if not provided, generates new key
    #[arg(short, long)]
    private_key: Option<String>,

    /// Message to send (will send periodically if listening)
    #[arg(short, long, default_value = "Hello from dual client")]
    message: String,

    /// Keep listening for new messages while sending
    #[arg(short, long)]
    follow: bool,

    /// Interval between sends in seconds
    #[arg(long, default_value = "10")]
    send_interval: u64,
}

async fn listen_for_messages(
    client: Arc<zoeyr_relay::QuicTarpcClient>,
    follow: bool,
) -> Result<()> {
    info!("🎧 Starting message listener task");

    let filters = MessageFilters::new(); // Listen to all messages
    let mut stream_request = StreamRequest::new(filters);
    stream_request = stream_request.with_follow(follow);

    if follow {
        info!("🔄 Listening continuously for new messages...");
    } else {
        info!("📦 Getting batch of existing messages...");
    }

    match client.start_message_stream(stream_request).await {
        Ok(()) => {
            info!("✅ Message listening completed successfully!");
        }
        Err(error) => {
            error!("❌ Failed to listen for messages: {}", error);
            return Err(error);
        }
    }

    Ok(())
}

async fn send_messages(
    client: Arc<zoeyr_relay::QuicTarpcClient>,
    client_key: Arc<SigningKey>,
    message: String,
    interval: Duration,
    follow: bool,
) -> Result<()> {
    info!("📤 Starting message sender task");

    let mut counter = 1;

    loop {
        let timestamped_message = if follow {
            format!(
                "{} #{} - {}",
                message,
                counter,
                chrono::Utc::now().format("%H:%M:%S")
            )
        } else {
            message.clone()
        };

        info!("📤 Sending message: {}", timestamped_message);

        // Create a simple message for testing
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let core_message = Message::new_v0(
            timestamped_message,
            client_key.verifying_key(),
            now,
            Kind::Regular,
            vec![Tag::Protected],
        );

        let test_message = MessageFull::new(core_message, &client_key)
            .map_err(|e| anyhow::anyhow!("Failed to create message: {}", e))?;

        // Serialize the message
        let message_data = test_message
            .storage_value()
            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?
            .to_vec();

        // Send via tarpc
        match client.relay_service().await {
            Ok(relay_service) => {
                match relay_service
                    .store_message(tarpc::context::current(), message_data)
                    .await
                {
                    Ok(Ok(stream_id)) => {
                        info!("✅ Message sent successfully! Stream ID: {}", stream_id);
                    }
                    Ok(Err(RelayError::StorageError(err))) => {
                        error!("❌ Server storage error: {}", err);
                    }
                    Ok(Err(error)) => {
                        error!("❌ Server error: {:?}", error);
                    }
                    Err(error) => {
                        error!("❌ Failed to send message via tarpc: {}", error);
                        // For the demo, we'll continue even if send fails
                    }
                }
            }
            Err(error) => {
                error!("❌ Failed to create tarpc service: {}", error);
            }
        }

        if !follow {
            break;
        }

        counter += 1;
        tokio::time::sleep(interval).await;
    }

    info!("📤 Message sender task completed");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging with INFO level
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    info!("🚀 Zoeyr Dual-Function QUIC Client (Send + Listen)");
    info!("📋 Server: {}", cli.server);
    info!("🔑 Expected server public key: {}", cli.server_public_key);

    let server_addr: std::net::SocketAddr = cli.server.parse().context("Invalid server address")?;

    // Build client using the reusable builder
    let mut builder = RelayClientBuilder::new(server_addr, cli.server_public_key);

    if let Some(private_key) = cli.private_key {
        builder = builder.with_private_key(private_key);
    }

    let client = builder.build().await?;
    let client_key = client.client_signing_key().clone();
    let client = Arc::new(client);
    let client_key = Arc::new(client_key);

    info!("🔗 Connected to server successfully!");
    info!(
        "📋 Client public key: {}",
        hex::encode(client.client_public_key())
    );

    let send_interval = Duration::from_secs(cli.send_interval);

    if cli.follow {
        info!("🔄 Starting dual mode: continuous listening + periodic sending");

        // Create two concurrent tasks
        let listen_client = Arc::clone(&client);
        let send_client = Arc::clone(&client);
        let send_key = Arc::clone(&client_key);
        let message = cli.message.clone();

        let listen_task =
            tokio::spawn(async move { listen_for_messages(listen_client, true).await });

        let send_task = tokio::spawn(async move {
            send_messages(send_client, send_key, message, send_interval, true).await
        });

        // Wait for either task to complete (or fail)
        tokio::select! {
            listen_result = listen_task => {
                match listen_result {
                    Ok(Ok(())) => info!("✅ Listen task completed successfully"),
                    Ok(Err(e)) => error!("❌ Listen task failed: {}", e),
                    Err(e) => error!("❌ Listen task panicked: {}", e),
                }
            }
            send_result = send_task => {
                match send_result {
                    Ok(Ok(())) => info!("✅ Send task completed successfully"),
                    Ok(Err(e)) => error!("❌ Send task failed: {}", e),
                    Err(e) => error!("❌ Send task panicked: {}", e),
                }
            }
        }
    } else {
        info!("📦 Single mode: send one message, then listen for batch");

        // Send once, then listen
        send_messages(
            Arc::clone(&client),
            Arc::clone(&client_key),
            cli.message,
            send_interval,
            false,
        )
        .await?;
        listen_for_messages(Arc::clone(&client), false).await?;
    }

    info!("🎉 Dual client completed successfully!");
    Ok(())
}
