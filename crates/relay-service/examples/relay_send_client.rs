use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use tracing::{error, info};

use zoeyr_relay_service::{RelayClient, parse_ed25519_public_key};
use zoeyr_wire_protocol::{
    generate_ed25519_keypair, load_ed25519_key_from_hex, Kind, Message, MessageFull, ProtocolMessage, Tag
};

#[derive(Parser)]
#[command(name = "relay-send-client")]
#[command(about = "Zoeyr relay client that sends text messages to the server")]
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
    
    /// Send health check instead of message
    #[arg(long)]
    health_check: bool,
}

struct RelaySendClient {
    relay_client: RelayClient,
}

impl RelaySendClient {
    pub async fn connect(
        server_addr: SocketAddr,
        expected_server_ed25519_key: ed25519_dalek::VerifyingKey,
        client_key: SigningKey,
    ) -> Result<Self> {
        let relay_client = RelayClient::connect(
            server_addr,
            expected_server_ed25519_key,
            client_key,
        ).await?;
        
        Ok(Self { relay_client })
    }
    
    pub async fn send_message(&self, message: String) -> Result<String> {
        info!("📤 Creating MessageFull for: {}", message);
        
        // Create a proper MessageFull<String> message
        let message_content = Message::new_v0(
            message,
            self.relay_client.client_key.verifying_key(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            Kind::Regular,
            vec![
                Tag::User { id: self.relay_client.server_key.to_bytes().to_vec(), relays: vec![] }
            ],
        );
        
        let message_full = MessageFull::new(
            message_content,
            &self.relay_client.client_key,
        ).map_err(|e| anyhow::anyhow!("Failed to create MessageFull: {}", e))?;
        
        info!("📤 Sending MessageFull to server");
        
        // Send the MessageFull to the server
        let protocol_message = ProtocolMessage::MessageFull {
            message: message_full,
        };
        
        let response: ProtocolMessage<String> = self.relay_client.send_json(&protocol_message).await?;
        
        match response {
            ProtocolMessage::MessageResponse { message_id, success } => {
                if success {
                    info!("✅ Message sent successfully: {}", message_id);
                    Ok(message_id)
                } else {
                    error!("❌ Message failed to send: {}", message_id);
                    Err(anyhow::anyhow!("Message failed to send"))
                }
            }
            ProtocolMessage::Error { message } => {
                error!("❌ Server error: {}", message);
                Err(anyhow::anyhow!("Server error: {}", message))
            }
            _ => {
                error!("❌ Unexpected response type");
                Err(anyhow::anyhow!("Unexpected response type"))
            }
        }
    }
    
    pub async fn send_health_check(&self) -> Result<(String, u64)> {
        info!("💚 Sending health check");
        
        let protocol_message: ProtocolMessage<String> = ProtocolMessage::HealthCheck;
        
        let response: ProtocolMessage<String> = self.relay_client.send_json(&protocol_message).await?;
        
        match response {
            ProtocolMessage::HealthResponse { status, timestamp } => {
                info!("✅ Health check OK: {}", status);
                Ok((status, timestamp))
            }
            ProtocolMessage::Error { message } => {
                error!("❌ Health check failed: {}", message);
                Err(anyhow::anyhow!("Health check failed: {}", message))
            }
            _ => {
                error!("❌ Unexpected response type for health check");
                Err(anyhow::anyhow!("Unexpected response type for health check"))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    info!("🚀 Zoeyr Relay Send Client");
    info!("📋 Server: {}", cli.server);
    info!("🔑 Expected server public key: {}", cli.server_public_key);
    
    // Load or generate client key
    let client_key = match cli.private_key {
        Some(key_hex) => {
            load_ed25519_key_from_hex(&key_hex)
                .context("Failed to load private key from hex")?
        }
        None => {
            let key = generate_ed25519_keypair();
            info!("🔑 Generated new client key: {}", hex::encode(key.verifying_key().to_bytes()));
            key
        }
    };
    
    let server_addr: SocketAddr = cli.server.parse()
        .context("Invalid server address")?;
    
    let expected_server_key = parse_ed25519_public_key(&cli.server_public_key)
        .context("Failed to parse server public key")?;
    
    let client = RelaySendClient::connect(server_addr, expected_server_key, client_key).await?;
    
    if cli.health_check {
        match client.send_health_check().await {
            Ok((status, timestamp)) => {
                info!("✅ Health check successful!");
                info!("   Status: {}", status);
                info!("   Timestamp: {}", timestamp);
            }
            Err(e) => {
                error!("❌ Health check failed: {}", e);
                return Err(e);
            }
        }
    } else {
        match client.send_message(cli.message).await {
            Ok(message_id) => {
                info!("✅ Message sent successfully!");
                info!("   Message ID: {}", message_id);
            }
            Err(e) => {
                error!("❌ Failed to send message: {}", e);
                return Err(e);
            }
        }
    }
    
    Ok(())
} 