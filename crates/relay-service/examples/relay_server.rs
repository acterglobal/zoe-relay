use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info, warn};

use quinn::Connection;

use zoeyr_relay_service::{storage::RedisStorage, config::RelayConfig, create_relay_server_endpoint};
use zoeyr_wire_protocol::{
    ProtocolMessage, 
    generate_ed25519_keypair, load_ed25519_key_from_hex
};

#[derive(Parser)]
#[command(name = "relay-server")]
#[command(about = "Zoeyr relay server that accepts and stores text messages")]
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

pub struct RelayServer {
    storage: Arc<RedisStorage>,
    server_key: SigningKey,
    addr: SocketAddr,
}

impl RelayServer {
    pub async fn new(
        addr: SocketAddr,
        server_key: SigningKey,
        redis_url: String,
    ) -> Result<Self> {
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
            server_key,
            addr,
        })
    }
    
    pub async fn run(&self) -> Result<()> {
        info!("🚀 Starting Zoeyr Relay Server");
        info!("📋 Server Address: {}", self.addr);
        info!("🔑 Server Public Key: {}", hex::encode(self.server_key.verifying_key().to_bytes()));
        info!("💾 Redis storage initialized");
        
        // Create server endpoint using shared utilities
        let endpoint = create_relay_server_endpoint(self.addr, &self.server_key)?;
        
        info!("✅ Server listening on {}", self.addr);
        println!("\n🔑 IMPORTANT: Server Public Key for clients:");
        println!("   {}", hex::encode(self.server_key.verifying_key().to_bytes()));
        println!("   Copy this key to connect clients!\n");
        
        // Accept connections
        while let Some(incoming) = endpoint.accept().await {
            let storage = Arc::clone(&self.storage);
            let server_key = self.server_key.clone();
            
            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        info!("🔗 New connection from {}", connection.remote_address());
                        if let Err(e) = Self::handle_connection(connection, storage, server_key).await {
                            error!("❌ Connection error: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("❌ Connection failed: {}", e);
                    }
                }
            });
        }
        
        Ok(())
    }
    
    async fn handle_connection(
        connection: Connection,
        storage: Arc<RedisStorage>,
        server_key: SigningKey,
    ) -> Result<()> {
        while let Ok((send, recv)) = connection.accept_bi().await {
            let storage = Arc::clone(&storage);
            let server_key = server_key.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_stream(send, recv, storage, server_key).await {
                    error!("❌ Stream error: {}", e);
                }
            });
        }
        
        Ok(())
    }
    
    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        storage: Arc<RedisStorage>,
        server_key: SigningKey,
    ) -> Result<()> {
        let request_bytes = recv.read_to_end(1024 * 1024).await?;
        let request_str = String::from_utf8(request_bytes)?;
        let request: ProtocolMessage<String> = serde_json::from_str(&request_str)?;
        
        let response = Self::process_message(request, storage, server_key).await?;
        
        let response_json = serde_json::to_string(&response)?;
        let response_bytes = response_json.as_bytes();
        
        send.write_all(response_bytes).await?;
        send.finish()?;
        
        Ok(())
    }
    
    async fn process_message(
        message: ProtocolMessage<String>,
        storage: Arc<RedisStorage>,
        _server_key: SigningKey,
    ) -> Result<ProtocolMessage<String>> {
        match message {
            ProtocolMessage::MessageFull { message: message_full } => {
                info!("📨 Received MessageFull from client, storing in Redis");
                info!("🔑 Message ID: {}", hex::encode(message_full.id.as_bytes()));
                info!("👤 From: {}", hex::encode(message_full.author().to_bytes()));
                
                // Just forward the MessageFull to Redis storage
                match storage.store_message(&message_full).await {
                    Ok(true) => {
                        let message_id = hex::encode(message_full.id.as_bytes());
                        info!("✅ Message stored with ID: {}", message_id);
                        
                        Ok(ProtocolMessage::MessageResponse {
                            message_id,
                            success: true,
                        })
                    }
                    Ok(false) => {
                        warn!("⚠️ Message already exists");
                        Ok(ProtocolMessage::MessageResponse {
                            message_id: hex::encode(message_full.id.as_bytes()),
                            success: false,
                        })
                    }
                    Err(e) => {
                        error!("❌ Failed to store message: {}", e);
                        Ok(ProtocolMessage::Error {
                            message: format!("Storage error: {}", e),
                        })
                    }
                }
            }
            
            ProtocolMessage::HealthCheck => {
                info!("💚 Health check received");
                Ok(ProtocolMessage::HealthResponse {
                    status: "OK - Relay Server Running".to_string(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs(),
                })
            }
            
            _ => {
                warn!("⚠️ Unsupported message type received");
                Ok(ProtocolMessage::Error {
                    message: "Unsupported message type".to_string(),
                })
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive(
            if std::env::var("RUST_LOG").is_ok() {
                "info".parse().unwrap()
            } else {
                "relay_server=info".parse().unwrap()
            }
        ))
        .init();
    
    let cli = Cli::parse();
    
    let server_addr: SocketAddr = cli.addr.parse()
        .context("Invalid server address format")?;
    
    // Load or generate server key
    let server_key = match &cli.private_key {
        Some(hex_key) => {
            info!("🔑 Loading private key from hex...");
            load_ed25519_key_from_hex(hex_key)
                .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?
        }
        None => {
            info!("🔑 Generating new server key...");
            let key = generate_ed25519_keypair();
            
            // Save the key to file
            let key_hex = hex::encode(key.to_bytes());
            std::fs::write(&cli.key_output, &key_hex)
                .context(format!("Failed to save key to {}", cli.key_output))?;
            
            info!("💾 Server key saved to: {}", cli.key_output);
            key
        }
    };
    
    // Create and run the server
    let server = RelayServer::new(server_addr, server_key, cli.redis_url).await?;
    server.run().await?;
    
    Ok(())
} 