//! Simple Bot Service Example
//!
//! This example demonstrates how to create a bot service that can be called
//! via RPC over the message infrastructure using tarpc and encrypted ephemeral messages.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
// use std::sync::Arc;
use tarpc::context;
use tracing::info;
// use zoe_client::RelayClient;

/// Simple bot service that can send messages and get info
#[tarpc::service]
pub trait BotService {
    /// Send a message via the bot
    async fn send_message(recipient: String, message: String) -> Result<String, String>;

    /// Get bot information
    async fn get_info() -> BotInfo;

    /// Echo a message back (for testing)
    async fn echo(message: String) -> String;
}

/// Information about the bot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotInfo {
    pub name: String,
    pub version: String,
    pub supported_features: Vec<String>,
}

/// Simple bot service implementation
#[derive(Clone)]
pub struct SimpleBotService {
    name: String,
}

impl SimpleBotService {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

// #[tarpc::server] // TODO: Fix when RPC transport is implemented
impl BotService for SimpleBotService {
    async fn send_message(
        self,
        _context: context::Context,
        recipient: String,
        message: String,
    ) -> Result<String, String> {
        info!(
            "Bot {} sending message to {}: {}",
            self.name, recipient, message
        );

        // Simulate sending a message
        if recipient.is_empty() {
            return Err("Recipient cannot be empty".to_string());
        }

        // In a real bot, this would integrate with WhatsApp/Signal/etc.
        let message_id = format!("msg_{}", rand::random::<u32>());
        Ok(message_id)
    }

    async fn get_info(self, _context: context::Context) -> BotInfo {
        BotInfo {
            name: self.name.clone(),
            version: "1.0.0".to_string(),
            supported_features: vec![
                "send_message".to_string(),
                "echo".to_string(),
                "get_info".to_string(),
            ],
        }
    }

    async fn echo(self, _context: context::Context, message: String) -> String {
        format!("{} echoes: {}", self.name, message)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Generate bot and client keys
    let bot_signing_key = SigningKey::generate(&mut OsRng);
    let client_signing_key = SigningKey::generate(&mut OsRng);

    let bot_public_key = bot_signing_key.verifying_key();
    let client_public_key = client_signing_key.verifying_key();

    info!("Bot public key: {}", hex::encode(bot_public_key.to_bytes()));
    info!(
        "Client public key: {}",
        hex::encode(client_public_key.to_bytes())
    );

    // For this example, we'll simulate both the bot and the client
    // In practice, they would run on different machines/processes

    // Simulate relay connection (you'd replace this with real relay connection)
    // For demonstration purposes, we'll just show the service definitions

    // Bot Service Setup (this would run on the bot)
    async fn run_bot_service() -> Result<()> {
        // Connect to relay as a bot
        let _bot_key = SigningKey::generate(&mut OsRng);
        // let relay_client = RelayClient::connect("bot_relay_url", bot_key).await?;
        // let (messages_service, messages_stream) = relay_client.connect_message_service().await?;

        // Create the bot service
        let _bot_service = SimpleBotService::new("ExampleBot".to_string());

        // This is where you'd set up the RPC server:
        // let transport = create_rpc_server(bot_key, client_public_key, Arc::new(messages_service), messages_stream);
        // server::BaseChannel::with_defaults(transport).execute(_bot_service.serve()).await?;

        info!("Bot service would be running here...");
        Ok(())
    }

    // Client Side (this would run on the client making RPC calls)
    async fn run_client_calls() -> Result<()> {
        // Connect to relay as a client
        let _client_key = SigningKey::generate(&mut OsRng);
        let _bot_public_key = SigningKey::generate(&mut OsRng).verifying_key();

        // let relay_client = RelayClient::connect("client_relay_url", client_key).await?;
        // let (messages_service, messages_stream) = relay_client.connect_message_service().await?;

        // Create RPC client pointing to the bot
        // let client = create_rpc_client(client_key, bot_public_key, Arc::new(messages_service), messages_stream).await;
        // let bot_client = BotServiceClient::new(Default::default(), client.spawn());

        // Example RPC calls:
        // let info = bot_client.get_info(context::current()).await??;
        // info!("Bot info: {:?}", info);

        // let echo_response = bot_client.echo(context::current(), "Hello!".to_string()).await??;
        // info!("Echo response: {}", echo_response);

        // let message_id = bot_client.send_message(
        //     context::current(),
        //     "user123".to_string(),
        //     "Hello from client!".to_string()
        // ).await??;
        // info!("Sent message with ID: {}", message_id);

        info!("Client calls would be made here...");
        Ok(())
    }

    info!("=== Simple Bot Service Example ===");
    info!("This example shows how to:");
    info!("1. Define a bot service using #[tarpc::service]");
    info!("2. Implement the service with business logic");
    info!("3. Set up RPC transport over encrypted messages");
    info!("4. Make RPC calls to the bot service");
    info!("");
    info!("In a real implementation:");
    info!("- The bot would connect to the relay server");
    info!("- Clients would discover bots by their public keys");
    info!("- RPC calls would be routed through encrypted ephemeral messages");
    info!("- Bots would integrate with WhatsApp/Signal/etc. APIs");

    // Run both parts (in practice these would be separate processes)
    let bot_handle = tokio::spawn(run_bot_service());
    let client_handle = tokio::spawn(run_client_calls());

    // Wait for both to complete
    let (bot_result, client_result) = tokio::join!(bot_handle, client_handle);
    bot_result??;
    client_result??;

    Ok(())
}
