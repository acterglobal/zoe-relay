use anyhow::Result;
use std::sync::Arc;
use tracing::info;
use whatsmeow::WhatsAppBot;
use zoe_client::client::Client;
use zoe_wire_protocol::PqxdhInboxProtocol;

use crate::bot::ZoeBridgeBot;

/// Builder for creating WhatsApp bots with different capabilities
#[derive(Debug)]
pub struct ZoeWhatsAppBotBuilder {
    db_path: Option<String>,
}

impl ZoeWhatsAppBotBuilder {
    /// Create a new bot builder
    pub fn new() -> Self {
        Self { db_path: None }
    }

    /// Set the database path for WhatsApp session storage
    pub fn with_db_path<P: Into<String>>(mut self, path: P) -> Self {
        self.db_path = Some(path.into());
        self
    }

    /// Build a WhatsApp-only bot (for listen mode)
    pub async fn build_whatsapp_only(self) -> Result<WhatsAppBot> {
        let bot = if let Some(db_path) = self.db_path {
            WhatsAppBot::new(&db_path)?
        } else {
            WhatsAppBot::new("whatsapp.db")?
        };

        Ok(bot)
    }

    /// Build a full bridge bot with both WhatsApp and PQXDH capabilities
    pub async fn build_bridge_bot(self, zoe_client: Arc<Client>) -> Result<ZoeBridgeBot> {
        let bot = if let Some(db_path) = self.db_path {
            WhatsAppBot::new(&db_path)?
        } else {
            WhatsAppBot::new("whatsapp.db")?
        };

        // Initialize PQXDH capabilities
        info!("🔐 Initializing PQXDH functionality for WhatsApp bot");

        // Create a custom protocol for WhatsApp bot
        let wa_bot_protocol = PqxdhInboxProtocol::WhatsAppBot;

        // Get session manager and PQXDH handler
        let session_manager = zoe_client.session_manager();
        let pqxdh_handler = session_manager
            .pqxdh_handler(wa_bot_protocol)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get PQXDH handler: {}", e))?;

        // Get the public key
        let public_key = zoe_client.public_key();

        info!("✅ PQXDH functionality initialized");

        Ok(ZoeBridgeBot::new(
            bot,
            zoe_client,
            pqxdh_handler,
            public_key,
        ))
    }
}

impl Default for ZoeWhatsAppBotBuilder {
    fn default() -> Self {
        Self::new()
    }
}
