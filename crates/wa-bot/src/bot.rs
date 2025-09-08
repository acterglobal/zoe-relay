/// WhatsApp bot functionality
use anyhow::Result;
use std::sync::Arc;
use tokio_stream::{Stream, StreamExt};
use tracing::{error, info, warn};
use whatsmeow::{ConnectionStatus, MessageEvent, WhatsAppBot};
use zoe_app_primitives::{QrOptions, display_qr_code};
use zoe_client::{Client, pqxdh::PqxdhProtocolHandler};
use zoe_wire_protocol::{PqxdhInboxProtocol, Tag, VerifyingKey};

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
        let session_manager = zoe_client.session_manager().await;
        let pqxdh_handler = session_manager
            .pqxdh_handler(wa_bot_protocol)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get PQXDH handler: {}", e))?;

        // Get the public key
        let public_key = zoe_client.public_key();

        info!("✅ PQXDH functionality initialized");

        Ok(ZoeBridgeBot {
            bot,
            zoe_client,
            pqxdh_handler,
            public_key,
        })
    }
}

impl Default for ZoeWhatsAppBotBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Full bridge bot with both WhatsApp and PQXDH capabilities
pub struct ZoeBridgeBot {
    bot: WhatsAppBot,
    zoe_client: Arc<Client>,
    pqxdh_handler: Arc<PqxdhProtocolHandler<zoe_client::services::MessagePersistenceManager>>,
    public_key: VerifyingKey,
}

impl std::ops::Deref for ZoeBridgeBot {
    type Target = WhatsAppBot;

    fn deref(&self) -> &Self::Target {
        &self.bot
    }
}

impl ZoeBridgeBot {
    /// Get the bot's public key for PQXDH connections
    pub fn public_key(&self) -> VerifyingKey {
        self.public_key.clone()
    }

    /// Publish PQXDH inbox
    pub async fn publish_pqxdh_inbox(&self, force_overwrite: bool) -> Result<Tag> {
        info!("📢 Publishing PQXDH inbox for WhatsApp bot");

        let inbox_tag = self
            .pqxdh_handler
            .publish_service(force_overwrite)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish PQXDH inbox: {}", e))?;

        info!("✅ PQXDH inbox published with tag: {:?}", inbox_tag);
        Ok(inbox_tag)
    }

    /// Create a PQXDH connection stream
    pub async fn pqxdh_connection_stream<T>(&self) -> Result<impl Stream<Item = ([u8; 32], T)>>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone + Send + 'static,
    {
        info!("👂 Starting PQXDH connection listener");

        let stream = self
            .pqxdh_handler
            .inbox_stream::<T>()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create PQXDH connection stream: {}", e))?;

        info!("✅ PQXDH connection listener started");
        Ok(stream)
    }

    /// Send a message via PQXDH
    pub async fn send_pqxdh_message<T>(&self, session_id: &[u8; 32], message: &T) -> Result<()>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        self.pqxdh_handler
            .send_message(session_id, message)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send PQXDH message: {}", e))?;

        Ok(())
    }

    /// Handle a PQXDH connection by sending a welcome message
    pub async fn handle_pqxdh_connection(
        &self,
        session_id: [u8; 32],
        data: PqxdhMessageData,
    ) -> Result<()> {
        info!("🔐 New PQXDH connection: {:?}", hex::encode(session_id));
        info!(
            "📦 Received data: {} bytes, type: {:?}",
            data.data.len(),
            data.message_type
        );

        // Define the message type for initial connections
        #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
        struct ConnectionWelcome {
            message: String,
            bot_type: String,
            capabilities: Vec<String>,
        }

        // Send welcome message to new connection
        let welcome = ConnectionWelcome {
            message: "Welcome to Zoe WhatsApp Bot!".to_string(),
            bot_type: "whatsapp-bridge".to_string(),
            capabilities: vec![
                "message-relay".to_string(),
                "status-updates".to_string(),
                "secure-messaging".to_string(),
            ],
        };

        if let Err(e) = self.send_pqxdh_message(&session_id, &welcome).await {
            error!(
                "❌ Failed to send welcome message to PQXDH connection: {}",
                e
            );
            return Err(e);
        }

        info!("✅ Sent welcome message to PQXDH connection");
        Ok(())
    }

    /// Run the full bridge mode - handles both WhatsApp messages and PQXDH connections internally
    /// Returns a stream that the main loop can poll for events
    pub async fn run_bridge(&self) -> Result<impl Stream<Item = BridgeEvent>> {
        info!("🌉 Starting Bridge Mode - WhatsApp ↔ PQXDH");

        // Publish PQXDH inbox (without force overwrite)
        info!("📢 Publishing PQXDH inbox...");
        let inbox_tag = self.publish_pqxdh_inbox(false).await?;
        info!("✅ PQXDH inbox published with tag: {:?}", inbox_tag);

        // Display bot's public key for clients to connect
        let public_key = self.public_key();
        match public_key.to_bytes() {
            Ok(bytes) => {
                info!("🔑 Bot Public Key: {}", hex::encode(bytes));
                info!("💡 Clients can use this key to establish PQXDH connections");
            }
            Err(e) => {
                error!("❌ Failed to serialize public key: {}", e);
            }
        }

        // Start WhatsApp message stream
        let message_stream = self.message_stream()?;
        info!("✅ WhatsApp message stream started");

        // Start PQXDH connection stream with raw bytes
        let pqxdh_stream = Box::pin(self.pqxdh_connection_stream::<Vec<u8>>().await?);
        info!("✅ PQXDH connection stream started");

        // Convert WhatsApp messages to events - filtering will be done in main.rs
        let whatsapp_events = message_stream.map(|message| BridgeEvent::WhatsAppMessage(message));

        let pqxdh_events = pqxdh_stream.map(|(session_id, raw_data)| {
            let data = PqxdhMessageData {
                data: raw_data,
                message_type: None, // Could be determined by inspecting the data
            };
            BridgeEvent::PqxdhConnection { session_id, data }
        });

        // Merge the streams
        use tokio_stream::StreamExt;
        let combined_stream = tokio_stream::StreamExt::merge(whatsapp_events, pqxdh_events);

        info!("🔄 Bridge active - ready to handle events");
        Ok(combined_stream)
    }
}

/// Configuration for WhatsApp message handling
#[derive(Debug, Clone)]
pub struct MessageHandlerConfig {
    pub show_timestamps: bool,
    pub show_ids: bool,
    pub filter_sender: Option<String>,
    pub filter_chat: Option<String>,
    pub groups_only: bool,
    pub dm_only: bool,
}

impl Default for MessageHandlerConfig {
    fn default() -> Self {
        Self {
            show_timestamps: false,
            show_ids: false,
            filter_sender: None,
            filter_chat: None,
            groups_only: false,
            dm_only: false,
        }
    }
}

/// PQXDH message data using postcard serialization
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PqxdhMessageData {
    /// The raw message bytes (postcard-serialized)
    pub data: Vec<u8>,
    /// Optional message type hint
    pub message_type: Option<String>,
}

/// Events that can occur in the bridge
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    /// A WhatsApp message was received
    WhatsAppMessage(MessageEvent),
    /// A PQXDH connection was established
    PqxdhConnection {
        session_id: [u8; 32],
        data: PqxdhMessageData,
    },
    /// An error occurred
    Error(String),
}

/// Extension trait for WhatsAppBot to add convenience methods
pub trait WhatsAppBotExt {
    /// Check if the bot is connected to WhatsApp
    async fn is_connected(&self) -> Result<bool>;
    /// Get connection status (alias for compatibility)
    async fn status(&self) -> Result<ConnectionStatus>;
    /// Get QR code for authentication (alias for compatibility)
    async fn qr_code(&self) -> Result<String>;
    /// Display QR code for WhatsApp authentication if not connected
    async fn show_qr_code_if_needed(&self) -> Result<bool>;
    /// Display the WhatsApp QR code for authentication
    async fn display_qr_code(&self) -> Result<()>;
    /// Wait for connection to be established
    async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool>;
    /// Run the bridge in listen-only mode (WhatsApp messages only)
    async fn run_listen(
        &self,
        config: MessageHandlerConfig,
    ) -> Result<impl Stream<Item = BridgeEvent>>;
}

impl WhatsAppBotExt for WhatsAppBot {
    /// Check if the bot is connected to WhatsApp
    async fn is_connected(&self) -> Result<bool> {
        match self.get_connection_status().await? {
            ConnectionStatus::Connected => Ok(true),
            _ => Ok(false),
        }
    }

    /// Get connection status (alias for compatibility)
    async fn status(&self) -> Result<ConnectionStatus> {
        self.get_connection_status().await
    }

    /// Get QR code for authentication (alias for compatibility)
    async fn qr_code(&self) -> Result<String> {
        self.get_qr_code().await
    }

    /// Display QR code for WhatsApp authentication if not connected
    ///
    /// Returns true if QR code was displayed, false if already connected
    async fn show_qr_code_if_needed(&self) -> Result<bool> {
        let status = self.get_connection_status().await?;

        match status {
            ConnectionStatus::Connected => {
                info!("✅ Already connected to WhatsApp");
                Ok(false)
            }
            ConnectionStatus::Connecting => {
                info!("🔄 Currently connecting to WhatsApp...");
                Ok(false)
            }
            ConnectionStatus::Disconnected | ConnectionStatus::LoggedOut => {
                info!("📱 Not connected to WhatsApp. Generating QR code...");
                self.display_qr_code().await?;
                Ok(true)
            }
        }
    }

    /// Display the WhatsApp QR code for authentication
    async fn display_qr_code(&self) -> Result<()> {
        match self.get_qr_code().await {
            Ok(qr_code) => {
                if qr_code.is_empty() {
                    info!("✅ No QR code needed - already authenticated");
                    return Ok(());
                }

                // Check if this is a mock QR code
                if qr_code.contains("MOCK_QR_CODE_FOR_TESTING") {
                    warn!("⚠️  Mock QR code received (testing mode)");
                }

                // Use the app-primitives QR display system for WhatsApp QR codes
                // Since WhatsApp QR codes are strings, we'll wrap them in a simple struct
                let qr_data = WhatsAppQrData { qr_code };

                let options = QrOptions::new("📱 WHATSAPP QR CODE")
                    .with_subtitle("Scan with WhatsApp mobile app")
                    .with_subtitle("1. Open WhatsApp on your phone")
                    .with_subtitle("2. Go to Settings > Linked Devices")
                    .with_subtitle("3. Tap 'Link a Device'")
                    .with_subtitle("4. Scan this QR code")
                    .with_footer("QR code expires in 20 seconds")
                    .with_border_width(65);

                display_qr_code(&qr_data, &options)?;

                info!("📱 QR code displayed. Scan with your WhatsApp mobile app.");
                info!("⏰ QR code expires in 20 seconds. Re-run if it expires.");

                Ok(())
            }
            Err(e) => {
                warn!("❌ Failed to get QR code: {}", e);
                info!("💡 This might be normal if already authenticated");
                Err(e)
            }
        }
    }

    /// Wait for connection to be established
    ///
    /// Returns true if connected, false if timed out
    async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool> {
        info!("⏳ Waiting for WhatsApp connection...");

        for attempt in 1..=max_attempts {
            match self.get_connection_status().await? {
                ConnectionStatus::Connected => {
                    info!("🎉 Successfully connected to WhatsApp!");
                    return Ok(true);
                }
                ConnectionStatus::Connecting => {
                    info!(
                        "🔄 Connection attempt {}/{} - still connecting...",
                        attempt, max_attempts
                    );
                }
                ConnectionStatus::Disconnected => {
                    info!(
                        "📴 Connection attempt {}/{} - disconnected",
                        attempt, max_attempts
                    );
                }
                ConnectionStatus::LoggedOut => {
                    info!(
                        "🚪 Connection attempt {}/{} - logged out",
                        attempt, max_attempts
                    );
                }
            }

            if attempt < max_attempts {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }

        warn!("⏰ Connection timeout after {} attempts", max_attempts);
        Ok(false)
    }

    /// Run the bridge in listen-only mode (WhatsApp messages only)
    ///
    /// Returns a stream of WhatsApp messages for processing.
    ///
    /// # Arguments
    /// * `config` - Configuration for message filtering and display
    async fn run_listen(
        &self,
        config: MessageHandlerConfig,
    ) -> Result<impl Stream<Item = BridgeEvent>> {
        info!("👂 Starting WhatsApp message listener...");

        // Validate conflicting options
        if config.groups_only && config.dm_only {
            return Err(anyhow::anyhow!("Cannot use both groups_only and dm_only"));
        }

        // Start message stream
        let message_stream = self.message_stream()?;
        info!("✅ WhatsApp message stream started");

        // Create filtered stream - convert all messages to events for now
        let filtered_stream = message_stream.map(|message| BridgeEvent::WhatsAppMessage(message));

        Ok(filtered_stream)
    }
}

/// Wrapper for WhatsApp QR code data to make it serializable
#[derive(serde::Serialize)]
struct WhatsAppQrData {
    qr_code: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use whatsmeow::WhatsAppBot;

    #[tokio::test]
    async fn test_bot_creation() {
        let bot = WhatsAppBot::new("test.db");
        assert!(bot.is_ok());
    }

    #[tokio::test]
    async fn test_connection_status_check() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let status = bot.get_connection_status().await;
        assert!(status.is_ok());
    }

    #[tokio::test]
    async fn test_is_connected() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let connected = bot.is_connected().await;
        assert!(connected.is_ok());
        // In test mode with mocks, should be disconnected by default
        assert!(!connected.unwrap());
    }

    #[tokio::test]
    async fn test_qr_code_display() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let result = bot.show_qr_code_if_needed().await;
        assert!(result.is_ok());
        // Should return true since mock bot is disconnected by default
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_send_message() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let result = bot
            .send_message("test@s.whatsapp.net", "Hello, World!")
            .await;
        assert!(result.is_ok());
        // Mock should return a message ID
        assert_eq!(result.unwrap(), "msg_mock_123");
    }

    #[tokio::test]
    async fn test_inner_access() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        // WhatsAppBot is now used directly, no inner() method needed
        // Should be able to access bot methods directly
        let status = bot.get_connection_status().await;
        assert!(status.is_ok());
    }

    #[tokio::test]
    async fn test_pqxdh_initialization() {
        // Skip this test as it requires complex setup with real network connections
        // In a real implementation, we would use dependency injection for better testability
    }

    #[tokio::test]
    async fn test_pqxdh_inbox_publishing() {
        // Skip this test as it requires complex setup with real network connections
        // In a real implementation, we would use dependency injection for better testability
    }

    #[tokio::test]
    async fn test_pqxdh_connection_stream_creation() {
        // Skip this test as it requires complex setup with real network connections
        // In a real implementation, we would use dependency injection for better testability
    }

    #[tokio::test]
    async fn test_whatsapp_only_functionality() {
        let bot = WhatsAppBot::new("test.db").unwrap();

        // ZoeWhatsAppBot should only have WhatsApp functionality
        // Test that basic WhatsApp methods are available
        assert!(bot.get_connection_status().await.is_ok());

        // Test that we can create message streams
        assert!(bot.message_stream().is_ok());
    }
}
