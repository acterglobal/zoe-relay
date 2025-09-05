/// WhatsApp bot functionality
use anyhow::Result;
use tokio_stream::Stream;
use tracing::{info, warn};
use whatsmeow::{ConnectionStatus, MessageEvent, WhatsAppBot};
use zoe_app_primitives::{QrOptions, display_qr_code};

/// WhatsApp bot wrapper with connection management
pub struct ZoeWhatsAppBot {
    bot: WhatsAppBot,
}

impl ZoeWhatsAppBot {
    /// Create a new WhatsApp bot instance with default database path
    pub fn new() -> Result<Self> {
        Self::new_with_db_path("whatsapp.db")
    }

    /// Create a new WhatsApp bot instance with custom database path
    pub fn new_with_db_path(db_path: &str) -> Result<Self> {
        let bot = WhatsAppBot::new(db_path)?;
        Ok(Self { bot })
    }

    /// Check if the bot is connected to WhatsApp
    pub async fn is_connected(&self) -> Result<bool> {
        match self.bot.get_connection_status().await? {
            ConnectionStatus::Connected => Ok(true),
            _ => Ok(false),
        }
    }

    /// Get the current connection status
    pub async fn get_connection_status(&self) -> Result<ConnectionStatus> {
        self.bot.get_connection_status().await
    }

    /// Display QR code for WhatsApp authentication if not connected
    ///
    /// Returns true if QR code was displayed, false if already connected
    pub async fn show_qr_code_if_needed(&self) -> Result<bool> {
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
        match self.bot.get_qr_code().await {
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

    /// Connect to WhatsApp
    pub async fn connect(&self) -> Result<()> {
        info!("🔄 Attempting to connect to WhatsApp...");
        self.bot.connect().await?;
        info!("✅ Connection attempt completed");
        Ok(())
    }

    /// Wait for connection to be established
    ///
    /// Returns true if connected, false if timed out
    pub async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool> {
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

    /// Send a text message
    pub async fn send_message(&self, to: &str, message: &str) -> Result<String> {
        self.bot.send_message(to, message).await
    }

    /// Get a stream of incoming WhatsApp messages
    ///
    /// This returns a stream that yields `MessageEvent` objects for all incoming messages.
    /// The stream will continue until `stop_message_stream()` is called or the bot is dropped.
    ///
    /// # Example
    /// ```rust,no_run
    /// use tokio_stream::StreamExt;
    ///
    /// let bot = ZoeWhatsAppBot::new()?;
    /// let mut message_stream = bot.message_stream()?;
    ///
    /// while let Some(message) = message_stream.next().await {
    ///     println!("Received message: {} from {}", message.content, message.sender);
    /// }
    /// ```
    pub fn message_stream(&self) -> Result<impl Stream<Item = MessageEvent>> {
        info!("📨 Starting WhatsApp message stream");
        self.bot.message_stream()
    }

    /// Stop the message stream
    ///
    /// This will stop receiving new messages and clean up the message handler.
    pub fn stop_message_stream(&self) -> Result<()> {
        info!("🛑 Stopping WhatsApp message stream");
        self.bot.stop_message_stream()
    }

    /// Get the underlying WhatsApp bot for advanced operations
    pub fn inner(&self) -> &WhatsAppBot {
        &self.bot
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

    #[tokio::test]
    async fn test_bot_creation() {
        let bot = ZoeWhatsAppBot::new();
        assert!(bot.is_ok());
    }

    #[tokio::test]
    async fn test_connection_status_check() {
        let bot = ZoeWhatsAppBot::new().unwrap();
        let status = bot.get_connection_status().await;
        assert!(status.is_ok());
    }

    #[tokio::test]
    async fn test_is_connected() {
        let bot = ZoeWhatsAppBot::new().unwrap();
        let connected = bot.is_connected().await;
        assert!(connected.is_ok());
        // In test mode with mocks, should be disconnected by default
        assert!(!connected.unwrap());
    }

    #[tokio::test]
    async fn test_qr_code_display() {
        let bot = ZoeWhatsAppBot::new().unwrap();
        let result = bot.show_qr_code_if_needed().await;
        assert!(result.is_ok());
        // Should return true since mock bot is disconnected by default
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_send_message() {
        let bot = ZoeWhatsAppBot::new().unwrap();
        let result = bot
            .send_message("test@s.whatsapp.net", "Hello, World!")
            .await;
        assert!(result.is_ok());
        // Mock should return a message ID
        assert_eq!(result.unwrap(), "msg_mock_123");
    }

    #[tokio::test]
    async fn test_inner_access() {
        let bot = ZoeWhatsAppBot::new().unwrap();
        let inner = bot.inner();
        // Should be able to access inner bot methods
        let status = inner.get_connection_status().await;
        assert!(status.is_ok());
    }
}
