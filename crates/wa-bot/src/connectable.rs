use crate::bridge_event::BridgeEvent;

/// WhatsApp bot functionality
use anyhow::Result;
use tokio_stream::{Stream, StreamExt as TokioStreamExt};
use tracing::{info, warn};
use whatsmeow::{ConnectionStatus, WhatsAppBot};
use zoe_app_primitives::{QrOptions, display_qr_code};

/// Extension trait for WhatsAppBot to add convenience methods
#[async_trait::async_trait]
pub trait WhatsAppBotExt {
    async fn connect(&self) -> Result<()>;
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
    async fn run_listen(&self) -> Result<impl Stream<Item = BridgeEvent>>;
}

#[async_trait::async_trait]

impl WhatsAppBotExt for WhatsAppBot {
    async fn connect(&self) -> Result<()> {
        self.connect().await
    }

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

                let options = QrOptions::new("📱 WHATSAPP QR CODE")
                    .with_subtitle("Scan with WhatsApp mobile app")
                    .with_subtitle("1. Open WhatsApp on your phone")
                    .with_subtitle("2. Go to Settings > Linked Devices")
                    .with_subtitle("3. Tap 'Link a Device'")
                    .with_subtitle("4. Scan this QR code")
                    .with_footer("QR code expires in 20 seconds")
                    .with_border_width(65);

                display_qr_code(&qr_code, &options)?;

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
    async fn run_listen(&self) -> Result<impl Stream<Item = BridgeEvent>> {
        info!("👂 Starting WhatsApp message listener...");

        // Start message stream
        let message_stream = self.message_stream()?;
        info!("✅ WhatsApp message stream started");

        // Create filtered stream - convert all messages to events for now
        let filtered_stream = TokioStreamExt::map(message_stream, BridgeEvent::WhatsAppMessage);

        Ok(filtered_stream)
    }
}

/// Generic helper to connect to WhatsApp for any bot type
pub async fn connect_whatsapp_bot<T>(
    bot: &T,
    max_connection_attempts: u32,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: WhatsAppBotExt,
{
    // Check connection status and show QR code if needed
    tracing::info!("🔍 Checking WhatsApp connection status...");
    match bot.show_qr_code_if_needed().await {
        Ok(qr_displayed) => {
            if qr_displayed {
                tracing::info!("📱 QR code displayed. Please scan with your WhatsApp mobile app.");

                // Attempt to connect
                if let Err(e) = bot.connect().await {
                    tracing::error!("❌ Failed to initiate WhatsApp connection: {}", e);
                }

                // Wait for connection
                tracing::info!("⏳ Waiting for WhatsApp connection...");
                match bot.wait_for_connection(max_connection_attempts).await {
                    Ok(true) => {
                        tracing::info!("🎉 Successfully connected to WhatsApp!");
                    }
                    Ok(false) => {
                        tracing::error!(
                            "⏰ WhatsApp connection timed out after {} attempts",
                            max_connection_attempts
                        );
                        tracing::error!("💡 Try scanning the QR code again or restart the bot");
                        return Err(anyhow::anyhow!("WhatsApp connection timeout").into());
                    }
                    Err(e) => {
                        tracing::error!("❌ Error while waiting for WhatsApp connection: {}", e);
                        return Err(e.into());
                    }
                }
            } else {
                tracing::info!("✅ Already connected to WhatsApp");
            }
        }
        Err(e) => {
            tracing::error!("❌ Failed to check WhatsApp connection: {}", e);
            return Err(e.into());
        }
    }

    tracing::info!("🎯 Zoe WhatsApp Bot is ready!");
    tracing::info!("📱 WhatsApp: Connected");
    tracing::info!("🔗 Zoe Network: Connected");
    Ok(())
}
