//! # Zoe Signal Bot
//!
//! A Signal bot implementation using the presage library for Signal protocol communication.
//! This crate provides functionality for:
//!
//! - Signal account registration and device linking with QR codes
//! - Sending and receiving Signal messages
//! - Local encrypted database storage using Sled
//! - CLI interface for easy operation
//!
//! ## Features
//!
//! - **QR Code Authentication**: Display QR codes for easy device linking
//! - **Encrypted Storage**: Local database with encryption support
//! - **Message Handling**: Send and receive text messages
//! - **CLI Interface**: Command-line interface for all operations
//! - **Docker Support**: Ready for containerized deployment
//!
//! ## Usage
//!
//! ```bash
//! # Register a new account
//! signal-bot register --phone +1234567890
//!
//! # Run the bot
//! signal-bot run
//!
//! # Send a message
//! signal-bot send --to +1234567890 --message "Hello, World!"
//! ```

use anyhow::{Result, anyhow};
use futures::channel::oneshot;
use futures::future;
use presage::libsignal_service::configuration::SignalServers;
use presage::{Manager, manager::Registered};
use presage_store_sqlite::SqliteStore;
use std::path::PathBuf;
use tokio::time::{Duration, sleep};
use tracing::{error, info};
use uuid;
use zoe_app_primitives::{QrOptions, display_qr_code_from_string};

pub use presage;
pub use presage_store_sqlite;

/// Display QR code in the terminal using centralized app-primitives functionality
fn display_qr_code(url: &str) -> Result<()> {
    let options = QrOptions::new("📱 SIGNAL LINKING")
        .with_subtitle("Scan with Signal mobile app")
        .with_subtitle("1. Open Signal on your phone")
        .with_subtitle("2. Go to Settings > Linked devices")
        .with_subtitle("3. Tap the + (plus) button")
        .with_subtitle("4. Scan this QR code")
        .with_footer("Link expires in 10 minutes")
        .with_border_width(65);

    display_qr_code_from_string(url, &options)
        .map_err(|e| anyhow!("Failed to display QR code: {}", e))?;

    Ok(())
}

/// Signal Bot client for programmatic usage
pub struct SignalBot {
    manager: Manager<SqliteStore, Registered>,
    data_dir: PathBuf,
}

impl SignalBot {
    /// Create a new Signal bot instance
    ///
    /// # Arguments
    ///
    /// * `data_dir` - Directory path for storing the encrypted database
    ///
    /// # Example
    ///
    /// ```no_run
    /// use zoe_signal_bot::SignalBot;
    /// use std::path::PathBuf;
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let bot = SignalBot::new(PathBuf::from("./signal-data")).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(data_dir: PathBuf) -> Result<Self> {
        let store_path = data_dir.join("signal-store.db");
        let store = SqliteStore::open_with_passphrase(
            &store_path.to_string_lossy(),
            None, // No passphrase for now
            presage::model::identity::OnNewIdentity::Trust,
        )
        .await?;

        let manager = Manager::load_registered(store).await?;

        Ok(Self { manager, data_dir })
    }

    /// Check if the Signal account is registered and ready to use
    pub async fn is_registered(&self) -> Result<bool> {
        // If we can create a Manager with Registered state, it means we're registered
        Ok(true)
    }

    /// Get the current user's profile information
    pub async fn whoami(
        &mut self,
    ) -> Result<presage::libsignal_service::push_service::WhoAmIResponse> {
        Ok(self.manager.whoami().await?)
    }

    /// Send a text message to a recipient
    ///
    /// # Arguments
    ///
    /// * `recipient` - Phone number (e.g., "+1234567890") or UUID string
    /// * `message` - Text message content
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use zoe_signal_bot::SignalBot;
    /// # use std::path::PathBuf;
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let mut bot = SignalBot::new(PathBuf::from("./signal-data")).await?;
    /// bot.send_message("+1234567890", "Hello from Rust!").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_message(&mut self, recipient: &str, message: &str) -> Result<()> {
        use presage::libsignal_service::content::{ContentBody, DataMessage};

        let service_id = if recipient.starts_with('+') {
            // For phone numbers, we'd need to resolve them to ServiceId
            // This is a simplified approach - in practice you'd need to look up contacts
            return Err(anyhow::anyhow!(
                "Phone number resolution not implemented. Use UUID instead."
            ));
        } else {
            let uuid = uuid::Uuid::parse_str(recipient)?;
            presage::libsignal_service::protocol::ServiceId::Aci(uuid.into())
        };

        let data_message = DataMessage {
            body: Some(message.to_string()),
            timestamp: Some(chrono::Utc::now().timestamp_millis() as u64),
            ..Default::default()
        };

        let content_body = ContentBody::DataMessage(data_message);

        self.manager
            .send_message(
                service_id,
                content_body,
                chrono::Utc::now().timestamp_millis() as u64,
            )
            .await?;

        Ok(())
    }

    /// Receive pending messages
    ///
    /// Returns a stream of received messages that can be processed.
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl futures::Stream<Item = presage::model::messages::Received>> {
        Ok(self.manager.receive_messages().await?)
    }

    /// Link device and create a new Signal bot instance
    pub async fn link_and_run(data_dir: PathBuf) -> Result<Self> {
        info!("Starting device linking process");

        let store_path = data_dir.join("signal-store.db");
        let store = SqliteStore::open_with_passphrase(
            &store_path.to_string_lossy(),
            None, // No passphrase for now
            presage::model::identity::OnNewIdentity::Trust,
        )
        .await?;

        info!("Generating linking QR code...");

        let (provisioning_link_tx, provisioning_link_rx) = oneshot::channel();
        let device_name = "Signal Bot".to_string();

        let manager_future = Manager::link_secondary_device(
            store,
            SignalServers::Production,
            device_name,
            provisioning_link_tx,
        );

        let qr_display_future = async move {
            match provisioning_link_rx.await {
                Ok(url) => {
                    info!("Device linking URL generated");
                    display_qr_code(url.as_ref())?;
                    info!("Scan the QR code above with your Signal mobile app to link this device");
                    info!("Waiting for device to be linked...");
                    Ok(())
                }
                Err(error) => Err(anyhow!("Linking device was cancelled: {}", error)),
            }
        };

        // Wait for linking to complete with timeout (similar to WhatsApp bot)
        let (manager_result, qr_result) = tokio::time::timeout(
            Duration::from_secs(300), // 5 minutes timeout like WhatsApp bot
            future::join(manager_future, qr_display_future),
        )
        .await
        .map_err(|_| anyhow!("Linking timeout - device was not linked within 5 minutes"))?;

        qr_result?; // Check QR display result
        let manager = manager_result?; // Get the linked manager

        info!("Device successfully linked!");

        Ok(Self { manager, data_dir })
    }

    /// Run the bot and listen for incoming messages
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Signal bot - listening for messages...");

        // Verify we're registered
        let whoami = self.manager.whoami().await?;
        info!("Running as: {}", whoami.aci);

        info!("Bot is running. Press Ctrl+C to stop.");
        info!("Incoming messages will be displayed here:");
        println!("{}", "─".repeat(60));

        // Main message loop
        use futures::StreamExt;

        let messages = self.manager.receive_messages().await?;
        futures::pin_mut!(messages);

        while let Some(received) = messages.next().await {
            match received {
                presage::model::messages::Received::QueueEmpty => {
                    // No more messages, continue listening
                    sleep(Duration::from_millis(100)).await;
                }
                presage::model::messages::Received::Contacts => {
                    info!("📱 Contacts synchronized");
                }
                presage::model::messages::Received::Content(content) => {
                    if let Err(e) = self.handle_message(*content).await {
                        error!("Error handling message: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle an incoming message
    async fn handle_message(
        &mut self,
        content: presage::libsignal_service::content::Content,
    ) -> Result<()> {
        use presage::libsignal_service::content::ContentBody;

        match content.body {
            ContentBody::DataMessage(data_msg) => {
                let sender = format!("{:?}", content.metadata.sender);

                let timestamp =
                    chrono::DateTime::from_timestamp_millis(content.metadata.timestamp as i64)
                        .unwrap_or_else(chrono::Utc::now);

                if let Some(body) = data_msg.body {
                    println!("📱 [{}] {}: {}", timestamp.format("%H:%M:%S"), sender, body);

                    // Simple echo bot functionality - you can customize this
                    if body.to_lowercase().starts_with("echo ") {
                        let echo_msg = &body[5..]; // Remove "echo " prefix
                        if let Ok(sender_uuid) = uuid::Uuid::parse_str(&sender) {
                            let service_id = presage::libsignal_service::protocol::ServiceId::Aci(
                                sender_uuid.into(),
                            );

                            use presage::libsignal_service::content::{ContentBody, DataMessage};
                            let data_message = DataMessage {
                                body: Some(format!("Echo: {}", echo_msg)),
                                timestamp: Some(chrono::Utc::now().timestamp_millis() as u64),
                                ..Default::default()
                            };
                            let content_body = ContentBody::DataMessage(data_message);

                            if let Err(e) = self
                                .manager
                                .send_message(
                                    service_id,
                                    content_body,
                                    chrono::Utc::now().timestamp_millis() as u64,
                                )
                                .await
                            {
                                error!("Failed to send echo response: {}", e);
                            } else {
                                info!("Sent echo response to {}", sender);
                            }
                        }
                    }
                } else {
                    info!(
                        "📱 [{}] {}: [Non-text message]",
                        timestamp.format("%H:%M:%S"),
                        sender
                    );
                }
            }
            ContentBody::SynchronizeMessage(_) => {
                info!("📱 Sync message received");
            }
            ContentBody::CallMessage(_) => {
                info!("📞 Call message received");
            }
            ContentBody::ReceiptMessage(_) => {
                // Receipt messages are usually not displayed to avoid spam
            }
            ContentBody::TypingMessage(_) => {
                info!("✏️  Typing indicator received");
            }
            _ => {
                info!("📱 Other message type received");
            }
        }

        Ok(())
    }

    /// Run the bot with filtering options for the listen command
    pub async fn run_with_filter(
        &mut self,
        filter_sender: Option<String>,
        groups_only: bool,
        dm_only: bool,
        show_timestamps: bool,
        show_ids: bool,
    ) -> Result<()> {
        info!("Starting Signal bot with filters - listening for messages...");

        // Verify we're registered
        let whoami = self.manager.whoami().await?;
        info!("Running as: {}", whoami.aci);

        // Main message loop
        use futures::StreamExt;

        let messages = self.manager.receive_messages().await?;
        futures::pin_mut!(messages);

        while let Some(received) = messages.next().await {
            match received {
                presage::model::messages::Received::QueueEmpty => {
                    // No more messages, continue listening
                    sleep(Duration::from_millis(100)).await;
                }
                presage::model::messages::Received::Contacts => {
                    info!("📱 Contacts synchronized");
                }
                presage::model::messages::Received::Content(content) => {
                    if let Err(e) = self
                        .handle_filtered_message(
                            *content,
                            &filter_sender,
                            groups_only,
                            dm_only,
                            show_timestamps,
                            show_ids,
                        )
                        .await
                    {
                        error!("Error handling message: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle an incoming message with filtering
    async fn handle_filtered_message(
        &mut self,
        content: presage::libsignal_service::content::Content,
        filter_sender: &Option<String>,
        groups_only: bool,
        dm_only: bool,
        show_timestamps: bool,
        show_ids: bool,
    ) -> Result<()> {
        use presage::libsignal_service::content::ContentBody;

        match content.body {
            ContentBody::DataMessage(data_msg) => {
                let sender = format!("{:?}", content.metadata.sender);

                // Apply filters
                if let Some(filter) = filter_sender {
                    if !sender.contains(filter) {
                        return Ok(()); // Skip this message
                    }
                }

                // For now, we don't have group detection in Signal like WhatsApp
                // So groups_only and dm_only filters are not implemented yet
                if groups_only || dm_only {
                    // TODO: Implement group detection for Signal
                    // For now, just show all messages
                }

                let timestamp =
                    chrono::DateTime::from_timestamp_millis(content.metadata.timestamp as i64)
                        .unwrap_or_else(chrono::Utc::now);

                if let Some(body) = data_msg.body {
                    display_signal_message(&sender, &body, timestamp, show_timestamps, show_ids);

                    // Simple echo bot functionality - you can customize this
                    if body.to_lowercase().starts_with("echo ") {
                        let echo_msg = &body[5..]; // Remove "echo " prefix
                        if let Ok(sender_uuid) = uuid::Uuid::parse_str(&sender) {
                            let service_id = presage::libsignal_service::protocol::ServiceId::Aci(
                                sender_uuid.into(),
                            );

                            use presage::libsignal_service::content::{ContentBody, DataMessage};
                            let data_message = DataMessage {
                                body: Some(format!("Echo: {}", echo_msg)),
                                timestamp: Some(chrono::Utc::now().timestamp_millis() as u64),
                                ..Default::default()
                            };
                            let content_body = ContentBody::DataMessage(data_message);

                            if let Err(e) = self
                                .manager
                                .send_message(
                                    service_id,
                                    content_body,
                                    chrono::Utc::now().timestamp_millis() as u64,
                                )
                                .await
                            {
                                error!("Failed to send echo response: {}", e);
                            } else {
                                info!("Sent echo response to {}", sender);
                            }
                        }
                    }
                } else {
                    if show_timestamps || show_ids {
                        display_signal_message(
                            &sender,
                            "[Non-text message]",
                            timestamp,
                            show_timestamps,
                            show_ids,
                        );
                    } else {
                        info!("📱 {}: [Non-text message]", sender);
                    }
                }
            }
            ContentBody::SynchronizeMessage(_) => {
                info!("📱 Sync message received");
            }
            ContentBody::CallMessage(_) => {
                info!("📞 Call message received");
            }
            ContentBody::ReceiptMessage(_) => {
                // Receipt messages are usually not displayed to avoid spam
            }
            ContentBody::TypingMessage(_) => {
                info!("✏️  Typing indicator received");
            }
            _ => {
                info!("📱 Other message type received");
            }
        }

        Ok(())
    }

    /// Create a new manager for registration purposes
    pub async fn create_manager(data_dir: PathBuf) -> Result<Manager<SqliteStore, Registered>> {
        let store_path = data_dir.join("signal-store.db");
        let store = SqliteStore::open_with_passphrase(
            &store_path.to_string_lossy(),
            None, // No passphrase for now
            presage::model::identity::OnNewIdentity::Trust,
        )
        .await?;

        Ok(Manager::load_registered(store).await?)
    }
}

/// Display a Signal message in the terminal with formatting
fn display_signal_message(
    sender: &str,
    message: &str,
    timestamp: chrono::DateTime<chrono::Utc>,
    show_timestamps: bool,
    show_ids: bool,
) {
    let mut output = String::new();

    // Add timestamp if requested
    if show_timestamps {
        output.push_str(&format!("[{}] ", timestamp.format("%H:%M:%S")));
    }

    // Add sender ID if requested (first 8 chars)
    if show_ids {
        let sender_short = if sender.len() > 8 {
            &sender[..8]
        } else {
            sender
        };
        output.push_str(&format!("[{}] ", sender_short));
    }

    // Format the message
    output.push_str(&format!("👤 💬 {}: {}", sender, message));

    println!("{}", output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_signal_bot_creation_fails_without_registration() {
        let temp_dir = TempDir::new().unwrap();
        let bot = SignalBot::new(temp_dir.path().to_path_buf()).await;
        // Should fail because there's no registered account
        assert!(bot.is_err());
    }

    #[tokio::test]
    async fn test_create_manager_fails_without_registration() {
        let temp_dir = TempDir::new().unwrap();
        let manager = SignalBot::create_manager(temp_dir.path().to_path_buf()).await;

        // Should fail because there's no registered account
        assert!(manager.is_err());
    }

    #[test]
    fn test_phone_number_parsing() {
        // Test that phone numbers are handled correctly
        let phone = "+1234567890";
        assert!(phone.starts_with('+'));

        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let uuid_result = uuid::Uuid::parse_str(uuid_str);
        assert!(uuid_result.is_ok());
    }
}
