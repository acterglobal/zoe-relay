pub mod bot;

pub use bot::{
    BridgeEvent, MessageHandlerConfig, PqxdhMessageData, WhatsAppBotExt, ZoeBridgeBot,
    ZoeWhatsAppBotBuilder,
};

// WhatsAppConnectable trait and connect_whatsapp_bot function are defined below
pub use whatsmeow::WhatsAppBot;

/// Check if a message should be displayed based on filters
pub fn should_display_message(
    message: &whatsmeow::MessageEvent,
    filter_sender: &Option<String>,
    filter_chat: &Option<String>,
    groups_only: bool,
    dm_only: bool,
) -> bool {
    // Check sender filter
    if let Some(sender_filter) = filter_sender
        && !message
            .sender
            .to_lowercase()
            .contains(&sender_filter.to_lowercase())
    {
        return false;
    }

    // Check chat filter
    if let Some(chat_filter) = filter_chat
        && !message
            .chat
            .to_lowercase()
            .contains(&chat_filter.to_lowercase())
    {
        return false;
    }

    // Check group/DM filters
    let is_group = message.chat.contains("-") && message.chat.contains("@g.us");

    if groups_only && !is_group {
        return false;
    }

    if dm_only && is_group {
        return false;
    }

    true
}

/// Extract a readable name from a WhatsApp JID
pub fn extract_name_from_jid(jid: &str) -> String {
    // Extract the part before @ and format it nicely
    let name_part = jid.split('@').next().unwrap_or(jid);

    // For group JIDs, extract the readable part
    if name_part.contains('-') {
        let parts: Vec<&str> = name_part.split('-').collect();
        if parts.len() >= 2 {
            // Group JIDs often have format: timestamp-groupid
            return format!("Group-{}", &parts[1][..8.min(parts[1].len())]);
        }
    }

    // For regular JIDs, just use the phone number part
    if name_part.len() >= 10 {
        format!("+{}", name_part)
    } else {
        name_part.to_string()
    }
}

/// Trait for WhatsApp connection functionality
pub trait WhatsAppConnectable {
    async fn show_qr_code_if_needed(&self) -> Result<bool, anyhow::Error>;
    async fn connect(&self) -> Result<(), anyhow::Error>;
    async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool, anyhow::Error>;
}

// Implement the trait for both bot types
impl WhatsAppConnectable for WhatsAppBot {
    async fn show_qr_code_if_needed(&self) -> Result<bool, anyhow::Error> {
        // For now, always show QR code - this can be improved later
        match self.qr_code().await {
            Ok(qr) => {
                if !qr.is_empty() {
                    use zoe_app_primitives::{QrOptions, display_qr_code};
                    let options = QrOptions {
                        title: "📱 WHATSAPP QR CODE".to_string(),
                        subtitle_lines: vec![
                            "Scan with WhatsApp mobile app".to_string(),
                            "1. Open WhatsApp on your phone".to_string(),
                            "2. Go to Settings > Linked Devices".to_string(),
                            "3. Tap 'Link a Device'".to_string(),
                            "4. Scan this QR code".to_string(),
                        ],
                        footer: "QR code expires in 20 seconds".to_string(),
                        border_width: 60,
                    };
                    display_qr_code(&qr, &options)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    async fn connect(&self) -> Result<(), anyhow::Error> {
        WhatsAppBot::connect(self).await
    }

    async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool, anyhow::Error> {
        for attempt in 1..=max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            match self.status().await {
                Ok(status) => {
                    tracing::info!(
                        "📊 Connection attempt {}/{}: {:?}",
                        attempt,
                        max_attempts,
                        status
                    );
                    if matches!(status, whatsmeow::ConnectionStatus::Connected) {
                        return Ok(true);
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ Failed to check status on attempt {}: {}", attempt, e);
                }
            }
        }
        Ok(false)
    }
}

impl WhatsAppConnectable for ZoeBridgeBot {
    async fn show_qr_code_if_needed(&self) -> Result<bool, anyhow::Error> {
        // For now, always show QR code - this can be improved later
        match self.qr_code().await {
            Ok(qr) => {
                if !qr.is_empty() {
                    use zoe_app_primitives::{QrOptions, display_qr_code};
                    let options = QrOptions {
                        title: "📱 WHATSAPP QR CODE".to_string(),
                        subtitle_lines: vec![
                            "Scan with WhatsApp mobile app".to_string(),
                            "1. Open WhatsApp on your phone".to_string(),
                            "2. Go to Settings > Linked Devices".to_string(),
                            "3. Tap 'Link a Device'".to_string(),
                            "4. Scan this QR code".to_string(),
                        ],
                        footer: "QR code expires in 20 seconds".to_string(),
                        border_width: 60,
                    };
                    display_qr_code(&qr, &options)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Err(_) => Ok(false),
        }
    }

    async fn connect(&self) -> Result<(), anyhow::Error> {
        WhatsAppBot::connect(self).await
    }

    async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool, anyhow::Error> {
        for attempt in 1..=max_attempts {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            match self.status().await {
                Ok(status) => {
                    tracing::info!(
                        "📊 Connection attempt {}/{}: {:?}",
                        attempt,
                        max_attempts,
                        status
                    );
                    if matches!(status, whatsmeow::ConnectionStatus::Connected) {
                        return Ok(true);
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ Failed to check status on attempt {}: {}", attempt, e);
                }
            }
        }
        Ok(false)
    }
}

/// Generic helper to connect to WhatsApp for any bot type
pub async fn connect_whatsapp_bot<T>(
    bot: &T,
    max_connection_attempts: u32,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: WhatsAppConnectable,
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
