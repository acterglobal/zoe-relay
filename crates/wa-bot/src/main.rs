use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{error, info};
use tokio_stream::StreamExt;
use zoe_client::cli::{RelayClientArgs, full_cli_client, main_setup};
use zoe_wa_bot::{ZoeWhatsAppBot, should_display_message, extract_name_from_jid};

#[derive(Parser, Debug)]
#[command(name = "zoe-wa-bot")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Zoe WhatsApp Bot - Bridge WhatsApp with Zoe network")]
struct ZoeWhatsappBotArgs {
    #[command(flatten)]
    relay_args: RelayClientArgs,

    /// Maximum attempts to wait for WhatsApp connection
    #[arg(long, default_value = "10")]
    max_connection_attempts: u32,

    /// WhatsApp database path (defaults to "whatsapp.db" in current directory)
    #[arg(long)]
    whatsapp_db_path: Option<String>,

    /// Skip WhatsApp setup for testing
    #[arg(long)]
    skip_whatsapp_setup: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Listen for incoming WhatsApp messages and display them in the terminal
    Listen {
        /// Show message timestamps
        #[arg(long)]
        show_timestamps: bool,
        
        /// Show message IDs
        #[arg(long)]
        show_ids: bool,
        
        /// Filter messages by sender (partial match)
        #[arg(long)]
        filter_sender: Option<String>,
        
        /// Filter messages by chat (partial match)
        #[arg(long)]
        filter_chat: Option<String>,
        
        /// Only show messages from groups
        #[arg(long)]
        groups_only: bool,
        
        /// Only show direct messages (not from groups)
        #[arg(long)]
        dm_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    main_setup()
        .await
        .map_err(|e| anyhow::anyhow!("Setup failed: {}", e))?;

    let args = ZoeWhatsappBotArgs::parse();

    info!("🚀 Starting Zoe WhatsApp Bot");

    // Initialize Zoe client
    info!("🔗 Connecting to Zoe network...");
    let _zoe_client = full_cli_client(args.relay_args).await?;
    info!("✅ Connected to Zoe network");

    // Initialize WhatsApp bot
    info!("📱 Initializing WhatsApp bot...");
    if let Some(ref db_path) = args.whatsapp_db_path {
        info!("💾 Using WhatsApp database: {}", db_path);
    } else {
        info!("💾 Using default WhatsApp database: whatsapp.db");
    }
    let db_path = args.whatsapp_db_path.as_deref().unwrap_or("whatsapp.db");
    let whatsapp_bot = match ZoeWhatsAppBot::new_with_db_path(db_path) {
        Ok(bot) => {
            info!("✅ WhatsApp bot initialized");
            bot
        }
        Err(e) => {
            error!("❌ Failed to initialize WhatsApp bot: {}", e);
            return Err(e);
        }
    };

    // Check connection status and show QR code if needed
    info!("🔍 Checking WhatsApp connection status...");
    match whatsapp_bot.show_qr_code_if_needed().await {
        Ok(qr_displayed) => {
            if qr_displayed {
                info!("📱 QR code displayed. Please scan with your WhatsApp mobile app.");

                // Attempt to connect
                if let Err(e) = whatsapp_bot.connect().await {
                    error!("❌ Failed to initiate WhatsApp connection: {}", e);
                }

                // Wait for connection
                info!("⏳ Waiting for WhatsApp connection...");
                match whatsapp_bot
                    .wait_for_connection(args.max_connection_attempts)
                    .await
                {
                    Ok(true) => {
                        info!("🎉 Successfully connected to WhatsApp!");
                    }
                    Ok(false) => {
                        error!(
                            "⏰ WhatsApp connection timed out after {} attempts",
                            args.max_connection_attempts
                        );
                        error!("💡 Try scanning the QR code again or restart the bot");
                        return Err(anyhow::anyhow!("WhatsApp connection timeout"));
                    }
                    Err(e) => {
                        error!("❌ Error while waiting for WhatsApp connection: {}", e);
                        return Err(e);
                    }
                }
            } else {
                info!("✅ Already connected to WhatsApp");
            }
        }
        Err(e) => {
            error!("❌ Failed to check WhatsApp connection: {}", e);
            return Err(e);
        }
    }

        info!("🎯 Zoe WhatsApp Bot is ready!");
    info!("📱 WhatsApp: Connected");
    info!("🔗 Zoe Network: Connected");
    
    // Handle subcommands
    match args.command {
        Some(Commands::Listen { 
            show_timestamps, 
            show_ids, 
            filter_sender, 
            filter_chat, 
            groups_only, 
            dm_only 
        }) => {
            run_listen_command(
                &whatsapp_bot,
                show_timestamps,
                show_ids,
                filter_sender,
                filter_chat,
                groups_only,
                dm_only,
            ).await?;
        }
        None => {
            // Default behavior - run as bridge bot
            info!("🔄 Bot running in bridge mode... Press Ctrl+C to stop");
            info!("💡 Use 'zoe-wa-bot listen' to just monitor messages");
            
            // TODO: Implement bot logic here
            // - Listen for WhatsApp messages
            // - Bridge messages to/from Zoe network
            // - Handle commands and interactions
            
            // Keep the bot running
            tokio::signal::ctrl_c().await?;
            info!("🛑 Shutdown signal received. Stopping bot...");
        }
    }
    
    Ok(())
}

/// Run the listen command to monitor incoming WhatsApp messages
async fn run_listen_command(
    whatsapp_bot: &ZoeWhatsAppBot,
    show_timestamps: bool,
    show_ids: bool,
    filter_sender: Option<String>,
    filter_chat: Option<String>,
    groups_only: bool,
    dm_only: bool,
) -> Result<()> {
    info!("👂 Starting WhatsApp message listener...");
    
    // Validate conflicting options
    if groups_only && dm_only {
        error!("❌ Cannot use both --groups-only and --dm-only");
        return Err(anyhow::anyhow!("Conflicting filter options"));
    }
    
    // Start message stream
    let mut message_stream = match whatsapp_bot.message_stream() {
        Ok(stream) => {
            info!("✅ Message stream started successfully");
            stream
        }
        Err(e) => {
            error!("❌ Failed to start message stream: {}", e);
            return Err(e);
        }
    };
    
    // Print filter information
    print_filter_info(&filter_sender, &filter_chat, groups_only, dm_only);
    
    info!("🔄 Listening for messages... Press Ctrl+C to stop");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Handle messages and shutdown signal concurrently
    tokio::select! {
        _ = async {
            while let Some(message) = message_stream.next().await {
                // Apply filters
                if should_display_message(&message, &filter_sender, &filter_chat, groups_only, dm_only) {
                    display_message(&message, show_timestamps, show_ids);
                }
            }
        } => {
            info!("📨 Message stream ended");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Shutdown signal received. Stopping listener...");
        }
    }
    
    // Clean up message stream
    if let Err(e) = whatsapp_bot.stop_message_stream() {
        error!("⚠️ Failed to stop message stream cleanly: {}", e);
    }
    
    info!("👋 Message listener stopped");
    Ok(())
}

/// Print information about active filters
fn print_filter_info(
    filter_sender: &Option<String>,
    filter_chat: &Option<String>,
    groups_only: bool,
    dm_only: bool,
) {
    let mut filters = Vec::new();
    
    if let Some(sender) = filter_sender {
        filters.push(format!("sender contains '{}'", sender));
    }
    
    if let Some(chat) = filter_chat {
        filters.push(format!("chat contains '{}'", chat));
    }
    
    if groups_only {
        filters.push("groups only".to_string());
    }
    
    if dm_only {
        filters.push("direct messages only".to_string());
    }
    
    if !filters.is_empty() {
        info!("🔍 Active filters: {}", filters.join(", "));
    } else {
        info!("🔍 No filters active - showing all messages");
    }
}

/// Display a message in the terminal with formatting
fn display_message(
    message: &whatsmeow::MessageEvent,
    show_timestamps: bool,
    show_ids: bool,
) {
    use chrono::{DateTime, Utc};
    
    let mut output = String::new();
    
    // Add timestamp if requested
    if show_timestamps {
        let datetime = DateTime::from_timestamp(message.timestamp, 0)
            .unwrap_or_else(|| Utc::now());
        output.push_str(&format!("[{}] ", datetime.format("%H:%M:%S")));
    }
    
    // Add message ID if requested
    if show_ids {
        output.push_str(&format!("[{}] ", &message.id[..8])); // Show first 8 chars of ID
    }
    
    // Determine message source type
    let is_group = message.chat.contains("-") && message.chat.contains("@g.us");
    let source_icon = if is_group { "👥" } else { "👤" };
    
    // Format sender name (extract from JID)
    let sender_name = extract_name_from_jid(&message.sender);
    let chat_name = if is_group {
        extract_name_from_jid(&message.chat)
    } else {
        sender_name.clone()
    };
    
    // Add message type icon
    let type_icon = match message.message_type.as_str() {
        "text" => "💬",
        "image" => "🖼️",
        "video" => "🎥",
        "audio" => "🎵",
        "document" => "📄",
        _ => "📨",
    };
    
    // Build the message display
    if is_group {
        output.push_str(&format!(
            "{} {} {} in {}: {}",
            source_icon, type_icon, sender_name, chat_name, message.content
        ));
    } else {
        output.push_str(&format!(
            "{} {} {}: {}",
            source_icon, type_icon, sender_name, message.content
        ));
    }
    
    // Add "from me" indicator
    if message.is_from_me {
        output.push_str(" (sent by me)");
    }
    
    println!("{}", output);
}