use anyhow::Result;
use clap::{Parser, Subcommand};
use futures::StreamExt;
use std::sync::Arc;
use tracing::{error, info, warn};
use zoe_client::cli::{
    RelayClientArgs, RelayClientDefaultCommands, full_cli_client, main_setup, run_default_command,
    run_with_health_check,
};
use zoe_wa_bot::{
    WhatsAppBot, ZoeWhatsAppBotBuilder,
    bot::ZoeBridgeBot,
    bridge_event::BridgeEvent,
    connectable::{WhatsAppBotExt, connect_whatsapp_bot},
    util::{extract_name_from_jid, should_display_message},
};
use zoe_wire_protocol::{PqxdhInboxProtocol, VerifyingKey};

/// Helper function to parse hex string to VerifyingKey
fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let hex = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {e}"))?;
    let key: VerifyingKey =
        VerifyingKey::try_from(hex.as_slice()).map_err(|e| format!("Invalid key: {e}"))?;
    Ok(key)
}

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
    /// Common relay client commands
    #[command(flatten)]
    Default(RelayClientDefaultCommands),
    /// Bridge mode: Listen for WhatsApp messages and PQXDH connections (default behavior)
    Bridge {
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
    /// Run PQXDH service to accept secure connections
    PqxdhService,
    /// Force publish PQXDH inbox (overwriting existing one)
    ForcePublishInbox,
    /// Test PQXDH connection to another WhatsApp bot
    TestPqxdhConnection {
        /// Target bot's public key in hex format
        #[arg(long, value_parser = parse_verifying_key)]
        target_public_key: zoe_wire_protocol::VerifyingKey,
        /// Message to send to the target bot
        #[arg(long, default_value = "Hello from Zoe WhatsApp Bot!")]
        message: String,
        /// Wait for response timeout in seconds
        #[arg(long, default_value = "10")]
        timeout_seconds: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    main_setup()
        .await
        .map_err(|e| anyhow::anyhow!("Setup failed: {}", e))?;

    let args = ZoeWhatsappBotArgs::parse();

    // Extract health check port from relay args
    let health_check_port = args.relay_args.health_check_port;

    // Run with health check support
    run_with_health_check(
        health_check_port,
        || async move { run_whatsapp_bot(args).await },
    )
    .await
    .map_err(|e| anyhow::anyhow!("Bot failed: {}", e))
}

async fn run_whatsapp_bot(args: ZoeWhatsappBotArgs) -> Result<(), Box<dyn std::error::Error>> {
    let arg = match args.command {
        Some(Commands::Default(default_cmd)) => {
            run_default_command(&default_cmd).await?;
            return Ok(());
        }
        Some(cmd) => cmd,
        None => {
            // Default to Bridge mode
            Commands::Bridge {
                show_timestamps: false,
                show_ids: false,
                filter_sender: None,
                filter_chat: None,
                groups_only: false,
                dm_only: false,
            }
        }
    };

    info!("🚀 Starting Zoe WhatsApp Bot");

    // Initialize Zoe client
    info!("🔗 Connecting to Zoe network...");
    let zoe_client = full_cli_client(args.relay_args)
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    info!("✅ Connected to Zoe network");

    // Initialize WhatsApp bot
    info!("📱 Initializing WhatsApp bot...");
    if let Some(ref db_path) = args.whatsapp_db_path {
        info!("💾 Using WhatsApp database: {}", db_path);
    } else {
        info!("💾 Using default WhatsApp database: whatsapp.db");
    }
    let db_path = args.whatsapp_db_path.as_deref().unwrap_or("whatsapp.db");

    // Create bot builder
    let builder = ZoeWhatsAppBotBuilder::new().with_db_path(db_path);

    // Handle subcommands with appropriate bot type
    match arg {
        Commands::Bridge {
            show_timestamps,
            show_ids,
            filter_sender,
            filter_chat,
            groups_only,
            dm_only,
        } => {
            // Build bridge bot with full capabilities
            info!("🌉 Building bridge bot with full capabilities...");
            let bridge_bot = builder
                .build_bridge_bot(Arc::new(zoe_client))
                .await
                .map_err(|e| {
                    error!("❌ Failed to initialize bridge bot: {}", e);
                    e
                })?;
            info!("✅ Bridge bot initialized");

            // Connect to WhatsApp
            connect_whatsapp_bot(&bridge_bot, args.max_connection_attempts).await?;

            run_bridge_command(
                &bridge_bot,
                show_timestamps,
                show_ids,
                filter_sender,
                filter_chat,
                groups_only,
                dm_only,
            )
            .await?;
        }
        Commands::Listen {
            show_timestamps,
            show_ids,
            filter_sender,
            filter_chat,
            groups_only,
            dm_only,
        } => {
            // Build WhatsApp-only bot for listen mode
            info!("👂 Building WhatsApp-only bot for listen mode...");
            let listen_bot = builder.build_whatsapp_only().await.map_err(|e| {
                error!("❌ Failed to initialize WhatsApp-only bot: {}", e);
                e
            })?;
            info!("✅ WhatsApp-only bot initialized");

            // Connect to WhatsApp
            connect_whatsapp_bot(&listen_bot, args.max_connection_attempts).await?;

            run_listen_command(
                &listen_bot,
                show_timestamps,
                show_ids,
                filter_sender,
                filter_chat,
                groups_only,
                dm_only,
            )
            .await?;
        }
        Commands::PqxdhService => {
            // Build bridge bot for PQXDH service
            info!("🔐 Building bridge bot for PQXDH service...");
            let bridge_bot = builder
                .build_bridge_bot(Arc::new(zoe_client))
                .await
                .map_err(|e| {
                    error!("❌ Failed to initialize bridge bot: {}", e);
                    e
                })?;
            info!("✅ Bridge bot initialized");

            // Connect to WhatsApp
            connect_whatsapp_bot(&bridge_bot, args.max_connection_attempts).await?;

            run_pqxdh_service(&bridge_bot).await?;
        }
        Commands::ForcePublishInbox => {
            // Build bridge bot for force publishing inbox
            info!("🔐 Building bridge bot to force publish inbox...");
            let bridge_bot = builder
                .build_bridge_bot(Arc::new(zoe_client))
                .await
                .map_err(|e| {
                    error!("❌ Failed to initialize bridge bot: {}", e);
                    e
                })?;
            info!("✅ Bridge bot initialized");

            // Connect to WhatsApp
            connect_whatsapp_bot(&bridge_bot, args.max_connection_attempts).await?;

            run_force_publish_inbox(&bridge_bot).await?;
        }
        Commands::TestPqxdhConnection {
            target_public_key,
            message,
            timeout_seconds,
        } => {
            // Use relay client directly for PQXDH testing (no WhatsApp bot needed)
            info!("🔐 Testing PQXDH connection using relay client only...");
            run_test_pqxdh_connection(&zoe_client, &target_public_key, &message, timeout_seconds)
                .await?;
        }
        Commands::Default(_) => unreachable!("already implementing at the function start."),
    }

    Ok(())
}

/// Run the bridge command to handle both WhatsApp messages and PQXDH connections
async fn run_bridge_command(
    bridge_bot: &ZoeBridgeBot,
    show_timestamps: bool,
    show_ids: bool,
    filter_sender: Option<String>,
    filter_chat: Option<String>,
    groups_only: bool,
    dm_only: bool,
) -> Result<()> {
    // Print filter information
    print_filter_info(&filter_sender, &filter_chat, groups_only, dm_only);

    info!("Press Ctrl+C to stop");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Start the bridge stream
    let mut bridge_stream = bridge_bot.run_bridge().await?;

    // Main event loop
    tokio::select! {
        _ = async {
            while let Some(event) = bridge_stream.next().await {
                match event {
                    BridgeEvent::WhatsAppMessage(message) => {
                        // Apply filtering in main.rs as requested
                        if should_display_message(&message, &filter_sender, &filter_chat, groups_only, dm_only) {
                            display_message(&message, show_timestamps, show_ids);
                        }
                    }
                    BridgeEvent::PqxdhConnection { session_id, raw_data } => {
                        if let Err(e) = bridge_bot.setup_pqxdh_connection(session_id, raw_data).await {
                            error!("❌ Failed to handle PQXDH connection: {}", e);
                            // Try to clean up the session on connection error
                            if let Err(cleanup_err) = bridge_bot.handle_pqxdh_connection_loss(&session_id).await {
                                error!("❌ Failed to clean up failed session {}: {}", hex::encode(session_id), cleanup_err);
                            }
                        }
                    }
                    BridgeEvent::Error(err) => {
                        error!("❌ Bridge error: {}", err);
                    }
                }
            }
            warn!("🌉 Bridge stream ended");
        } => {}

        // Handle shutdown signal
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Shutdown signal received. Stopping bridge...");
        }
    }

    // Clean up streams
    if let Err(e) = bridge_bot.stop_message_stream() {
        error!("⚠️ Failed to stop WhatsApp message stream cleanly: {}", e);
    }

    // Clean up all active sessions
    info!("🧹 Cleaning up all active sessions...");
    if let Err(e) = bridge_bot.cleanup_all_sessions().await {
        error!("⚠️ Failed to clean up all sessions: {}", e);
    } else {
        info!("✅ All sessions cleaned up successfully");
    }

    info!("👋 Bridge mode stopped");
    Ok(())
}

/// Run the listen command to monitor incoming WhatsApp messages
async fn run_listen_command(
    listen_bot: &WhatsAppBot,
    show_timestamps: bool,
    show_ids: bool,
    filter_sender: Option<String>,
    filter_chat: Option<String>,
    groups_only: bool,
    dm_only: bool,
) -> Result<()> {
    // Print filter information
    print_filter_info(&filter_sender, &filter_chat, groups_only, dm_only);

    info!("🔄 Listening for messages... Press Ctrl+C to stop");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Start the listen stream
    let mut listen_stream = listen_bot.run_listen().await?;

    // Handle messages and shutdown signal concurrently
    tokio::select! {
        _ = async {
            while let Some(event) = listen_stream.next().await {
                match event {
                    BridgeEvent::WhatsAppMessage(message) => {
                        // Apply filtering in main.rs as requested
                        if should_display_message(&message, &filter_sender, &filter_chat, groups_only, dm_only) {
                            display_message(&message, show_timestamps, show_ids);
                        }
                    }
                    BridgeEvent::PqxdhConnection { .. } => {
                        // This shouldn't happen in listen mode, but handle gracefully
                        warn!("⚠️ Unexpected PQXDH connection in listen mode");
                    }
                    BridgeEvent::Error(err) => {
                        error!("❌ Listen error: {}", err);
                    }
                }
            }
            info!("📨 Message stream ended");
        } => {}
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Shutdown signal received. Stopping listener...");
        }
    }

    // Clean up message stream
    if let Err(e) = listen_bot.stop_message_stream() {
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
        filters.push(format!("sender contains '{sender}'"));
    }

    if let Some(chat) = filter_chat {
        filters.push(format!("chat contains '{chat}'"));
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
fn display_message(message: &whatsmeow::MessageEvent, show_timestamps: bool, show_ids: bool) {
    use chrono::{DateTime, Utc};

    let mut output = String::new();

    // Add timestamp if requested
    if show_timestamps {
        let datetime = DateTime::from_timestamp(message.timestamp, 0).unwrap_or_else(Utc::now);
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

    println!("{output}");
}

/// Run the PQXDH service to accept secure connections
async fn run_pqxdh_service(bridge_bot: &ZoeBridgeBot) -> Result<()> {
    info!("🔐 Starting PQXDH service for WhatsApp bot");

    // Display bot's public key for clients to connect
    let public_key = bridge_bot.public_key();
    match public_key.to_bytes() {
        Ok(bytes) => {
            info!("🔑 Bot Public Key: {}", hex::encode(bytes));
            info!("💡 Clients can use this key to establish PQXDH connections");
        }
        Err(e) => {
            error!("❌ Failed to serialize public key: {}", e);
        }
    }

    // Publish the PQXDH inbox (without force overwrite)
    info!("📢 Publishing PQXDH inbox...");
    let inbox_tag = bridge_bot.publish_pqxdh_inbox(false).await?;
    info!("✅ PQXDH inbox published with tag: {:?}", inbox_tag);

    // Define the message type for initial connections
    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    struct ConnectionRequest {
        client_name: String,
        message: String,
    }

    // Start listening for connections
    info!("👂 Starting PQXDH connection listener...");
    let mut connection_stream = Box::pin(
        bridge_bot
            .pqxdh_connection_stream::<ConnectionRequest>()
            .await?,
    );

    info!("🔄 Listening for PQXDH connections... Press Ctrl+C to stop");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Handle connections and shutdown signal concurrently
    tokio::select! {
        _ = async {
            while let Some((session_id, connection_request)) = connection_stream.next().await {
                info!("🔗 New PQXDH connection from: {}", connection_request.client_name);
                info!("📨 Initial message: {}", connection_request.message);
                info!("🆔 Session ID: {}", hex::encode(session_id));

                // Send a welcome response
                let response = format!("Welcome to WhatsApp Bot, {}! Your connection is established.", connection_request.client_name);
                if let Err(e) = bridge_bot.send_pqxdh_message(&session_id, &response).await {
                    error!("❌ Failed to send welcome message: {}", e);
                } else {
                    info!("✅ Sent welcome message to {}", connection_request.client_name);
                }

                println!("🔗 Connection established with: {} (Session: {})",
                    connection_request.client_name,
                    hex::encode(&session_id[..4]) // Show first 4 bytes for brevity
                );
            }
        } => {
            info!("📨 PQXDH connection stream ended");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Shutdown signal received. Stopping PQXDH service...");
        }
    }

    info!("👋 PQXDH service stopped");
    Ok(())
}

/// Force publish PQXDH inbox (overwriting existing one)
async fn run_force_publish_inbox(bridge_bot: &ZoeBridgeBot) -> Result<()> {
    info!("🔐 Force publishing PQXDH inbox for WhatsApp bot");

    // Display bot's public key for clients to connect
    let public_key = bridge_bot.public_key();
    match public_key.to_bytes() {
        Ok(bytes) => {
            info!("🔑 Bot Public Key: {}", hex::encode(bytes));
            info!("💡 Clients can use this key to establish PQXDH connections");
        }
        Err(e) => {
            error!("❌ Failed to serialize public key: {}", e);
        }
    }

    // Force publish the PQXDH inbox (with overwrite)
    info!("📢 Force publishing PQXDH inbox (overwriting existing)...");
    let inbox_tag = bridge_bot.publish_pqxdh_inbox(true).await?;
    info!("✅ PQXDH inbox force published with tag: {:?}", inbox_tag);

    info!("🎉 Force publish completed successfully");
    Ok(())
}

/// Test PQXDH connection to another WhatsApp bot
async fn run_test_pqxdh_connection(
    zoe_client: &zoe_client::Client,
    target_public_key: &VerifyingKey,
    message: &str,
    timeout_seconds: u64,
) -> Result<()> {
    info!("🤖 Testing PQXDH connection to another WhatsApp bot");
    info!(
        "🔑 Target bot public key: {}",
        hex::encode(target_public_key.to_bytes()?)
    );
    info!("💬 Message to send: {}", message);

    // Get session manager and create PQXDH handler for WhatsApp bot protocol
    let session_manager = zoe_client.session_manager().await;
    let pqxdh_handler = session_manager
        .pqxdh_handler(PqxdhInboxProtocol::WhatsAppBot)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get PQXDH handler: {}", e))?;

    info!("🔐 PQXDH handler created for WhatsApp bot protocol");

    // Define the initial message structure that matches what the bot expects
    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    struct ClientMessage {
        client_name: String,
        message: String,
    }

    // Define the expected welcome response structure
    #[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
    struct ConnectionWelcome {
        message: String,
        bot_type: String,
        capabilities: Vec<String>,
    }

    let client_message = ClientMessage {
        client_name: "Zoe WhatsApp Bot (Test Client)".to_string(),
        message: message.to_string(),
    };

    info!("📡 Establishing PQXDH connection to target WhatsApp bot...");

    // Connect to the target bot and send initial message
    let (session_id, response_stream) = pqxdh_handler
        .connect_to_service::<ClientMessage, ConnectionWelcome>(target_public_key, &client_message)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to target WhatsApp bot: {}", e))?;

    info!("✅ PQXDH connection established!");
    info!("🆔 Session ID: {}", hex::encode(session_id));

    // Pin the stream to make it work with timeout
    let mut response_stream = Box::pin(response_stream);

    // Wait for welcome response with timeout
    info!("👂 Waiting for welcome response from target WhatsApp bot...");

    let timeout_duration = tokio::time::Duration::from_secs(timeout_seconds);
    let response_result = tokio::time::timeout(timeout_duration, response_stream.next()).await;

    match response_result {
        Ok(Some(welcome)) => {
            info!("🎉 Received welcome response from target WhatsApp bot!");
            info!("📝 Welcome message: {}", welcome.message);
            info!("🤖 Bot type: {}", welcome.bot_type);
            info!("🔧 Capabilities: {:?}", welcome.capabilities);

            // Verify this is the expected welcome message
            if welcome.bot_type == "whatsapp-bridge"
                && welcome.message.contains("Welcome to Zoe WhatsApp Bot")
            {
                info!(
                    "✅ Connection test PASSED! Target bot responded with expected welcome message."
                );
            } else {
                warn!(
                    "⚠️ Connection test PARTIAL: Target bot responded but with unexpected content."
                );
            }
        }
        Ok(None) => {
            error!(
                "❌ Connection test FAILED: No response received from target bot (stream ended)"
            );
            return Err(anyhow::anyhow!("No response received from target bot"));
        }
        Err(_) => {
            error!(
                "❌ Connection test FAILED: Timeout waiting for response after {} seconds",
                timeout_seconds
            );
            return Err(anyhow::anyhow!(
                "Timeout waiting for response after {} seconds",
                timeout_seconds
            ));
        }
    }

    info!("🏁 WhatsApp bot PQXDH connection test completed successfully");
    Ok(())
}
