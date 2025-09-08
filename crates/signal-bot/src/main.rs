use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{error, info};
use zoe_client::cli::{
    RelayClientArgs, RelayClientDefaultCommands, full_cli_client, main_setup, run_default_command,
    run_with_health_check,
};
use zoe_signal_bot::SignalBot;

/// Signal Bot CLI - A command-line Signal client
#[derive(Parser, Debug)]
#[command(name = "zoe-signal-bot")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Zoe Signal Bot - Bridge Signal with Zoe network")]
struct ZoeSignalBotArgs {
    #[command(flatten)]
    relay_args: RelayClientArgs,

    /// Path to the database directory
    #[arg(long, default_value = "signal-bot-data")]
    data_dir: PathBuf,

    /// Maximum attempts to wait for Signal connection
    #[arg(long, default_value = "10")]
    max_connection_attempts: u32,

    /// Skip Signal setup for testing
    #[arg(long)]
    skip_signal_setup: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Common relay client commands
    #[command(flatten)]
    Default(RelayClientDefaultCommands),
    /// Listen for incoming Signal messages and display them in the terminal
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

        /// Only show messages from groups
        #[arg(long)]
        groups_only: bool,

        /// Only show direct messages (not from groups)
        #[arg(long)]
        dm_only: bool,
    },
    /// Send a message to a contact
    Send {
        /// Recipient UUID
        #[arg(long)]
        to: String,
        /// Message content
        #[arg(long)]
        message: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    main_setup()
        .await
        .map_err(|e| anyhow::anyhow!("Setup failed: {}", e))?;

    let args = ZoeSignalBotArgs::parse();

    // Extract health check port from relay args
    let health_check_port = args.relay_args.health_check_port;

    // Run with health check support
    run_with_health_check(
        health_check_port,
        || async move { run_signal_bot(args).await },
    )
    .await
    .map_err(|e| anyhow::anyhow!("Bot failed: {}", e))
}

async fn run_signal_bot(args: ZoeSignalBotArgs) -> Result<(), Box<dyn std::error::Error>> {
    info!("🚀 Starting Zoe Signal Bot");
    let arg = match args.command {
        Commands::Default(default_cmd) => {
            run_default_command(&default_cmd).await?;
            return Ok(());
        },
        _ => args.command
    };

    // Initialize Zoe client
    info!("🔗 Connecting to Zoe network...");
    let _zoe_client = full_cli_client(args.relay_args).await?;
    info!("✅ Connected to Zoe network");

    // Ensure data directory exists
    if !args.data_dir.exists() {
        std::fs::create_dir_all(&args.data_dir)?;
        info!("💾 Created data directory: {:?}", args.data_dir);
    }

    // Initialize Signal bot
    info!("📱 Initializing Signal bot...");
    let mut signal_bot = match SignalBot::new(args.data_dir.clone()).await {
        Ok(bot) => {
            info!("✅ Signal bot initialized (already registered)");
            bot
        }
        Err(_) => {
            info!("📱 No registered Signal account found, starting device linking...");

            if args.skip_signal_setup {
                error!("❌ Signal setup skipped but no registered account found");
                return Err(anyhow::anyhow!("Signal account required").into());
            }

            // Show QR code and wait for linking
            info!("📱 QR code will be displayed. Please scan with your Signal mobile app.");

            match SignalBot::link_and_run(args.data_dir).await {
                Ok(bot) => {
                    info!("🎉 Successfully linked Signal device!");
                    bot
                }
                Err(e) => {
                    error!("❌ Failed to link Signal device: {}", e);
                    error!("💡 Make sure to scan the QR code within 5 minutes");
                    return Err(e.into());
                }
            }
        }
    };

    info!("🎯 Zoe Signal Bot is ready!");
    info!("📱 Signal: Connected");
    info!("🔗 Zoe Network: Connected");

    // Handle subcommands
    match arg {
        Commands::Listen {
            show_timestamps,
            show_ids,
            filter_sender,
            groups_only,
            dm_only,
        } => {
            run_listen_command(
                &mut signal_bot,
                show_timestamps,
                show_ids,
                filter_sender,
                groups_only,
                dm_only,
            )
            .await?;
        }
        Commands::Send { to, message } => {
            info!("📤 Sending message to {}: {}", to, message);
            signal_bot.send_message(&to, &message).await?;
            info!("✅ Message sent successfully");
        }
        Commands::Default(_) => unreachable!("already implemented at the function start."),
    }

    Ok(())
}

/// Run the listen command to monitor incoming Signal messages
async fn run_listen_command(
    signal_bot: &mut SignalBot,
    show_timestamps: bool,
    show_ids: bool,
    filter_sender: Option<String>,
    groups_only: bool,
    dm_only: bool,
) -> Result<()> {
    info!("👂 Starting Signal message listener...");

    // Validate conflicting options
    if groups_only && dm_only {
        error!("❌ Cannot use both --groups-only and --dm-only");
        return Err(anyhow::anyhow!("Conflicting filter options"));
    }

    // Print filter information
    print_filter_info(&filter_sender, groups_only, dm_only);

    info!("🔄 Listening for messages... Press Ctrl+C to stop");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Handle messages and shutdown signal concurrently
    tokio::select! {
        result = signal_bot.run_with_filter(filter_sender, groups_only, dm_only, show_timestamps, show_ids) => {
            if let Err(e) = result {
                error!("❌ Error in message listener: {}", e);
                return Err(e);
            }
            info!("📨 Message stream ended");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Shutdown signal received. Stopping listener...");
        }
    }

    info!("👋 Message listener stopped");
    Ok(())
}

/// Print information about active filters
fn print_filter_info(filter_sender: &Option<String>, groups_only: bool, dm_only: bool) {
    let mut filters = Vec::new();

    if let Some(sender) = filter_sender {
        filters.push(format!("sender contains '{}'", sender));
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
