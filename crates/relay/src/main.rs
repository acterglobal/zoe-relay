use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use tracing::info;
use zoe_relay::ZoeRelayServer;
use zoe_wire_protocol::{Algorithm, KeyPair};

/// Zoe Relay Server - QUIC relay with ed25519 authentication
#[derive(Parser)]
#[command(name = "zoe-relay")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Zoe Relay Server")]
struct Cli {
    /// Server bind interface
    #[arg(
        short = 'i',
        long = "interface",
        env = "ZOERELAY_INTERFACE",
        default_value = "127.0.0.1"
    )]
    interface: String,

    /// Server bind port
    #[arg(
        short = 'p',
        long = "port",
        env = "ZOERELAY_PORT",
        default_value = "13908"
    )]
    port: u16,

    /// Blob storage directory
    #[arg(
        short = 'b',
        long = "blob-dir",
        env = "ZOERELAY_BLOB_DIR",
        default_value = "./blob-store-data"
    )]
    blob_dir: PathBuf,

    /// Redis URL
    #[arg(
        long = "redis-url",
        env = "ZOERELAY_REDIS_URL",
        default_value = "redis://127.0.0.1:6379"
    )]
    redis_url: String,

    /// Private key for the server (PEM format)
    #[arg(short = 'k', long = "private-key", env = "ZOERELAY_PRIVATE_KEY")]
    private_key: Option<String>,

    /// Show the server key
    #[arg(long = "show-key")]
    show_key: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new server key and exit
    GenerateKey {
        /// Algorithm to use for the key
        #[arg(short = 'a', long = "algorithm", env = "ZOERELAY_KEY_ALGORITHM", default_value = "ed25519", value_parser = parse_algorithm)]
        algorithm: Algorithm,
    },
}

fn parse_algorithm(s: &str) -> Result<Algorithm, String> {
    match s.to_lowercase().as_str() {
        "ed25519" | "ed-25519" => Ok(Algorithm::Ed25519),
        // "ml-dsa-44" => Ok(Algorithm::MlDsa44),
        // "ml-dsa-65" | "ml-dsa" => Ok(Algorithm::MlDsa65),
        // "ml-dsa-87"  => Ok(Algorithm::MlDsa87),
        _ => Err(format!(
            "Invalid algorithm: {}. We only support Ed25519 at the moment.",
            s
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with default info level if RUST_LOG is not set
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // Handle subcommands
    if let Some(command) = cli.command {
        match command {
            Commands::GenerateKey { algorithm } => {
                let server_keypair =
                    KeyPair::generate_for_algorithm(algorithm, &mut rand::thread_rng());
                let pem_string = server_keypair
                    .to_pem()
                    .map_err(|e| anyhow::anyhow!("Failed to encode keypair to PEM: {}", e))?;

                println!("Generated server keypair ({}):", algorithm);
                println!(
                    "Public key ID: {}",
                    hex::encode(server_keypair.public_key().id())
                );
                println!("\nPrivate key (PEM format):");
                println!("{}", pem_string);
                println!("\nTo use this key, set the ZOERELAY_PRIVATE_KEY environment variable:");
                println!(
                    "export ZOERELAY_PRIVATE_KEY='{}'",
                    pem_string.replace('\n', "\\n")
                );

                return Ok(());
            }
        }
    }

    let address = SocketAddr::from((cli.interface.parse::<IpAddr>()?, cli.port));

    // Load or generate server keypair
    let server_keypair = if let Some(private_key_pem) = cli.private_key {
        // Load keypair from PEM string (from environment variable or command line)
        KeyPair::from_pem(&private_key_pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse private key PEM: {}", e))?
    } else {
        // Generate a new Ed25519 keypair if no key is provided
        info!("No private key provided, generating new Ed25519 keypair");
        let server_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        if cli.show_key {
            println!("Generated server keypair ({}):", Algorithm::Ed25519);
            println!(
                "Public key ID: {}",
                hex::encode(server_keypair.public_key().id())
            );
            println!("\nPrivate key (PEM format):");
            println!(
                "{}",
                server_keypair
                    .to_pem()
                    .expect("Failed to encode keypair to PEM")
            );
        }
        server_keypair
    };

    info!("Starting Zoe Relay Server");

    let relay_server = ZoeRelayServer::builder()
        .server_keypair(server_keypair)
        .address(address)
        .redis_url(cli.redis_url.clone())
        .blob_dir(cli.blob_dir.clone())
        .build()
        .await?;

    let local_address = relay_server.local_addr()?;
    let public_key = relay_server.public_key();

    info!("Server address: {}", local_address);
    info!(
        "Server identity: #{} ({})",
        hex::encode(public_key.encode()),
        public_key.algorithm()
    );
    info!("Press Ctrl+C to stop the server");

    // Handle graceful shutdown
    let shutdown_signal = tokio::signal::ctrl_c();

    tokio::select! {
        result = relay_server.run() => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            info!("Received shutdown signal, stopping server...");
        }
    }

    info!("Server shutdown complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_algorithm() {
        assert_eq!(parse_algorithm("ed25519").unwrap(), Algorithm::Ed25519);
        assert_eq!(parse_algorithm("ed-25519").unwrap(), Algorithm::Ed25519);
        assert_eq!(parse_algorithm("ED25519").unwrap(), Algorithm::Ed25519);

        assert!(parse_algorithm("invalid").is_err());
        assert!(parse_algorithm("ml-dsa-65").is_err()); // Not supported yet
    }
}
