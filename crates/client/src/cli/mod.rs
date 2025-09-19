use crate::{Client, ClientError, util::resolve_to_socket_addr};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use zoe_wire_protocol::VerifyingKey;

#[derive(Parser, Debug)]
pub struct RelayClientArgs {
    /// Relay server address (e.g., "127.0.0.1:8080")
    #[arg(
        short,
        long,
        env = "ZOE_RELAY_ADDRESS",
        default_value = "127.0.0.1:13908"
    )]
    pub relay_address: String,

    /// Server public key in hex format
    #[arg(short, long, value_parser = parse_verifying_key, conflicts_with = "server_key_file")]
    pub server_key: Option<VerifyingKey>,

    /// Path to file containing server public key in hex format
    #[arg(long, env = "ZOE_SERVER_KEY_FILE", conflicts_with = "server_key")]
    pub server_key_file: Option<PathBuf>,

    #[arg(short, long, conflicts_with = "ephemeral")]
    pub persist_path: Option<PathBuf>,

    #[arg(short, long, env = "ZOE_EPHEMERAL", conflicts_with = "persist_path")]
    pub ephemeral: bool,

    /// Enable health check server on specified port
    #[arg(long, env = "ZOE_HEALTH_CHECK_PORT")]
    pub health_check_port: Option<u16>,
}

#[derive(Subcommand, Debug)]
pub enum RelayClientDefaultCommands {
    /// Perform health check (for Docker health checks)
    HealthCheck {
        /// Health check port (defaults to ZOE_HEALTH_CHECK_PORT env var or 8080)
        #[arg(long, env = "ZOE_HEALTH_CHECK_PORT", default_value = "8080")]
        port: u16,
    },
    #[cfg(feature = "health-bridge")]
    /// Run HTTP health bridge server
    HealthBridge {
        /// HTTP port to bind the health bridge to
        #[arg(long, env = "ZOE_HEALTH_HTTP_PORT", default_value = "8083")]
        http_port: u16,
        /// Health check port for bots (ignored for relay)
        #[arg(long, env = "ZOE_HEALTH_CHECK_PORT", default_value = "8080")]
        health_check_port: u16,
        /// Relay address for relay health checks
        #[arg(long, env = "ZOE_TARGET_ADDRESS", default_value = "127.0.0.1")]
        target_address: String,
    },
}

/// Helper function to parse hex string to VerifyingKey (simplified for demo)
fn parse_verifying_key(hex_str: &str) -> Result<VerifyingKey, String> {
    let hex = hex::decode(hex_str).map_err(|e| format!("Invalid hex string: {e}"))?;
    let key: VerifyingKey = postcard::from_bytes(&hex).map_err(|e| format!("Invalid key: {e}"))?;
    Ok(key)
}

/// Common setup to be done in a client cli
pub async fn main_setup() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize Rustls crypto provider before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("full=info")),
        )
        .init();

    Ok(())
}

pub async fn run_default_command(
    cmd: &RelayClientDefaultCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        RelayClientDefaultCommands::HealthCheck { port } => run_health_check_command(*port).await,
        #[cfg(feature = "health-bridge")]
        RelayClientDefaultCommands::HealthBridge {
            http_port,
            target_address,
            health_check_port,
        } => run_health_bridge(*http_port, target_address.clone(), *health_check_port).await,
    }
}

pub async fn full_cli_client(args: RelayClientArgs) -> Result<Client, ClientError> {
    info!("🚀 Starting Zoe Client Connection Test");
    info!("📍 Target server: {}", args.relay_address);

    let server_addr: SocketAddr = match resolve_to_socket_addr(&args.relay_address).await {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid server address or failed to resolve: {e}");
            std::process::exit(1);
        }
    };

    // Get server public key from either direct argument or file
    let server_public_key = if let Some(file_path) = args.server_key_file {
        info!("📖 Reading server public key from: {}", file_path.display());
        let content = std::fs::read_to_string(&file_path).map_err(|e| {
            ClientError::BuildError(format!(
                "Failed to read key file {}: {e}",
                file_path.display()
            ))
        })?;
        VerifyingKey::from_pem(&content).map_err(|e| {
            ClientError::BuildError(format!(
                "Failed to parse key file {}: {e}",
                file_path.display()
            ))
        })?
    } else if let Some(key) = args.server_key {
        key
    } else {
        error!("Must specify either --server-key or --server-key-file");
        std::process::exit(1);
    };

    let mut builder = Client::builder();
    // Don't use autoconnect - we'll manually establish the connection to ensure it's ready
    builder.autoconnect(false);

    if let Some(persist_path) = args.persist_path {
        info!("💾 Using persistent storage at: {}", persist_path.display());
        error!("persistence not yet implemented");
    } else if !args.ephemeral {
        error!("💾 Must specify either --persist-path or --ephemeral");
        std::process::exit(1);
    } else {
        // ephemeral mode

        let temp_dir = TempDir::new()?;
        // Create temporary directories for storage

        info!(
            "💾 Using temporary storage at: {}",
            temp_dir.path().display()
        );
        let media_storage_path = temp_dir.path().join("blobs");
        let db_storage_path = temp_dir.path().join("db");

        info!("🔧 Building client...");

        // Build the client
        builder.media_storage_dir_pathbuf(media_storage_path);
        builder.db_storage_dir_pathbuf(db_storage_path);
    }

    let client = builder.build().await?;

    // Now manually establish the relay connection and wait for it to be ready
    info!("🔗 Establishing relay connection...");
    use zoe_app_primitives::connection::RelayAddress;
    let relay_address = RelayAddress::new(server_public_key)
        .with_address(server_addr.into())
        .with_name("CLI Server".to_string());

    client.add_relay(relay_address).await?;

    // Wait for the connection to be established
    info!("⏳ Waiting for relay connection to be ready...");
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 50; // 5 seconds total (50 * 100ms)

    while attempts < MAX_ATTEMPTS {
        if client.has_connected_relays().await {
            info!("✅ Relay connection established successfully");
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        attempts += 1;
    }

    if attempts >= MAX_ATTEMPTS {
        return Err(ClientError::Generic(
            "Failed to establish relay connection within timeout".to_string(),
        ));
    }

    Ok(client)
}

/// Health check server that responds to ping requests
pub struct HealthCheckServer {
    listener: TcpListener,
    port: u16,
}

impl HealthCheckServer {
    /// Create a new health check server on the specified port
    pub async fn new(port: u16) -> Result<Self, std::io::Error> {
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = TcpListener::bind(addr).await?;
        info!("🏥 Health check server listening on {}", addr);
        Ok(Self { listener, port })
    }

    /// Get the port the server is listening on
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Run the health check server
    pub async fn run(&self) -> Result<(), std::io::Error> {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    tokio::spawn(async move {
                        if let Err(e) = handle_health_check_connection(stream).await {
                            warn!("Health check connection error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept health check connection: {}", e);
                    return Err(e);
                }
            }
        }
    }
}

/// Handle a single health check connection
async fn handle_health_check_connection(mut stream: TcpStream) -> Result<(), std::io::Error> {
    let mut buffer = [0; 1024];

    // Read the request
    let bytes_read = stream.read(&mut buffer).await?;
    if bytes_read == 0 {
        return Ok(()); // Connection closed
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let request = request.trim();

    // Simple protocol: respond to "ping" with "pong"
    let response = match request {
        "ping" => "pong\n",
        "health" => "ok\n",
        "status" => "running\n",
        _ => "unknown\n",
    };

    // Send response
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

/// Run a bot with health check support
/// This function combines the main bot logic with a health check server
pub async fn run_with_health_check<F, Fut>(
    health_check_port: Option<u16>,
    main_task: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    if let Some(port) = health_check_port {
        // Create health check server
        let health_server = HealthCheckServer::new(port).await?;
        info!("🏥 Health check enabled on port {}", port);

        // Run both the main task and health check server concurrently
        tokio::select! {
            result = main_task() => {
                info!("🛑 Main task completed");
                result
            }
            result = health_server.run() => {
                error!("🏥 Health check server stopped unexpectedly");
                result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
        }
    } else {
        // Run only the main task
        main_task().await
    }
}

async fn health_check_ping(addr: SocketAddr) -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect(addr).await?;

    // Send ping
    stream.write_all(b"ping").await?;
    stream.flush().await?;

    // Read response
    let mut buffer = [0; 1024];
    let bytes_read = stream.read(&mut buffer).await?;

    let response = String::from_utf8_lossy(&buffer[..bytes_read])
        .trim()
        .to_string();

    if response == "pong" {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "Health check failed. Unexpected response: {response}",
        ))
    }
}

/// Perform a health check and exit with appropriate code
/// This is designed to be used as a Docker health check command
pub async fn run_health_check_command(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    health_check_ping(addr).await?;
    Ok(())
}

// Health bridge implementation (
#[cfg(feature = "health-bridge")]
mod health_bridge {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tokio::time::{Duration, interval};
    use warp::Filter;

    /// Health status for the bridge
    #[derive(Clone, Debug)]
    pub struct HealthStatus {
        pub is_healthy: bool,
        pub last_check: std::time::SystemTime,
        pub error_message: Option<String>,
    }

    impl HealthStatus {
        pub fn new() -> Self {
            Self {
                is_healthy: false,
                last_check: std::time::SystemTime::now(),
                error_message: None,
            }
        }
    }

    /// Run HTTP health bridge server
    pub async fn run_health_bridge(
        http_port: u16,
        target_address: String,
        health_check_port: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        info!("🌉 Starting HTTP Health Bridge on port {}", http_port);
        let target_addr: std::net::IpAddr = target_address.parse()?;
        let target_address = SocketAddr::from((target_addr, health_check_port));

        // Shared health status
        let health_status = Arc::new(RwLock::new(HealthStatus::new()));

        // Start background health checker
        let health_checker = {
            let health_status = health_status.clone();

            tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(30));
                loop {
                    interval.tick().await;
                    let ping = health_check_ping(target_address).await;
                    let mut status = health_status.write().await;
                    let is_healthy = ping.is_ok();
                    status.is_healthy = is_healthy;
                    status.last_check = std::time::SystemTime::now();
                    status.error_message = ping.err().map(|e| e.to_string());

                    if is_healthy {
                        info!("✅ health check passed");
                    } else {
                        warn!("❌ health check failed: {:?}", status.error_message);
                    }
                }
            })
        };

        // HTTP routes
        let health_status_filter = warp::any().map(move || health_status.clone());

        let health = warp::path("health")
            .and(warp::get())
            .and(health_status_filter.clone())
            .and_then(handle_health_endpoint);

        let status = warp::path("status")
            .and(warp::get())
            .and(health_status_filter.clone())
            .and_then(handle_status_endpoint);

        let routes = health.or(status);

        // Start HTTP server
        let server = warp::serve(routes).run(([0, 0, 0, 0], http_port));

        info!("🚀 Health bridge ready on port {}", http_port);

        // Run both the server and health checker
        tokio::select! {
            _ = server => {
                error!("HTTP server stopped unexpectedly");
            }
            _ = health_checker => {
                error!("Health checker stopped unexpectedly");
            }
        }

        Ok(())
    }

    /// Handle /health endpoint
    async fn handle_health_endpoint(
        health_status: Arc<RwLock<HealthStatus>>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let status = health_status.read().await;

        if status.is_healthy {
            Ok(warp::reply::with_status("OK", warp::http::StatusCode::OK))
        } else {
            Ok(warp::reply::with_status(
                "ERROR",
                warp::http::StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }

    /// Handle /status endpoint (detailed JSON)
    async fn handle_status_endpoint(
        health_status: Arc<RwLock<HealthStatus>>,
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let status = health_status.read().await;
        let last_check_ago = status
            .last_check
            .elapsed()
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        let response = json!({
            "status": if status.is_healthy { "healthy" } else { "unhealthy" },
            "last_check_seconds_ago": last_check_ago,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "error": status.error_message
        });

        let status_code = if status.is_healthy {
            warp::http::StatusCode::OK
        } else {
            warp::http::StatusCode::SERVICE_UNAVAILABLE
        };

        Ok(warp::reply::with_status(
            warp::reply::json(&response),
            status_code,
        ))
    }
}

#[cfg(feature = "health-bridge")]
pub use health_bridge::run_health_bridge;
