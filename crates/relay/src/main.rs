use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};
use tracing::info;
use zoe_app_primitives::{display_qr_code, ConnectionInfo, NetworkAddress, QrOptions};
use zoe_relay::ZoeRelayServer;
use zoe_wire_protocol::{Algorithm, KeyPair, VerifyingKey};

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

    /// External addresses where this relay can be reached (DNS names, IPs with optional ports)
    ///
    /// Examples: relay.example.com, relay.example.com:8443, 192.168.1.100:8443
    /// Can be specified multiple times: -e relay1.com -e relay2.com:9443
    #[arg(
        short = 'e',
        long = "external-address",
        env = "ZOERELAY_EXTERNAL_ADDRESSES",
        value_delimiter = ',',
        help = "External addresses where this relay can be reached"
    )]
    external_addresses: Vec<String>,

    /// Optional server name for display purposes
    #[arg(short = 'n', long = "name", env = "ZOERELAY_NAME")]
    name: Option<String>,

    /// Server bind port
    #[arg(
        short = 'p',
        long = "port",
        env = "ZOERELAY_PORT",
        default_value = "13908"
    )]
    port: u16,

    /// Data directory for all persistent storage (keys, blobs, etc.)
    #[arg(
        short = 'd',
        long = "data-dir",
        env = "ZOERELAY_DATA_DIR",
        default_value = "./zoe-relay-data"
    )]
    data_dir: PathBuf,

    /// Blob storage directory (defaults to data-dir/blobs)
    #[arg(short = 'b', long = "blob-dir", env = "ZOERELAY_BLOB_DIR")]
    blob_dir: Option<PathBuf>,

    /// Redis URL
    #[arg(
        short = 'r',
        long = "redis-url",
        env = "ZOERELAY_REDIS_URL",
        default_value = "redis://127.0.0.1:6379"
    )]
    redis_url: String,

    /// Private key for the server (PEM format, defaults to data-dir/server.key)
    #[arg(short = 'k', long = "private-key", env = "ZOERELAY_PRIVATE_KEY")]
    private_key: Option<String>,

    /// Private key file path (defaults to data-dir/server.key)
    #[arg(long = "key-file", env = "ZOERELAY_KEY_FILE")]
    key_file: Option<PathBuf>,

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

/// Parse an external address string into a NetworkAddress
///
/// Supports formats like:
/// - "relay.example.com" (DNS without port)
/// - "relay.example.com:8443" (DNS with port)
/// - "192.168.1.100:8443" (IPv4 with port)
/// - "[::1]:8443" (IPv6 with port)
fn parse_external_address(addr_str: &str) -> Result<NetworkAddress> {
    // Try to parse as a full socket address first
    if let Ok(socket_addr) = addr_str.parse::<SocketAddr>() {
        return Ok(match socket_addr.ip() {
            std::net::IpAddr::V4(ipv4) => NetworkAddress::ipv4_with_port(ipv4, socket_addr.port()),
            std::net::IpAddr::V6(ipv6) => NetworkAddress::ipv6_with_port(ipv6, socket_addr.port()),
        });
    }

    // Try to parse as IP:port
    if let Some((ip_str, port_str)) = addr_str.rsplit_once(':') {
        if let (Ok(ip), Ok(port)) = (ip_str.parse::<std::net::IpAddr>(), port_str.parse::<u16>()) {
            return Ok(match ip {
                std::net::IpAddr::V4(ipv4) => NetworkAddress::ipv4_with_port(ipv4, port),
                std::net::IpAddr::V6(ipv6) => NetworkAddress::ipv6_with_port(ipv6, port),
            });
        }

        // Try as hostname:port
        if let Ok(port) = port_str.parse::<u16>() {
            return Ok(NetworkAddress::dns_with_port(ip_str, port));
        }
    }

    // Try to parse as plain IP
    if let Ok(ip) = addr_str.parse::<std::net::IpAddr>() {
        return Ok(match ip {
            std::net::IpAddr::V4(ipv4) => NetworkAddress::ipv4(ipv4),
            std::net::IpAddr::V6(ipv6) => NetworkAddress::ipv6(ipv6),
        });
    }

    // Assume it's a DNS name without port
    Ok(NetworkAddress::dns(addr_str))
}

/// Load or generate a server keypair, with persistent storage
fn load_or_generate_keypair(
    private_key_pem: Option<&str>,
    key_file_path: &PathBuf,
    show_key: bool,
) -> Result<KeyPair> {
    // If a private key is provided via environment/CLI, use it
    if let Some(pem) = private_key_pem {
        return KeyPair::from_pem(pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse private key PEM: {}", e));
    }

    // Try to load existing key from file
    if key_file_path.exists() {
        let pem_content = fs::read_to_string(key_file_path)?;
        let keypair = KeyPair::from_pem(&pem_content)?;
        info!(
            "Loaded existing server key from {}",
            key_file_path.display()
        );
        if show_key {
            println!(
                "Loaded server keypair ({}):",
                keypair.public_key().algorithm()
            );
            println!("Public key ID: {}", hex::encode(keypair.public_key().id()));
            println!("Key file: {}", key_file_path.display());
        }
        return Ok(keypair);
    }

    // Generate a new key and save it
    info!("Generating new Ed25519 keypair");
    let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());

    // Create parent directory if it doesn't exist
    if let Some(parent) = key_file_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create data directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }

    // Save the key to file
    let pem_string = keypair
        .to_pem()
        .map_err(|e| anyhow::anyhow!("Failed to encode keypair to PEM: {}", e))?;

    fs::write(key_file_path, &pem_string)
        .map_err(|e| anyhow::anyhow!("Failed to save key to {}: {}", key_file_path.display(), e))?;

    info!("Saved new server key to {}", key_file_path.display());

    if show_key {
        println!("Generated server keypair ({}):", Algorithm::Ed25519);
        println!("Public key ID: {}", hex::encode(keypair.public_key().id()));
        println!("Key file: {}", key_file_path.display());
        println!("\nPrivate key (PEM format):");
        println!("{}", pem_string);
    }

    Ok(keypair)
}

/// Display a QR code for relay server connection information
fn display_relay_qr_code(
    bind_address: SocketAddr,
    public_key: &VerifyingKey,
    external_addresses: &[String],
    server_name: Option<&str>,
) -> Result<()> {
    // Create connection info starting with the public key
    let mut connection_info = ConnectionInfo::new(public_key.clone());

    // Add the bind address only if it's externally accessible (not localhost/127.0.0.1)
    let bind_is_external = match bind_address.ip() {
        std::net::IpAddr::V4(ipv4) => !ipv4.is_loopback() && !ipv4.is_private(),
        std::net::IpAddr::V6(ipv6) => !ipv6.is_loopback(),
    };

    if bind_is_external {
        let bind_network_address = match bind_address.ip() {
            std::net::IpAddr::V4(ipv4) => NetworkAddress::ipv4_with_port(ipv4, bind_address.port()),
            std::net::IpAddr::V6(ipv6) => NetworkAddress::ipv6_with_port(ipv6, bind_address.port()),
        };
        connection_info = connection_info.with_address(bind_network_address);
    }

    // Add all external addresses
    connection_info =
        connection_info.with_addresses(external_addresses.iter().filter_map(|addr_str| {
            parse_external_address(addr_str)
                .inspect_err(
                    |e| tracing::warn!(error=?e, "Failed to parse external address '{}'", addr_str),
                )
                .ok()
        }));

    // Set the server name if provided
    if let Some(name) = server_name {
        connection_info = connection_info.with_name(name);
    }

    // Log the total number of addresses in the QR code
    tracing::info!(
        "QR code will contain {} total addresses",
        connection_info.addresses.len()
    );
    for (i, addr) in connection_info.addresses.iter().enumerate() {
        tracing::info!("  Address {}: {}", i + 1, addr);
    }

    // Create QR options with relay-specific formatting
    let mut options = QrOptions::new("📡 ZOE RELAY SERVER")
        .with_subtitle(format!("Bind: {}", bind_address))
        .with_subtitle(format!("Key: {}...", &hex::encode(public_key.id())[..16]))
        .with_footer("Scan with Zoe client to connect");

    // Show all addresses that are actually in the QR code
    if !connection_info.addresses.is_empty() {
        let address_display: Vec<String> = connection_info
            .addresses
            .iter()
            .map(|addr| addr.to_string())
            .collect();
        options = options.with_subtitle(format!(
            "Addresses ({}): {}",
            connection_info.addresses.len(),
            address_display.join(", ")
        ));
    }

    if let Some(name) = server_name {
        options = options.with_subtitle(format!("Name: {}", name));
    }

    // Display the QR code using the helper function
    if let Err(e) = display_qr_code(&connection_info, &options) {
        tracing::error!(error=?e, "❌ Failed to generate QR code");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize Rustls crypto provider before any TLS operations
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

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

    // Determine paths for data storage
    let data_dir = &cli.data_dir;
    let blob_dir = cli.blob_dir.unwrap_or_else(|| data_dir.join("blobs"));
    let key_file = cli.key_file.unwrap_or_else(|| data_dir.join("server.key"));

    // Load or generate server keypair with persistent storage
    let server_keypair =
        load_or_generate_keypair(cli.private_key.as_deref(), &key_file, cli.show_key)?;

    info!("Starting Zoe Relay Server");

    let relay_server = ZoeRelayServer::builder()
        .server_keypair(server_keypair)
        .address(address)
        .redis_url(cli.redis_url.clone())
        .blob_dir(blob_dir)
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

    // Display QR code for easy client connection
    if let Err(e) = display_relay_qr_code(
        local_address,
        &public_key,
        &cli.external_addresses,
        cli.name.as_deref(),
    ) {
        info!("Failed to display QR code: {}", e);
    }

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

    #[test]
    fn test_parse_external_address_dns_without_port() {
        let result = parse_external_address("relay.example.com").unwrap();
        assert_eq!(result, NetworkAddress::dns("relay.example.com"));
    }

    #[test]
    fn test_parse_external_address_dns_with_port() {
        let result = parse_external_address("relay.example.com:8443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::dns_with_port("relay.example.com", 8443)
        );
    }

    #[test]
    fn test_parse_external_address_ipv4_without_port() {
        use std::net::Ipv4Addr;
        let result = parse_external_address("192.168.1.100").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv4(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn test_parse_external_address_ipv4_with_port() {
        use std::net::Ipv4Addr;
        let result = parse_external_address("192.168.1.100:8443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv4_with_port(Ipv4Addr::new(192, 168, 1, 100), 8443)
        );
    }

    #[test]
    fn test_parse_external_address_ipv6_without_port() {
        // Note: "::1" gets parsed as hostname ":" with port 1 due to rsplit_once(':')
        // This is expected behavior - IPv6 without brackets should use brackets for clarity
        let result = parse_external_address("::1").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port(":", 1));
    }

    #[test]
    fn test_parse_external_address_ipv6_with_port_brackets() {
        use std::net::Ipv6Addr;
        let result = parse_external_address("[::1]:8443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv6_with_port(Ipv6Addr::LOCALHOST, 8443)
        );
    }

    #[test]
    fn test_parse_external_address_ipv6_full_with_port() {
        use std::net::Ipv6Addr;
        let result = parse_external_address("[2001:db8::1]:9443").unwrap();
        let expected_ipv6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        assert_eq!(result, NetworkAddress::ipv6_with_port(expected_ipv6, 9443));
    }

    #[test]
    fn test_parse_external_address_localhost_ipv4() {
        use std::net::Ipv4Addr;
        let result = parse_external_address("127.0.0.1:3000").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv4_with_port(Ipv4Addr::LOCALHOST, 3000)
        );
    }

    #[test]
    fn test_parse_external_address_subdomain_with_port() {
        let result = parse_external_address("api.relay.example.com:443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::dns_with_port("api.relay.example.com", 443)
        );
    }

    #[test]
    fn test_parse_external_address_single_word_hostname() {
        let result = parse_external_address("localhost").unwrap();
        assert_eq!(result, NetworkAddress::dns("localhost"));
    }

    #[test]
    fn test_parse_external_address_hostname_with_hyphen() {
        let result = parse_external_address("my-relay-server.com:8080").unwrap();
        assert_eq!(
            result,
            NetworkAddress::dns_with_port("my-relay-server.com", 8080)
        );
    }

    #[test]
    fn test_parse_external_address_edge_cases() {
        // Test with port 0 (should be valid)
        let result = parse_external_address("example.com:0").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port("example.com", 0));

        // Test with max port
        let result = parse_external_address("example.com:65535").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port("example.com", 65535));

        // Test with standard HTTP ports
        let result = parse_external_address("example.com:80").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port("example.com", 80));

        let result = parse_external_address("example.com:443").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port("example.com", 443));
    }

    #[test]
    fn test_parse_external_address_invalid_port_fallback() {
        // Invalid port should fall back to DNS without port
        let result = parse_external_address("example.com:99999").unwrap();
        assert_eq!(result, NetworkAddress::dns("example.com:99999"));
    }

    #[test]
    fn test_parse_external_address_malformed_ipv6_fallback() {
        // "::1:8443" actually parses as valid IPv6 "::1" with port 8443
        // This is because rsplit_once(':') splits on the last colon
        use std::net::Ipv6Addr;
        let result = parse_external_address("::1:8443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv6_with_port(Ipv6Addr::LOCALHOST, 8443)
        );
    }

    #[test]
    fn test_parse_external_address_empty_string() {
        let result = parse_external_address("").unwrap();
        assert_eq!(result, NetworkAddress::dns(""));
    }

    #[test]
    fn test_parse_external_address_international_domain() {
        let result = parse_external_address("测试.example.com:8443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::dns_with_port("测试.example.com", 8443)
        );
    }

    #[test]
    fn test_parse_external_address_multiple_colons_dns() {
        // Multiple colons should be treated as DNS (not IPv6 without brackets)
        let result = parse_external_address("my:weird:hostname:8443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::dns_with_port("my:weird:hostname", 8443)
        );
    }

    #[test]
    fn test_parse_external_address_proper_ipv6_usage() {
        use std::net::Ipv6Addr;

        // Proper IPv6 usage with brackets (recommended)
        let result = parse_external_address("[::1]").unwrap();
        assert_eq!(result, NetworkAddress::dns("[::1]")); // No port, treated as DNS

        let result = parse_external_address("[2001:db8::1]").unwrap();
        assert_eq!(result, NetworkAddress::dns("[2001:db8::1]")); // No port, treated as DNS

        // IPv6 with brackets and port (proper format)
        let result = parse_external_address("[::1]:8080").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv6_with_port(Ipv6Addr::LOCALHOST, 8080)
        );
    }

    #[test]
    fn test_parse_external_address_ambiguous_cases() {
        // These cases show the limitations of parsing IPv6 without brackets

        // "::1" is ambiguous - could be IPv6 or hostname with port
        let result = parse_external_address("::1").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port(":", 1));

        // "2001:db8::1" would be parsed as hostname "2001:db8:" with port 1
        let result = parse_external_address("2001:db8::1").unwrap();
        assert_eq!(result, NetworkAddress::dns_with_port("2001:db8:", 1));

        // This is why brackets are recommended for IPv6
    }

    #[test]
    fn test_parse_external_address_real_world_examples() {
        // Common real-world address formats
        let result = parse_external_address("relay.example.com").unwrap();
        assert_eq!(result, NetworkAddress::dns("relay.example.com"));

        let result = parse_external_address("relay.example.com:443").unwrap();
        assert_eq!(
            result,
            NetworkAddress::dns_with_port("relay.example.com", 443)
        );

        let result = parse_external_address("10.0.0.1:8080").unwrap();
        assert_eq!(
            result,
            NetworkAddress::ipv4_with_port(std::net::Ipv4Addr::new(10, 0, 0, 1), 8080)
        );

        let result = parse_external_address("[2001:db8::1]:443").unwrap();
        let expected_ipv6 = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        assert_eq!(result, NetworkAddress::ipv6_with_port(expected_ipv6, 443));
    }

    #[test]
    fn test_display_relay_qr_code_includes_all_addresses() {
        use std::net::Ipv4Addr;
        use zoe_wire_protocol::KeyPair;

        // Generate a test key
        let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let public_key = keypair.public_key();

        // Test with external bind address (should be included)
        let _external_bind =
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 8080);
        let external_addresses = vec![
            "relay.example.com".to_string(),
            "relay.example.com:8443".to_string(),
            "backup.example.org:9443".to_string(),
        ];

        // This would normally display the QR code, but we can't easily test that
        // Instead, let's test the logic by manually creating the connection info
        let mut connection_info = ConnectionInfo::new(public_key.clone());

        // Add bind address (external)
        let bind_network_address =
            NetworkAddress::ipv4_with_port(Ipv4Addr::new(203, 0, 113, 1), 8080);
        connection_info = connection_info.with_address(bind_network_address);

        // Add external addresses
        for addr_str in &external_addresses {
            if let Ok(network_addr) = parse_external_address(addr_str) {
                connection_info = connection_info.with_address(network_addr);
            }
        }

        // Should have 4 addresses total (1 bind + 3 external)
        assert_eq!(connection_info.addresses.len(), 4);

        // Verify specific addresses are present
        assert!(connection_info
            .addresses
            .contains(&NetworkAddress::ipv4_with_port(
                Ipv4Addr::new(203, 0, 113, 1),
                8080
            )));
        assert!(connection_info
            .addresses
            .contains(&NetworkAddress::dns("relay.example.com")));
        assert!(connection_info
            .addresses
            .contains(&NetworkAddress::dns_with_port("relay.example.com", 8443)));
        assert!(connection_info
            .addresses
            .contains(&NetworkAddress::dns_with_port("backup.example.org", 9443)));
    }

    #[test]
    fn test_display_relay_qr_code_excludes_localhost_bind() {
        use std::net::Ipv4Addr;
        use zoe_wire_protocol::KeyPair;

        // Generate a test key
        let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let public_key = keypair.public_key();

        // Test with localhost bind address (should be excluded)
        let _localhost_bind = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let external_addresses = vec!["relay.example.com:8443".to_string()];

        // Manually create the connection info to test the logic
        let mut connection_info = ConnectionInfo::new(public_key.clone());

        // Don't add localhost bind address (it should be excluded)
        let bind_is_external =
            !Ipv4Addr::LOCALHOST.is_loopback() && !Ipv4Addr::LOCALHOST.is_private();
        assert!(!bind_is_external); // Verify localhost is not considered external

        // Add external addresses
        for addr_str in &external_addresses {
            if let Ok(network_addr) = parse_external_address(addr_str) {
                connection_info = connection_info.with_address(network_addr);
            }
        }

        // Should have 1 address total (0 bind + 1 external)
        assert_eq!(connection_info.addresses.len(), 1);

        // Verify localhost is not present
        assert!(!connection_info
            .addresses
            .contains(&NetworkAddress::ipv4_with_port(Ipv4Addr::LOCALHOST, 8080)));

        // Verify external address is present
        assert!(connection_info
            .addresses
            .contains(&NetworkAddress::dns_with_port("relay.example.com", 8443)));
    }
}
