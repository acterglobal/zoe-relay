use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::VerifyingKey;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

/// Network address information for connecting to a service
///
/// Supports multiple address types including DNS names, IPv4, and IPv6 addresses
/// with optional port specifications for maximum flexibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub enum NetworkAddress {
    /// DNS hostname with optional port
    ///
    /// Examples: "relay.example.com", "relay.example.com:8443"
    /// If no port is specified, the default port should be used.
    Dns { hostname: String, port: Option<u16> },

    /// IPv4 address with optional port
    ///
    /// Examples: "192.168.1.100", "192.168.1.100:8443"
    /// If no port is specified, the default port should be used.
    Ipv4 {
        address: Ipv4Addr,
        port: Option<u16>,
    },

    /// IPv6 address with optional port
    ///
    /// Examples: "::1", "\[::1\]:8443"
    /// If no port is specified, the default port should be used.
    Ipv6 {
        address: Ipv6Addr,
        port: Option<u16>,
    },
}

#[cfg_attr(feature = "frb-api", frb)]
impl NetworkAddress {
    /// Create a DNS network address
    pub fn dns(hostname: impl Into<String>) -> Self {
        Self::Dns {
            hostname: hostname.into(),
            port: None,
        }
    }

    /// Create a DNS network address with port
    pub fn dns_with_port(hostname: impl Into<String>, port: u16) -> Self {
        Self::Dns {
            hostname: hostname.into(),
            port: Some(port),
        }
    }

    /// Create an IPv4 network address
    pub fn ipv4(address: Ipv4Addr) -> Self {
        Self::Ipv4 {
            address,
            port: None,
        }
    }

    /// Create an IPv4 network address with port
    pub fn ipv4_with_port(address: Ipv4Addr, port: u16) -> Self {
        Self::Ipv4 {
            address,
            port: Some(port),
        }
    }

    /// Create an IPv6 network address
    pub fn ipv6(address: Ipv6Addr) -> Self {
        Self::Ipv6 {
            address,
            port: None,
        }
    }

    /// Create an IPv6 network address with port
    pub fn ipv6_with_port(address: Ipv6Addr, port: u16) -> Self {
        Self::Ipv6 {
            address,
            port: Some(port),
        }
    }

    /// Get the port if specified, otherwise return the default port
    pub fn port_or_default(&self, default_port: u16) -> u16 {
        match self {
            NetworkAddress::Dns { port, .. } => port.unwrap_or(default_port),
            NetworkAddress::Ipv4 { port, .. } => port.unwrap_or(default_port),
            NetworkAddress::Ipv6 { port, .. } => port.unwrap_or(default_port),
        }
    }

    /// Get the port if specified
    pub fn port(&self) -> Option<u16> {
        match self {
            NetworkAddress::Dns { port, .. } => *port,
            NetworkAddress::Ipv4 { port, .. } => *port,
            NetworkAddress::Ipv6 { port, .. } => *port,
        }
    }

    /// Convert to a string representation suitable for connection
    pub fn to_connection_string(&self, default_port: Option<u16>) -> String {
        match self {
            NetworkAddress::Dns { hostname, port } => {
                if let Some(port) = port {
                    format!("{}:{}", hostname, port)
                } else if let Some(default) = default_port {
                    format!("{}:{}", hostname, default)
                } else {
                    hostname.clone()
                }
            }
            NetworkAddress::Ipv4 { address, port } => {
                if let Some(port) = port {
                    format!("{}:{}", address, port)
                } else if let Some(default) = default_port {
                    format!("{}:{}", address, default)
                } else {
                    address.to_string()
                }
            }
            NetworkAddress::Ipv6 { address, port } => {
                if let Some(port) = port {
                    format!("[{}]:{}", address, port)
                } else if let Some(default) = default_port {
                    format!("[{}]:{}", address, default)
                } else {
                    address.to_string()
                }
            }
        }
    }

    /// Resolve this network address to a socket address
    ///
    /// For IP addresses, returns immediately. For DNS addresses, performs resolution.
    pub async fn resolve_to_socket_addr(&self, default_port: u16) -> Result<SocketAddr, String> {
        match self {
            NetworkAddress::Ipv4 { address, port } => Ok(SocketAddr::V4(
                std::net::SocketAddrV4::new(*address, port.unwrap_or(default_port)),
            )),
            NetworkAddress::Ipv6 { address, port } => Ok(SocketAddr::V6(
                std::net::SocketAddrV6::new(*address, port.unwrap_or(default_port), 0, 0),
            )),
            NetworkAddress::Dns { hostname, port } => {
                let connection_string = match port {
                    Some(p) => format!("{}:{}", hostname, p),
                    None => format!("{}:{}", hostname, default_port),
                };

                // Use tokio's lookup_host for DNS resolution
                use tokio::net::lookup_host;
                let addrs = lookup_host(connection_string.clone())
                    .await
                    .map_err(|e| e.to_string())?;
                if let Some(addr) = addrs.into_iter().next() {
                    Ok(addr)
                } else {
                    Err(format!("No addresses found for {}", connection_string))
                }
            }
        }
    }
}

impl From<IpAddr> for NetworkAddress {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(ipv4) => NetworkAddress::ipv4(ipv4),
            IpAddr::V6(ipv6) => NetworkAddress::ipv6(ipv6),
        }
    }
}

impl From<SocketAddr> for NetworkAddress {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(ipv4) => NetworkAddress::ipv4(*ipv4.ip()),
            SocketAddr::V6(ipv6) => NetworkAddress::ipv6(*ipv6.ip()),
        }
    }
}

impl std::fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_connection_string(None))
    }
}

/// Relay address information for a service
///
/// Contains the public key and network addresses needed to connect to a service.
/// This structure is designed to be compact and suitable for QR code encoding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayAddress {
    /// Public key of the service
    ///
    /// Used to verify the service's identity during the connection handshake.
    /// This prevents man-in-the-middle attacks and ensures the client is
    /// connecting to the correct service. Supports Ed25519 and ML-DSA keys.
    pub public_key: VerifyingKey,

    /// Network addresses where the service can be reached
    ///
    /// Multiple addresses can be provided for redundancy and different network
    /// configurations. Clients should try addresses in order until one succeeds.
    pub addresses: BTreeSet<NetworkAddress>,

    /// Optional human-readable name for the service
    ///
    /// Can be used for display purposes or debugging. Examples:
    /// "Primary Relay", "EU West", "Backup Server", etc.
    pub name: Option<String>,
}

#[cfg_attr(feature = "frb-api", frb(opaque))]
impl RelayAddress {
    /// Create a new connection info with minimal required fields
    pub fn new(public_key: VerifyingKey) -> Self {
        Self {
            public_key,
            addresses: BTreeSet::new(),
            name: None,
        }
    }

    /// Add a network address
    pub fn with_address(mut self, address: NetworkAddress) -> Self {
        self.addresses.insert(address);
        self
    }

    /// Add multiple network addresses
    pub fn with_addresses(mut self, addresses: impl IntoIterator<Item = NetworkAddress>) -> Self {
        self.addresses.extend(addresses);
        self
    }

    /// Set a human-readable name for this service
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Get the service's display name (name if set, otherwise first address)
    pub fn display_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.addresses
                .iter()
                .next()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "Unknown Service".to_string())
        })
    }

    /// Get all addresses that use the specified port (or default port)
    pub fn addresses_with_port(&self, port: u16) -> Vec<NetworkAddress> {
        self.addresses
            .iter()
            .filter(|addr| addr.port_or_default(port) == port)
            .cloned()
            .collect()
    }

    /// Get the first address, if any
    pub fn primary_address(&self) -> Option<&NetworkAddress> {
        self.addresses.iter().next()
    }

    /// Get the relay ID (public key ID)
    pub fn id(&self) -> zoe_wire_protocol::KeyId {
        self.public_key.id()
    }

    /// Get all addresses for connection attempts
    pub fn all_addresses(&self) -> &BTreeSet<NetworkAddress> {
        &self.addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_network_address_dns() {
        let addr = NetworkAddress::dns("example.com");
        assert_eq!(addr.to_connection_string(Some(8080)), "example.com:8080");
        assert_eq!(addr.to_connection_string(None), "example.com");
        assert_eq!(addr.port(), None);
        assert_eq!(addr.port_or_default(8080), 8080);
    }

    #[test]
    fn test_network_address_dns_with_port() {
        let addr = NetworkAddress::dns_with_port("example.com", 9090);
        assert_eq!(addr.to_connection_string(Some(8080)), "example.com:9090");
        assert_eq!(addr.to_connection_string(None), "example.com:9090");
        assert_eq!(addr.port(), Some(9090));
        assert_eq!(addr.port_or_default(8080), 9090);
    }

    #[test]
    fn test_network_address_ipv4() {
        let addr = NetworkAddress::ipv4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(addr.to_connection_string(Some(8080)), "192.168.1.1:8080");
        assert_eq!(addr.to_connection_string(None), "192.168.1.1");
        assert_eq!(addr.port(), None);
        assert_eq!(addr.port_or_default(8080), 8080);
    }

    #[test]
    fn test_network_address_ipv4_with_port() {
        let addr = NetworkAddress::ipv4_with_port(Ipv4Addr::new(192, 168, 1, 1), 9090);
        assert_eq!(addr.to_connection_string(Some(8080)), "192.168.1.1:9090");
        assert_eq!(addr.to_connection_string(None), "192.168.1.1:9090");
        assert_eq!(addr.port(), Some(9090));
        assert_eq!(addr.port_or_default(8080), 9090);
    }

    #[test]
    fn test_network_address_ipv6() {
        let addr = NetworkAddress::ipv6(Ipv6Addr::LOCALHOST);
        assert_eq!(addr.to_connection_string(Some(8080)), "[::1]:8080");
        assert_eq!(addr.to_connection_string(None), "::1");
        assert_eq!(addr.port(), None);
        assert_eq!(addr.port_or_default(8080), 8080);
    }

    #[test]
    fn test_network_address_ipv6_with_port() {
        let addr = NetworkAddress::ipv6_with_port(Ipv6Addr::LOCALHOST, 9090);
        assert_eq!(addr.to_connection_string(Some(8080)), "[::1]:9090");
        assert_eq!(addr.to_connection_string(None), "[::1]:9090");
        assert_eq!(addr.port(), Some(9090));
        assert_eq!(addr.port_or_default(8080), 9090);
    }

    #[test]
    fn test_network_address_from_ip_addr() {
        let ipv4_addr = NetworkAddress::from(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(matches!(ipv4_addr, NetworkAddress::Ipv4 { .. }));

        let ipv6_addr = NetworkAddress::from(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(matches!(ipv6_addr, NetworkAddress::Ipv6 { .. }));
    }

    #[test]
    fn test_connection_info_creation() {
        use zoe_wire_protocol::KeyPair;

        let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let public_key = keypair.public_key();
        let info = RelayAddress::new(public_key)
            .with_address(NetworkAddress::dns("relay.example.com"))
            .with_address(NetworkAddress::ipv4_with_port(
                Ipv4Addr::new(192, 168, 1, 100),
                8443,
            ))
            .with_name("Test Relay");

        assert_eq!(info.addresses.len(), 2);
        assert_eq!(info.name, Some("Test Relay".to_string()));
        assert_eq!(info.display_name(), "Test Relay");
    }

    #[test]
    fn test_connection_info_display_name_fallback() {
        use zoe_wire_protocol::KeyPair;

        let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let public_key = keypair.public_key();
        let info =
            RelayAddress::new(public_key).with_address(NetworkAddress::dns("relay.example.com"));

        assert_eq!(info.display_name(), "relay.example.com");
    }

    #[test]
    fn test_connection_info_addresses_with_port() {
        use zoe_wire_protocol::KeyPair;

        let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let public_key = keypair.public_key();
        let info = RelayAddress::new(public_key)
            .with_address(NetworkAddress::dns_with_port("relay1.example.com", 8443))
            .with_address(NetworkAddress::dns_with_port("relay2.example.com", 9443))
            .with_address(NetworkAddress::ipv4_with_port(
                Ipv4Addr::new(192, 168, 1, 100),
                8443,
            ));

        let port_8443_addrs = info.addresses_with_port(8443);
        assert_eq!(port_8443_addrs.len(), 2);
    }

    #[test]
    fn test_postcard_serialization_network_address() {
        let addr = NetworkAddress::dns_with_port("example.com", 8443);
        let serialized = postcard::to_stdvec(&addr).unwrap();
        let deserialized: NetworkAddress = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(addr, deserialized);
    }

    #[test]
    fn test_postcard_serialization_connection_info() {
        use zoe_wire_protocol::KeyPair;

        let keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let public_key = keypair.public_key();
        let info = RelayAddress::new(public_key)
            .with_address(NetworkAddress::dns("relay.example.com"))
            .with_name("Test Relay");

        let serialized = postcard::to_stdvec(&info).unwrap();
        let deserialized: RelayAddress = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(info, deserialized);
    }
}
