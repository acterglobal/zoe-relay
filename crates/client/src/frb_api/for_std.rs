use flutter_rust_bridge::frb;
use std::net::{IpAddr, SocketAddr};
use tokio::net::lookup_host;

#[allow(dead_code)]
const DEFAULT_PORT: u16 = 13908;

// Socket address utilities
#[frb]
pub fn create_socket_addr(ip: String, port: u16) -> Result<SocketAddr, String> {
    format!("{}:{}", ip, port)
        .parse()
        .map_err(|e| format!("Invalid socket address: {}", e))
}

#[frb]
pub fn socket_addr_to_string(addr: &SocketAddr) -> String {
    addr.to_string()
}

#[frb]
pub fn socket_addr_ip(addr: &SocketAddr) -> String {
    addr.ip().to_string()
}

#[frb]
pub fn socket_addr_port(addr: &SocketAddr) -> u16 {
    addr.port()
}

#[frb]
pub async fn resolve_to_socket_addr(s: &str) -> Result<SocketAddr, String> {
    // Try to parse as a complete SocketAddr first (IP:port)
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Try to parse as just an IP address
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_PORT));
    }

    // Handle DNS resolution - check if it already has a port
    if s.contains(':') {
        // Assume it's hostname:port format, let ToSocketAddrs handle it
        let addrs = lookup_host(s).await.map_err(|e| e.to_string())?;
        if let Some(addr) = addrs.into_iter().next() {
            return Ok(addr);
        }
    } else {
        // It's just a hostname, add default port
        let addrs = lookup_host(format!("{s}:{DEFAULT_PORT}"))
            .await
            .map_err(|e| e.to_string())?;
        if let Some(addr) = addrs.into_iter().next() {
            return Ok(addr);
        }
    }

    Err(format!("Invalid socket address: {s}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_resolve_ipv4_with_port() {
        let result = resolve_to_socket_addr("192.168.1.1:8080").await.unwrap();
        assert_eq!(
            result,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080)
        );
    }

    #[tokio::test]
    async fn test_resolve_ipv4_without_port() {
        let result = resolve_to_socket_addr("192.168.1.1").await.unwrap();
        assert_eq!(
            result,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), DEFAULT_PORT)
        );
    }

    #[tokio::test]
    async fn test_resolve_ipv6_with_port() {
        let result = resolve_to_socket_addr("[::1]:8080").await.unwrap();
        assert_eq!(
            result,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)
        );
    }

    #[tokio::test]
    async fn test_resolve_ipv6_without_port() {
        let result = resolve_to_socket_addr("::1").await.unwrap();
        assert_eq!(
            result,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), DEFAULT_PORT)
        );
    }

    #[tokio::test]
    async fn test_resolve_localhost_with_port() {
        let result = resolve_to_socket_addr("localhost:9000").await.unwrap();
        assert_eq!(result.port(), 9000);
        // The IP could be either 127.0.0.1 or ::1 depending on system configuration
        assert!(result.ip().is_loopback());
    }

    #[tokio::test]
    async fn test_resolve_localhost_without_port() {
        let result = resolve_to_socket_addr("localhost").await.unwrap();
        assert_eq!(result.port(), DEFAULT_PORT);
        assert!(result.ip().is_loopback());
    }

    #[tokio::test]
    async fn test_resolve_domain_with_port() {
        // Using a well-known domain that should resolve
        let result = resolve_to_socket_addr("google.com:443").await;
        assert!(result.is_ok());
        if let Ok(addr) = result {
            assert_eq!(addr.port(), 443);
        }
    }

    #[tokio::test]
    async fn test_resolve_domain_without_port() {
        // Using a well-known domain that should resolve
        let result = resolve_to_socket_addr("google.com").await;
        assert!(result.is_ok());
        if let Ok(addr) = result {
            assert_eq!(addr.port(), DEFAULT_PORT);
        }
    }

    #[tokio::test]
    async fn test_resolve_invalid_address() {
        let result = resolve_to_socket_addr("invalid..domain..name").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_empty_string() {
        let result = resolve_to_socket_addr("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_port_only() {
        let result = resolve_to_socket_addr(":8080").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resolve_invalid_port() {
        let result = resolve_to_socket_addr("192.168.1.1:99999").await;
        assert!(result.is_err());
    }
}
