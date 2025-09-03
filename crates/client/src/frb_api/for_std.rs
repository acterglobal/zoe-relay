use flutter_rust_bridge::frb;
use std::net::SocketAddr;

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
