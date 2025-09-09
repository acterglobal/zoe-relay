use std::net::SocketAddr;
use zoe_app_primitives::RelayAddress;
use zoe_wire_protocol::KeyId;

/// Connection information for a relay server
///
/// Stores the full RelayAddress configuration so we can attempt reconnection
/// to all available addresses, not just the last successful one.
#[derive(Debug, Clone)]
pub struct RelayInfo {
    pub relay_id: KeyId,
    pub relay_address: RelayAddress,
}

/// Connection status for a relay
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConnectionStatus {
    /// Not connected
    Disconnected {
        /// Optional connection error that caused the disconnection
        error: Option<String>,
    },
    /// Currently connecting
    Connecting,
    /// Connected and operational to a specific address
    Connected {
        /// The specific address that the connection succeeded on
        connected_address: SocketAddr,
    },
    /// Connection failed
    Failed { error: String },
}

/// Represents a relay connection with its status
#[derive(Debug, Clone)]
pub struct RelayConnectionInfo {
    pub info: RelayInfo,
    pub status: RelayConnectionStatus,
}

// ClientSecret is used directly - no wrapper needed

/// Per-relay connection status update
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatusUpdate {
    /// The relay ID
    pub relay_id: KeyId,
    /// The relay address information
    pub relay_address: RelayAddress,
    /// Current connection status
    pub status: RelayConnectionStatus,
}

/// Overall connection status for the client
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverallConnectionStatus {
    /// True if connected to at least one relay
    pub is_connected: bool,
    /// Number of connected relays
    pub connected_count: usize,
    /// Total number of configured relays
    pub total_count: usize,
}
