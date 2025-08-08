use std::net::SocketAddr;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::Metadata;

/// Relay endpoint information for group participants
///
/// Contains the network address and public key needed to connect to a relay server.
/// Multiple relay endpoints can be provided to a group participant for redundancy,
/// with the list order indicating priority preference.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Network address of the relay server
    ///
    /// This is the socket address (IP:port) where the relay server
    /// can be reached for QUIC connections.
    pub address: SocketAddr,

    /// Ed25519 public key of the relay server
    ///
    /// Used to verify the relay server's identity during the QUIC TLS handshake.
    /// This prevents man-in-the-middle attacks and ensures the client is
    /// connecting to the correct relay server.
    pub public_key: VerifyingKey,

    /// Optional human-readable name for the relay
    ///
    /// Can be used for display purposes or debugging. Examples:
    /// "Primary Relay", "EU West", "Backup Server", etc.
    pub name: Option<String>,

    /// Additional relay metadata
    ///
    /// Can store information like geographic region, performance metrics,
    /// supported features, or other relay-specific data.
    pub metadata: Vec<Metadata>,
}

impl RelayEndpoint {
    /// Create a new relay endpoint with minimal required fields
    pub fn new(address: SocketAddr, public_key: VerifyingKey) -> Self {
        Self {
            address,
            public_key,
            name: None,
            metadata: Vec::new(),
        }
    }

    /// Set a human-readable name for this relay
    pub fn with_name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    /// Add metadata to this relay endpoint
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata.push(metadata);
        self
    }

    /// Get the relay's display name (name if set, otherwise address)
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.address.to_string())
    }
}
