//! Connection information for authenticated connections
//!
//! This module provides the `ConnectionInfo` type that tracks both transport-level
//! and application-level authentication for active connections in the Zoe protocol.

use crate::VerifyingKey;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::SystemTime;

/// Connection information with verified cryptographic keys
///
/// This structure tracks both transport-level and application-level authentication
/// for active connections in the Zoe protocol. It provides the foundation for
/// connection-scoped message authentication across multiple key algorithms.
///
/// ## Authentication Layers
///
/// 1. **Transport Layer**: TLS certificate provides connection-level identity
/// 2. **Application Layer**: Verified keys provide message-level authentication
///
/// The separation allows for different keys to be used for different purposes
/// while maintaining a clear security model across Ed25519 and ML-DSA algorithms.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The public key from the client's TLS certificate
    ///
    /// This key identifies the client at the transport layer and is used
    /// for QUIC connection authentication. It remains constant for the
    /// lifetime of the connection. Supports Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87.
    pub transport_public_key: VerifyingKey,

    /// Set of public keys verified during challenge handshake
    ///
    /// These keys were proven during the initial handshake and can be used
    /// for message-level authentication. The set is populated during the
    /// challenge phase and remains immutable for the connection lifetime.
    ///
    /// Supports all key algorithms: Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87.
    /// Use `has_verified_key()` for membership testing.
    pub verified_keys: HashSet<VerifyingKey>,

    /// The remote network address of the client
    pub remote_address: SocketAddr,

    /// Timestamp when the connection was established
    pub connected_at: SystemTime,
}

impl ConnectionInfo {
    /// Create a new ConnectionInfo with the given transport public key and remote address
    ///
    /// # Parameters
    ///
    /// * `transport_public_key` - The public key from the client's TLS certificate
    /// * `remote_address` - The remote network address of the client
    ///
    /// # Returns
    ///
    /// A new `ConnectionInfo` with empty verified keys set and current timestamp
    pub fn new(transport_public_key: VerifyingKey, remote_address: SocketAddr) -> Self {
        Self {
            transport_public_key,
            verified_keys: HashSet::new(),
            remote_address,
            connected_at: SystemTime::now(),
        }
    }

    /// Create a new ConnectionInfo with verified keys
    ///
    /// # Parameters
    ///
    /// * `transport_public_key` - The public key from the client's TLS certificate
    /// * `verified_keys` - Set of keys verified during handshake
    /// * `remote_address` - The remote network address of the client
    ///
    /// # Returns
    ///
    /// A new `ConnectionInfo` with the provided verified keys and current timestamp
    pub fn with_verified_keys(
        transport_public_key: VerifyingKey,
        verified_keys: HashSet<VerifyingKey>,
        remote_address: SocketAddr,
    ) -> Self {
        Self {
            transport_public_key,
            verified_keys,
            remote_address,
            connected_at: SystemTime::now(),
        }
    }

    /// Add a verified key to this connection
    ///
    /// # Parameters
    ///
    /// * `public_key` - The public key to add
    pub fn add_verified_key(&mut self, public_key: VerifyingKey) {
        self.verified_keys.insert(public_key);
    }

    /// Check if a specific public key has been verified for this connection
    ///
    /// This is the primary method for checking message authentication permissions.
    /// Services should call this before processing messages that require specific
    /// key possession proofs.
    ///
    /// # Parameters
    ///
    /// * `public_key` - The public key to check
    ///
    /// # Returns
    ///
    /// `true` if the key was successfully verified during handshake, `false` otherwise
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::ConnectionInfo;
    /// use std::net::SocketAddr;
    ///
    /// # fn example(connection_info: &ConnectionInfo, required_key: &zoe_wire_protocol::VerifyingKey) -> Result<(), String> {
    /// // In a message service handler
    /// if !connection_info.has_verified_key(required_key) {
    ///     return Err(format!(
    ///         "Verification required for key: {}",
    ///         hex::encode(required_key.id())
    ///     ));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn has_verified_key(&self, public_key: &VerifyingKey) -> bool {
        self.verified_keys.contains(public_key)
    }

    /// Get the number of verified keys for this connection
    ///
    /// Useful for logging and debugging connection capabilities.
    ///
    /// # Returns
    ///
    /// The count of keys that were successfully verified during handshake
    pub fn verified_key_count(&self) -> usize {
        self.verified_keys.len()
    }

    /// Get all verified public keys as hex strings (for logging/debugging)
    ///
    /// Returns a vector of hex-encoded key IDs for human-readable logging.
    /// Uses the key's ID (which is a hash for ML-DSA keys or the key bytes for Ed25519).
    ///
    /// # Returns
    ///
    /// Vector of hex strings representing the key IDs of each verified key
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::ConnectionInfo;
    ///
    /// # fn example(connection_info: &ConnectionInfo) {
    /// let key_previews = connection_info.verified_keys_hex();
    /// println!("Connection has verified keys: {:?}", key_previews);
    /// // Output: ["a1b2c3d4e5f6g7h8...", "9a8b7c6d5e4f3g2h..."]
    /// # }
    /// ```
    pub fn verified_keys_hex(&self) -> Vec<String> {
        self.verified_keys
            .iter()
            .map(|key| hex::encode(key.id()))
            .collect()
    }

    /// Get a reference to the verified keys set
    ///
    /// # Returns
    ///
    /// A reference to the HashSet containing all verified keys
    pub fn verified_keys(&self) -> &HashSet<VerifyingKey> {
        &self.verified_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_connection_info_creation() {
        let keypair = KeyPair::generate_ml_dsa44(&mut rand::thread_rng());
        let transport_key = keypair.public_key();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let conn_info = ConnectionInfo::new(transport_key.clone(), remote_addr);

        assert_eq!(conn_info.transport_public_key, transport_key);
        assert_eq!(conn_info.remote_address, remote_addr);
        assert_eq!(conn_info.verified_key_count(), 0);
        assert!(conn_info.verified_keys().is_empty());
    }

    #[test]
    fn test_connection_info_with_verified_keys() {
        let keypair1 = KeyPair::generate_ml_dsa44(&mut rand::thread_rng());
        let keypair2 = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let transport_key = keypair1.public_key();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let mut verified_keys = HashSet::new();
        verified_keys.insert(keypair1.public_key());
        verified_keys.insert(keypair2.public_key());

        let conn_info = ConnectionInfo::with_verified_keys(
            transport_key.clone(),
            verified_keys.clone(),
            remote_addr,
        );

        assert_eq!(conn_info.transport_public_key, transport_key);
        assert_eq!(conn_info.remote_address, remote_addr);
        assert_eq!(conn_info.verified_key_count(), 2);
        assert_eq!(conn_info.verified_keys(), &verified_keys);
    }

    #[test]
    fn test_add_verified_key() {
        let keypair1 = KeyPair::generate_ml_dsa44(&mut rand::thread_rng());
        let keypair2 = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let transport_key = keypair1.public_key();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let mut conn_info = ConnectionInfo::new(transport_key, remote_addr);
        assert_eq!(conn_info.verified_key_count(), 0);

        let test_key = keypair2.public_key();
        conn_info.add_verified_key(test_key.clone());
        assert_eq!(conn_info.verified_key_count(), 1);
        assert!(conn_info.has_verified_key(&test_key));
    }

    #[test]
    fn test_has_verified_key() {
        let keypair1 = KeyPair::generate_ml_dsa44(&mut rand::thread_rng());
        let keypair2 = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let keypair3 = KeyPair::generate_ml_dsa65(&mut rand::thread_rng());
        let transport_key = keypair1.public_key();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let mut verified_keys = HashSet::new();
        let verified_key = keypair2.public_key();
        verified_keys.insert(verified_key.clone());

        let conn_info =
            ConnectionInfo::with_verified_keys(transport_key, verified_keys, remote_addr);

        assert!(conn_info.has_verified_key(&verified_key));
        assert!(!conn_info.has_verified_key(&keypair3.public_key()));
    }

    #[test]
    fn test_verified_keys_hex() {
        let keypair1 = KeyPair::generate_ml_dsa44(&mut rand::thread_rng());
        let keypair2 = KeyPair::generate_ed25519(&mut rand::thread_rng());
        let transport_key = keypair1.public_key();
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);

        let mut verified_keys = HashSet::new();
        let key1 = keypair1.public_key();
        let key2 = keypair2.public_key();
        verified_keys.insert(key1.clone());
        verified_keys.insert(key2.clone());

        let conn_info =
            ConnectionInfo::with_verified_keys(transport_key, verified_keys, remote_addr);
        let hex_keys = conn_info.verified_keys_hex();

        assert_eq!(hex_keys.len(), 2);
        assert!(hex_keys.contains(&hex::encode(key1.id())));
        assert!(hex_keys.contains(&hex::encode(key2.id())));
    }
}
