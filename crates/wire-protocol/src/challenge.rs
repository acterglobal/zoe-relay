use crate::{Signature, VerifyingKey};
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

/// Default challenge timeout in seconds
const DEFAULT_CHALLENGE_TIMEOUT_SECS: u64 = 30;

/// Maximum size for challenge messages (to prevent DoS)
const MAX_PACKAGE_SIZE: usize = 1024 * 1024; // Should be enough for challenge data

/// Forward-compatible challenge system for connection-level authentication
///
/// The Zoe protocol uses a challenge-response handshake immediately after QUIC connection
/// establishment to verify possession of cryptographic private keys. This happens before
/// any service streams are created, ensuring all connections have verified credentials.
///
/// ## Protocol Flow
///
/// 1. **QUIC Connection**: Client connects using ML-DSA-44 mutual TLS
/// 2. **Challenge Phase**: Server sends `ZoeChallenge` on first bi-directional stream
/// 3. **Response Phase**: Client responds with `ZoeChallengeResponse`
/// 4. **Verification**: Server verifies proofs and sends `ZoeChallengeResult`
/// 5. **Service Phase**: Normal service streams can now be established
///
/// ## Wire Format
///
/// All challenge messages are serialized using postcard format for compact binary encoding.
///
/// ### Challenge Message (Server → Client)
/// ```text
/// | Field                | Type              | Description                    |
/// |---------------------|-------------------|--------------------------------|
/// | challenge_type      | u8                | Forward-compatible enum tag    |
/// | challenge_data      | Vec<u8>           | Serialized challenge content   |
/// ```
///
/// ### Response Message (Client → Server)  
/// ```text
/// | Field                | Type              | Description                    |
/// |---------------------|-------------------|--------------------------------|
/// | response_type       | u8                | Forward-compatible enum tag    |
/// | response_data       | Vec<u8>           | Serialized response content    |
/// ```
///
/// ### Result Message (Server → Client)
/// ```text
/// | Field                | Type              | Description                    |
/// |---------------------|-------------------|--------------------------------|
/// | result_type         | u8                | Forward-compatible enum tag    |
/// | result_data         | Vec<u8>           | Serialized result content      |
/// ```
///
/// ## Security Properties
///
/// - **Replay Protection**: Each challenge includes a unique nonce
/// - **Server Binding**: Signatures include server's public key
/// - **Time Bounds**: Challenges have expiration timestamps
/// - **Connection Scoped**: Verified keys are tied to specific QUIC connections
/// - **Forward Secrecy**: New challenges generated for each connection
///
/// ## Example Usage
///
/// ```rust
/// use zoe_wire_protocol::{ZoeChallenge, ZoeChallengeResponse, KeyChallenge};
///
/// // Server sends challenge
/// let challenge = ZoeChallenge::Key(KeyChallenge {
///     nonce: generate_nonce(),
///     server_public_key: server_key.to_bytes().to_vec(),
///     expires_at: current_time() + 30,
/// });
///
/// // Client creates multiple key proofs
/// let response = ZoeChallengeResponse::Key(KeyResponse {
///     key_proofs: vec![
///         KeyProof { public_key: key1_bytes, signature: sig1_bytes },
///         KeyProof { public_key: key2_bytes, signature: sig2_bytes },
///     ],
/// });
/// ```
#[derive(Debug, Clone, ForwardCompatibleEnum)]
pub enum ZoeChallenge {
    /// Multi-key ML-DSA challenge allowing clients to prove multiple private keys
    ///
    /// This challenge type allows clients to prove possession of multiple ML-DSA
    /// private keys in a single handshake round-trip. This is useful for:
    ///
    /// - **Role-based authentication**: Different keys for personal, work, admin roles
    /// - **Key rotation**: Proving both old and new keys during transition periods  
    /// - **Delegation**: Proving keys for multiple identities or organizations
    /// - **Batch verification**: Efficient verification of multiple keys at once
    ///
    /// The client must sign `(nonce || server_public_key)` with each private key
    /// they wish to prove possession of.
    #[discriminant(1)]
    Key(Box<KeyChallenge>),

    /// Unknown challenge type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

#[derive(Debug, Clone, ForwardCompatibleEnum)]
pub enum ZoeChallengeRejection {
    /// The challenge has been rejected. The connection will be closed. A message
    /// might be provided to explain why and what to do before trying again.
    #[discriminant(30)]
    GenericRejection(Option<String>),

    /// The client failed to respond to the challenge with the valied answer.
    #[discriminant(31)]
    ChallengeFailed,

    /// The client failed to respond to the challenge on time
    #[discriminant(32)]
    ChallengeExpired,

    /// The client failed to respond to the challenge with a valid complete answer.
    #[discriminant(33)]
    ChallengeIncomplete,

    /// The client has been blocked by the server. Any fruther requests from this
    /// client will be rejected.
    #[discriminant(40)]
    Blocked,

    /// Unknown rejection type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Forward-compatible result system for challenge verification
///
/// After verifying challenge responses, the server sends back results indicating
/// which proofs succeeded or failed. This allows clients to understand the
/// verification status and take appropriate action.
#[derive(Debug, Clone, ForwardCompatibleEnum)]
pub enum ZoeChallengeResult {
    /// The challanges have been accepted.
    #[discriminant(20)]
    Accepted,

    /// This challenge has been accepted, but there is another challenge to come
    /// and perform. After this read for another ZoeChallenge.
    #[discriminant(30)]
    Next,

    /// The challenge has been rejected The connection will be closed. A message
    /// might be provided to explain why and what to do before trying again.
    #[discriminant(40)]
    Rejected(ZoeChallengeRejection),

    /// An error occured (on the server side). The connection will be closed.
    /// The error should probably be shown to the user to allow them to figure
    /// out what went wrong before trying again.
    #[discriminant(50)]
    Error(String),

    /// Unknown result type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Challenge for proving possession of multiple ML-DSA private keys
///
/// This challenge is sent by the server immediately after QUIC connection
/// establishment. The client must respond by proving possession of one or
/// more ML-DSA private keys.
///
/// ## Security Considerations
///
/// - **Nonce**: Must be cryptographically random and unique per challenge
/// - **Server Key**: Binds the signature to this specific server
/// - **Expiration**: Prevents replay attacks and limits challenge lifetime
/// - **Key Encoding**: ML-DSA public keys should use the standard encoding
///
/// ## Wire Size
///
/// Approximate serialized size: ~80 bytes
/// - nonce: 32 bytes
/// - server_public_key: ~1312 bytes (ML-DSA-44)  
/// - expires_at: 8 bytes
/// - overhead: ~8 bytes (postcard encoding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyChallenge {
    /// Cryptographically random nonce that must be included in signatures
    ///
    /// This 32-byte nonce provides replay protection by ensuring each challenge
    /// is unique. Clients must include this exact nonce when constructing
    /// their signature data.
    pub nonce: [u8; 32],

    /// Server's ML-DSA-44 public key that must be included in signatures
    ///
    /// Including the server's public key in the signature data prevents
    /// signature replay attacks across different servers. This should be
    /// the same ML-DSA-44 key used in the server's TLS certificate.
    pub signature: Signature,

    /// Unix timestamp when this challenge expires
    ///
    /// Challenges have a limited lifetime (typically 30-60 seconds) to prevent
    /// replay attacks. Clients must respond before this timestamp or the
    /// challenge will be rejected.
    pub expires_at: u64,
}

/// Response containing proofs of ML-DSA private key possession
///
/// The client responds to an `KeyChallenge` by providing one or more
/// key proofs. Each proof demonstrates possession of a specific ML-DSA private key.
///
/// ## Proof Construction
///
/// For each key the client wishes to prove:
///
/// 1. Construct signature data: `nonce || server_public_key`
/// 2. Sign the data using the ML-DSA private key
/// 3. Create a `KeyProof` with the public key and signature
///
/// ## Wire Size
///
/// Approximate serialized size per key proof: ~2500 bytes
/// - public_key: ~1312 bytes (ML-DSA-65 public key)
/// - signature: ~2420 bytes (ML-DSA-65 signature)
/// - overhead: ~8 bytes (postcard encoding)
///
/// Total message size scales linearly with number of keys being proven.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyResponse {
    /// List of key proofs - one for each ML-DSA key being proven
    ///
    /// The client can prove multiple keys in a single response. Each proof
    /// is verified independently by the server. At least one proof must
    /// succeed for the handshake to complete successfully.
    ///
    /// ## Ordering
    ///
    /// The order of proofs in this vector corresponds to the indices used
    /// in `KeyResult.failed_indices` for error reporting.
    pub key_proofs: Vec<KeyProof>,
}

/// Cryptographic proof of ML-DSA private key possession
///
/// Each proof consists of a public key and a signature that demonstrates
/// the client possesses the corresponding private key. The signature is
/// computed over challenge-specific data to prevent replay attacks.
///
/// ## Verification Process
///
/// The server verifies each proof by:
///
/// 1. Decoding the ML-DSA public key from `public_key`
/// 2. Reconstructing signature data: `nonce || server_public_key`  
/// 3. Verifying the signature using the public key and signature data
/// 4. Adding successfully verified keys to the connection's verified set
///
/// ## Key Encoding
///
/// ML-DSA public keys must be encoded using the standard ML-DSA encoding:
/// - ML-DSA-44: 1312 bytes
/// - ML-DSA-65: 1952 bytes  
/// - ML-DSA-87: 2592 bytes
///
/// This implementation uses ML-DSA-65 (security level 3, ~192-bit security).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyProof {
    /// Encoded ML-DSA public key being proven
    ///
    /// This should be the result of calling `verifying_key.encode()` on
    /// an ML-DSA verifying key. The encoding includes all necessary
    /// information to reconstruct the public key for verification.
    pub public_key: VerifyingKey,

    /// ML-DSA signature over (nonce || server_public_key)
    ///
    /// This signature proves possession of the private key corresponding
    /// to `public_key`. It must be computed over the exact concatenation
    /// of the challenge nonce and server public key.
    ///
    /// Signature sizes:
    /// - ML-DSA-44: ~2420 bytes
    /// - ML-DSA-65: ~3309 bytes
    /// - ML-DSA-87: ~4627 bytes
    pub signature: Signature,
}

/// Result of ML-DSA multi-key challenge verification
///
/// After verifying all key proofs in a response, the server sends back
/// this result indicating which proofs succeeded or failed. This allows
/// the client to understand their verification status.
///
/// ## Success Criteria
///
/// The handshake is considered successful if at least one key proof is valid.
/// Even if some proofs fail, the connection can continue with the successfully
/// verified keys.
///
/// ## Error Handling
///
/// If all proofs fail, the server should close the connection. Clients can
/// use the failure information to:
/// - Log which specific keys were rejected
/// - Retry the connection with different keys
/// - Debug key or signature generation issues
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyResult {
    /// All key proofs were successfully verified
    ///
    /// This is the ideal case where every key the client attempted to prove
    /// was successfully verified. All provided keys are now available for
    /// use in message authentication on this connection.
    AllValid,

    /// Some key proofs failed verification
    ///
    /// Contains the indices (into the original `key_proofs` vector) of proofs
    /// that failed verification. The connection continues with the successfully
    /// verified keys.
    ///
    /// Common failure reasons:
    /// - Invalid signature (wrong private key used)
    /// - Malformed public key encoding
    /// - Signature over wrong data (incorrect nonce/server key)
    /// - Expired challenge (client took too long to respond)
    PartialFailure {
        /// Zero-based indices of failed key proofs
        ///
        /// These indices correspond to positions in the original
        /// `KeyResponse.key_proofs` vector that failed verification.
        failed_indices: Vec<usize>,
    },

    /// All key proofs failed verification
    ///
    /// No keys were successfully verified. The server will typically close
    /// the connection after sending this result. Clients should not attempt
    /// to establish service streams after receiving this result.
    AllFailed,
}

impl KeyResult {
    /// Check if the handshake was successful (at least one key verified)
    ///
    /// Returns `true` if at least one key was successfully verified,
    /// `false` if all keys failed verification.
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::KeyResult;
    ///
    /// let result = KeyResult::PartialFailure {
    ///     failed_indices: vec![1, 3]
    /// };
    /// assert!(result.is_successful());
    ///
    /// let result = KeyResult::AllFailed;
    /// assert!(!result.is_successful());
    /// ```
    pub fn is_successful(&self) -> bool {
        !matches!(self, KeyResult::AllFailed)
    }

    /// Get the number of failed key proofs
    ///
    /// Returns the count of key proofs that failed verification.
    /// For `AllValid`, returns 0. For `AllFailed`, the count depends
    /// on how many keys were originally submitted.
    ///
    /// # Parameters
    ///
    /// * `total_keys` - Total number of keys that were submitted (needed for AllFailed case)
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::KeyResult;
    ///
    /// let result = KeyResult::PartialFailure {
    ///     failed_indices: vec![1, 3]
    /// };
    /// assert_eq!(result.failed_count(5), 2);
    ///
    /// let result = KeyResult::AllFailed;
    /// assert_eq!(result.failed_count(3), 3);
    /// ```
    pub fn failed_count(&self, total_keys: usize) -> usize {
        match self {
            KeyResult::AllValid => 0,
            KeyResult::PartialFailure { failed_indices } => failed_indices.len(),
            KeyResult::AllFailed => total_keys,
        }
    }

    /// Get the number of successfully verified keys
    ///
    /// Returns the count of key proofs that passed verification.
    ///
    /// # Parameters
    ///
    /// * `total_keys` - Total number of keys that were submitted
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::KeyResult;
    ///
    /// let result = KeyResult::PartialFailure {
    ///     failed_indices: vec![1]
    /// };
    /// assert_eq!(result.success_count(3), 2);
    ///
    /// let result = KeyResult::AllValid;
    /// assert_eq!(result.success_count(5), 5);
    /// ```
    pub fn success_count(&self, total_keys: usize) -> usize {
        total_keys - self.failed_count(total_keys)
    }
}

/// Connection information extended with verified ML-DSA keys
///
/// This structure tracks both the ML-DSA-44 transport authentication and
/// the ML-DSA keys verified during the challenge handshake. It provides
/// the foundation for connection-scoped message authentication.
///
/// ## Authentication Layers
///
/// 1. **Transport Layer**: ML-DSA-44 mutual TLS provides connection-level identity
/// 2. **Application Layer**: ML-DSA keys provide message-level authentication
///
/// The separation allows for different keys to be used for different purposes
/// while maintaining a clear security model.
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The ML-DSA-44 public key from the client's TLS certificate
    ///
    /// This key identifies the client at the transport layer and is used
    /// for QUIC connection authentication. It remains constant for the
    /// lifetime of the connection.
    pub client_public_key: VerifyingKey,

    /// Set of ML-DSA public keys verified during challenge handshake
    ///
    /// These keys were proven during the initial handshake and can be used
    /// for message-level authentication. The set is populated during the
    /// challenge phase and remains immutable for the connection lifetime.
    ///
    /// Keys are stored as encoded bytes for efficient lookup and comparison.
    /// Use `has_verified_ml_dsa_key()` for membership testing.
    pub verified_ml_dsa_keys: BTreeSet<Vec<u8>>,

    /// The remote network address of the client
    pub remote_address: std::net::SocketAddr,

    /// Timestamp when the connection was established
    pub connected_at: std::time::SystemTime,
}

impl ConnectionInfo {
    /// Check if a specific ML-DSA public key has been verified for this connection
    ///
    /// This is the primary method for checking message authentication permissions.
    /// Services should call this before processing messages that require specific
    /// key possession proofs.
    ///
    /// # Parameters
    ///
    /// * `public_key` - The encoded ML-DSA public key to check
    ///
    /// # Returns
    ///
    /// `true` if the key was successfully verified during handshake, `false` otherwise
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::ConnectionInfo;
    ///
    /// // In a message service handler
    /// if !connection_info.has_verified_ml_dsa_key(&required_key) {
    ///     return Err(MessageError::VerificationRequired {
    ///         public_key_hex: hex::encode(&required_key)
    ///     });
    /// }
    /// ```
    pub fn has_verified_ml_dsa_key(&self, public_key: &[u8]) -> bool {
        self.verified_ml_dsa_keys.contains(public_key)
    }

    /// Get the number of verified ML-DSA keys for this connection
    ///
    /// Useful for logging and debugging connection capabilities.
    ///
    /// # Returns
    ///
    /// The count of ML-DSA keys that were successfully verified during handshake
    pub fn verified_key_count(&self) -> usize {
        self.verified_ml_dsa_keys.len()
    }

    /// Get all verified ML-DSA public keys as hex strings (for logging/debugging)
    ///
    /// Returns a vector of hex-encoded key prefixes for human-readable logging.
    /// Only the first 8 bytes of each key are included for brevity.
    ///
    /// # Returns
    ///
    /// Vector of hex strings representing the first 8 bytes of each verified key
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoe_wire_protocol::ConnectionInfo;
    ///
    /// let key_previews = connection_info.verified_keys_hex();
    /// info!("Connection has verified keys: {:?}", key_previews);
    /// // Output: ["a1b2c3d4...", "e5f6g7h8..."]
    /// ```
    pub fn verified_keys_hex(&self) -> Vec<String> {
        self.verified_ml_dsa_keys
            .iter()
            .map(|key| {
                let preview_len = std::cmp::min(8, key.len());
                hex::encode(&key[..preview_len])
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_result_success_check() {
        assert!(KeyResult::AllValid.is_successful());
        assert!(KeyResult::PartialFailure {
            failed_indices: vec![1]
        }
        .is_successful());
        assert!(!KeyResult::AllFailed.is_successful());
    }

    #[test]
    fn test_ml_dsa_result_counts() {
        let result = KeyResult::PartialFailure {
            failed_indices: vec![0, 2],
        };
        assert_eq!(result.failed_count(5), 2);
        assert_eq!(result.success_count(5), 3);

        let result = KeyResult::AllValid;
        assert_eq!(result.failed_count(3), 0);
        assert_eq!(result.success_count(3), 3);

        let result = KeyResult::AllFailed;
        assert_eq!(result.failed_count(4), 4);
        assert_eq!(result.success_count(4), 0);
    }

    #[test]
    fn test_connection_info_key_verification() {
        let mut verified_keys = BTreeSet::new();
        verified_keys.insert(vec![1, 2, 3, 4]);
        verified_keys.insert(vec![5, 6, 7, 8]);

        let connection_info = ConnectionInfo {
            client_public_key: {
                use crate::generate_keypair;
                generate_keypair(&mut rand::thread_rng()).public_key()
            },
            verified_ml_dsa_keys: verified_keys,
            remote_address: "127.0.0.1:8080".parse().unwrap(),
            connected_at: std::time::SystemTime::now(),
        };

        assert!(connection_info.has_verified_ml_dsa_key(&[1, 2, 3, 4]));
        assert!(connection_info.has_verified_ml_dsa_key(&[5, 6, 7, 8]));
        assert!(!connection_info.has_verified_ml_dsa_key(&[9, 10, 11, 12]));
        assert_eq!(connection_info.verified_key_count(), 2);
    }
}
