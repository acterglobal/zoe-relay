use serde::{Deserialize, Serialize};

/// Information about the group's encryption key (not the key itself)
///
/// This enum contains typed information about different encryption algorithms
/// and their key derivation methods, without exposing the key material itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupKeyInfo {
    /// ChaCha20-Poly1305 encryption with BIP39+Argon2 key derivation
    ///
    /// This is the standard encryption method for groups, using ChaCha20-Poly1305
    /// for encryption and BIP39 mnemonics with Argon2 for key derivation.
    ChaCha20Poly1305 {
        /// Key identifier (typically a hash of the derived key)
        key_id: Vec<u8>,
        /// Key derivation information for recreating the key from a mnemonic
        derivation_info: zoe_wire_protocol::crypto::KeyDerivationInfo,
    },
}

impl GroupKeyInfo {
    /// Create a new ChaCha20-Poly1305 GroupKeyInfo
    pub fn new_chacha20_poly1305(
        key_id: Vec<u8>,
        derivation_info: zoe_wire_protocol::crypto::KeyDerivationInfo,
    ) -> Self {
        Self::ChaCha20Poly1305 {
            key_id,
            derivation_info,
        }
    }

    /// Get the key ID for this key info
    pub fn key_id(&self) -> &[u8] {
        match self {
            Self::ChaCha20Poly1305 { key_id, .. } => key_id,
        }
    }

    /// Get the algorithm name for this key info
    pub fn algorithm(&self) -> &str {
        match self {
            Self::ChaCha20Poly1305 { .. } => "ChaCha20-Poly1305",
        }
    }

    /// Get the derivation info if available
    pub fn derivation_info(&self) -> Option<&zoe_wire_protocol::crypto::KeyDerivationInfo> {
        match self {
            Self::ChaCha20Poly1305 {
                derivation_info, ..
            } => Some(derivation_info),
        }
    }

    /// Check if this key info matches a given key ID
    pub fn matches_key_id(&self, other_key_id: &[u8]) -> bool {
        self.key_id() == other_key_id
    }
}
