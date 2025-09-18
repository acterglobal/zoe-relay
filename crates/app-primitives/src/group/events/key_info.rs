use blake3::Hash;
use serde::{Deserialize, Serialize};

/// Information about the group's encryption key (not the key itself)
///
/// This enum contains typed information about different encryption algorithms
/// and their key derivation methods, without exposing the key material itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupKeyInfo {
    /// ChaCha20-Poly1305 encryption
    ///
    /// This is the standard encryption method for groups, using ChaCha20-Poly1305
    /// for encryption
    ChaCha20Poly1305 {
        /// Key identifier (typically a hash of the derived key)
        key_id: Hash,
    },
}

impl GroupKeyInfo {
    /// Create a new ChaCha20-Poly1305 GroupKeyInfo
    pub fn new_chacha20_poly1305(key_id: Hash) -> Self {
        Self::ChaCha20Poly1305 { key_id }
    }

    /// Get the key ID for this key info
    pub fn key_id(&self) -> &Hash {
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

    /// Check if this key info matches a given key ID
    pub fn matches_key_id(&self, other_key_id: &Hash) -> bool {
        self.key_id() == other_key_id
    }
}
