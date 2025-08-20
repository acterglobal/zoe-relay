use serde::{Deserialize, Serialize};
use zoe_wire_protocol::VerifyingKey;

use crate::Metadata;

/// Unified identity type - either a raw VerifyingKey or a VerifyingKey + alias
///
/// This is the fundamental identity concept in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityRef {
    /// Raw verifying key identity (always valid, no declaration needed)
    Key(#[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef")] VerifyingKey),
    /// Alias identity controlled by a specific key
    Alias {
        /// The controlling verifying key
        #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef")]
        key: VerifyingKey,
        /// The alias name
        alias: String,
    },
}

impl IdentityRef {
    /// Get the controlling verifying key for this identity
    pub fn controlling_key(&self) -> VerifyingKey {
        match self {
            IdentityRef::Key(key) => key.clone(),
            IdentityRef::Alias { key, .. } => key.clone(),
        }
    }

    /// Check if this identity is controlled by the given key
    pub fn is_controlled_by(&self, key: &VerifyingKey) -> bool {
        self.controlling_key() == *key
    }

    /// Check if this identity is controlled by the given ML-DSA key
    /// This is a compatibility method for the ML-DSA transition
    pub fn is_controlled_by_ml_dsa(&self, _key: &VerifyingKey) -> bool {
        // For now, ML-DSA keys cannot control Ed25519-based identities
        // This will need to be updated when we fully transition to ML-DSA
        false
    }

    /// Get a display string for this identity (used when no display name is set)
    pub fn fallback_display(&self) -> String {
        match self {
            IdentityRef::Key(key) => format!("Key:{key:?}"),
            IdentityRef::Alias { alias, .. } => alias.clone(),
        }
    }
}

/// Type of alias being declared
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentityType {
    /// This identity is the same as the key itself
    Main,
    /// This is about an alias identfied by the alias is
    Alias {
        /// Which external system this alias represents
        alias_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityInfo {
    /// The display name for this identity
    pub display_name: String,
    /// The metadata for this identity
    pub metadata: Vec<Metadata>,
}

// Manual trait implementations for IdentityRef using encoded bytes for comparison
impl PartialEq for IdentityRef {
    fn eq(&self, other: &Self) -> bool {
        use zoe_wire_protocol::verifying_key_to_bytes;
        match (self, other) {
            (IdentityRef::Key(k1), IdentityRef::Key(k2)) => {
                verifying_key_to_bytes(k1) == verifying_key_to_bytes(k2)
            }
            (
                IdentityRef::Alias { key: k1, alias: a1 },
                IdentityRef::Alias { key: k2, alias: a2 },
            ) => verifying_key_to_bytes(k1) == verifying_key_to_bytes(k2) && a1 == a2,
            _ => false,
        }
    }
}

impl Eq for IdentityRef {}

impl PartialOrd for IdentityRef {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for IdentityRef {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use zoe_wire_protocol::verifying_key_to_bytes;
        match (self, other) {
            (IdentityRef::Key(k1), IdentityRef::Key(k2)) => {
                verifying_key_to_bytes(k1).cmp(&verifying_key_to_bytes(k2))
            }
            (
                IdentityRef::Alias { key: k1, alias: a1 },
                IdentityRef::Alias { key: k2, alias: a2 },
            ) => {
                let key_cmp = verifying_key_to_bytes(k1).cmp(&verifying_key_to_bytes(k2));
                if key_cmp == std::cmp::Ordering::Equal {
                    a1.cmp(a2)
                } else {
                    key_cmp
                }
            }
            (IdentityRef::Key(_), IdentityRef::Alias { .. }) => std::cmp::Ordering::Less,
            (IdentityRef::Alias { .. }, IdentityRef::Key(_)) => std::cmp::Ordering::Greater,
        }
    }
}
