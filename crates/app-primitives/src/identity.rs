use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::Metadata;

/// Unified identity type - either a raw VerifyingKey or a VerifyingKey + alias
///
/// This is the fundamental identity concept in the system.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IdentityRef {
    /// Raw verifying key identity (always valid, no declaration needed)
    Key(VerifyingKey),
    /// Alias identity controlled by a specific key
    Alias {
        /// The controlling verifying key
        key: VerifyingKey,
        /// The alias name
        alias: String,
    },
}

impl IdentityRef {
    /// Get the controlling verifying key for this identity
    pub fn controlling_key(&self) -> VerifyingKey {
        match self {
            IdentityRef::Key(key) => *key,
            IdentityRef::Alias { key, .. } => *key,
        }
    }

    /// Check if this identity is controlled by the given key
    pub fn is_controlled_by(&self, key: &VerifyingKey) -> bool {
        self.controlling_key() == *key
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
