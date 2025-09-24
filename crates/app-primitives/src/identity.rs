use serde::{Deserialize, Serialize};
use zoe_wire_protocol::VerifyingKey;

use crate::metadata::Metadata;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

/// Unified identity type - either a raw VerifyingKey or a VerifyingKey + alias
///
/// This is the fundamental identity concept in the system.
#[cfg_attr(feature = "frb-api", frb(opaque, ignore_all))]
#[derive(Debug, Clone, Hash, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
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

/// Identity type declaration for events
///
/// This enum is serialized within encrypted events to indicate how the
/// VerifyingKey should be interpreted. Combined with the VerifyingKey from
/// the message envelope, this creates an IdentityRef for permission checking.
#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone, Hash, PartialEq, PartialOrd, Eq, Ord, Serialize, Deserialize)]
pub enum IdentityType {
    /// Acting as the main identity (the verifying key itself)
    Main,
    /// Acting as a registered alias
    Alias {
        /// The alias identifier
        alias_id: String,
    },
}

impl IdentityType {
    /// Convert this IdentityType + VerifyingKey into an IdentityRef
    pub fn to_identity_ref(&self, verifying_key: VerifyingKey) -> IdentityRef {
        match self {
            IdentityType::Main => IdentityRef::Key(verifying_key),
            IdentityType::Alias { alias_id } => IdentityRef::Alias {
                key: verifying_key,
                alias: alias_id.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityInfo {
    /// The display name for this identity
    pub display_name: String,
    /// The metadata for this identity
    pub metadata: Vec<Metadata>,
}
