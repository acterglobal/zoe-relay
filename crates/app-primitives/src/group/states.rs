use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use super::events::roles::GroupRole;
use crate::{IdentityInfo, IdentityRef, IdentityType};

/// Group membership state with identity management
///
/// This models a system where VerifyingKeys are the fundamental participants,
/// and they can set identity info for themselves (Main) or aliases they control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    /// Identity information for keys and their aliases: (key, identity_type) -> identity_info
    pub identity_info: HashMap<(VerifyingKey, IdentityType), IdentityInfo>,
    /// Role assignments for identities (both keys and aliases)
    pub identity_roles: HashMap<IdentityRef, GroupRole>,
}

impl GroupMembership {
    /// Create a new empty membership state
    pub fn new() -> Self {
        Self {
            identity_info: HashMap::new(),
            identity_roles: HashMap::new(),
        }
    }

    /// Check if a verifying key is authorized to act as a specific identity
    pub fn is_authorized(&self, key: &VerifyingKey, identity_ref: &IdentityRef) -> bool {
        // Check if this key controls the identity
        identity_ref.is_controlled_by(key)
    }

    /// Get all identities that a verifying key can act as
    pub fn get_available_identities(&self, key: &VerifyingKey) -> HashSet<IdentityRef> {
        let mut identities = HashSet::new();

        // Always add the raw key identity
        identities.insert(IdentityRef::Key(*key));

        // Add all aliases that have been declared for this key
        for (identity_key, identity_type) in self.identity_info.keys() {
            if identity_key == key {
                match identity_type {
                    IdentityType::Main => {
                        // Main identity is already added above
                    }
                    IdentityType::Alias { alias_id } => {
                        identities.insert(IdentityRef::Alias {
                            key: *key,
                            alias: alias_id.clone(),
                        });
                    }
                }
            }
        }

        identities
    }

    /// Get the role for a specific identity
    pub fn get_role(&self, identity_ref: &IdentityRef) -> Option<GroupRole> {
        // Check for explicit role assignment first
        if let Some(role) = self.identity_roles.get(identity_ref) {
            return Some(role.clone());
        }

        // Fall back to default member role for any valid identity
        Some(GroupRole::Member)
    }

    /// Get effective role when a key acts as a specific identity
    pub fn get_effective_role(
        &self,
        key: &VerifyingKey,
        acting_as_alias: &Option<String>,
    ) -> Option<GroupRole> {
        let identity_ref = match acting_as_alias {
            Some(alias) => IdentityRef::Alias {
                key: *key,
                alias: alias.clone(),
            },
            None => IdentityRef::Key(*key),
        };

        self.get_role(&identity_ref)
    }

    /// Get display name for an identity
    pub fn get_display_name(&self, key: &VerifyingKey, identity_type: &IdentityType) -> String {
        // Look up the identity info
        if let Some(identity_info) = self.identity_info.get(&(*key, identity_type.clone())) {
            return identity_info.display_name.clone();
        }

        // Fall back to default display
        match identity_type {
            IdentityType::Main => format!("Key:{key:?}"),
            IdentityType::Alias { alias_id } => alias_id.clone(),
        }
    }

    /// Check if an identity has been declared by a key
    pub fn has_identity_info(&self, key: &VerifyingKey, identity_type: &IdentityType) -> bool {
        self.identity_info
            .contains_key(&(*key, identity_type.clone()))
    }
}

impl Default for GroupMembership {
    fn default() -> Self {
        Self::new()
    }
}
