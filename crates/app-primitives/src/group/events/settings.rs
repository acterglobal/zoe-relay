use serde::{Deserialize, Serialize};

use super::permissions::GroupPermissions;

/// Group settings and configuration for encrypted groups
///
/// These settings control various aspects of group behavior and permissions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct GroupSettings {
    /// Required permissions for various actions
    pub permissions: GroupPermissions,
    /// Group encryption and security settings
    pub encryption_settings: EncryptionSettings,
}

/// Encryption-related settings for a group
///
/// Controls various encryption and security features for the group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct EncryptionSettings {
    /// Whether to rotate keys periodically (future feature)
    ///
    /// When enabled, the group will periodically rotate its encryption keys
    /// to provide forward secrecy.
    pub key_rotation_enabled: bool,

    /// Key rotation interval in seconds (if enabled)
    ///
    /// How often to rotate keys when key rotation is enabled.
    pub key_rotation_interval: Option<u64>,

    /// Additional authenticated data to include in encryption
    ///
    /// Extra context that will be included in the authenticated encryption
    /// to provide additional security guarantees.
    pub additional_context: Option<String>,
}

impl GroupSettings {
    /// Create new group settings with default permissions
    pub fn new() -> Self {
        Self::default()
    }

    /// Set group permissions
    pub fn permissions(mut self, permissions: GroupPermissions) -> Self {
        self.permissions = permissions;
        self
    }

    /// Set encryption settings
    pub fn encryption_settings(mut self, settings: EncryptionSettings) -> Self {
        self.encryption_settings = settings;
        self
    }
}

impl EncryptionSettings {
    /// Create new encryption settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable key rotation with specified interval
    pub fn with_key_rotation(mut self, interval_seconds: u64) -> Self {
        self.key_rotation_enabled = true;
        self.key_rotation_interval = Some(interval_seconds);
        self
    }

    /// Set additional authenticated context
    pub fn with_additional_context(mut self, context: String) -> Self {
        self.additional_context = Some(context);
        self
    }
}
