//! Application-specific protocol variants for group types
//!
//! This module defines protocol variants that are specific to application-level
//! functionality, separate from the wire protocol variants used for network communication.

use serde::{Deserialize, Serialize};
use std::fmt;
use zoe_wire_protocol::{ChannelId, version::Version};

/// Protocol variants for application-level group types
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum AppProtocolVariant {
    /// Digital Groups Organizer - collaborative workspace with tasks, calendar, etc.
    DigitalGroupsOrganizer,
    /// Not yet known variant
    Unknown(String),
}

impl From<String> for AppProtocolVariant {
    fn from(value: String) -> Self {
        match value.as_str() {
            "dgo" => AppProtocolVariant::DigitalGroupsOrganizer,
            _ => AppProtocolVariant::Unknown(value),
        }
    }
}

impl From<AppProtocolVariant> for String {
    fn from(val: AppProtocolVariant) -> Self {
        match val {
            AppProtocolVariant::DigitalGroupsOrganizer => "dgo".to_string(),
            AppProtocolVariant::Unknown(value) => value,
        }
    }
}

impl AppProtocolVariant {
    /// Get all supported app protocol variants
    pub fn all_variants() -> Vec<Self> {
        vec![AppProtocolVariant::DigitalGroupsOrganizer]
    }
}

impl fmt::Display for AppProtocolVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name: String = self.clone().into();
        write!(f, "{name}")
    }
}

/// Represents an installed application in a group with channel-per-app support
///
/// Each installed app gets its own communication channel for isolated messaging
/// while sharing the same group encryption and membership.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InstalledApp {
    /// Application protocol variant (e.g., DigitalGroupsOrganizer)
    pub app_id: AppProtocolVariant,
    /// Version of the application protocol
    pub version: Version,
    /// Application-specific channel tag for isolated communication
    /// Each app gets its own unique channel identifier
    pub app_tag: ChannelId,
}

impl InstalledApp {
    /// Create a new installed app
    pub fn new(app_id: AppProtocolVariant, version: Version, app_tag: ChannelId) -> Self {
        Self {
            app_id,
            version,
            app_tag,
        }
    }

    /// Create an installed app from major.minor version numbers
    pub fn new_simple(
        app_id: AppProtocolVariant,
        major: u64,
        minor: u64,
        app_tag: ChannelId,
    ) -> Self {
        Self {
            app_id,
            version: Version::new(major, minor, 0),
            app_tag,
        }
    }

    /// Create an installed app with a random channel tag
    pub fn with_random_tag(app_id: AppProtocolVariant, version: Version) -> Self {
        Self {
            app_id,
            version,
            app_tag: generate_random_tag(),
        }
    }

    /// Get the channel tag for this application
    pub fn channel_tag(&self) -> &ChannelId {
        &self.app_tag
    }

    /// Check if this app version is compatible with a requirement
    pub fn is_compatible_with(&self, req: &zoe_wire_protocol::version::VersionReq) -> bool {
        req.matches(&self.version)
    }
}

impl fmt::Display for InstalledApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.app_id, self.version)
    }
}

/// Generate a random 32-byte tag for app channel identification
fn generate_random_tag() -> ChannelId {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut tag = vec![0u8; 32]; // 256-bit random tag
    rng.fill_bytes(&mut tag);
    tag.into()
}

/// Create a default DGO installed app
pub fn default_dgo_app() -> InstalledApp {
    InstalledApp::with_random_tag(
        AppProtocolVariant::DigitalGroupsOrganizer,
        Version::new(1, 0, 0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_protocol_variant_serialization() {
        let variants = vec![
            AppProtocolVariant::DigitalGroupsOrganizer,
            AppProtocolVariant::Unknown("custom".to_string()),
        ];

        for variant in variants {
            let serialized = postcard::to_stdvec(&variant).unwrap();
            let deserialized: AppProtocolVariant = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_string_conversion() {
        assert_eq!(
            AppProtocolVariant::DigitalGroupsOrganizer.to_string(),
            "dgo"
        );

        assert_eq!(
            AppProtocolVariant::from("dgo".to_string()),
            AppProtocolVariant::DigitalGroupsOrganizer
        );
        assert_eq!(
            AppProtocolVariant::from("unknown".to_string()),
            AppProtocolVariant::Unknown("unknown".to_string())
        );
    }

    #[test]
    fn test_installed_app_creation() {
        let app_tag = ChannelId::from([1u8; 32]);
        let app = InstalledApp::new(
            AppProtocolVariant::DigitalGroupsOrganizer,
            Version::new(1, 2, 3),
            app_tag.clone(),
        );
        assert_eq!(app.app_id, AppProtocolVariant::DigitalGroupsOrganizer);
        assert_eq!(app.version.major, 1);
        assert_eq!(app.version.minor, 2);
        assert_eq!(app.version.patch, 3);
        assert_eq!(app.app_tag, app_tag);

        let app_simple_tag = ChannelId::from([1u8; 32]);
        let app_simple = InstalledApp::new_simple(
            AppProtocolVariant::Unknown("chat".to_string()),
            2,
            1,
            app_simple_tag.clone(),
        );
        assert_eq!(
            app_simple.app_id,
            AppProtocolVariant::Unknown("chat".to_string())
        );
        assert_eq!(app_simple.version.major, 2);
        assert_eq!(app_simple.version.minor, 1);
        assert_eq!(app_simple.version.patch, 0);
        assert_eq!(app_simple.app_tag, app_simple_tag);
    }

    #[test]
    fn test_installed_app_with_random_tags() {
        let app = InstalledApp::with_random_tag(
            AppProtocolVariant::DigitalGroupsOrganizer,
            Version::new(1, 0, 0),
        );
        assert_eq!(app.app_tag.len(), 32); // 32-byte random tag

        let custom_tag = ChannelId::from([1u8; 32]);
        let app_custom = InstalledApp::new(
            AppProtocolVariant::Unknown("calendar".to_string()),
            Version::new(1, 0, 0),
            custom_tag.clone(),
        );
        assert_eq!(app_custom.app_tag, custom_tag);
    }

    #[test]
    fn test_installed_app_channel_tag() {
        let custom_tag = ChannelId::from([1u8; 32]);
        let app = InstalledApp::new(
            AppProtocolVariant::DigitalGroupsOrganizer,
            Version::new(1, 0, 0),
            custom_tag.clone(),
        );
        assert_eq!(app.channel_tag(), &custom_tag);
    }

    #[test]
    fn test_installed_app_serialization() {
        let app = InstalledApp::new(
            AppProtocolVariant::DigitalGroupsOrganizer,
            Version::new(1, 2, 0),
            ChannelId::from([1u8; 32]),
        );

        let serialized = postcard::to_stdvec(&app).unwrap();
        let deserialized: InstalledApp = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(app, deserialized);
    }

    #[test]
    fn test_installed_app_display() {
        let app = InstalledApp::new(
            AppProtocolVariant::DigitalGroupsOrganizer,
            Version::new(1, 2, 0),
            ChannelId::from([1u8; 32]),
        );
        assert_eq!(app.to_string(), "dgo v1.2.0");
    }

    #[test]
    fn test_default_dgo_app() {
        let dgo_app = default_dgo_app();
        assert_eq!(dgo_app.app_id, AppProtocolVariant::DigitalGroupsOrganizer);
        assert_eq!(dgo_app.version.major, 1);
        assert_eq!(dgo_app.version.minor, 0);
        assert_eq!(dgo_app.version.patch, 0);
        assert_eq!(dgo_app.app_tag.len(), 32); // Random 32-byte tag
    }
}
