use forward_compatible_enum::ForwardCompatibleEnum;

use crate::file::Image;
use crate::icon::Icon;
#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(non_opaque))]
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum Metadata {
    #[discriminant(0)]
    Generic { key: String, value: String },

    #[discriminant(10)]
    Description(String),

    #[discriminant(20)]
    Avatar(Image),
    #[discriminant(21)]
    Background(Image),
    #[discriminant(22)]
    Icon(Icon),
    #[discriminant(30)]
    Website(String),
    #[discriminant(40)]
    Email(String),
    #[discriminant(41)]
    Phone(String),
    #[discriminant(50)]
    Address(String),
    #[discriminant(60)]
    Social { platform: String, handle: String },

    /// Unknown metadata type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

impl Metadata {
    /// Determines if this metadata item should replace an existing metadata item.
    ///
    /// Returns `true` if the existing item should be replaced by this one.
    ///
    /// # Replacement Rules
    ///
    /// - `Generic`: Replaces if the key matches
    /// - `Description`, `Avatar`, `Background`, `Icon`, `Website`, `Email`, `Phone`, `Address`:
    ///   Replaces any existing item of the same type (only one allowed)
    /// - `Social`: Replaces if both the platform and discriminant match (allows multiple social
    ///   platforms, but only one handle per platform)
    /// - `Unknown`: Never replaces (forward compatibility)
    pub fn should_replace(&self, existing: &Metadata) -> bool {
        match (self, existing) {
            // Generic metadata: replace if key matches
            (Metadata::Generic { key: k1, .. }, Metadata::Generic { key: k2, .. }) => k1 == k2,

            // Single-instance metadata: replace if same type
            (Metadata::Description(_), Metadata::Description(_)) => true,
            (Metadata::Avatar(_), Metadata::Avatar(_)) => true,
            (Metadata::Background(_), Metadata::Background(_)) => true,
            (Metadata::Icon(_), Metadata::Icon(_)) => true,
            (Metadata::Website(_), Metadata::Website(_)) => true,
            (Metadata::Email(_), Metadata::Email(_)) => true,
            (Metadata::Phone(_), Metadata::Phone(_)) => true,
            (Metadata::Address(_), Metadata::Address(_)) => true,

            // Social metadata: replace only if same platform
            (Metadata::Social { platform: p1, .. }, Metadata::Social { platform: p2, .. }) => {
                p1 == p2
            }
            // Different types and unknowns: don't replace
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_should_replace_generic() {
        let meta1 = Metadata::Generic {
            key: "department".to_string(),
            value: "engineering".to_string(),
        };
        let meta2 = Metadata::Generic {
            key: "department".to_string(),
            value: "sales".to_string(),
        };
        let meta3 = Metadata::Generic {
            key: "team".to_string(),
            value: "backend".to_string(),
        };

        // Same key should replace
        assert!(meta2.should_replace(&meta1));
        // Different keys should not replace
        assert!(!meta3.should_replace(&meta1));
    }

    #[test]
    fn test_metadata_should_replace_single_instance() {
        let desc1 = Metadata::Description("Old description".to_string());
        let desc2 = Metadata::Description("New description".to_string());
        let email = Metadata::Email("test@example.com".to_string());

        // Same type should replace
        assert!(desc2.should_replace(&desc1));
        // Different types should not replace
        assert!(!email.should_replace(&desc1));
        assert!(!desc1.should_replace(&email));
    }

    #[test]
    fn test_metadata_should_replace_social() {
        let twitter1 = Metadata::Social {
            platform: "twitter".to_string(),
            handle: "@oldhandle".to_string(),
        };
        let twitter2 = Metadata::Social {
            platform: "twitter".to_string(),
            handle: "@newhandle".to_string(),
        };
        let github = Metadata::Social {
            platform: "github".to_string(),
            handle: "@user".to_string(),
        };

        // Same platform should replace
        assert!(twitter2.should_replace(&twitter1));
        // Different platforms should not replace
        assert!(!github.should_replace(&twitter1));
        assert!(!twitter1.should_replace(&github));
    }

    #[test]
    fn test_metadata_should_replace_unknown() {
        let unknown1 = Metadata::Unknown {
            discriminant: 100,
            data: vec![1, 2, 3],
        };
        let unknown2 = Metadata::Unknown {
            discriminant: 100,
            data: vec![4, 5, 6],
        };
        let desc = Metadata::Description("Test".to_string());

        // Unknown should never replace
        assert!(!unknown1.should_replace(&unknown2));
        assert!(!unknown1.should_replace(&desc));
        assert!(!desc.should_replace(&unknown1));
    }
}
