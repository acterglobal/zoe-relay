use forward_compatible_enum::{ForwardCompatibleEnum, U32Discriminants};
use serde::{Deserialize, Serialize};

use crate::file::Image;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum NamedIcon {
    Apple,
    Atom,
    Axe,
    Ball,
    Bell,
    Bike,
    Bird,
    Bone,
    Brush,
    Bug,
    Building,
    Car,
    Castle,
    Cat,
    Compass,
    Document,
    Dog,
    Egg,
    Envelope,
    Fish,
    Fist,
    Flame,
    Flower,
    Gauge,
    Hammer,
    Heart,
    House,
    Key,
    Leaf,
    Lock,
    MailBox,
    Map,
    Moon,
    Mountain,
    Palm,
    Panda,
    PaperClip,
    PaperPlane,
    PawPrint,
    Plan,
    Rabbit,
    Rat,
    Scale,
    Shield,
    Ship,
    Shovel,
    Snail,
    Squirrel,
    Star,
    Sun,
    Telescope,
    Tent,
    Tractor,
    Train,
    Tree,
    Truck,
    Turtle,
    Utensil,
    Wrench,
}

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum Icon {
    NamedIcon(NamedIcon),
    Emoji(String),
    Image(Image),
    /// Unknown metadata type for forward compatibility
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_named_icon_auto_discriminant_assignment() {
        // Test that auto-assigned discriminants work correctly
        assert_eq!(u32::from(&NamedIcon::Apple), 0);
        assert_eq!(u32::from(&NamedIcon::Atom), 1);
        assert_eq!(u32::from(&NamedIcon::Axe), 2);

        // Test conversion back from u32
        assert_eq!(NamedIcon::from(0), NamedIcon::Apple);
        assert_eq!(NamedIcon::from(1), NamedIcon::Atom);
        assert_eq!(NamedIcon::from(2), NamedIcon::Axe);
    }

    #[test]
    fn test_named_icon_round_trip() {
        let icons = vec![
            NamedIcon::Apple,
            NamedIcon::Heart,
            NamedIcon::Star,
            NamedIcon::Tree,
        ];

        for icon in icons {
            let serialized = postcard::to_stdvec(&icon).unwrap();
            let deserialized: NamedIcon = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(icon, deserialized);
        }
    }

    #[test]
    fn test_icon_auto_discriminant_assignment() {
        // Test Icon enum with auto-assigned discriminants
        let named = Icon::NamedIcon(NamedIcon::Star);
        let emoji = Icon::Emoji("🌟".to_string());

        // Test serialization for named and emoji variants
        for icon in [named, emoji] {
            let serialized = postcard::to_stdvec(&icon).unwrap();
            let deserialized: Icon = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(icon, deserialized);
        }
    }

    #[test]
    fn test_icon_unknown_variant_preservation() {
        let unknown = Icon::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3, 4],
        };

        let serialized = postcard::to_stdvec(&unknown).unwrap();
        let deserialized: Icon = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(unknown, deserialized);
    }

    #[test]
    fn test_named_icon_fallback_to_first_variant() {
        // Unknown discriminant should fallback to first variant (Apple)
        assert_eq!(NamedIcon::from(999), NamedIcon::Apple);
    }
}
