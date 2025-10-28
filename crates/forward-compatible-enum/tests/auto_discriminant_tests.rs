//! Tests for automatic discriminant assignment
//!
//! These tests verify that both U32Discriminants and ForwardCompatibleEnum
//! can automatically assign discriminants when #[discriminant(N)] attributes
//! are not provided.

use forward_compatible_enum::{ForwardCompatibleEnum, U32Discriminants};
use serde::{Deserialize, Serialize};

// ============================================================================
// U32Discriminants Tests - Auto-assignment
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum SimpleAutoRole {
    Member,
    Moderator,
    Admin,
    Owner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
#[u32_discriminants(fallback = "Unknown")]
pub enum AutoStatusWithFallback {
    Unknown,
    Active,
    Inactive,
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum MixedAutoAndExplicit {
    // Auto-assigned (should be 0)
    First,

    #[discriminant(10)]
    Second,

    // Auto-assigned (should be 11)
    Third,

    #[discriminant(20)]
    Fourth,

    // Auto-assigned (should be 21)
    Fifth,
}

// ============================================================================
// ForwardCompatibleEnum Tests - Auto-assignment
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum AutoBasicEnum {
    UnitVariant,
    TupleVariant(String),
    StructVariant {
        name: String,
        value: u32,
    },

    /// Unknown variant for forward compatibility
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum MixedAutoExplicitEnum {
    // Auto-assigned (should be 0)
    First,

    #[discriminant(10)]
    Second(String),

    // Auto-assigned (should be 11)
    Third {
        data: u32,
    },

    #[discriminant(100)]
    Fourth,

    // Auto-assigned (should be 101)
    Fifth(Vec<u8>),

    /// Unknown variant for forward compatibility
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "UnknownType")]
pub enum AutoWithCustomUnknown {
    TypeA,
    TypeB(String),
    TypeC {
        value: u32,
    },

    /// Custom unknown variant
    UnknownType {
        discriminant: u32,
        data: Vec<u8>,
    },
}

// ============================================================================
// U32Discriminants Tests
// ============================================================================

#[cfg(test)]
mod u32_discriminants_auto_tests {
    use super::*;

    #[test]
    fn test_simple_auto_assignment() {
        // Auto-assigned discriminants should start at 0 and increment by 1
        assert_eq!(u32::from(&SimpleAutoRole::Member), 0);
        assert_eq!(u32::from(&SimpleAutoRole::Moderator), 1);
        assert_eq!(u32::from(&SimpleAutoRole::Admin), 2);
        assert_eq!(u32::from(&SimpleAutoRole::Owner), 3);
    }

    #[test]
    fn test_simple_auto_round_trip() {
        let roles = vec![
            SimpleAutoRole::Member,
            SimpleAutoRole::Moderator,
            SimpleAutoRole::Admin,
            SimpleAutoRole::Owner,
        ];

        for role in roles {
            let serialized = postcard::to_stdvec(&role).unwrap();
            let deserialized: SimpleAutoRole = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(role, deserialized);
        }
    }

    #[test]
    fn test_auto_from_u32_conversion() {
        assert_eq!(SimpleAutoRole::from(0), SimpleAutoRole::Member);
        assert_eq!(SimpleAutoRole::from(1), SimpleAutoRole::Moderator);
        assert_eq!(SimpleAutoRole::from(2), SimpleAutoRole::Admin);
        assert_eq!(SimpleAutoRole::from(3), SimpleAutoRole::Owner);
    }

    #[test]
    fn test_auto_fallback_to_first_variant() {
        // Unknown discriminant should fallback to first variant
        assert_eq!(SimpleAutoRole::from(999), SimpleAutoRole::Member);
    }

    #[test]
    fn test_auto_with_custom_fallback() {
        assert_eq!(u32::from(&AutoStatusWithFallback::Unknown), 0);
        assert_eq!(u32::from(&AutoStatusWithFallback::Active), 1);
        assert_eq!(u32::from(&AutoStatusWithFallback::Inactive), 2);
        assert_eq!(u32::from(&AutoStatusWithFallback::Pending), 3);

        // Custom fallback should be used for unknown values
        assert_eq!(
            AutoStatusWithFallback::from(999),
            AutoStatusWithFallback::Unknown
        );
    }

    #[test]
    fn test_mixed_auto_and_explicit() {
        // First is auto-assigned 0
        assert_eq!(u32::from(&MixedAutoAndExplicit::First), 0);

        // Second is explicit 10
        assert_eq!(u32::from(&MixedAutoAndExplicit::Second), 10);

        // Third is auto-assigned (previous + 1 = 11)
        assert_eq!(u32::from(&MixedAutoAndExplicit::Third), 11);

        // Fourth is explicit 20
        assert_eq!(u32::from(&MixedAutoAndExplicit::Fourth), 20);

        // Fifth is auto-assigned (previous + 1 = 21)
        assert_eq!(u32::from(&MixedAutoAndExplicit::Fifth), 21);
    }

    #[test]
    fn test_mixed_round_trip() {
        let values = vec![
            MixedAutoAndExplicit::First,
            MixedAutoAndExplicit::Second,
            MixedAutoAndExplicit::Third,
            MixedAutoAndExplicit::Fourth,
            MixedAutoAndExplicit::Fifth,
        ];

        for value in values {
            let serialized = postcard::to_stdvec(&value).unwrap();
            let deserialized: MixedAutoAndExplicit = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(value, deserialized);
        }
    }

    #[test]
    fn test_mixed_from_u32() {
        assert_eq!(MixedAutoAndExplicit::from(0), MixedAutoAndExplicit::First);
        assert_eq!(MixedAutoAndExplicit::from(10), MixedAutoAndExplicit::Second);
        assert_eq!(MixedAutoAndExplicit::from(11), MixedAutoAndExplicit::Third);
        assert_eq!(MixedAutoAndExplicit::from(20), MixedAutoAndExplicit::Fourth);
        assert_eq!(MixedAutoAndExplicit::from(21), MixedAutoAndExplicit::Fifth);
    }
}

// ============================================================================
// ForwardCompatibleEnum Tests
// ============================================================================

#[cfg(test)]
mod forward_compatible_auto_tests {
    use super::*;

    #[test]
    fn test_auto_basic_enum_discriminants() {
        // Verify auto-assigned discriminants through serialization
        let unit = AutoBasicEnum::UnitVariant;
        let tuple = AutoBasicEnum::TupleVariant("test".to_string());
        let struct_var = AutoBasicEnum::StructVariant {
            name: "name".to_string(),
            value: 42,
        };

        // Just ensure they serialize/deserialize correctly
        for variant in [unit, tuple, struct_var] {
            let serialized = postcard::to_stdvec(&variant).unwrap();
            let deserialized: AutoBasicEnum = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_auto_basic_enum_round_trip() {
        let original = AutoBasicEnum::TupleVariant("Hello, world!".to_string());
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: AutoBasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_auto_struct_variant_round_trip() {
        let original = AutoBasicEnum::StructVariant {
            name: "test".to_string(),
            value: 123,
        };
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: AutoBasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_mixed_auto_explicit_enum() {
        let first = MixedAutoExplicitEnum::First;
        let second = MixedAutoExplicitEnum::Second("data".to_string());
        let third = MixedAutoExplicitEnum::Third { data: 100 };
        let fourth = MixedAutoExplicitEnum::Fourth;
        let fifth = MixedAutoExplicitEnum::Fifth(vec![1, 2, 3]);

        for variant in [first, second, third, fourth, fifth] {
            let serialized = postcard::to_stdvec(&variant).unwrap();
            let deserialized: MixedAutoExplicitEnum = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_auto_with_custom_unknown() {
        let type_a = AutoWithCustomUnknown::TypeA;
        let type_b = AutoWithCustomUnknown::TypeB("test".to_string());
        let type_c = AutoWithCustomUnknown::TypeC { value: 42 };

        for variant in [type_a, type_b, type_c] {
            let serialized = postcard::to_stdvec(&variant).unwrap();
            let deserialized: AutoWithCustomUnknown = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_auto_unknown_variant_preservation() {
        let unknown = AutoBasicEnum::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3, 4],
        };
        let serialized = postcard::to_stdvec(&unknown).unwrap();
        let deserialized: AutoBasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(unknown, deserialized);
    }

    #[test]
    fn test_mixed_unknown_variant() {
        let unknown = MixedAutoExplicitEnum::Unknown {
            discriminant: 500,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let serialized = postcard::to_stdvec(&unknown).unwrap();
        let deserialized: MixedAutoExplicitEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(unknown, deserialized);
    }

    #[test]
    fn test_auto_enum_data_preservation() {
        // Test that complex data in auto-assigned variants is preserved
        let original = AutoBasicEnum::TupleVariant("Complex data: 日本語 🚀".to_string());
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: AutoBasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_auto_wire_format_efficiency() {
        // Auto-assigned discriminants starting at 0 should be very compact
        let role = SimpleAutoRole::Member; // discriminant 0
        let serialized = postcard::to_stdvec(&role).unwrap();
        assert_eq!(serialized, vec![0]); // Single byte

        let role = SimpleAutoRole::Moderator; // discriminant 1
        let serialized = postcard::to_stdvec(&role).unwrap();
        assert_eq!(serialized, vec![1]); // Single byte
    }

    #[test]
    fn test_mixed_wire_format() {
        // Explicit discriminant 10
        let value = MixedAutoAndExplicit::Second;
        let serialized = postcard::to_stdvec(&value).unwrap();
        assert_eq!(serialized, vec![10]); // Single byte

        // Explicit discriminant 20
        let value = MixedAutoAndExplicit::Fourth;
        let serialized = postcard::to_stdvec(&value).unwrap();
        assert_eq!(serialized, vec![20]); // Single byte
    }

    #[test]
    fn test_auto_reference_conversion() {
        let role = SimpleAutoRole::Admin;
        let discriminant: u32 = (&role).into();
        assert_eq!(discriminant, 2);
    }
}
