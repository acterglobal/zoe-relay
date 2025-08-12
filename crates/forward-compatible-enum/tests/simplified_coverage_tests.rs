use forward_compatible_enum::{ForwardCompatibleEnum, U32Discriminants};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

// Test various field combinations to cover serialize/deserialize code paths
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum FieldTypeTestEnum {
    #[discriminant(0)]
    UnitVariant,

    #[discriminant(1)]
    SingleTuple(String),

    #[discriminant(4)]
    SingleNamed { field: String },

    #[discriminant(5)]
    DoubleNamed { first: String, second: u32 },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with range validation edge cases
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(range = "0..10")]
pub enum EdgeRangeEnum {
    #[discriminant(0)]
    FirstAllowed,

    #[discriminant(9)]
    LastAllowed,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with both custom unknown variant and range
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "CustomUnknown", range = "100..200")]
pub enum CombinedFeaturesEnum {
    #[discriminant(100)]
    FirstValue,

    #[discriminant(199)]
    LastValue,

    /// Custom unknown variant
    CustomUnknown { discriminant: u32, data: Vec<u8> },
}

// Test generic enum with proper bounds
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize + Clone",
    serde_deserialize = "T: DeserializeOwned + Clone"
)]
pub enum GenericWithWhere<T>
where
    T: Clone,
{
    #[discriminant(1)]
    Value(T),

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test simple non-generic enum with serialize bounds
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(serde_serialize = "Self: Clone")]
pub enum NonGenericBounds {
    #[discriminant(1)]
    SimpleValue,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test simple non-generic enum with deserialize bounds
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(serde_deserialize = "Self: Clone")]
pub enum NonGenericDeserializeBounds {
    #[discriminant(1)]
    SimpleValue,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test U32Discriminants with various edge cases
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum SingleVariantEnum {
    #[discriminant(42)]
    OnlyVariant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
#[u32_discriminants(fallback = "Last")]
pub enum LastFallbackEnum {
    #[discriminant(1)]
    First,

    #[discriminant(2)]
    Second,

    #[discriminant(999)]
    Last,
}

#[cfg(test)]
mod field_type_coverage_tests {
    use super::*;

    #[test]
    fn test_unit_variant_serialization() {
        let variant = FieldTypeTestEnum::UnitVariant;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Verify the wire format structure
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 0);

        // Unit variant should serialize to empty tuple
        let unit_data: () = postcard::from_bytes(&data).unwrap();
        assert_eq!(unit_data, ());
    }

    #[test]
    fn test_single_tuple_serialization() {
        let variant = FieldTypeTestEnum::SingleTuple("test".to_string());
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Verify the wire format structure
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 1);

        // Single tuple should serialize directly as the field value
        let field_data: String = postcard::from_bytes(&data).unwrap();
        assert_eq!(field_data, "test");
    }

    #[test]
    fn test_single_named_serialization() {
        let variant = FieldTypeTestEnum::SingleNamed {
            field: "test".to_string(),
        };
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Verify the wire format structure
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 4);

        // Single named field should serialize as tuple with one element
        let (field_value,): (String,) = postcard::from_bytes(&data).unwrap();
        assert_eq!(field_value, "test");
    }

    #[test]
    fn test_double_named_serialization() {
        let variant = FieldTypeTestEnum::DoubleNamed {
            first: "test".to_string(),
            second: 42,
        };
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Verify the wire format structure
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 5);

        // Named fields should serialize as tuple in field order
        let (first, second): (String, u32) = postcard::from_bytes(&data).unwrap();
        assert_eq!(first, "test");
        assert_eq!(second, 42);
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_edge_range_enum() {
        // Test first allowed value (0)
        let variant = EdgeRangeEnum::FirstAllowed;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: EdgeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test last allowed value (9)
        let variant = EdgeRangeEnum::LastAllowed;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: EdgeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test unknown variant outside range
        let unknown = EdgeRangeEnum::Unknown {
            discriminant: 50,
            data: vec![1, 2],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: EdgeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_combined_features_enum() {
        // Test first value at range boundary
        let variant = CombinedFeaturesEnum::FirstValue;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: CombinedFeaturesEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test custom unknown variant
        let unknown = CombinedFeaturesEnum::CustomUnknown {
            discriminant: 50,
            data: vec![1, 2, 3],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: CombinedFeaturesEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_generic_with_existing_where_clause() {
        let variant = GenericWithWhere::Value("test".to_string());
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: GenericWithWhere<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test unknown variant
        let unknown = GenericWithWhere::<String>::Unknown {
            discriminant: 999,
            data: vec![4, 5, 6],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: GenericWithWhere<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_non_generic_serialize_bounds() {
        let variant = NonGenericBounds::SimpleValue;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: NonGenericBounds = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_non_generic_deserialize_bounds() {
        let variant = NonGenericDeserializeBounds::SimpleValue;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: NonGenericDeserializeBounds = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }
}

#[cfg(test)]
mod u32_discriminants_edge_cases {
    use super::*;

    #[test]
    fn test_single_variant_enum() {
        let variant = SingleVariantEnum::OnlyVariant;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: SingleVariantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test conversion functions
        let discriminant: u32 = variant.into();
        assert_eq!(discriminant, 42);

        let from_u32 = SingleVariantEnum::from(42);
        assert_eq!(from_u32, SingleVariantEnum::OnlyVariant);

        // Test fallback behavior (should use first/only variant)
        let unknown_fallback = SingleVariantEnum::from(999);
        assert_eq!(unknown_fallback, SingleVariantEnum::OnlyVariant);
    }

    #[test]
    fn test_last_fallback_enum() {
        let variant = LastFallbackEnum::First;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: LastFallbackEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test discriminant values
        let disc: u32 = LastFallbackEnum::First.into();
        assert_eq!(disc, 1);

        let disc: u32 = LastFallbackEnum::Second.into();
        assert_eq!(disc, 2);

        let disc: u32 = LastFallbackEnum::Last.into();
        assert_eq!(disc, 999);

        // Test fallback to specific variant (Last)
        let unknown_fallback = LastFallbackEnum::from(12345);
        assert_eq!(unknown_fallback, LastFallbackEnum::Last);
    }

    #[test]
    fn test_reference_into_conversion() {
        let variant = LastFallbackEnum::Second;
        let disc_from_ref: u32 = (&variant).into();
        let disc_from_owned: u32 = variant.clone().into();

        assert_eq!(disc_from_ref, 2);
        assert_eq!(disc_from_owned, 2);
        assert_eq!(disc_from_ref, disc_from_owned);
    }

    #[test]
    fn test_boundary_discriminant_values() {
        // Test conversion for all discriminant values
        assert_eq!(LastFallbackEnum::from(1), LastFallbackEnum::First);
        assert_eq!(LastFallbackEnum::from(2), LastFallbackEnum::Second);
        assert_eq!(LastFallbackEnum::from(999), LastFallbackEnum::Last);

        // Test boundary cases for fallback
        assert_eq!(LastFallbackEnum::from(0), LastFallbackEnum::Last);
        assert_eq!(LastFallbackEnum::from(3), LastFallbackEnum::Last);
        assert_eq!(LastFallbackEnum::from(4294967295), LastFallbackEnum::Last);
    }
}

#[cfg(test)]
mod error_simulation_tests {
    use super::*;

    #[test]
    fn test_serialization_error_handling() {
        // Test what happens with corrupted unknown variant data
        let unknown = FieldTypeTestEnum::Unknown {
            discriminant: 999,
            data: vec![255, 255, 255, 255, 255], // Invalid postcard data
        };

        // The unknown variant itself should serialize/deserialize fine
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        // But attempting to deserialize the inner data would fail
        // (this is expected behavior for unknown variants)
        if let FieldTypeTestEnum::Unknown { data, .. } = &unknown {
            let invalid_inner_result: Result<String, _> = postcard::from_bytes(data);
            assert!(invalid_inner_result.is_err());
        }
    }

    #[test]
    fn test_large_discriminant_values() {
        // Test edge case with very large discriminant values
        let unknown = FieldTypeTestEnum::Unknown {
            discriminant: 4294967295, // u32::MAX
            data: vec![1, 2, 3],
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_empty_data_in_unknown_variant() {
        // Test unknown variant with empty data
        let unknown = FieldTypeTestEnum::Unknown {
            discriminant: 777,
            data: vec![],
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_very_large_data_in_unknown_variant() {
        // Test unknown variant with large data payload
        let large_data = vec![42u8; 1000];
        let unknown = FieldTypeTestEnum::Unknown {
            discriminant: 888,
            data: large_data.clone(),
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: FieldTypeTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        if let FieldTypeTestEnum::Unknown { discriminant, data } = recovered {
            assert_eq!(discriminant, 888);
            assert_eq!(data, large_data);
        } else {
            panic!("Expected Unknown variant");
        }
    }
}
