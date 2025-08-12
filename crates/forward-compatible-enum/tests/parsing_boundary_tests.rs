// Test for specific parsing edge cases and boundary conditions
// This test file focuses on exercising code paths that are hard to reach through normal usage

use forward_compatible_enum::ForwardCompatibleEnum;

// Test enum designed to exercise specific code paths in the derive macro
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "UnknownType")]
pub enum BoundaryTestEnum {
    #[discriminant(1)]
    FirstCase,

    /// Test unknown variant with specific name
    UnknownType { discriminant: u32, data: Vec<u8> },
}

// Test enum to exercise range boundaries exactly
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(range = "1..2")]
pub enum TinyRangeEnum {
    #[discriminant(1)]
    OnlyAllowed,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with range that uses larger numbers to test parsing
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(range = "1000000..1000002")]
pub enum LargeRangeEnum {
    #[discriminant(1000000)]
    FirstLarge,

    #[discriminant(1000001)]
    SecondLarge,

    /// Unknown variant for forward compatibility  
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum that exercises serde bounds parsing edge cases
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: serde::Serialize + std::fmt::Debug + Clone",
    serde_deserialize = "T: serde::de::DeserializeOwned + std::fmt::Debug + Clone"
)]
pub enum ComplexBoundsEnum<T> {
    #[discriminant(100)]
    Value(T),

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum designed to exercise unknown variant field validation paths
// This will be used in combination with manual testing
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualTestEnum {
    #[allow(dead_code)]
    RegularVariant,
    // Note: We intentionally don't derive ForwardCompatibleEnum here
    // This is for testing error conditions manually in unit tests
}

#[cfg(test)]
mod boundary_condition_tests {
    use super::*;

    #[test]
    fn test_boundary_test_enum() {
        let variant = BoundaryTestEnum::FirstCase;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test the custom unknown variant name
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 999,
            data: vec![1, 2, 3],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_tiny_range_enum() {
        // Test the single allowed value
        let variant = TinyRangeEnum::OnlyAllowed;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: TinyRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test unknown variant outside the tiny range
        let unknown = TinyRangeEnum::Unknown {
            discriminant: 0, // Below range
            data: vec![42],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: TinyRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        let unknown = TinyRangeEnum::Unknown {
            discriminant: 2, // At range boundary (exclusive)
            data: vec![43],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: TinyRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_large_range_enum() {
        // Test both allowed values in the large range
        let variant = LargeRangeEnum::FirstLarge;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: LargeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        let variant = LargeRangeEnum::SecondLarge;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: LargeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test unknown variant outside large range
        let unknown = LargeRangeEnum::Unknown {
            discriminant: 999999, // Below range
            data: vec![100],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: LargeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        let unknown = LargeRangeEnum::Unknown {
            discriminant: 1000002, // At range boundary (exclusive)
            data: vec![101],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: LargeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_complex_bounds_enum() {
        use std::collections::BTreeMap;

        // Test with a complex type that satisfies the bounds
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), "value".to_string());

        let variant = ComplexBoundsEnum::Value(map.clone());
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: ComplexBoundsEnum<BTreeMap<String, String>> =
            postcard::from_bytes(&bytes).unwrap();

        match recovered {
            ComplexBoundsEnum::Value(recovered_map) => {
                assert_eq!(recovered_map, map);
            }
            _ => panic!("Expected Value variant"),
        }
    }

    #[test]
    fn test_complex_bounds_unknown() {
        let unknown = ComplexBoundsEnum::<String>::Unknown {
            discriminant: 500,
            data: vec![200, 201, 202],
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: ComplexBoundsEnum<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }
}

#[cfg(test)]
mod wire_format_edge_cases {
    use super::*;

    #[test]
    fn test_discriminant_encoding_boundaries() {
        // Test discriminant values that exercise varint encoding boundaries

        // Single byte varint (0-127)
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 127,
            data: vec![1],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        // Two byte varint (128-16383)
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 128,
            data: vec![2],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 16383,
            data: vec![3],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        // Three byte varint (16384+)
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 16384,
            data: vec![4],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_data_length_encoding_boundaries() {
        // Test Vec<u8> length encoding at varint boundaries
        // Use unknown discriminants (not 1, which is FirstCase)

        // Empty vec (length 0)
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 100,
            data: vec![],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        // 127 bytes (single byte length)
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 200,
            data: vec![42; 127],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        // 128 bytes (two byte length)
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 300,
            data: vec![43; 128],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_round_trip_large_discriminant_and_data() {
        // Test combination of large discriminant and large data
        let unknown = LargeRangeEnum::Unknown {
            discriminant: u32::MAX,
            data: vec![255; 1000],
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: LargeRangeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }
}

#[cfg(test)]
mod forward_compatibility_edge_cases {
    use super::*;

    #[test]
    fn test_unknown_variant_round_trip_fidelity() {
        // Create unknown variant with complex inner data
        let inner_data = (
            "complex".to_string(),
            vec![1u32, 2, 3, 4, 5],
            Some(42u64),
            None::<String>,
        );
        let serialized_inner = postcard::to_stdvec(&inner_data).unwrap();

        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: 12345,
            data: serialized_inner.clone(),
        };

        // Multiple round trips should preserve the exact data
        let bytes1 = postcard::to_stdvec(&unknown).unwrap();
        let recovered1: BoundaryTestEnum = postcard::from_bytes(&bytes1).unwrap();

        let bytes2 = postcard::to_stdvec(&recovered1).unwrap();
        let recovered2: BoundaryTestEnum = postcard::from_bytes(&bytes2).unwrap();

        let bytes3 = postcard::to_stdvec(&recovered2).unwrap();
        let recovered3: BoundaryTestEnum = postcard::from_bytes(&bytes3).unwrap();

        // All should be identical
        assert_eq!(unknown, recovered1);
        assert_eq!(recovered1, recovered2);
        assert_eq!(recovered2, recovered3);

        // Verify inner data is still recoverable
        if let BoundaryTestEnum::UnknownType { discriminant, data } = recovered3 {
            assert_eq!(discriminant, 12345);
            assert_eq!(data, serialized_inner);

            // Should be able to deserialize the inner data
            let recovered_inner: (String, Vec<u32>, Option<u64>, Option<String>) =
                postcard::from_bytes(&data).unwrap();
            assert_eq!(recovered_inner, inner_data);
        } else {
            panic!("Expected UnknownType variant");
        }
    }

    #[test]
    fn test_cross_enum_unknown_variant_data() {
        // Create unknown variant using data from a different enum type
        let original_variant = LargeRangeEnum::FirstLarge;
        let original_bytes = postcard::to_stdvec(&original_variant).unwrap();

        // Extract the wire format
        let (original_discriminant, original_data): (u32, Vec<u8>) =
            postcard::from_bytes(&original_bytes).unwrap();

        // Use this data in a different enum's unknown variant
        let unknown = BoundaryTestEnum::UnknownType {
            discriminant: original_discriminant,
            data: original_data.clone(),
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: BoundaryTestEnum = postcard::from_bytes(&bytes).unwrap();

        if let BoundaryTestEnum::UnknownType { discriminant, data } = recovered {
            assert_eq!(discriminant, original_discriminant);
            assert_eq!(data, original_data);
        } else {
            panic!("Expected UnknownType variant");
        }
    }
}
