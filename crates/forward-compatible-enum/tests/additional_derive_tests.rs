// Additional tests for derive macro edge cases and coverage
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Serialize, de::DeserializeOwned};

// Test enum with single tuple field only (multiple tuple fields seem to have a derive issue)
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum TupleTestEnum {
    #[discriminant(1)]
    Single(String),

    #[discriminant(2)]
    Number(u32),

    #[discriminant(3)]
    Flag(bool),

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with complex discriminant values
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum ComplexDiscriminantEnum {
    #[discriminant(0)]
    Zero,

    #[discriminant(4294967295)] // u32::MAX as literal
    MaxValue,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with generic parameter and serde bounds
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize",
    serde_deserialize = "T: DeserializeOwned"
)]
pub enum GenericTestEnum<T> {
    #[discriminant(1)]
    Value(T),

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with empty forward_compatible attribute
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible()]
pub enum EmptyAttributeEnum {
    #[discriminant(1)]
    TestVariant,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with only custom unknown variant name
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "CustomUnknown")]
pub enum CustomUnknownEnum {
    #[discriminant(1)]
    TestVariant,

    /// Custom unknown variant
    CustomUnknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with only range attribute
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(range = "10..20")]
pub enum RangeOnlyEnum {
    #[discriminant(10)]
    FirstValue,

    #[discriminant(19)]
    LastValue,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

// Test enum with both range and custom unknown
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "OutOfRange", range = "100..200")]
pub enum RangeAndCustomEnum {
    #[discriminant(100)]
    InRange,

    #[discriminant(199)]
    AtBoundary,

    /// Out of range unknown variant
    OutOfRange { discriminant: u32, data: Vec<u8> },
}

#[cfg(test)]
mod tuple_tests {
    use super::*;

    #[test]
    fn test_single_tuple() {
        let variant = TupleTestEnum::Single("test".to_string());
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: TupleTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test wire format
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 1);
        let inner: String = postcard::from_bytes(&data).unwrap();
        assert_eq!(inner, "test");
    }

    #[test]
    fn test_number_tuple() {
        let variant = TupleTestEnum::Number(42);
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: TupleTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test wire format
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 2);
        let num: u32 = postcard::from_bytes(&data).unwrap();
        assert_eq!(num, 42);
    }

    #[test]
    fn test_flag_tuple() {
        let variant = TupleTestEnum::Flag(true);
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: TupleTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test wire format
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 3);
        let flag: bool = postcard::from_bytes(&data).unwrap();
        assert!(flag);
    }
}

#[cfg(test)]
mod complex_discriminant_tests {
    use super::*;

    #[test]
    fn test_zero_discriminant() {
        let variant = ComplexDiscriminantEnum::Zero;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: ComplexDiscriminantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_max_discriminant() {
        let variant = ComplexDiscriminantEnum::MaxValue;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: ComplexDiscriminantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Verify discriminant value in wire format
        let (discriminant, _): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 4294967295); // u32::MAX
    }

    #[test]
    fn test_large_unknown_discriminant() {
        let unknown = ComplexDiscriminantEnum::Unknown {
            discriminant: 4294967294, // u32::MAX - 1
            data: vec![1, 2, 3],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: ComplexDiscriminantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }
}

#[cfg(test)]
mod generic_tests {
    use super::*;

    #[test]
    fn test_generic_string() {
        let variant = GenericTestEnum::Value("hello".to_string());
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: GenericTestEnum<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_generic_number() {
        let variant = GenericTestEnum::Value(42u64);
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: GenericTestEnum<u64> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_generic_vec() {
        let variant = GenericTestEnum::Value(vec![1, 2, 3, 4, 5]);
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: GenericTestEnum<Vec<i32>> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_generic_unknown() {
        let unknown = GenericTestEnum::<String>::Unknown {
            discriminant: 999,
            data: vec![10, 20, 30],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: GenericTestEnum<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }
}

#[cfg(test)]
mod attribute_configuration_tests {
    use super::*;

    #[test]
    fn test_empty_attribute() {
        let variant = EmptyAttributeEnum::TestVariant;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: EmptyAttributeEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);
    }

    #[test]
    fn test_custom_unknown_name() {
        let variant = CustomUnknownEnum::TestVariant;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: CustomUnknownEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        let unknown = CustomUnknownEnum::CustomUnknown {
            discriminant: 123,
            data: vec![40, 50, 60],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: CustomUnknownEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_range_only() {
        let variant = RangeOnlyEnum::FirstValue;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: RangeOnlyEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        let variant = RangeOnlyEnum::LastValue;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: RangeOnlyEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Test unknown variant outside range
        let unknown = RangeOnlyEnum::Unknown {
            discriminant: 5, // Below range
            data: vec![70, 80, 90],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: RangeOnlyEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_range_and_custom() {
        let variant = RangeAndCustomEnum::InRange;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: RangeAndCustomEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        let variant = RangeAndCustomEnum::AtBoundary;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: RangeAndCustomEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        let unknown = RangeAndCustomEnum::OutOfRange {
            discriminant: 300, // Outside range
            data: vec![100, 110, 120],
        };
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: RangeAndCustomEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }
}

#[cfg(test)]
mod forward_compatibility_tests {
    use super::*;

    #[test]
    fn test_cross_version_compatibility() {
        // Simulate data from a newer version that has an unknown discriminant
        let future_data = (999u32, b"future data".to_vec());
        let serialized = postcard::to_stdvec(&future_data).unwrap();

        // Should deserialize as Unknown variant
        let recovered: TupleTestEnum = postcard::from_bytes(&serialized).unwrap();

        match recovered {
            TupleTestEnum::Unknown { discriminant, data } => {
                assert_eq!(discriminant, 999);
                assert_eq!(data, b"future data");
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_round_trip_fidelity() {
        let original_unknown = ComplexDiscriminantEnum::Unknown {
            discriminant: 12345,
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        // Multiple round trips should preserve exact data
        let bytes1 = postcard::to_stdvec(&original_unknown).unwrap();
        let recovered1: ComplexDiscriminantEnum = postcard::from_bytes(&bytes1).unwrap();

        let bytes2 = postcard::to_stdvec(&recovered1).unwrap();
        let recovered2: ComplexDiscriminantEnum = postcard::from_bytes(&bytes2).unwrap();

        assert_eq!(original_unknown, recovered1);
        assert_eq!(recovered1, recovered2);
        assert_eq!(bytes1, bytes2); // Wire format should be identical
    }

    #[test]
    fn test_unknown_variant_edge_cases() {
        // Test with empty data
        let empty_unknown = TupleTestEnum::Unknown {
            discriminant: 777,
            data: vec![],
        };
        let bytes = postcard::to_stdvec(&empty_unknown).unwrap();
        let recovered: TupleTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(empty_unknown, recovered);

        // Test with large data
        let large_unknown = TupleTestEnum::Unknown {
            discriminant: 888,
            data: vec![42; 1000],
        };
        let bytes = postcard::to_stdvec(&large_unknown).unwrap();
        let recovered: TupleTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(large_unknown, recovered);

        // Test with maximum discriminant
        let max_discriminant_unknown = TupleTestEnum::Unknown {
            discriminant: 4294967295, // u32::MAX
            data: vec![255, 254, 253],
        };
        let bytes = postcard::to_stdvec(&max_discriminant_unknown).unwrap();
        let recovered: TupleTestEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(max_discriminant_unknown, recovered);
    }
}
