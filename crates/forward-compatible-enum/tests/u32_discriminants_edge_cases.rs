// Comprehensive tests for U32Discriminants derive macro edge cases
use forward_compatible_enum::U32Discriminants;
use serde::{Deserialize, Serialize};

// Test U32Discriminants with maximum discriminant value
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum MaxDiscriminantEnum {
    #[discriminant(0)]
    Zero,

    #[discriminant(4294967295)] // u32::MAX as literal
    Maximum,
}

// Test U32Discriminants with sparse discriminant values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum SparseDiscriminantEnum {
    #[discriminant(1)]
    First,

    #[discriminant(1000)]
    Thousand,

    #[discriminant(1000000)]
    Million,
}

// Test U32Discriminants with custom fallback
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
#[u32_discriminants(fallback = "Error")]
pub enum FallbackEnum {
    #[discriminant(10)]
    Success,

    #[discriminant(20)]
    Warning,

    #[discriminant(0)]
    Error, // Used as fallback
}

// Test U32Discriminants with single variant
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum SingleVariantEnum {
    #[discriminant(42)]
    OnlyOption,
}

// Test U32Discriminants with varint boundary values
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum VarintBoundaryEnum {
    #[discriminant(127)]
    SingleByteMax,

    #[discriminant(128)]
    TwoByteMin,

    #[discriminant(16383)]
    TwoByteMax,

    #[discriminant(16384)]
    ThreeByteMin,
}

#[cfg(test)]
mod max_discriminant_tests {
    use super::*;

    #[test]
    fn test_max_discriminant_conversion() {
        let zero: u32 = MaxDiscriminantEnum::Zero.into();
        assert_eq!(zero, 0);

        let max: u32 = MaxDiscriminantEnum::Maximum.into();
        assert_eq!(max, 4294967295); // u32::MAX
    }

    #[test]
    fn test_max_discriminant_from_u32() {
        assert_eq!(MaxDiscriminantEnum::from(0), MaxDiscriminantEnum::Zero);
        assert_eq!(
            MaxDiscriminantEnum::from(4294967295),
            MaxDiscriminantEnum::Maximum
        );
    }

    #[test]
    fn test_max_discriminant_fallback() {
        // Should fallback to first variant (Zero) for unknown values
        assert_eq!(MaxDiscriminantEnum::from(1), MaxDiscriminantEnum::Zero);
        assert_eq!(
            MaxDiscriminantEnum::from(4294967294),
            MaxDiscriminantEnum::Zero
        );
    }

    #[test]
    fn test_max_discriminant_serialization() {
        let zero = MaxDiscriminantEnum::Zero;
        let bytes = postcard::to_stdvec(&zero).unwrap();
        let recovered: MaxDiscriminantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(zero, recovered);

        let max = MaxDiscriminantEnum::Maximum;
        let bytes = postcard::to_stdvec(&max).unwrap();
        let recovered: MaxDiscriminantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(max, recovered);
    }

    #[test]
    fn test_max_discriminant_reference_conversion() {
        let max = MaxDiscriminantEnum::Maximum;
        let disc_from_ref: u32 = (&max).into();
        let disc_from_owned: u32 = max.into();

        assert_eq!(disc_from_ref, 4294967295);
        assert_eq!(disc_from_owned, 4294967295);
    }
}

#[cfg(test)]
mod sparse_discriminant_tests {
    use super::*;

    #[test]
    fn test_sparse_discriminant_conversion() {
        let first: u32 = SparseDiscriminantEnum::First.into();
        assert_eq!(first, 1);

        let thousand: u32 = SparseDiscriminantEnum::Thousand.into();
        assert_eq!(thousand, 1000);

        let million: u32 = SparseDiscriminantEnum::Million.into();
        assert_eq!(million, 1000000);
    }

    #[test]
    fn test_sparse_discriminant_from_u32() {
        assert_eq!(
            SparseDiscriminantEnum::from(1),
            SparseDiscriminantEnum::First
        );
        assert_eq!(
            SparseDiscriminantEnum::from(1000),
            SparseDiscriminantEnum::Thousand
        );
        assert_eq!(
            SparseDiscriminantEnum::from(1000000),
            SparseDiscriminantEnum::Million
        );
    }

    #[test]
    fn test_sparse_discriminant_fallback() {
        // Should fallback to first variant for gaps
        assert_eq!(
            SparseDiscriminantEnum::from(0),
            SparseDiscriminantEnum::First
        );
        assert_eq!(
            SparseDiscriminantEnum::from(2),
            SparseDiscriminantEnum::First
        );
        assert_eq!(
            SparseDiscriminantEnum::from(999),
            SparseDiscriminantEnum::First
        );
        assert_eq!(
            SparseDiscriminantEnum::from(1001),
            SparseDiscriminantEnum::First
        );
        assert_eq!(
            SparseDiscriminantEnum::from(4294967295),
            SparseDiscriminantEnum::First
        );
    }

    #[test]
    fn test_sparse_discriminant_serialization() {
        let variants = vec![
            SparseDiscriminantEnum::First,
            SparseDiscriminantEnum::Thousand,
            SparseDiscriminantEnum::Million,
        ];

        for variant in variants {
            let bytes = postcard::to_stdvec(&variant).unwrap();
            let recovered: SparseDiscriminantEnum = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(variant, recovered);
        }
    }
}

#[cfg(test)]
mod fallback_tests {
    use super::*;

    #[test]
    fn test_fallback_conversion() {
        let success: u32 = FallbackEnum::Success.into();
        assert_eq!(success, 10);

        let warning: u32 = FallbackEnum::Warning.into();
        assert_eq!(warning, 20);

        let error: u32 = FallbackEnum::Error.into();
        assert_eq!(error, 0);
    }

    #[test]
    fn test_fallback_from_u32() {
        assert_eq!(FallbackEnum::from(10), FallbackEnum::Success);
        assert_eq!(FallbackEnum::from(20), FallbackEnum::Warning);
        assert_eq!(FallbackEnum::from(0), FallbackEnum::Error);
    }

    #[test]
    fn test_fallback_unknown() {
        // Should fallback to Error variant (not Success, despite it being first)
        assert_eq!(FallbackEnum::from(1), FallbackEnum::Error);
        assert_eq!(FallbackEnum::from(15), FallbackEnum::Error);
        assert_eq!(FallbackEnum::from(25), FallbackEnum::Error);
        assert_eq!(FallbackEnum::from(4294967295), FallbackEnum::Error);
    }

    #[test]
    fn test_fallback_serialization() {
        let variants = vec![
            FallbackEnum::Success,
            FallbackEnum::Warning,
            FallbackEnum::Error,
        ];

        for variant in variants {
            let bytes = postcard::to_stdvec(&variant).unwrap();
            let recovered: FallbackEnum = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(variant, recovered);
        }
    }
}

#[cfg(test)]
mod single_variant_tests {
    use super::*;

    #[test]
    fn test_single_variant_conversion() {
        let only: u32 = SingleVariantEnum::OnlyOption.into();
        assert_eq!(only, 42);
    }

    #[test]
    fn test_single_variant_from_u32() {
        assert_eq!(SingleVariantEnum::from(42), SingleVariantEnum::OnlyOption);
    }

    #[test]
    fn test_single_variant_fallback() {
        // All unknown values should fallback to the only variant
        assert_eq!(SingleVariantEnum::from(0), SingleVariantEnum::OnlyOption);
        assert_eq!(SingleVariantEnum::from(1), SingleVariantEnum::OnlyOption);
        assert_eq!(SingleVariantEnum::from(41), SingleVariantEnum::OnlyOption);
        assert_eq!(SingleVariantEnum::from(43), SingleVariantEnum::OnlyOption);
        assert_eq!(
            SingleVariantEnum::from(4294967295),
            SingleVariantEnum::OnlyOption
        );
    }

    #[test]
    fn test_single_variant_serialization() {
        let variant = SingleVariantEnum::OnlyOption;
        let bytes = postcard::to_stdvec(&variant).unwrap();
        let recovered: SingleVariantEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(variant, recovered);

        // Verify wire format is just the discriminant
        assert_eq!(bytes, vec![42]);
    }

    #[test]
    fn test_single_variant_reference_conversion() {
        let variant = SingleVariantEnum::OnlyOption;
        let disc_from_ref: u32 = (&variant).into();
        let disc_from_owned: u32 = variant.into();

        assert_eq!(disc_from_ref, 42);
        assert_eq!(disc_from_owned, 42);
    }
}

#[cfg(test)]
mod varint_boundary_tests {
    use super::*;

    #[test]
    fn test_varint_boundary_conversion() {
        let single_byte: u32 = VarintBoundaryEnum::SingleByteMax.into();
        assert_eq!(single_byte, 127);

        let two_byte_min: u32 = VarintBoundaryEnum::TwoByteMin.into();
        assert_eq!(two_byte_min, 128);

        let two_byte_max: u32 = VarintBoundaryEnum::TwoByteMax.into();
        assert_eq!(two_byte_max, 16383);

        let three_byte_min: u32 = VarintBoundaryEnum::ThreeByteMin.into();
        assert_eq!(three_byte_min, 16384);
    }

    #[test]
    fn test_varint_boundary_from_u32() {
        assert_eq!(
            VarintBoundaryEnum::from(127),
            VarintBoundaryEnum::SingleByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(128),
            VarintBoundaryEnum::TwoByteMin
        );
        assert_eq!(
            VarintBoundaryEnum::from(16383),
            VarintBoundaryEnum::TwoByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(16384),
            VarintBoundaryEnum::ThreeByteMin
        );
    }

    #[test]
    fn test_varint_boundary_serialization() {
        // Test that different varint encodings work correctly
        let single_byte = VarintBoundaryEnum::SingleByteMax;
        let bytes = postcard::to_stdvec(&single_byte).unwrap();
        assert_eq!(bytes.len(), 1); // 127 fits in single byte
        let recovered: VarintBoundaryEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(single_byte, recovered);

        let two_byte = VarintBoundaryEnum::TwoByteMin;
        let bytes = postcard::to_stdvec(&two_byte).unwrap();
        assert_eq!(bytes.len(), 2); // 128 requires two bytes
        let recovered: VarintBoundaryEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(two_byte, recovered);

        let two_byte_max = VarintBoundaryEnum::TwoByteMax;
        let bytes = postcard::to_stdvec(&two_byte_max).unwrap();
        assert_eq!(bytes.len(), 2); // 16383 still fits in two bytes
        let recovered: VarintBoundaryEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(two_byte_max, recovered);

        let three_byte = VarintBoundaryEnum::ThreeByteMin;
        let bytes = postcard::to_stdvec(&three_byte).unwrap();
        assert_eq!(bytes.len(), 3); // 16384 requires three bytes
        let recovered: VarintBoundaryEnum = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(three_byte, recovered);
    }

    #[test]
    fn test_varint_boundary_fallback() {
        // Test fallback behavior at varint boundaries
        assert_eq!(
            VarintBoundaryEnum::from(126),
            VarintBoundaryEnum::SingleByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(129),
            VarintBoundaryEnum::SingleByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(16382),
            VarintBoundaryEnum::SingleByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(16385),
            VarintBoundaryEnum::SingleByteMax
        );
    }
}

#[cfg(test)]
mod comprehensive_edge_cases {
    use super::*;

    #[test]
    fn test_all_enum_round_trips() {
        // Test that all enum types work with their basic functionality
        let max_enum = MaxDiscriminantEnum::Maximum;
        let bytes = postcard::to_stdvec(&max_enum).unwrap();
        assert!(!bytes.is_empty());

        let sparse_enum = SparseDiscriminantEnum::Million;
        let bytes = postcard::to_stdvec(&sparse_enum).unwrap();
        assert!(!bytes.is_empty());

        let fallback_enum = FallbackEnum::Warning;
        let bytes = postcard::to_stdvec(&fallback_enum).unwrap();
        assert!(!bytes.is_empty());

        let single_enum = SingleVariantEnum::OnlyOption;
        let bytes = postcard::to_stdvec(&single_enum).unwrap();
        assert!(!bytes.is_empty());

        let varint_enum = VarintBoundaryEnum::ThreeByteMin;
        let bytes = postcard::to_stdvec(&varint_enum).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_discriminant_boundary_values() {
        // Test discriminants at various boundaries work correctly
        assert_eq!(MaxDiscriminantEnum::from(0), MaxDiscriminantEnum::Zero);
        assert_eq!(
            MaxDiscriminantEnum::from(4294967295),
            MaxDiscriminantEnum::Maximum
        );

        assert_eq!(
            VarintBoundaryEnum::from(127),
            VarintBoundaryEnum::SingleByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(128),
            VarintBoundaryEnum::TwoByteMin
        );
        assert_eq!(
            VarintBoundaryEnum::from(16383),
            VarintBoundaryEnum::TwoByteMax
        );
        assert_eq!(
            VarintBoundaryEnum::from(16384),
            VarintBoundaryEnum::ThreeByteMin
        );
    }

    #[test]
    fn test_reference_vs_owned_conversions() {
        // Test that reference and owned conversions produce same results
        let variants = [
            FallbackEnum::Success,
            FallbackEnum::Warning,
            FallbackEnum::Error,
        ];

        for variant in variants {
            let owned_disc: u32 = variant.into();
            let ref_disc: u32 = (&variant).into();
            assert_eq!(owned_disc, ref_disc);
        }
    }
}
