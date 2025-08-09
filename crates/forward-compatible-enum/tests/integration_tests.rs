use forward_compatible_enum::ForwardCompatibleEnum;

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum BasicEnum {
    #[discriminant(0)]
    UnitVariant,

    #[discriminant(1)]
    TupleVariant(String),

    #[discriminant(2)]
    StructVariant { name: String, value: u32 },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "UnknownMessage")]
pub enum MessageType {
    #[discriminant(10)]
    Text(String),

    #[discriminant(20)]
    Image {
        url: String,
        caption: Option<String>,
    },

    #[discriminant(30)]
    File { name: String, size: u64 },

    /// Unknown variant for forward compatibility
    UnknownMessage { discriminant: u32, data: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(range = "100..200")]
pub enum RangedEnum {
    #[discriminant(100)]
    First,

    #[discriminant(150)]
    Second(u32),

    #[discriminant(199)]
    Last { data: String },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

mod postcard_serialization {
    use super::*;

    #[test]
    fn test_unit_variant_round_trip() {
        let original = BasicEnum::UnitVariant;
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: BasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_tuple_variant_round_trip() {
        let original = BasicEnum::TupleVariant("Hello, world!".to_string());
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: BasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_struct_variant_round_trip() {
        let original = BasicEnum::StructVariant {
            name: "test".to_string(),
            value: 42,
        };
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: BasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_complex_message_round_trip() {
        let original = MessageType::Image {
            url: "https://example.com/image.jpg".to_string(),
            caption: Some("A beautiful sunset".to_string()),
        };
        let serialized = postcard::to_stdvec(&original).unwrap();
        let deserialized: MessageType = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_unknown_variant_preservation() {
        let unknown = BasicEnum::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3, 4],
        };
        let serialized = postcard::to_stdvec(&unknown).unwrap();
        let deserialized: BasicEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(unknown, deserialized);
    }

    #[test]
    fn test_custom_unknown_variant_name() {
        let unknown = MessageType::UnknownMessage {
            discriminant: 999,
            data: vec![5, 6, 7, 8],
        };
        let serialized = postcard::to_stdvec(&unknown).unwrap();
        let deserialized: MessageType = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(unknown, deserialized);
    }
}

mod forward_compatibility {
    use super::*;

    /// Simulate data from a newer version of BasicEnum with a new variant
    #[test]
    fn test_newer_version_compatibility() {
        // Manually create serialized data that would come from a newer version
        // Format: (discriminant: u32, data: Vec<u8>)
        let future_discriminant = 999u32;
        let future_data = b"future data".to_vec();
        let simulated_future_data = (future_discriminant, future_data.clone());

        let serialized = postcard::to_stdvec(&simulated_future_data).unwrap();
        let deserialized: BasicEnum = postcard::from_bytes(&serialized).unwrap();

        match deserialized {
            BasicEnum::Unknown { discriminant, data } => {
                assert_eq!(discriminant, future_discriminant);
                assert_eq!(data, future_data);
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_round_trip_unknown_data() {
        // Start with unknown data
        let original_unknown = MessageType::UnknownMessage {
            discriminant: 999,
            data: vec![42, 24, 68, 92],
        };

        // Serialize and deserialize multiple times
        let bytes1 = postcard::to_stdvec(&original_unknown).unwrap();
        let recovered1: MessageType = postcard::from_bytes(&bytes1).unwrap();
        let bytes2 = postcard::to_stdvec(&recovered1).unwrap();
        let recovered2: MessageType = postcard::from_bytes(&bytes2).unwrap();

        // Should be identical after multiple round trips
        assert_eq!(original_unknown, recovered1);
        assert_eq!(recovered1, recovered2);
    }

    #[test]
    fn test_wire_format_structure() {
        let message = BasicEnum::TupleVariant("test".to_string());
        let serialized = postcard::to_stdvec(&message).unwrap();

        // Deserialize as raw tuple to inspect wire format
        let (discriminant, data): (u32, Vec<u8>) = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(discriminant, 1); // TupleVariant discriminant

        // The data should be the serialized string "test"
        let recovered_data: String = postcard::from_bytes(&data).unwrap();
        assert_eq!(recovered_data, "test");
    }
}

mod error_handling {
    use super::*;

    #[test]
    fn test_corrupted_data_handling() {
        // Create valid data first
        let valid_message = BasicEnum::TupleVariant("test".to_string());
        let mut serialized = postcard::to_stdvec(&valid_message).unwrap();

        // Corrupt the data
        if let Some(last) = serialized.last_mut() {
            *last = !*last; // Flip all bits in the last byte
        }

        // Deserialization should fail gracefully
        let result: Result<BasicEnum, _> = postcard::from_bytes(&serialized);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_discriminant_handling() {
        // Create data with invalid discriminant but valid structure
        let invalid_tuple = (999u32, b"some data".to_vec());
        let serialized = postcard::to_stdvec(&invalid_tuple).unwrap();

        // Should deserialize as Unknown variant
        let result: BasicEnum = postcard::from_bytes(&serialized).unwrap();
        match result {
            BasicEnum::Unknown { discriminant, data } => {
                assert_eq!(discriminant, 999);
                assert_eq!(data, b"some data");
            }
            _ => panic!("Expected Unknown variant"),
        }
    }
}

mod performance {
    use super::*;

    #[test]
    fn test_serialization_overhead() {
        let message = BasicEnum::TupleVariant("short".to_string());
        let forward_compatible_size = postcard::to_stdvec(&message).unwrap().len();

        // Compare with direct string serialization
        let direct_string_size = postcard::to_stdvec("short").unwrap().len();

        // The overhead should be minimal (discriminant + Vec overhead)
        let overhead = forward_compatible_size - direct_string_size;

        // Overhead should be reasonable (discriminant u32 + Vec length)
        // This is a rough check - exact overhead depends on varint encoding
        assert!(overhead < 10, "Overhead {overhead} bytes is too large");
    }

    #[test]
    fn test_large_data_handling() {
        let large_string = "x".repeat(10_000);
        let message = BasicEnum::TupleVariant(large_string.clone());

        let serialized = postcard::to_stdvec(&message).unwrap();
        let deserialized: BasicEnum = postcard::from_bytes(&serialized).unwrap();

        match deserialized {
            BasicEnum::TupleVariant(s) => assert_eq!(s, large_string),
            _ => panic!("Expected TupleVariant"),
        }
    }
}

mod range_validation {
    use super::*;

    #[test]
    fn test_ranged_enum_serialization() {
        let variants = vec![
            RangedEnum::First,
            RangedEnum::Second(42),
            RangedEnum::Last {
                data: "test".to_string(),
            },
        ];

        for variant in variants {
            let serialized = postcard::to_stdvec(&variant).unwrap();
            let deserialized: RangedEnum = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_unknown_variant_outside_range() {
        let unknown = RangedEnum::Unknown {
            discriminant: 50, // Outside the 100..200 range
            data: vec![1, 2, 3],
        };

        let serialized = postcard::to_stdvec(&unknown).unwrap();
        let deserialized: RangedEnum = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(unknown, deserialized);
    }
}
