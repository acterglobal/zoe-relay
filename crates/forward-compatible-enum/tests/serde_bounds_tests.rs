use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Serialize, de::DeserializeOwned};

/// Test enum with generic type parameter and custom serde bounds
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize",
    serde_deserialize = "T: DeserializeOwned"
)]
pub enum GenericEvent<T> {
    #[discriminant(0)]
    Data(T),

    #[discriminant(1)]
    Message { content: T, id: u32 },

    #[discriminant(2)]
    Empty,

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Test enum with multiple generic parameters
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize, U: Serialize",
    serde_deserialize = "T: DeserializeOwned, U: DeserializeOwned"
)]
pub enum MultiGeneric<T, U> {
    #[discriminant(10)]
    First(T),

    #[discriminant(20)]
    Second(U),

    #[discriminant(30)]
    Both { first: T, second: U },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Test enum without serde bounds (should work with default behavior)
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum SimpleBounded<T>
where
    T: Serialize + DeserializeOwned,
{
    #[discriminant(100)]
    Value(T),

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Test enum with complex bounds including lifetimes
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize + Clone",
    serde_deserialize = "T: DeserializeOwned + Clone"
)]
pub enum ComplexBounded<T> {
    #[discriminant(200)]
    Item(T),

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_event_serialization() {
        let event = GenericEvent::Data("hello world".to_string());
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: GenericEvent<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_generic_event_struct_variant() {
        let event = GenericEvent::Message {
            content: 42u32,
            id: 123,
        };
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: GenericEvent<u32> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_generic_event_unit_variant() {
        let event: GenericEvent<String> = GenericEvent::Empty;
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: GenericEvent<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_generic_event_unknown_variant() {
        let event: GenericEvent<String> = GenericEvent::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3, 4],
        };
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: GenericEvent<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_multi_generic_first() {
        let event = MultiGeneric::First("test".to_string());
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: MultiGeneric<String, u32> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_multi_generic_second() {
        let event: MultiGeneric<String, u32> = MultiGeneric::Second(42);
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: MultiGeneric<String, u32> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_multi_generic_both() {
        let event = MultiGeneric::Both {
            first: "hello".to_string(),
            second: 123u32,
        };
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: MultiGeneric<String, u32> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_simple_bounded_enum() {
        let event = SimpleBounded::Value("test".to_string());
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: SimpleBounded<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_complex_bounded_enum() {
        let event = ComplexBounded::Item(vec![1, 2, 3]);
        let bytes = postcard::to_stdvec(&event).unwrap();
        let recovered: ComplexBounded<Vec<i32>> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(event, recovered);
    }

    #[test]
    fn test_forward_compatibility_with_bounds() {
        // Create an unknown variant as if from a newer version
        let unknown = GenericEvent::<String>::Unknown {
            discriminant: 555,
            data: postcard::to_stdvec(&("future data", 999u64)).unwrap(),
        };

        // Should round-trip preserving the unknown data
        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: GenericEvent<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);

        // Should be able to extract the original data
        if let GenericEvent::Unknown { discriminant, data } = recovered {
            assert_eq!(discriminant, 555);
            let (original_str, original_num): (String, u64) = postcard::from_bytes(&data).unwrap();
            assert_eq!(original_str, "future data");
            assert_eq!(original_num, 999);
        } else {
            panic!("Expected Unknown variant");
        }
    }

    #[test]
    fn test_different_concrete_types() {
        // Test that the same enum can work with different concrete types
        let string_event = GenericEvent::Data("hello".to_string());
        let int_event = GenericEvent::Data(42i32);
        let vec_event = GenericEvent::Data(vec![1, 2, 3]);

        // Each should serialize/deserialize correctly with their concrete type
        let string_bytes = postcard::to_stdvec(&string_event).unwrap();
        let int_bytes = postcard::to_stdvec(&int_event).unwrap();
        let vec_bytes = postcard::to_stdvec(&vec_event).unwrap();

        let recovered_string: GenericEvent<String> = postcard::from_bytes(&string_bytes).unwrap();
        let recovered_int: GenericEvent<i32> = postcard::from_bytes(&int_bytes).unwrap();
        let recovered_vec: GenericEvent<Vec<i32>> = postcard::from_bytes(&vec_bytes).unwrap();

        assert_eq!(string_event, recovered_string);
        assert_eq!(int_event, recovered_int);
        assert_eq!(vec_event, recovered_vec);
    }
}
