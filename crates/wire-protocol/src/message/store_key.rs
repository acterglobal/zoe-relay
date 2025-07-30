use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(from = "u32", into = "u32")]
pub enum StoreKey {
    PublicUserInfo,
    MlsKeyPackage,
    CustomKey(u32), // yet to be known variant
}

impl From<u32> for StoreKey {
    fn from(value: u32) -> Self {
        match value {
            0 => StoreKey::PublicUserInfo,
            100 => StoreKey::MlsKeyPackage,
            a => StoreKey::CustomKey(a),
        }
    }
}

impl From<StoreKey> for u32 {
    fn from(val: StoreKey) -> Self {
        match val {
            StoreKey::PublicUserInfo => 0,
            StoreKey::MlsKeyPackage => 100,
            StoreKey::CustomKey(a) => a,
        }
    }
}

impl From<&StoreKey> for u32 {
    fn from(val: &StoreKey) -> Self {
        match val {
            StoreKey::PublicUserInfo => 0,
            StoreKey::MlsKeyPackage => 100,
            StoreKey::CustomKey(a) => *a,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use postcard;

    #[test]
    fn test_store_key_seriazilation() {
        let keys = vec![
            StoreKey::PublicUserInfo,
            StoreKey::MlsKeyPackage,
            StoreKey::CustomKey(10),
        ];
        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&keys).unwrap();
        let deserialized: Vec<StoreKey> = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(keys, deserialized);
    }

    #[test]
    fn test_store_key_regular_is_flat() {
        let key = StoreKey::PublicUserInfo;
        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&key).unwrap();
        assert_eq!(serialized.len(), 1);
        let deserialized: StoreKey = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_store_key_custom_type_is_flat() {
        let key = StoreKey::CustomKey(42);
        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&key).unwrap();
        assert_eq!(serialized.len(), 1); // same length
        let deserialized: StoreKey = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_store_key_long_custom_type_is_flat() {
        let key = StoreKey::CustomKey(1024);
        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&key).unwrap();
        assert_eq!(serialized.len(), 2); // varint
        let deserialized: StoreKey = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(key, deserialized);
    }
}
