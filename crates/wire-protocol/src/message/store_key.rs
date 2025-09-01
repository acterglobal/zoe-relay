use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

// PQXDH types are available through the main crate re-exports

/// PQXDH-based inbox protocols
///
/// Reserved ranges:
/// - 10000-10999: Core PQXDH protocols (group invites, direct messages, etc.)
/// - 11000-11999: PQXDH RPC services
/// - 15001-19999: Available for custom/experimental PQXDH protocols
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(from = "u32", into = "u32")]
#[repr(u32)]
pub enum PqxdhInboxProtocol {
    // Core protocols (10000-10999) - commented until implemented
    // GroupInvite = 0,            // 10000 - PQXDH group invitations
    // DirectMessage = 1,          // 10001 - PQXDH direct messaging
    // FileTransfer = 2,           // 10002 - PQXDH file transfer
    // VideoCallInvite = 3,        // 10003 - PQXDH video call invitations

    // RPC services (11000-11999)
    EchoService = 1000, // 11000 - Echo/ping RPC service

    // Custom protocols (anything else)
    CustomProtocol(u32), // 15001+ - Custom PQXDH protocols
}

impl PartialOrd for PqxdhInboxProtocol {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PqxdhInboxProtocol {
    fn cmp(&self, other: &Self) -> Ordering {
        u32::from(self).cmp(&u32::from(other))
    }
}

impl PqxdhInboxProtocol {
    pub fn as_u32(&self) -> u32 {
        u32::from(self)
    }
    pub fn into_bytes(&self) -> Vec<u8> {
        self.as_u32().to_le_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let value = u32::from_le_bytes(bytes.try_into().map_err(|_| "Invalid bytes")?);
        Ok(Self::from(value))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(from = "u32", into = "u32")]
pub enum StoreKey {
    PublicUserInfo,
    MlsKeyPackage,
    PqxdhInbox(PqxdhInboxProtocol), // PQXDH inbox system
    CustomKey(u32),                 // yet to be known variant
}

impl From<u32> for PqxdhInboxProtocol {
    fn from(value: u32) -> Self {
        match value {
            // Core protocols - commented until implemented
            // 0 => PqxdhInboxProtocol::GroupInvite,
            // 1 => PqxdhInboxProtocol::DirectMessage,
            // 2 => PqxdhInboxProtocol::FileTransfer,
            // 3 => PqxdhInboxProtocol::VideoCallInvite,

            // RPC services (1000-1999 maps to 11000-11999)
            1000 => PqxdhInboxProtocol::EchoService,

            // Everything else is custom
            a => PqxdhInboxProtocol::CustomProtocol(a),
        }
    }
}

impl std::fmt::Display for PqxdhInboxProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PqxdhInboxProtocol::EchoService => write!(f, "EchoService"),
            PqxdhInboxProtocol::CustomProtocol(a) => write!(f, "CustomProtocol({a})"),
        }
    }
}

impl From<&PqxdhInboxProtocol> for u32 {
    fn from(val: &PqxdhInboxProtocol) -> Self {
        match val {
            // Core protocols - commented until implemented
            // PqxdhInboxProtocol::GroupInvite => 0,
            // PqxdhInboxProtocol::DirectMessage => 1,
            // PqxdhInboxProtocol::FileTransfer => 2,
            // PqxdhInboxProtocol::VideoCallInvite => 3,

            // RPC services
            PqxdhInboxProtocol::EchoService => 1000,

            // Custom protocols
            PqxdhInboxProtocol::CustomProtocol(a) => *a,
        }
    }
}

impl From<PqxdhInboxProtocol> for u32 {
    fn from(val: PqxdhInboxProtocol) -> Self {
        u32::from(&val)
    }
}

impl From<u32> for StoreKey {
    fn from(value: u32) -> Self {
        match value {
            0 => StoreKey::PublicUserInfo,
            100 => StoreKey::MlsKeyPackage,
            10000..=19999 => {
                let protocol_id = value - 10000;
                StoreKey::PqxdhInbox(PqxdhInboxProtocol::from(protocol_id))
            }
            a => StoreKey::CustomKey(a),
        }
    }
}

impl From<StoreKey> for u32 {
    fn from(val: StoreKey) -> Self {
        match val {
            StoreKey::PublicUserInfo => 0,
            StoreKey::MlsKeyPackage => 100,
            StoreKey::PqxdhInbox(protocol) => 10000 + u32::from(&protocol),
            StoreKey::CustomKey(a) => a,
        }
    }
}

impl From<&StoreKey> for u32 {
    fn from(val: &StoreKey) -> Self {
        match val {
            StoreKey::PublicUserInfo => 0,
            StoreKey::MlsKeyPackage => 100,
            StoreKey::PqxdhInbox(protocol) => 10000 + u32::from(protocol),
            StoreKey::CustomKey(a) => *a,
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use postcard;

    #[test]
    fn test_store_key_serialization() {
        let keys = vec![
            StoreKey::PublicUserInfo,
            StoreKey::MlsKeyPackage,
            StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService),
            StoreKey::PqxdhInbox(PqxdhInboxProtocol::CustomProtocol(5001)),
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

    #[test]
    fn test_pqxdh_inbox_protocol_mapping() {
        // Test EchoService mapping
        let echo_protocol = PqxdhInboxProtocol::EchoService;
        let echo_u32: u32 = echo_protocol.clone().into();
        assert_eq!(echo_u32, 1000);
        let echo_back = PqxdhInboxProtocol::from(echo_u32);
        assert_eq!(echo_protocol, echo_back);

        // Test CustomProtocol mapping
        let custom_protocol = PqxdhInboxProtocol::CustomProtocol(5001);
        let custom_u32: u32 = custom_protocol.clone().into();
        assert_eq!(custom_u32, 5001);
        let custom_back = PqxdhInboxProtocol::from(custom_u32);
        assert_eq!(custom_protocol, custom_back);
    }

    #[test]
    fn test_pqxdh_store_key_mapping() {
        // Test EchoService StoreKey mapping
        let echo_store_key = StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService);
        let echo_u32: u32 = echo_store_key.clone().into();
        assert_eq!(echo_u32, 11000); // 10000 + 1000
        let echo_back = StoreKey::from(echo_u32);
        assert_eq!(echo_store_key, echo_back);

        // Test CustomProtocol StoreKey mapping
        let custom_store_key = StoreKey::PqxdhInbox(PqxdhInboxProtocol::CustomProtocol(5001));
        let custom_u32: u32 = custom_store_key.clone().into();
        assert_eq!(custom_u32, 15001); // 10000 + 5001
        let custom_back = StoreKey::from(custom_u32);
        assert_eq!(custom_store_key, custom_back);
    }

    #[test]
    fn test_pqxdh_inbox_protocol_serialization() {
        let protocols = vec![
            PqxdhInboxProtocol::EchoService,
            PqxdhInboxProtocol::CustomProtocol(5001),
            PqxdhInboxProtocol::CustomProtocol(9999),
        ];

        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&protocols).unwrap();
        let deserialized: Vec<PqxdhInboxProtocol> = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(protocols, deserialized);
    }

    #[test]
    fn test_pqxdh_store_key_ranges() {
        // Test that PQXDH inbox range is correctly handled

        // Test lower bound (10000 = EchoService)
        let lower_bound = StoreKey::from(11000u32);
        assert_eq!(
            lower_bound,
            StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService)
        );

        // Test custom protocol in range
        let custom_in_range = StoreKey::from(15001u32);
        assert_eq!(
            custom_in_range,
            StoreKey::PqxdhInbox(PqxdhInboxProtocol::CustomProtocol(5001))
        );

        // Test upper bound (19999)
        let upper_bound = StoreKey::from(19999u32);
        assert_eq!(
            upper_bound,
            StoreKey::PqxdhInbox(PqxdhInboxProtocol::CustomProtocol(9999))
        );

        // Test outside range becomes CustomKey
        let outside_range = StoreKey::from(20000u32);
        assert_eq!(outside_range, StoreKey::CustomKey(20000));
    }

    #[test]
    fn test_store_key_reference_conversion() {
        let echo_store_key = StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService);
        let echo_u32: u32 = (&echo_store_key).into();
        assert_eq!(echo_u32, 11000);

        let custom_store_key = StoreKey::PqxdhInbox(PqxdhInboxProtocol::CustomProtocol(5001));
        let custom_u32: u32 = (&custom_store_key).into();
        assert_eq!(custom_u32, 15001);
    }
}
