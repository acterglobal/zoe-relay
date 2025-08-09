use forward_compatible_enum::U32Discriminants;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum GroupRole {
    #[discriminant(9)]
    Owner,

    #[discriminant(5)]
    Admin,

    #[discriminant(3)]
    Moderator,

    #[discriminant(0)]
    Member,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
#[u32_discriminants(fallback = "Unknown")]
pub enum Status {
    #[discriminant(1)]
    Active,

    #[discriminant(2)]
    Inactive,

    #[discriminant(0)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_role_round_trip() {
        let roles = vec![
            GroupRole::Owner,
            GroupRole::Admin,
            GroupRole::Moderator,
            GroupRole::Member,
        ];

        for role in roles {
            let serialized = postcard::to_stdvec(&role).unwrap();
            let deserialized: GroupRole = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(role, deserialized);
        }
    }

    #[test]
    fn test_discriminant_values() {
        let discriminant: u32 = GroupRole::Owner.into();
        assert_eq!(discriminant, 9);

        let discriminant: u32 = GroupRole::Admin.into();
        assert_eq!(discriminant, 5);

        let discriminant: u32 = GroupRole::Moderator.into();
        assert_eq!(discriminant, 3);

        let discriminant: u32 = GroupRole::Member.into();
        assert_eq!(discriminant, 0);
    }

    #[test]
    fn test_from_u32_conversion() {
        assert_eq!(GroupRole::from(9), GroupRole::Owner);
        assert_eq!(GroupRole::from(5), GroupRole::Admin);
        assert_eq!(GroupRole::from(3), GroupRole::Moderator);
        assert_eq!(GroupRole::from(0), GroupRole::Member);
    }

    #[test]
    fn test_fallback_handling() {
        // Test default fallback (first variant)
        assert_eq!(GroupRole::from(999), GroupRole::Owner); // First variant

        // Test custom fallback
        assert_eq!(Status::from(999), Status::Unknown); // Custom fallback
    }

    #[test]
    fn test_postcard_wire_format() {
        // Test that the wire format is compact
        let role = GroupRole::Member; // discriminant 0
        let serialized = postcard::to_stdvec(&role).unwrap();

        // Should be a single byte for discriminant 0
        assert_eq!(serialized, vec![0]);

        let role = GroupRole::Owner; // discriminant 9  
        let serialized = postcard::to_stdvec(&role).unwrap();

        // Should be a single byte for discriminant 9
        assert_eq!(serialized, vec![9]);
    }

    #[test]
    fn test_status_custom_fallback() {
        let status = Status::Active;
        let serialized = postcard::to_stdvec(&status).unwrap();
        let deserialized: Status = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(status, deserialized);

        // Test fallback behavior
        assert_eq!(Status::from(42), Status::Unknown);
    }

    #[test]
    fn test_reference_conversion() {
        let role = GroupRole::Admin;
        let discriminant: u32 = (&role).into();
        assert_eq!(discriminant, 5);
    }
}
