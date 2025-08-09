//! Example demonstrating the U32Discriminants derive macro
//!
//! This shows how to create unit enums with custom discriminant values
//! that serialize efficiently as plain u32 values.

use forward_compatible_enum::U32Discriminants;
use serde::{Deserialize, Serialize};

/// Example enum similar to the user's GroupRole
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum GroupRole {
    /// Highest privilege level
    #[discriminant(9)]
    Owner,

    /// Administrative access
    #[discriminant(5)]
    Admin,

    /// Moderation privileges  
    #[discriminant(3)]
    Moderator,

    /// Basic member access
    #[discriminant(0)]
    Member,
}

/// Status enum with custom fallback
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== U32Discriminants Example ===\n");

    // Demonstrate discriminant mappings
    println!("GroupRole discriminant mappings:");
    for role in [
        GroupRole::Owner,
        GroupRole::Admin,
        GroupRole::Moderator,
        GroupRole::Member,
    ] {
        let discriminant: u32 = role.clone().into();
        println!("  {role:?} => {discriminant}");
    }

    println!("\n=== Serialization with postcard ===");

    // Test serialization efficiency
    let roles = vec![
        GroupRole::Member, // discriminant 0
        GroupRole::Admin,  // discriminant 5
        GroupRole::Owner,  // discriminant 9
    ];

    for role in roles {
        let serialized = postcard::to_stdvec(&role)?;
        println!(
            "Role {:?} serializes to {} bytes: {:?}",
            role,
            serialized.len(),
            serialized
        );

        let deserialized: GroupRole = postcard::from_bytes(&serialized)?;
        assert_eq!(role, deserialized);
        println!("  Round-trip successful!");
    }

    println!("\n=== Forward Compatibility ===");

    // Test unknown discriminant handling
    println!("Testing unknown discriminants:");

    // Simulate data from future version with unknown discriminant
    for unknown_discriminant in [42, 100, 255] {
        let future_role = GroupRole::from(unknown_discriminant);
        println!("  Discriminant {unknown_discriminant} => {future_role:?}");
        // Unknown discriminants default to first variant (Owner)
        assert_eq!(future_role, GroupRole::Owner);
    }

    // Test custom fallback behavior
    println!("\nStatus with custom fallback:");
    for unknown_discriminant in [42, 100, 255] {
        let status = Status::from(unknown_discriminant);
        println!("  Discriminant {unknown_discriminant} => {status:?}");
        // Unknown discriminants use custom fallback (Unknown)
        assert_eq!(status, Status::Unknown);
    }

    println!("\n=== Compact Wire Format ===");

    // Show how compact the format is
    let member = GroupRole::Member;
    let admin = GroupRole::Admin;

    let member_bytes = postcard::to_stdvec(&member)?;
    let admin_bytes = postcard::to_stdvec(&admin)?;

    println!("Wire format examples:");
    println!(
        "  Member (discriminant 0): {:?} ({} byte)",
        member_bytes,
        member_bytes.len()
    );
    println!(
        "  Admin (discriminant 5):  {:?} ({} byte)",
        admin_bytes,
        admin_bytes.len()
    );

    // Verify the discriminants are exactly what we expect
    assert_eq!(member_bytes, vec![0]); // varint encoding of 0
    assert_eq!(admin_bytes, vec![5]); // varint encoding of 5

    println!("\n✅ All tests passed!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_role_discriminants() {
        assert_eq!(GroupRole::from(9), GroupRole::Owner);
        assert_eq!(GroupRole::from(5), GroupRole::Admin);
        assert_eq!(GroupRole::from(3), GroupRole::Moderator);
        assert_eq!(GroupRole::from(0), GroupRole::Member);

        let discriminant: u32 = GroupRole::Owner.into();
        assert_eq!(discriminant, 9);
    }

    #[test]
    fn test_status_fallback() {
        assert_eq!(Status::from(999), Status::Unknown);
        assert_eq!(Status::from(1), Status::Active);
    }

    #[test]
    fn test_wire_format() {
        let role = GroupRole::Member;
        let bytes = postcard::to_stdvec(&role).unwrap();
        assert_eq!(bytes, vec![0]);

        let recovered: GroupRole = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(role, recovered);
    }
}
