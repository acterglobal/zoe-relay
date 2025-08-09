//! Example showing how to migrate from manual discriminant implementation
//! to using the U32Discriminants derive macro.
//!
//! This demonstrates the exact pattern from the user's GroupRole example.

use forward_compatible_enum::U32Discriminants;
use serde::{Deserialize, Serialize};

// OLD WAY: Manual implementation (like user's original code)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(from = "u32", into = "u32")]
pub enum GroupRoleManual {
    Owner,
    Admin,
    Moderator,
    Member,
}

impl From<u32> for GroupRoleManual {
    fn from(value: u32) -> Self {
        match value {
            9 => GroupRoleManual::Owner,
            5 => GroupRoleManual::Admin,
            3 => GroupRoleManual::Moderator,
            _ => GroupRoleManual::Member, // 0 or anything else
        }
    }
}

impl From<GroupRoleManual> for u32 {
    fn from(value: GroupRoleManual) -> Self {
        match value {
            GroupRoleManual::Owner => 9,
            GroupRoleManual::Admin => 5,
            GroupRoleManual::Moderator => 3,
            GroupRoleManual::Member => 0,
        }
    }
}

// NEW WAY: Using the derive macro
#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, U32Discriminants,
)]
#[serde(from = "u32", into = "u32")]
#[u32_discriminants(fallback = "Member")]
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== GroupRole Migration Example ===\n");

    println!("Testing both implementations have identical behavior:\n");

    // Test all discriminant values
    let test_values = [0, 3, 5, 9, 42, 999];

    for discriminant in test_values {
        let manual_role = GroupRoleManual::from(discriminant);
        let derive_role = GroupRole::from(discriminant);

        println!("Discriminant {discriminant}: Manual={manual_role:?}, Derive={derive_role:?}");

        // They should behave identically
        let manual_discriminant: u32 = manual_role.clone().into();
        let derive_discriminant: u32 = derive_role.clone().into();

        println!("  Back to u32: Manual={manual_discriminant}, Derive={derive_discriminant}");

        // For known discriminants, they should be identical
        if [0, 3, 5, 9].contains(&discriminant) {
            assert_eq!(manual_discriminant, derive_discriminant);
            assert_eq!(format!("{manual_role:?}"), format!("{:?}", derive_role));
        }

        println!();
    }

    println!("=== Postcard Serialization ===\n");

    // Test that serialization is identical
    let roles = [
        (GroupRoleManual::Owner, GroupRole::Owner),
        (GroupRoleManual::Admin, GroupRole::Admin),
        (GroupRoleManual::Moderator, GroupRole::Moderator),
        (GroupRoleManual::Member, GroupRole::Member),
    ];

    for (manual_role, derive_role) in roles {
        let manual_bytes = postcard::to_stdvec(&manual_role)?;
        let derive_bytes = postcard::to_stdvec(&derive_role)?;

        println!("Role {derive_role:?}:");
        println!("  Manual:  {manual_bytes:?}");
        println!("  Derived: {derive_bytes:?}");
        println!("  Identical: {}", manual_bytes == derive_bytes);

        // Verify cross-compatibility
        let manual_from_derive: GroupRoleManual = postcard::from_bytes(&derive_bytes)?;
        let derive_from_manual: GroupRole = postcard::from_bytes(&manual_bytes)?;

        println!(
            "  Cross-compatible: {}",
            format!("{manual_from_derive:?}") == format!("{derive_from_manual:?}")
        );

        assert_eq!(manual_bytes, derive_bytes);
        println!();
    }

    println!("=== Benefits of the Derive Macro ===\n");

    println!("1. ✅ Less boilerplate code");
    println!("2. ✅ Explicit discriminant values in attribute");
    println!("3. ✅ Custom fallback variant configuration");
    println!("4. ✅ Compile-time validation of discriminants");
    println!("5. ✅ Identical runtime behavior and wire format");
    println!("6. ✅ Automatic From<&T> for u32 implementation");

    // Test the reference conversion that's only available with derive
    let role = GroupRole::Admin;
    let discriminant_from_ref: u32 = (&role).into();
    println!("7. ✅ Reference conversion: &{role:?} => {discriminant_from_ref}");

    println!("\n🎉 Migration successful! The derive macro is a drop-in replacement.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_behavior() {
        for discriminant in [0, 3, 5, 9, 42, 999] {
            let manual = GroupRoleManual::from(discriminant);
            let derived = GroupRole::from(discriminant);

            let manual_back: u32 = manual.into();
            let derived_back: u32 = derived.into();

            // For known discriminants, behavior should be identical
            if [0, 3, 5, 9].contains(&discriminant) {
                assert_eq!(manual_back, derived_back);
                assert_eq!(format!("{:?}", manual), format!("{:?}", derived));
            }
        }
    }

    #[test]
    fn test_wire_compatibility() {
        let roles = [
            (GroupRoleManual::Owner, GroupRole::Owner),
            (GroupRoleManual::Admin, GroupRole::Admin),
            (GroupRoleManual::Moderator, GroupRole::Moderator),
            (GroupRoleManual::Member, GroupRole::Member),
        ];

        for (manual, derived) in roles {
            let manual_bytes = postcard::to_stdvec(&manual).unwrap();
            let derived_bytes = postcard::to_stdvec(&derived).unwrap();

            // Wire format must be identical
            assert_eq!(manual_bytes, derived_bytes);

            // Cross-deserialization must work
            let _: GroupRoleManual = postcard::from_bytes(&derived_bytes).unwrap();
            let _: GroupRole = postcard::from_bytes(&manual_bytes).unwrap();
        }
    }
}
