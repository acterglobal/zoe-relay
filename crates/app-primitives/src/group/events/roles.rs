use forward_compatible_enum::U32Discriminants;
use serde::{Deserialize, Serialize};

use super::permissions::Permission;

/// Roles within a group
///
/// Hierarchical roles that determine what actions a member can perform.
/// Roles are ordered from highest (Owner) to lowest (Member) privilege.
#[derive(
    Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, U32Discriminants,
)]
#[u32_discriminants(fallback = "Member")]
pub enum GroupRole {
    /// Group owner (highest privilege)
    ///
    /// Can perform all actions including deleting the group and managing all other roles.
    #[discriminant(9)]
    Owner,
    /// Administrator
    ///
    /// Can manage most group settings and moderate other members.
    #[discriminant(5)]
    Admin,
    /// Moderator
    ///
    /// Can moderate discussions and manage some group settings.
    #[discriminant(3)]
    Moderator,
    /// Regular member
    ///
    /// Basic participation rights, can post activities and read group content.
    #[discriminant(0)]
    Member,
}

impl GroupRole {
    /// Check if this role has the required permission level
    ///
    /// Returns true if this role meets or exceeds the required permission level.
    pub fn has_permission(&self, required: &Permission) -> bool {
        match required {
            Permission::OwnerOnly => matches!(self, GroupRole::Owner),
            Permission::AdminOrAbove => matches!(self, GroupRole::Owner | GroupRole::Admin),
            Permission::ModeratorOrAbove => matches!(
                self,
                GroupRole::Owner | GroupRole::Admin | GroupRole::Moderator
            ),
            Permission::AllMembers => true,
        }
    }

    /// Get a human-readable name for this role
    pub fn display_name(&self) -> &'static str {
        match self {
            GroupRole::Owner => "Owner",
            GroupRole::Admin => "Administrator",
            GroupRole::Moderator => "Moderator",
            GroupRole::Member => "Member",
        }
    }

    /// Check if this role can assign the target role to another member
    ///
    /// Generally, you can only assign roles that are lower than your own.
    pub fn can_assign_role(&self, target_role: &GroupRole) -> bool {
        match self {
            GroupRole::Owner => true, // Owners can assign any role
            GroupRole::Admin => !matches!(target_role, GroupRole::Owner),
            GroupRole::Moderator => matches!(target_role, GroupRole::Member),
            GroupRole::Member => false, // Members can't assign roles
        }
    }
}
