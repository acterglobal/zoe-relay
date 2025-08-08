use serde::{Deserialize, Serialize};

use super::roles::GroupRole;

/// Actions that can be performed in a group
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupAction {
    /// Update group settings and metadata
    UpdateGroup,
    /// Assign roles to members
    AssignRoles,
    /// Post activities in the group
    PostActivities,
    /// Update encryption settings
    UpdateEncryption,
}

/// Permissions for group actions in encrypted groups
///
/// Defines who can perform various actions within the group based on their role.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupPermissions {
    /// Who can update group settings
    pub update_group: Permission,
    /// Who can assign roles to other members
    pub assign_roles: Permission,
    /// Who can post activities (typically all key holders)
    pub post_activities: Permission,
    /// Who can update group encryption settings
    pub update_encryption: Permission,
}

/// Permission levels for group actions
///
/// Defines the minimum role level required to perform certain actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Permission {
    /// Only group owners
    OwnerOnly,
    /// Owners and admins
    AdminOrAbove,
    /// Owners, admins, and moderators
    ModeratorOrAbove,
    /// Any group member
    AllMembers,
}

impl Default for GroupPermissions {
    fn default() -> Self {
        Self {
            update_group: Permission::AdminOrAbove,
            assign_roles: Permission::OwnerOnly,
            post_activities: Permission::AllMembers,
            update_encryption: Permission::OwnerOnly,
        }
    }
}

impl GroupPermissions {
    /// Create a new GroupPermissions with custom settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set permission for updating group settings
    pub fn update_group(mut self, permission: Permission) -> Self {
        self.update_group = permission;
        self
    }

    /// Set permission for assigning roles
    pub fn assign_roles(mut self, permission: Permission) -> Self {
        self.assign_roles = permission;
        self
    }

    /// Set permission for posting activities
    pub fn post_activities(mut self, permission: Permission) -> Self {
        self.post_activities = permission;
        self
    }

    /// Set permission for updating encryption settings
    pub fn update_encryption(mut self, permission: Permission) -> Self {
        self.update_encryption = permission;
        self
    }

    /// Check if a role can perform a specific action
    pub fn can_perform_action(&self, role: &GroupRole, action: GroupAction) -> bool {
        let required_permission = match action {
            GroupAction::UpdateGroup => &self.update_group,
            GroupAction::AssignRoles => &self.assign_roles,
            GroupAction::PostActivities => &self.post_activities,
            GroupAction::UpdateEncryption => &self.update_encryption,
        };

        role.has_permission(required_permission)
    }
}
