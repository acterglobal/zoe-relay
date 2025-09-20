//! Administrative event types for redaction and system management
//!
//! This module contains event types for administrative actions like redaction
//! and other system-level operations. The permission system is modeled after
//! Acter's space settings, allowing granular control over who can perform
//! specific operations within each feature type.

use serde::{Deserialize, Serialize};

/// DGO feature settings for a group
///
/// Controls granular permissions for each DGO feature, allowing different
/// permission levels for different operations within each feature type.
/// Modeled after Acter's space settings system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DgoFeatureSettings {
    /// Text blocks feature permissions
    pub text_blocks: TextBlocksSettings,
    /// Calendar events feature permissions  
    pub calendar: CalendarSettings,
    /// Tasks and task lists feature permissions
    pub tasks: TasksSettings,
}

/// Granular permission settings for text blocks feature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextBlocksSettings {
    /// Who can create new text blocks
    pub create: FeaturePermission,
    /// Who can update existing text blocks (beyond creator permissions)
    pub update: FeaturePermission,
    /// Who can delete text blocks (beyond creator permissions)
    pub delete: FeaturePermission,
    /// Who can comment on text blocks
    pub comment: FeaturePermission,
    /// Who can react to text blocks
    pub react: FeaturePermission,
    /// Who can attach files to text blocks
    pub attach: FeaturePermission,
}

/// Granular permission settings for calendar events feature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarSettings {
    /// Who can create new calendar events
    pub create: FeaturePermission,
    /// Who can update existing calendar events (beyond creator permissions)
    pub update: FeaturePermission,
    /// Who can delete calendar events (beyond creator permissions)
    pub delete: FeaturePermission,
    /// Who can RSVP to calendar events
    pub rsvp: FeaturePermission,
    /// Who can comment on calendar events
    pub comment: FeaturePermission,
    /// Who can react to calendar events
    pub react: FeaturePermission,
    /// Who can attach files to calendar events
    pub attach: FeaturePermission,
}

/// Granular permission settings for tasks feature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TasksSettings {
    /// Who can create new task lists
    pub create_task_list: FeaturePermission,
    /// Who can update existing task lists (beyond creator permissions)
    pub update_task_list: FeaturePermission,
    /// Who can delete task lists (beyond creator permissions)
    pub delete_task_list: FeaturePermission,
    /// Who can create new tasks within task lists
    pub create_task: FeaturePermission,
    /// Who can update existing tasks (beyond creator permissions)
    pub update_task: FeaturePermission,
    /// Who can delete tasks (beyond creator permissions)
    pub delete_task: FeaturePermission,
    /// Who can self-assign to tasks
    pub assign_task: FeaturePermission,
    /// Who can comment on tasks and task lists
    pub comment: FeaturePermission,
    /// Who can react to tasks and task lists
    pub react: FeaturePermission,
    /// Who can attach files to tasks and task lists
    pub attach: FeaturePermission,
}

/// Permission level required for a specific operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeaturePermission {
    /// Operation is disabled for everyone
    Disabled,
    /// Only group owners can perform this operation
    OwnerOnly,
    /// Owners and admins can perform this operation
    AdminOrAbove,
    /// Owners, admins, and moderators can perform this operation
    ModeratorOrAbove,
    /// All group members can perform this operation
    AllMembers,
}

impl Default for TextBlocksSettings {
    fn default() -> Self {
        Self {
            create: FeaturePermission::AllMembers,
            update: FeaturePermission::AllMembers, // More restrictive for updates
            delete: FeaturePermission::ModeratorOrAbove, // More restrictive for deletes
            comment: FeaturePermission::AllMembers,
            react: FeaturePermission::AllMembers,
            attach: FeaturePermission::AllMembers,
        }
    }
}

impl Default for CalendarSettings {
    fn default() -> Self {
        Self {
            create: FeaturePermission::AllMembers,
            update: FeaturePermission::AllMembers, // More restrictive for updates
            delete: FeaturePermission::ModeratorOrAbove, // More restrictive for deletes
            rsvp: FeaturePermission::AllMembers,
            comment: FeaturePermission::AllMembers,
            react: FeaturePermission::AllMembers,
            attach: FeaturePermission::AllMembers,
        }
    }
}

impl Default for TasksSettings {
    fn default() -> Self {
        Self {
            create_task_list: FeaturePermission::AllMembers, // Task lists are more structural
            update_task_list: FeaturePermission::AllMembers,
            delete_task_list: FeaturePermission::ModeratorOrAbove, // More restrictive for task list deletion
            create_task: FeaturePermission::AllMembers,
            update_task: FeaturePermission::AllMembers, // Anyone can update tasks they can see
            delete_task: FeaturePermission::ModeratorOrAbove,
            assign_task: FeaturePermission::AllMembers,
            comment: FeaturePermission::AllMembers,
            react: FeaturePermission::AllMembers,
            attach: FeaturePermission::AllMembers,
        }
    }
}

impl FeaturePermission {
    /// Check if a user role meets this permission requirement
    pub fn allows_role(&self, user_role: &crate::group::events::roles::GroupRole) -> bool {
        match self {
            FeaturePermission::Disabled => false,
            FeaturePermission::OwnerOnly => {
                user_role.has_permission(&crate::group::events::permissions::Permission::OwnerOnly)
            }
            FeaturePermission::AdminOrAbove => user_role
                .has_permission(&crate::group::events::permissions::Permission::AdminOrAbove),
            FeaturePermission::ModeratorOrAbove => user_role
                .has_permission(&crate::group::events::permissions::Permission::ModeratorOrAbove),
            FeaturePermission::AllMembers => {
                user_role.has_permission(&crate::group::events::permissions::Permission::AllMembers)
            }
        }
    }
}

impl DgoFeatureSettings {
    /// Create settings with all features disabled
    pub fn all_disabled() -> Self {
        Self {
            text_blocks: TextBlocksSettings {
                create: FeaturePermission::Disabled,
                update: FeaturePermission::Disabled,
                delete: FeaturePermission::Disabled,
                comment: FeaturePermission::Disabled,
                react: FeaturePermission::Disabled,
                attach: FeaturePermission::Disabled,
            },
            calendar: CalendarSettings {
                create: FeaturePermission::Disabled,
                update: FeaturePermission::Disabled,
                delete: FeaturePermission::Disabled,
                rsvp: FeaturePermission::Disabled,
                comment: FeaturePermission::Disabled,
                react: FeaturePermission::Disabled,
                attach: FeaturePermission::Disabled,
            },
            tasks: TasksSettings {
                create_task_list: FeaturePermission::Disabled,
                update_task_list: FeaturePermission::Disabled,
                delete_task_list: FeaturePermission::Disabled,
                create_task: FeaturePermission::Disabled,
                update_task: FeaturePermission::Disabled,
                delete_task: FeaturePermission::Disabled,
                assign_task: FeaturePermission::Disabled,
                comment: FeaturePermission::Disabled,
                react: FeaturePermission::Disabled,
                attach: FeaturePermission::Disabled,
            },
        }
    }

    /// Create settings for a minimal group (just basic text blocks)
    pub fn minimal() -> Self {
        Self {
            text_blocks: TextBlocksSettings {
                create: FeaturePermission::AllMembers,
                update: FeaturePermission::AllMembers,
                delete: FeaturePermission::AllMembers,
                comment: FeaturePermission::AllMembers,
                react: FeaturePermission::AllMembers,
                attach: FeaturePermission::Disabled,
            },
            calendar: CalendarSettings {
                create: FeaturePermission::Disabled,
                update: FeaturePermission::Disabled,
                delete: FeaturePermission::Disabled,
                rsvp: FeaturePermission::Disabled,
                comment: FeaturePermission::Disabled,
                react: FeaturePermission::Disabled,
                attach: FeaturePermission::Disabled,
            },
            tasks: TasksSettings {
                create_task_list: FeaturePermission::Disabled,
                update_task_list: FeaturePermission::Disabled,
                delete_task_list: FeaturePermission::Disabled,
                create_task: FeaturePermission::Disabled,
                update_task: FeaturePermission::Disabled,
                delete_task: FeaturePermission::Disabled,
                assign_task: FeaturePermission::Disabled,
                comment: FeaturePermission::Disabled,
                react: FeaturePermission::Disabled,
                attach: FeaturePermission::Disabled,
            },
        }
    }

    /// Create settings for a highly moderated group (admins control most content)
    pub fn highly_moderated() -> Self {
        Self {
            text_blocks: TextBlocksSettings {
                create: FeaturePermission::ModeratorOrAbove,
                update: FeaturePermission::AdminOrAbove,
                delete: FeaturePermission::AdminOrAbove,
                comment: FeaturePermission::AllMembers,
                react: FeaturePermission::AllMembers,
                attach: FeaturePermission::ModeratorOrAbove,
            },
            calendar: CalendarSettings {
                create: FeaturePermission::ModeratorOrAbove,
                update: FeaturePermission::AdminOrAbove,
                delete: FeaturePermission::AdminOrAbove,
                rsvp: FeaturePermission::AllMembers,
                comment: FeaturePermission::AllMembers,
                react: FeaturePermission::AllMembers,
                attach: FeaturePermission::ModeratorOrAbove,
            },
            tasks: TasksSettings {
                create_task_list: FeaturePermission::AdminOrAbove,
                update_task_list: FeaturePermission::AdminOrAbove,
                delete_task_list: FeaturePermission::OwnerOnly,
                create_task: FeaturePermission::ModeratorOrAbove,
                update_task: FeaturePermission::AllMembers,
                delete_task: FeaturePermission::ModeratorOrAbove,
                assign_task: FeaturePermission::AllMembers,
                comment: FeaturePermission::AllMembers,
                react: FeaturePermission::AllMembers,
                attach: FeaturePermission::ModeratorOrAbove,
            },
        }
    }

    /// Check if a user can perform a specific operation on a specific feature type
    pub fn can_perform_operation(
        &self,
        feature_type: DgoFeatureType,
        operation: DgoOperationType,
        user_role: &crate::group::events::roles::GroupRole,
    ) -> bool {
        let permission = self.get_permission_for_operation(feature_type, operation);
        permission.allows_role(user_role)
    }

    /// Get the permission requirement for a specific operation on a feature type
    pub fn get_permission_for_operation(
        &self,
        feature_type: DgoFeatureType,
        operation: DgoOperationType,
    ) -> &FeaturePermission {
        match feature_type {
            DgoFeatureType::TextBlock => match operation {
                DgoOperationType::Create => &self.text_blocks.create,
                DgoOperationType::Update => &self.text_blocks.update,
                DgoOperationType::Delete => &self.text_blocks.delete,
                DgoOperationType::Comment => &self.text_blocks.comment,
                DgoOperationType::React => &self.text_blocks.react,
                DgoOperationType::Attach => &self.text_blocks.attach,
                DgoOperationType::Rsvp => &FeaturePermission::Disabled, // Not applicable
                DgoOperationType::Assign => &FeaturePermission::Disabled, // Not applicable
                DgoOperationType::MarkRead => &FeaturePermission::AllMembers, // Always allowed
            },
            DgoFeatureType::CalendarEvent => match operation {
                DgoOperationType::Create => &self.calendar.create,
                DgoOperationType::Update => &self.calendar.update,
                DgoOperationType::Delete => &self.calendar.delete,
                DgoOperationType::Comment => &self.calendar.comment,
                DgoOperationType::React => &self.calendar.react,
                DgoOperationType::Attach => &self.calendar.attach,
                DgoOperationType::Rsvp => &self.calendar.rsvp,
                DgoOperationType::Assign => &FeaturePermission::Disabled, // Not applicable
                DgoOperationType::MarkRead => &FeaturePermission::AllMembers, // Always allowed
            },
            DgoFeatureType::TaskList => match operation {
                DgoOperationType::Create => &self.tasks.create_task_list,
                DgoOperationType::Update => &self.tasks.update_task_list,
                DgoOperationType::Delete => &self.tasks.delete_task_list,
                DgoOperationType::Comment => &self.tasks.comment,
                DgoOperationType::React => &self.tasks.react,
                DgoOperationType::Attach => &self.tasks.attach,
                DgoOperationType::Rsvp => &FeaturePermission::Disabled, // Not applicable
                DgoOperationType::Assign => &FeaturePermission::Disabled, // Not applicable
                DgoOperationType::MarkRead => &FeaturePermission::AllMembers, // Always allowed
            },
            DgoFeatureType::Task => match operation {
                DgoOperationType::Create => &self.tasks.create_task,
                DgoOperationType::Update => &self.tasks.update_task,
                DgoOperationType::Delete => &self.tasks.delete_task,
                DgoOperationType::Comment => &self.tasks.comment,
                DgoOperationType::React => &self.tasks.react,
                DgoOperationType::Attach => &self.tasks.attach,
                DgoOperationType::Rsvp => &FeaturePermission::Disabled, // Not applicable
                DgoOperationType::Assign => &self.tasks.assign_task,
                DgoOperationType::MarkRead => &FeaturePermission::AllMembers, // Always allowed
            },
        }
    }

    /// Apply a vector of permission updates to these settings
    ///
    /// This method implements the efficient Vec<UpdateEnum> pattern for permission updates.
    /// Only the specified permissions are changed, leaving others unchanged.
    ///
    /// # Example
    /// ```rust
    /// let mut settings = DgoFeatureSettings::default();
    /// let updates = vec![
    ///     PermissionUpdate::Tasks(TasksPermissionUpdate::CreateTaskList(FeaturePermission::AllMembers)),
    ///     PermissionUpdate::Calendar(CalendarPermissionUpdate::Create(FeaturePermission::ModeratorOrAbove)),
    /// ];
    /// settings.apply_updates(updates);
    /// ```
    pub fn apply_updates(&mut self, updates: Vec<PermissionUpdate>) {
        for update in updates {
            match update {
                PermissionUpdate::TextBlocks(text_update) => {
                    self.apply_text_blocks_update(text_update);
                }
                PermissionUpdate::Calendar(calendar_update) => {
                    self.apply_calendar_update(calendar_update);
                }
                PermissionUpdate::Tasks(tasks_update) => {
                    self.apply_tasks_update(tasks_update);
                }
            }
        }
    }

    /// Apply a text blocks permission update
    fn apply_text_blocks_update(&mut self, update: TextBlocksPermissionUpdate) {
        match update {
            TextBlocksPermissionUpdate::Create(permission) => {
                self.text_blocks.create = permission;
            }
            TextBlocksPermissionUpdate::Update(permission) => {
                self.text_blocks.update = permission;
            }
            TextBlocksPermissionUpdate::Delete(permission) => {
                self.text_blocks.delete = permission;
            }
            TextBlocksPermissionUpdate::Comment(permission) => {
                self.text_blocks.comment = permission;
            }
            TextBlocksPermissionUpdate::React(permission) => {
                self.text_blocks.react = permission;
            }
            TextBlocksPermissionUpdate::Attach(permission) => {
                self.text_blocks.attach = permission;
            }
        }
    }

    /// Apply a calendar permission update
    fn apply_calendar_update(&mut self, update: CalendarPermissionUpdate) {
        match update {
            CalendarPermissionUpdate::Create(permission) => {
                self.calendar.create = permission;
            }
            CalendarPermissionUpdate::Update(permission) => {
                self.calendar.update = permission;
            }
            CalendarPermissionUpdate::Delete(permission) => {
                self.calendar.delete = permission;
            }
            CalendarPermissionUpdate::Rsvp(permission) => {
                self.calendar.rsvp = permission;
            }
            CalendarPermissionUpdate::Comment(permission) => {
                self.calendar.comment = permission;
            }
            CalendarPermissionUpdate::React(permission) => {
                self.calendar.react = permission;
            }
            CalendarPermissionUpdate::Attach(permission) => {
                self.calendar.attach = permission;
            }
        }
    }

    /// Apply a tasks permission update
    fn apply_tasks_update(&mut self, update: TasksPermissionUpdate) {
        match update {
            TasksPermissionUpdate::CreateTaskList(permission) => {
                self.tasks.create_task_list = permission;
            }
            TasksPermissionUpdate::UpdateTaskList(permission) => {
                self.tasks.update_task_list = permission;
            }
            TasksPermissionUpdate::DeleteTaskList(permission) => {
                self.tasks.delete_task_list = permission;
            }
            TasksPermissionUpdate::CreateTask(permission) => {
                self.tasks.create_task = permission;
            }
            TasksPermissionUpdate::UpdateTask(permission) => {
                self.tasks.update_task = permission;
            }
            TasksPermissionUpdate::DeleteTask(permission) => {
                self.tasks.delete_task = permission;
            }
            TasksPermissionUpdate::AssignTask(permission) => {
                self.tasks.assign_task = permission;
            }
            TasksPermissionUpdate::Comment(permission) => {
                self.tasks.comment = permission;
            }
            TasksPermissionUpdate::React(permission) => {
                self.tasks.react = permission;
            }
            TasksPermissionUpdate::Attach(permission) => {
                self.tasks.attach = permission;
            }
        }
    }
}

/// DGO feature types for granular permission checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DgoFeatureType {
    TextBlock,
    CalendarEvent,
    TaskList,
    Task,
}

/// DGO operation types for granular permission checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DgoOperationType {
    Create,
    Update,
    Delete,
    Comment,
    React,
    Attach,
    Rsvp,
    Assign,
    MarkRead,
}

/// Efficient permission update system using the Vec<UpdateEnum> pattern
///
/// This allows for compact, targeted updates to specific permissions without
/// requiring the entire settings structure to be passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermissionUpdate {
    /// Update text blocks permissions
    TextBlocks(TextBlocksPermissionUpdate),
    /// Update calendar permissions
    Calendar(CalendarPermissionUpdate),
    /// Update tasks permissions
    Tasks(TasksPermissionUpdate),
}

/// Text blocks permission updates
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextBlocksPermissionUpdate {
    Create(FeaturePermission),
    Update(FeaturePermission),
    Delete(FeaturePermission),
    Comment(FeaturePermission),
    React(FeaturePermission),
    Attach(FeaturePermission),
}

/// Calendar permission updates
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalendarPermissionUpdate {
    Create(FeaturePermission),
    Update(FeaturePermission),
    Delete(FeaturePermission),
    Rsvp(FeaturePermission),
    Comment(FeaturePermission),
    React(FeaturePermission),
    Attach(FeaturePermission),
}

/// Tasks permission updates
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TasksPermissionUpdate {
    CreateTaskList(FeaturePermission),
    UpdateTaskList(FeaturePermission),
    DeleteTaskList(FeaturePermission),
    CreateTask(FeaturePermission),
    UpdateTask(FeaturePermission),
    DeleteTask(FeaturePermission),
    AssignTask(FeaturePermission),
    Comment(FeaturePermission),
    React(FeaturePermission),
    Attach(FeaturePermission),
}

/// Content for creating new DGO permission settings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDgoSettingsContent {
    /// Initial permission settings (defaults to DgoFeatureSettings::default() if None)
    pub initial_settings: Option<DgoFeatureSettings>,
}

impl Default for CreateDgoSettingsContent {
    fn default() -> Self {
        Self::new()
    }
}

impl CreateDgoSettingsContent {
    /// Create permission settings content with default settings
    pub fn new() -> Self {
        Self {
            initial_settings: None,
        }
    }

    /// Create permission settings content with custom settings
    pub fn with_settings(settings: DgoFeatureSettings) -> Self {
        Self {
            initial_settings: Some(settings),
        }
    }

    /// Get the settings to use (either provided or default)
    pub fn get_settings(&self) -> DgoFeatureSettings {
        self.initial_settings.clone().unwrap_or_default()
    }
}

/// Content for updating DGO feature settings - vector of specific updates
///
/// This efficient update pattern allows for:
/// - Compact serialization (only changed permissions are included)
/// - Atomic updates (all changes applied together or none)
/// - Clear intent (exactly which permissions are being changed)
///
/// Example usage:
/// ```rust
/// let updates = vec![
///     PermissionUpdate::Tasks(TasksPermissionUpdate::CreateTaskList(FeaturePermission::AllMembers)),
///     PermissionUpdate::Tasks(TasksPermissionUpdate::AssignTask(FeaturePermission::ModeratorOrAbove)),
///     PermissionUpdate::Calendar(CalendarPermissionUpdate::Create(FeaturePermission::AllMembers)),
/// ];
/// ```
pub type UpdateDgoSettingsContent = Vec<PermissionUpdate>;

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// Helper to test postcard serialization round-trip
    fn test_postcard_roundtrip<T>(value: &T) -> postcard::Result<()>
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let serialized = postcard::to_stdvec(value)?;
        let deserialized: T = postcard::from_bytes(&serialized)?;
        assert_eq!(*value, deserialized);
        Ok(())
    }

    #[test]
    fn test_dgo_feature_settings_postcard() {
        let settings = DgoFeatureSettings::default();
        test_postcard_roundtrip(&settings)
            .expect("DgoFeatureSettings should serialize/deserialize");

        let minimal = DgoFeatureSettings::minimal();
        test_postcard_roundtrip(&minimal)
            .expect("Minimal DgoFeatureSettings should serialize/deserialize");

        let disabled = DgoFeatureSettings::all_disabled();
        test_postcard_roundtrip(&disabled)
            .expect("Disabled DgoFeatureSettings should serialize/deserialize");
    }

    #[test]
    fn test_permission_update_postcard() {
        let updates = vec![
            PermissionUpdate::TextBlocks(TextBlocksPermissionUpdate::Create(
                FeaturePermission::AllMembers,
            )),
            PermissionUpdate::TextBlocks(TextBlocksPermissionUpdate::Update(
                FeaturePermission::ModeratorOrAbove,
            )),
            PermissionUpdate::Calendar(CalendarPermissionUpdate::Create(
                FeaturePermission::AllMembers,
            )),
            PermissionUpdate::Calendar(CalendarPermissionUpdate::Rsvp(
                FeaturePermission::AllMembers,
            )),
            PermissionUpdate::Tasks(TasksPermissionUpdate::CreateTaskList(
                FeaturePermission::ModeratorOrAbove,
            )),
            PermissionUpdate::Tasks(TasksPermissionUpdate::AssignTask(
                FeaturePermission::AllMembers,
            )),
        ];

        test_postcard_roundtrip(&updates)
            .expect("PermissionUpdate vec should serialize/deserialize");
    }

    #[test]
    fn test_create_dgo_settings_content_postcard() {
        let content = CreateDgoSettingsContent::new();
        test_postcard_roundtrip(&content)
            .expect("CreateDgoSettingsContent should serialize/deserialize");

        let content_with_settings =
            CreateDgoSettingsContent::with_settings(DgoFeatureSettings::highly_moderated());
        test_postcard_roundtrip(&content_with_settings)
            .expect("CreateDgoSettingsContent with settings should serialize/deserialize");
    }

    #[test]
    fn test_dgo_feature_type_postcard() {
        let feature_types = vec![
            DgoFeatureType::TextBlock,
            DgoFeatureType::CalendarEvent,
            DgoFeatureType::TaskList,
            DgoFeatureType::Task,
        ];

        for feature_type in feature_types {
            test_postcard_roundtrip(&feature_type).unwrap_or_else(|_| {
                panic!(
                    "DgoFeatureType::{:?} should serialize/deserialize",
                    feature_type
                )
            });
        }
    }

    #[test]
    fn test_dgo_operation_type_postcard() {
        let operation_types = vec![
            DgoOperationType::Create,
            DgoOperationType::Update,
            DgoOperationType::Delete,
            DgoOperationType::Comment,
            DgoOperationType::React,
            DgoOperationType::Attach,
            DgoOperationType::Rsvp,
            DgoOperationType::Assign,
            DgoOperationType::MarkRead,
        ];

        for operation_type in operation_types {
            test_postcard_roundtrip(&operation_type).unwrap_or_else(|_| {
                panic!(
                    "DgoOperationType::{:?} should serialize/deserialize",
                    operation_type
                )
            });
        }
    }

    #[test]
    fn test_granular_settings_postcard() {
        let text_blocks = TextBlocksSettings::default();
        test_postcard_roundtrip(&text_blocks)
            .expect("TextBlocksSettings should serialize/deserialize");

        let calendar = CalendarSettings::default();
        test_postcard_roundtrip(&calendar).expect("CalendarSettings should serialize/deserialize");

        let tasks = TasksSettings::default();
        test_postcard_roundtrip(&tasks).expect("TasksSettings should serialize/deserialize");
    }

    #[test]
    fn test_permission_checking() {
        use crate::group::events::roles::GroupRole;

        let settings = DgoFeatureSettings::default();

        // Test that members can create text blocks by default
        assert!(settings.can_perform_operation(
            DgoFeatureType::TextBlock,
            DgoOperationType::Create,
            &GroupRole::Member
        ));

        // Test that members can now update text blocks (changed to AllMembers)
        assert!(settings.can_perform_operation(
            DgoFeatureType::TextBlock,
            DgoOperationType::Update,
            &GroupRole::Member
        ));

        // Test that moderators can update text blocks
        assert!(settings.can_perform_operation(
            DgoFeatureType::TextBlock,
            DgoOperationType::Update,
            &GroupRole::Moderator
        ));

        // Test that members can now create task lists (changed to AllMembers)
        assert!(settings.can_perform_operation(
            DgoFeatureType::TaskList,
            DgoOperationType::Create,
            &GroupRole::Member
        ));

        // Test that moderators can create task lists
        assert!(settings.can_perform_operation(
            DgoFeatureType::TaskList,
            DgoOperationType::Create,
            &GroupRole::Moderator
        ));
    }

    #[test]
    fn test_apply_updates_functionality() {
        use crate::group::events::roles::GroupRole;

        let mut settings = DgoFeatureSettings::default();

        // Initially, members can create task lists (changed to AllMembers)
        assert!(settings.can_perform_operation(
            DgoFeatureType::TaskList,
            DgoOperationType::Create,
            &GroupRole::Member
        ));

        // Apply updates to restrict task list creation to moderators and change assign permissions
        let updates = vec![
            PermissionUpdate::Tasks(TasksPermissionUpdate::CreateTaskList(
                FeaturePermission::ModeratorOrAbove,
            )),
            PermissionUpdate::Tasks(TasksPermissionUpdate::AssignTask(
                FeaturePermission::ModeratorOrAbove,
            )),
        ];

        settings.apply_updates(updates);

        // Now members cannot create task lists (restricted to moderators)
        assert!(!settings.can_perform_operation(
            DgoFeatureType::TaskList,
            DgoOperationType::Create,
            &GroupRole::Member
        ));

        // But members cannot assign tasks (updated to require moderator)
        assert!(!settings.can_perform_operation(
            DgoFeatureType::Task,
            DgoOperationType::Assign,
            &GroupRole::Member
        ));

        // Moderators can assign tasks
        assert!(settings.can_perform_operation(
            DgoFeatureType::Task,
            DgoOperationType::Assign,
            &GroupRole::Moderator
        ));
    }

    #[test]
    fn test_efficient_serialization() {
        // Test that the Vec<PermissionUpdate> pattern is more efficient than full settings
        let updates = vec![PermissionUpdate::Tasks(
            TasksPermissionUpdate::CreateTaskList(FeaturePermission::AllMembers),
        )];

        let full_settings = DgoFeatureSettings::default();

        let updates_serialized = postcard::to_stdvec(&updates).unwrap();
        let full_settings_serialized = postcard::to_stdvec(&full_settings).unwrap();

        // Updates should be significantly smaller than full settings
        assert!(updates_serialized.len() < full_settings_serialized.len());

        // Verify the update is very compact (should be just a few bytes)
        assert!(
            updates_serialized.len() < 20,
            "Update should be very compact, got {} bytes",
            updates_serialized.len()
        );
    }
}
