//! Task management event types for task lists and individual tasks
//!
//! This module contains simplified event types for creating and managing task lists and tasks.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

/// Content for creating a task list
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateTaskListContent {
    /// Title of the task list
    pub title: String,
    /// Optional description (HTML formatted)
    #[serde(default)]
    pub description: Option<String>,
    /// Optional icon (emoji)
    #[serde(default)]
    pub icon: Option<String>,
    /// Optional parent object (for threading/nesting)
    #[serde(default)]
    pub parent_id: Option<MessageId>,
    /// Time zone for this task list (IANA timezone identifier)
    #[serde(default)]
    pub time_zone: Option<String>,
}

/// Individual task list update operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskListUpdate {
    /// Update the title
    Title(String),
    /// Update the description
    Description(String),
    /// Clear the description
    ClearDescription,
    /// Update the icon
    Icon(String),
    /// Clear the icon
    ClearIcon,
    /// Update the parent relationship
    ParentId(MessageId),
    /// Clear the parent relationship
    ClearParentId,
    /// Update the time zone
    TimeZone(String),
    /// Clear the time zone
    ClearTimeZone,
}

/// Content for updating a task list - vector of specific updates
pub type UpdateTaskListContent = Vec<TaskListUpdate>;

/// Date representation (YYYY-MM-DD format)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Date {
    /// Year (e.g., 2024)
    pub year: u16,
    /// Month (1-12)
    pub month: u8,
    /// Day (1-31)
    pub day: u8,
}

/// Content for creating a task
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateTaskContent {
    /// Title of the task
    pub title: String,
    /// Optional description (HTML formatted)
    #[serde(default)]
    pub description: Option<String>,
    /// Optional icon (emoji)
    #[serde(default)]
    pub icon: Option<String>,
    /// Optional parent object (for threading/nesting)
    #[serde(default)]
    pub parent_id: Option<MessageId>,
    /// Task list this task belongs to
    pub task_list_id: MessageId,
    /// Which day is this task due
    #[serde(default)]
    pub due_date: Option<Date>,
    /// Specific time this task is due (seconds since midnight UTC, 0-86399)
    #[serde(default)]
    pub utc_due_time_of_day: Option<u32>,
    /// When was this task started (Unix timestamp in UTC)
    #[serde(default)]
    pub utc_started: Option<u64>,
    /// How far along is this task in percent (0-100)
    #[serde(default)]
    pub progress_percent: Option<u8>,
}

/// Individual task update operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TaskUpdate {
    /// Update the title
    Title(String),
    /// Update the description
    Description(String),
    /// Clear the description
    ClearDescription,
    /// Update the icon
    Icon(String),
    /// Clear the icon
    ClearIcon,
    /// Update the parent relationship
    ParentId(MessageId),
    /// Clear the parent relationship
    ClearParentId,
    /// Update the due date
    DueDate(Date),
    /// Clear the due date
    ClearDueDate,
    /// Update the due time of day
    UtcDueTimeOfDay(u32),
    /// Clear the due time of day
    ClearUtcDueTimeOfDay,
    /// Update the start time
    UtcStarted(u64),
    /// Clear the start time
    ClearUtcStarted,
    /// Update the progress percentage
    ProgressPercent(u8),
    /// Clear the progress percentage
    ClearProgressPercent,
}

/// Content for updating a task - vector of specific updates
pub type UpdateTaskContent = Vec<TaskUpdate>;

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_wire_protocol::MessageId;

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
    fn test_create_task_list_content_postcard() {
        let content = CreateTaskListContent {
            title: "Sprint Backlog".to_string(),
            description: Some("Tasks for the current sprint".to_string()),
            icon: Some("📋".to_string()),
            parent_id: None,
            time_zone: Some("America/New_York".to_string()),
        };

        test_postcard_roundtrip(&content)
            .expect("CreateTaskListContent should serialize/deserialize");
    }

    #[test]
    fn test_create_task_list_content_minimal_postcard() {
        let content = CreateTaskListContent {
            title: "Simple List".to_string(),
            description: None,
            icon: None,
            parent_id: None,
            time_zone: None,
        };

        test_postcard_roundtrip(&content)
            .expect("Minimal CreateTaskListContent should serialize/deserialize");
    }

    #[test]
    fn test_update_task_list_content_postcard() {
        let content = vec![
            TaskListUpdate::Title("Updated Sprint Backlog".to_string()),
            TaskListUpdate::Description("Updated description for the sprint".to_string()),
            TaskListUpdate::Icon("📝".to_string()),
            TaskListUpdate::TimeZone("Europe/London".to_string()),
        ];

        test_postcard_roundtrip(&content)
            .expect("UpdateTaskListContent should serialize/deserialize");
    }
    #[test]
    fn test_date_postcard() {
        let date = Date {
            year: 2023,
            month: 12,
            day: 25,
        };

        test_postcard_roundtrip(&date).expect("Date should serialize/deserialize");
    }

    #[test]
    fn test_create_task_content_postcard() {
        let content = CreateTaskContent {
            title: "Implement user authentication".to_string(),
            description: Some(
                "Add OAuth2 support with <strong>secure</strong> token handling".to_string(),
            ),
            icon: Some("🔐".to_string()),
            parent_id: None,
            task_list_id: MessageId::from_bytes([1; 32]),
            due_date: Some(Date {
                year: 2023,
                month: 12,
                day: 31,
            }),
            utc_due_time_of_day: Some(17 * 3600), // 5 PM UTC
            utc_started: Some(1703001600),
            progress_percent: Some(75),
        };

        test_postcard_roundtrip(&content).expect("CreateTaskContent should serialize/deserialize");
    }

    #[test]
    fn test_create_task_content_minimal_postcard() {
        let content = CreateTaskContent {
            title: "Quick task".to_string(),
            description: None,
            icon: None,
            parent_id: None,
            task_list_id: MessageId::from_bytes([2; 32]),
            due_date: None,
            utc_due_time_of_day: None,
            utc_started: None,
            progress_percent: None,
        };

        test_postcard_roundtrip(&content)
            .expect("Minimal CreateTaskContent should serialize/deserialize");
    }

    #[test]
    fn test_update_task_content_postcard() {
        let content = vec![
            TaskUpdate::Title("Updated task title".to_string()),
            TaskUpdate::Description("Updated description with progress notes".to_string()),
            TaskUpdate::Icon("✅".to_string()),
            TaskUpdate::DueDate(Date {
                year: 2024,
                month: 1,
                day: 15,
            }),
            TaskUpdate::UtcDueTimeOfDay(12 * 3600), // Noon UTC
            TaskUpdate::UtcStarted(1703005200),
            TaskUpdate::ProgressPercent(90),
        ];

        test_postcard_roundtrip(&content).expect("UpdateTaskContent should serialize/deserialize");
    }

    #[test]
    fn test_update_task_content_partial_postcard() {
        let content = vec![
            TaskUpdate::ClearIcon,            // Clearing icon
            TaskUpdate::ClearDueDate,         // Clearing due date
            TaskUpdate::ProgressPercent(100), // Marking as complete
        ];

        test_postcard_roundtrip(&content)
            .expect("Partial UpdateTaskContent should serialize/deserialize");
    }
}
