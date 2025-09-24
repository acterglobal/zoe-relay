//! Core event types and shared structures for the Digital Groups Organizer
//!
//! This module contains the main `DgoActivityEvent` enum and shared data structures
//! used across all event types.

use crate::group::app::ExecutorEvent;
use crate::identity::IdentityType;
use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

// Re-export event content types from submodules
use super::admin::*;
use super::calendar::*;
use super::content::*;
use super::generic::*;
use super::tasks::*;

/// Forward-compatible enum for all Digital Groups Organizer activity events
///
/// This enum uses discriminants to ensure forward compatibility as new
/// event types are added over time.
///
/// ## Event Structure
///
/// Events contain only the business logic data. Metadata like activity_id,
/// actor, timestamp, and group_id come from the wire-protocol Message envelope.
/// Parent relationships are stored as fields within the content objects themselves.
#[derive(Debug, Clone, PartialEq, ForwardCompatibleEnum)]
pub enum DgoActivityEventContent {
    // === Text Content Events (10-19) ===
    /// Create a new text block
    #[discriminant(10)]
    CreateTextBlock { content: CreateTextBlockContent },

    /// Update an existing text block
    #[discriminant(11)]
    UpdateTextBlock {
        /// ID of the text block to update
        target_id: MessageId,
        /// New content for the text block
        content: UpdateTextBlockContent,
    },

    // === Calendar Events (20-29) ===
    /// Create a new calendar event
    #[discriminant(20)]
    CreateCalendarEvent { content: CreateCalendarEventContent },

    /// Update an existing calendar event
    #[discriminant(21)]
    UpdateCalendarEvent {
        /// ID of the calendar event to update
        target_id: MessageId,
        /// Updated event details
        content: UpdateCalendarEventContent,
    },

    /// RSVP to a calendar event
    #[discriminant(22)]
    RsvpCalendarEvent {
        /// ID of the calendar event
        target_id: MessageId,
        /// RSVP response
        response: RsvpResponse,
    },

    // === Task Management Events (30-39) ===
    /// Create a new task list
    #[discriminant(30)]
    CreateTaskList { content: CreateTaskListContent },

    /// Update a task list
    #[discriminant(31)]
    UpdateTaskList {
        /// ID of the task list to update
        target_id: MessageId,
        /// Updated task list details
        content: UpdateTaskListContent,
    },

    /// Create a new task within a task list
    #[discriminant(32)]
    CreateTask { content: CreateTaskContent },

    /// Update an existing task
    #[discriminant(33)]
    UpdateTask {
        /// ID of the task to update
        target_id: MessageId,
        /// Updated task details
        content: UpdateTaskContent,
    },

    /// Self-assign to a task
    #[discriminant(34)]
    SelfAssignTask {
        /// ID of the task to assign to self
        target_id: MessageId,
    },

    /// Unassign from a task
    #[discriminant(35)]
    UnassignTask {
        /// ID of the task to unassign from
        target_id: MessageId,
    },

    // === Generic Feature Events (40-59) ===
    /// Add a comment to any commentable object
    #[discriminant(40)]
    AddComment {
        /// ID of the object being commented on
        target_id: MessageId,
        /// Comment content
        content: AddCommentContent,
    },

    /// Update an existing comment
    #[discriminant(41)]
    UpdateComment {
        /// ID of the comment to update
        target_id: MessageId,
        /// Updated comment content
        content: UpdateCommentContent,
    },

    /// Add a reaction to any reactable object
    #[discriminant(42)]
    AddReaction {
        /// ID of the object being reacted to
        target_id: MessageId,
        /// Reaction content (emoji, like, etc.)
        reaction: ReactionContent,
    },

    /// Remove a reaction from an object
    #[discriminant(43)]
    RemoveReaction {
        /// ID of the object to remove reaction from
        target_id: MessageId,
        /// Reaction to remove
        reaction: ReactionContent,
    },

    /// Attach a file to any attachmentable object
    #[discriminant(44)]
    AddAttachment {
        /// ID of the object to attach to
        target_id: MessageId,
        /// Attachment details
        attachment: AttachmentContent,
    },

    /// Remove an attachment from an object
    #[discriminant(45)]
    RemoveAttachment {
        /// ID of the object to remove attachment from
        target_id: MessageId,
        /// ID of the attachment to remove
        attachment_id: MessageId,
    },

    /// Mark an object as read
    #[discriminant(46)]
    MarkRead {
        /// ID of the object being marked as read
        target_id: MessageId,
    },

    // === Administrative Events (60-69) ===
    /// Redact/delete an object or activity
    #[discriminant(60)]
    Redact {
        /// ID of the object/activity to redact
        target_id: MessageId,
        /// Optional reason for redaction
        reason: Option<String>,
    },
    /// Unknown event type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgoSettingsEvent {
    identity: IdentityType,
    /// Reference to the group state message for permission validation
    /// This allows the app event to be validated against the group permissions
    /// that were active at the time this reference was created.
    group_state_reference: MessageId,
    /// Permission settings content changes
    content: UpdateDgoSettingsContent,
}

impl ExecutorEvent for DgoSettingsEvent {
    fn applies_to(&self) -> Option<Vec<MessageId>> {
        None
    }
    fn group_state_reference(&self) -> MessageId {
        self.group_state_reference
    }
}

impl DgoSettingsEvent {
    /// Get the content of this settings event
    pub fn content(&self) -> &UpdateDgoSettingsContent {
        &self.content
    }
}

/// Core object data that all Zoe objects share
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectCore {
    /// Title of the object (plain text)
    pub title: String,
    /// Optional description (HTML formatted)
    pub description: Option<String>,
    /// Optional icon (emoji)
    pub icon: Option<String>,
    /// Optional parent object (for threading/nesting)
    pub parent_id: Option<MessageId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgoActivityEvent {
    identity: IdentityType,
    content: DgoActivityEventContent,
    /// Reference to the group state message for permission validation
    /// This allows the app event to be validated against the group permissions
    /// that were active at the time this reference was created.
    group_state_reference: MessageId,
}

impl DgoActivityEvent {
    /// Create a new DGO activity event with identity, content, and group state reference
    pub fn new(
        identity: IdentityType,
        content: DgoActivityEventContent,
        group_state_reference: MessageId,
    ) -> Self {
        Self {
            identity,
            content,
            group_state_reference,
        }
    }

    /// Get the identity type for this event
    pub fn identity(&self) -> &IdentityType {
        &self.identity
    }

    /// Get the event content
    pub fn content(&self) -> &DgoActivityEventContent {
        &self.content
    }

    /// Construct an IdentityRef from the event's identity and a verifying key
    pub fn identity_ref(
        &self,
        verifying_key: &zoe_wire_protocol::VerifyingKey,
    ) -> crate::identity::IdentityRef {
        self.identity.to_identity_ref(verifying_key.clone())
    }

    /// Get the group state reference for permission validation
    pub fn get_group_state_reference(&self) -> MessageId {
        self.group_state_reference
    }
}

impl ExecutorEvent for DgoActivityEvent {
    fn applies_to(&self) -> Option<Vec<MessageId>> {
        match &self.content {
            // Text block events
            DgoActivityEventContent::CreateTextBlock { .. } => {
                // For create events, we return None to indicate this creates a new model
                None
            }
            DgoActivityEventContent::UpdateTextBlock { target_id, .. } => Some(vec![*target_id]),

            // Calendar events
            DgoActivityEventContent::CreateCalendarEvent { .. } => None,
            DgoActivityEventContent::UpdateCalendarEvent { target_id, .. } => {
                Some(vec![*target_id])
            }

            // Task events
            DgoActivityEventContent::CreateTaskList { .. } => None,
            DgoActivityEventContent::UpdateTaskList { target_id, .. } => Some(vec![*target_id]),
            DgoActivityEventContent::CreateTask { .. } => None,
            DgoActivityEventContent::UpdateTask { target_id, .. } => Some(vec![*target_id]),

            // Comment events (would affect parent + create comment)
            DgoActivityEventContent::AddComment { target_id, .. } => Some(vec![*target_id]),
            DgoActivityEventContent::UpdateComment { target_id, .. } => Some(vec![*target_id]),

            // Reaction events (would affect parent)
            DgoActivityEventContent::AddReaction { target_id, .. } => Some(vec![*target_id]),

            // RSVP events (would affect parent) - TODO: Add when RSVP events exist
            // DgoActivityEventContent::AddRsvp { target_id, .. } => Some(vec![*target_id]),

            // Admin events
            DgoActivityEventContent::Redact { target_id, .. } => Some(vec![*target_id]),

            // Calendar RSVP events
            DgoActivityEventContent::RsvpCalendarEvent { target_id, .. } => Some(vec![*target_id]),

            // Task assignment events
            DgoActivityEventContent::SelfAssignTask { target_id, .. } => Some(vec![*target_id]),
            DgoActivityEventContent::UnassignTask { target_id, .. } => Some(vec![*target_id]),

            // Reaction removal events
            DgoActivityEventContent::RemoveReaction { target_id, .. } => Some(vec![*target_id]),

            // Attachment events
            DgoActivityEventContent::AddAttachment { target_id, .. } => Some(vec![*target_id]),
            DgoActivityEventContent::RemoveAttachment { target_id, .. } => Some(vec![*target_id]),

            // Read status events
            DgoActivityEventContent::MarkRead { target_id, .. } => Some(vec![*target_id]),

            // Unknown events
            DgoActivityEventContent::Unknown { .. } => None,
        }
    }

    fn group_state_reference(&self) -> MessageId {
        self.group_state_reference
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_object_core_postcard() {
        let core = ObjectCore {
            title: "Test Title".to_string(),
            description: Some("Test description with <b>HTML</b>".to_string()),
            icon: Some("📝".to_string()),
            parent_id: None, // Simplified for testing
        };

        test_postcard_roundtrip(&core).expect("ObjectCore should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_text_block_postcard() {
        let event = DgoActivityEventContent::CreateTextBlock {
            content: CreateTextBlockContent {
                title: "My Text Block".to_string(),
                description: Some("Rich text content".to_string()),
                icon: Some("📄".to_string()),
                parent_id: None,
            },
        };

        test_postcard_roundtrip(&event)
            .expect("CreateTextBlock event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_calendar_postcard() {
        let event = DgoActivityEventContent::CreateCalendarEvent {
            content: CreateCalendarEventContent {
                title: "Team Meeting".to_string(),
                description: Some("Weekly team sync".to_string()),
                icon: Some("📅".to_string()),
                parent_id: None,
                utc_start_time: 1703001600, // 2023-12-19 12:00:00 UTC
                utc_end_time: 1703005200,   // 2023-12-19 13:00:00 UTC
                locations: vec![EventLocation::Virtual {
                    name: Some("Zoom Meeting".to_string()),
                    description: Some("Join via Zoom".to_string()),
                    icon: Some("💻".to_string()),
                    uri: "https://zoom.us/j/123456789".to_string(),
                    notes: Some("Meeting ID: 123 456 789".to_string()),
                }],
                all_day: false,
            },
        };

        test_postcard_roundtrip(&event)
            .expect("CreateCalendarEvent event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_task_postcard() {
        let event = DgoActivityEventContent::CreateTask {
            content: CreateTaskContent {
                title: "Fix bug #123".to_string(),
                description: Some("Critical bug in user authentication".to_string()),
                icon: Some("🐛".to_string()),
                parent_id: None,
                task_list_id: MessageId::from_bytes([2; 32]),
                due_date: Some(Date {
                    year: 2023,
                    month: 12,
                    day: 25,
                }),
                utc_due_time_of_day: Some(17 * 3600), // 5 PM UTC
                utc_started: Some(1703001600),
                progress_percent: Some(25),
            },
        };

        test_postcard_roundtrip(&event).expect("CreateTask event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_comment_postcard() {
        let event = DgoActivityEventContent::AddComment {
            target_id: MessageId::from_bytes([3; 32]),
            content: AddCommentContent {
                comment: "This looks great! 👍".to_string(),
                references: vec![
                    MessageId::from_bytes([4; 32]),
                    MessageId::from_bytes([5; 32]),
                ],
            },
        };

        test_postcard_roundtrip(&event).expect("AddComment event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_reaction_postcard() {
        let event = DgoActivityEventContent::AddReaction {
            target_id: MessageId::from_bytes([6; 32]),
            reaction: ReactionContent {
                reaction_type: "❤️".to_string(),
            },
        };

        test_postcard_roundtrip(&event).expect("AddReaction event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_rsvp_postcard() {
        let event = DgoActivityEventContent::RsvpCalendarEvent {
            target_id: MessageId::from_bytes([9; 32]),
            response: RsvpResponse::Yes,
        };

        test_postcard_roundtrip(&event)
            .expect("RsvpCalendarEvent event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_redact_postcard() {
        let event = DgoActivityEventContent::Redact {
            target_id: MessageId::from_bytes([10; 32]),
            reason: Some("Inappropriate content".to_string()),
        };

        test_postcard_roundtrip(&event).expect("Redact event should serialize/deserialize");
    }

    #[test]
    fn test_dgo_activity_event_group_state_reference() {
        use crate::identity::IdentityType;
        use zoe_wire_protocol::MessageId;

        let group_state_ref = MessageId::from_bytes([1; 32]);
        let event = DgoActivityEvent::new(
            IdentityType::Main,
            DgoActivityEventContent::CreateTextBlock {
                content: crate::digital_groups_organizer::events::content::CreateTextBlockContent {
                    title: "Test".to_string(),
                    description: Some("Test content".to_string()),
                    icon: None,
                    parent_id: None,
                },
            },
            group_state_ref,
        );

        // Test the group state reference is correctly stored and retrieved
        assert_eq!(event.get_group_state_reference(), group_state_ref);
        assert_eq!(event.group_state_reference(), group_state_ref);
    }

    #[test]
    fn test_dgo_activity_event_unknown_postcard() {
        let event = DgoActivityEventContent::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3, 4, 5],
        };

        test_postcard_roundtrip(&event).expect("Unknown event should serialize/deserialize");
    }
}
