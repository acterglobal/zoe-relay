//! Core indexing types for Digital Groups Organizer
//!
//! This module defines the core index types used for organizing and categorizing
//! content within encrypted groups.

use serde::{Deserialize, Serialize};

/// Different types of sections for organizing content within a group
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SectionIndex {
    /// Calendar events and scheduling
    Calendar,
    /// Task lists and individual tasks  
    Tasks,
    /// Pinned announcements and important content
    Pins,
    /// News entries and updates
    News,
    /// Stories and narrative content
    Stories,
    /// Text blocks and documents
    TextBlocks,
    /// Custom section type
    Custom(String),
}

/// Different types of object lists for organizing related content
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObjectListIndex {
    /// Comments on an object
    Comments,
    /// File attachments on an object
    Attachments,
    /// Reactions (likes, emojis) on an object
    Reactions,
    /// Read receipts for an object
    ReadReceipts,
    /// RSVPs for an object (calendar events, etc.)
    Rsvps,
    /// Tasks within a task list
    Tasks,
    /// Explicit invitations for an object
    Invites,
    /// Custom object list type
    Custom(String),
}

/// Special cross-group indexes for user-specific views
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SpecialListsIndex {
    /// Tasks assigned to the current user that are not completed
    MyOpenTasks,
    /// Tasks assigned to the current user that are completed
    MyCompletedTasks,
    /// Objects the current user has been explicitly invited to
    InvitedTo,
    /// Objects the current user has bookmarked or starred
    Bookmarked,
    /// Recent activity across all groups
    RecentActivity,
    /// Custom special list type
    Custom(String),
}

/// Different types of model parameters for storing metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ModelParam {
    /// Statistics about comments on an object
    CommentsStats,
    /// Statistics about attachments on an object
    AttachmentsStats,
    /// Statistics about reactions on an object
    ReactionStats,
    /// Statistics about RSVPs on an object
    RsvpStats,
    /// Statistics about read receipts on an object
    ReadReceiptsStats,
    /// Statistics about invitations for an object
    InviteStats,
    /// Custom parameter type
    Custom(String),
}

/// Different types of group parameters for storing group-level metadata
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GroupParam {
    /// Latest activity message in the group
    LatestActivity,
    /// Group settings and configuration
    GroupSettings,
    /// Custom parameter type
    Custom(String),
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
    fn test_section_index_postcard() {
        let indices = vec![
            SectionIndex::Calendar,
            SectionIndex::Tasks,
            SectionIndex::Pins,
            SectionIndex::Stories,
            SectionIndex::Custom("CustomSection".to_string()),
        ];

        for index in indices {
            test_postcard_roundtrip(&index).expect("SectionIndex should serialize/deserialize");
        }
    }

    #[test]
    fn test_object_list_index_postcard() {
        let indices = vec![
            ObjectListIndex::Comments,
            ObjectListIndex::Attachments,
            ObjectListIndex::Reactions,
            ObjectListIndex::Tasks,
            ObjectListIndex::Custom("CustomList".to_string()),
        ];

        for index in indices {
            test_postcard_roundtrip(&index).expect("ObjectListIndex should serialize/deserialize");
        }
    }

    #[test]
    fn test_special_lists_index_postcard() {
        let indices = vec![
            SpecialListsIndex::MyOpenTasks,
            SpecialListsIndex::InvitedTo,
            SpecialListsIndex::Custom("MyCustomList".to_string()),
        ];

        for index in indices {
            test_postcard_roundtrip(&index)
                .expect("SpecialListsIndex should serialize/deserialize");
        }
    }

    #[test]
    fn test_model_param_postcard() {
        let params = vec![ModelParam::Custom("custom_field".to_string())];

        for param in params {
            test_postcard_roundtrip(&param).expect("ModelParam should serialize/deserialize");
        }
    }

    #[test]
    fn test_group_param_postcard() {
        let params = vec![
            GroupParam::LatestActivity,
            GroupParam::GroupSettings,
            GroupParam::Custom("group_metadata".to_string()),
        ];

        for param in params {
            test_postcard_roundtrip(&param).expect("GroupParam should serialize/deserialize");
        }
    }
}
