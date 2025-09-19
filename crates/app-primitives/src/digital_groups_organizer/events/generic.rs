//! Generic feature event types for comments, reactions, and attachments
//!
//! This module contains event types for generic features that can be applied
//! to any capable object (comments, reactions, attachments, read receipts).

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

/// Content for adding a comment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddCommentContent {
    /// The comment text content
    pub comment: String,
    /// Optional references to other message IDs (for future UI features)
    #[serde(default)]
    pub references: Vec<MessageId>,
}

/// Individual comment update operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommentUpdate {
    /// Update the comment text
    Comment(String),
    /// Update the references to other objects
    References(Vec<MessageId>),
    /// Clear all references
    ClearReferences,
}

/// Content for updating a comment - vector of specific updates
pub type UpdateCommentContent = Vec<CommentUpdate>;

/// Reaction content (emoji, like, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionContent {
    /// Reaction type (emoji, "like", "heart", etc.)
    pub reaction_type: String,
}

/// Attachment content with typed file information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttachmentContent {
    /// Title of the attachment
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
    /// Reference to the stored file
    pub file_ref: crate::file::FileRef,
    /// Typed content information based on file type
    pub content_info: AttachmentContentInfo,
}

/// Typed content information for different attachment types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AttachmentContentInfo {
    /// Image attachment with dimensions and format info
    Image {
        /// Image width in pixels (if known)
        width: Option<u32>,
        /// Image height in pixels (if known)
        height: Option<u32>,
        /// Image format (e.g., "PNG", "JPEG", "WEBP")
        format: Option<String>,
        /// Alternative text for accessibility
        alt_text: Option<String>,
    },
    /// Video attachment with duration and resolution
    Video {
        /// Video duration in seconds (if known)
        duration_seconds: Option<u32>,
        /// Video width in pixels (if known)
        width: Option<u32>,
        /// Video height in pixels (if known)
        height: Option<u32>,
        /// Video codec (e.g., "H.264", "VP9", "AV1")
        codec: Option<String>,
        /// Frame rate (if known)
        fps: Option<f32>,
    },
    /// Audio attachment with duration and format info
    Audio {
        /// Audio duration in seconds (if known)
        duration_seconds: Option<u32>,
        /// Audio codec (e.g., "MP3", "AAC", "FLAC")
        codec: Option<String>,
        /// Bitrate in kbps (if known)
        bitrate_kbps: Option<u32>,
        /// Sample rate in Hz (if known)
        sample_rate_hz: Option<u32>,
    },
    /// Document attachment (PDF, Word, etc.)
    Document {
        /// Number of pages (if applicable)
        page_count: Option<u32>,
        /// Document format (e.g., "PDF", "DOCX", "TXT")
        format: Option<String>,
        /// Whether the document is searchable/has text content
        has_text_content: Option<bool>,
    },
    /// Archive/compressed file
    Archive {
        /// Archive format (e.g., "ZIP", "TAR", "7Z")
        format: Option<String>,
        /// Number of files in the archive (if known)
        file_count: Option<u32>,
        /// Uncompressed size in bytes (if known)
        uncompressed_size: Option<u64>,
    },
    /// Generic file attachment for unknown or unsupported types
    Generic {
        /// File category hint (e.g., "spreadsheet", "presentation", "code")
        category: Option<String>,
    },
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
    fn test_add_comment_content_postcard() {
        let content = AddCommentContent {
            comment: "This is a great idea! 🎉 Let's implement it soon.".to_string(),
            references: vec![
                MessageId::from_bytes([1; 32]),
                MessageId::from_bytes([2; 32]),
                MessageId::from_bytes([3; 32]),
            ],
        };

        test_postcard_roundtrip(&content).expect("AddCommentContent should serialize/deserialize");
    }

    #[test]
    fn test_update_comment_content_postcard() {
        let content = vec![
            CommentUpdate::Comment("Updated comment with <em>emphasis</em>".to_string()),
            CommentUpdate::References(vec![MessageId::from_bytes([4; 32])]),
        ];

        test_postcard_roundtrip(&content)
            .expect("UpdateCommentContent should serialize/deserialize");
    }

    #[test]
    fn test_update_comment_clear_references_postcard() {
        let content = vec![
            CommentUpdate::Comment("Updated comment text".to_string()),
            CommentUpdate::ClearReferences, // Clear all references
        ];

        test_postcard_roundtrip(&content)
            .expect("UpdateCommentContent with ClearReferences should serialize/deserialize");
    }

    #[test]
    fn test_reaction_content_postcard() {
        let reactions = vec![
            ReactionContent {
                reaction_type: "👍".to_string(),
            },
            ReactionContent {
                reaction_type: "❤️".to_string(),
            },
            ReactionContent {
                reaction_type: "😂".to_string(),
            },
            ReactionContent {
                reaction_type: "🎉".to_string(),
            },
            ReactionContent {
                reaction_type: "like".to_string(),
            },
        ];

        for reaction in reactions {
            test_postcard_roundtrip(&reaction)
                .expect("ReactionContent should serialize/deserialize");
        }
    }
}
