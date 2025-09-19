//! Content-related event types for text blocks and basic content
//!
//! This module contains event types for creating and managing text-based content
//! within encrypted groups.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

/// Content for creating a new text block
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateTextBlockContent {
    /// Title of the text block
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
}

/// Individual text block update operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextBlockUpdate {
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
}

/// Content for updating a text block - vector of specific updates
pub type UpdateTextBlockContent = Vec<TextBlockUpdate>;

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
    fn test_create_text_block_content_postcard() {
        let content = CreateTextBlockContent {
            title: "My Document".to_string(),
            description: Some("A comprehensive guide to <strong>Rust</strong>".to_string()),
            icon: Some("📚".to_string()),
            parent_id: Some(MessageId::from_bytes([1; 32])),
        };

        test_postcard_roundtrip(&content)
            .expect("CreateTextBlockContent should serialize/deserialize");
    }

    #[test]
    fn test_create_text_block_content_minimal_postcard() {
        let content = CreateTextBlockContent {
            title: "Simple Note".to_string(),
            description: None,
            icon: None,
            parent_id: None,
        };

        test_postcard_roundtrip(&content)
            .expect("Minimal CreateTextBlockContent should serialize/deserialize");
    }

    #[test]
    fn test_update_text_block_content_postcard() {
        let content = vec![
            TextBlockUpdate::Title("Updated Document Title".to_string()),
            TextBlockUpdate::Description("Updated description with <em>emphasis</em>".to_string()),
            TextBlockUpdate::Icon("📖".to_string()),
            TextBlockUpdate::ParentId(MessageId::from_bytes([2; 32])),
        ];

        test_postcard_roundtrip(&content)
            .expect("UpdateTextBlockContent should serialize/deserialize");
    }

    #[test]
    fn test_update_text_block_content_partial_postcard() {
        let content = vec![
            TextBlockUpdate::Title("New Title Only".to_string()),
            TextBlockUpdate::ClearIcon,        // Clearing icon
            TextBlockUpdate::ClearDescription, // Clearing description
        ];

        test_postcard_roundtrip(&content)
            .expect("Partial UpdateTextBlockContent should serialize/deserialize");
    }
}
