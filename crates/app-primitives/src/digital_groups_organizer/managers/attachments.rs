//! Attachments manager for handling attachments on any attachable object
//!
//! This module provides the AttachmentsManager type and related functionality
//! for managing attachments and attachment statistics on DGO objects.

use crate::identity::IdentityRef;
use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use crate::digital_groups_organizer::{
    indexing::{core::ModelParam, core::ObjectListIndex, keys::ExecuteReference, keys::IndexKey},
    models::core::DgoResult,
};

/// Statistics about attachments on an object
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentStats {
    /// Whether this object has any attachments
    pub has_attachments: bool,
    /// Total number of attachments
    pub total_attachments_count: u32,
    /// Whether the current user has added attachments
    pub user_has_attachments: bool,
    /// Attachment IDs from the current user
    pub user_attachments: Vec<MessageId>,
}

/// Manager for handling attachments on any attachable object
#[derive(Debug, Clone)]
pub struct AttachmentsManager {
    /// The object being managed
    object_id: MessageId,
    /// Current statistics
    stats: AttachmentStats,
    /// Current user
    user_id: IdentityRef,
}

impl AttachmentsManager {
    /// Create a new attachments manager for an object
    pub fn new(object_id: MessageId, user_id: IdentityRef) -> Self {
        Self {
            object_id,
            stats: AttachmentStats::default(),
            user_id,
        }
    }

    /// Create an attachments manager with existing stats
    pub fn with_stats(object_id: MessageId, user_id: IdentityRef, stats: AttachmentStats) -> Self {
        Self {
            object_id,
            stats,
            user_id,
        }
    }

    /// Get the object ID this manager is for
    pub fn object_id(&self) -> MessageId {
        self.object_id
    }

    /// Get the current statistics
    pub fn stats(&self) -> &AttachmentStats {
        &self.stats
    }

    /// Get the index key for attachments on this object
    pub fn attachments_index(&self) -> IndexKey {
        IndexKey::ObjectList(self.object_id, ObjectListIndex::Attachments)
    }

    /// Get the storage key for attachment statistics
    pub fn stats_key(&self) -> ExecuteReference {
        ExecuteReference::ModelParam(self.object_id, ModelParam::AttachmentsStats)
    }

    /// Add an attachment to this object
    pub fn add_attachment(
        &mut self,
        attachment_id: MessageId,
        author: &IdentityRef,
    ) -> DgoResult<bool> {
        self.stats.has_attachments = true;
        self.stats.total_attachments_count += 1;

        if author == &self.user_id {
            self.stats.user_has_attachments = true;
            self.stats.user_attachments.push(attachment_id);
        }

        Ok(true)
    }

    /// Remove an attachment from this object (for redaction)
    pub fn remove_attachment(
        &mut self,
        attachment_id: MessageId,
        author: &IdentityRef,
    ) -> DgoResult<bool> {
        if self.stats.total_attachments_count > 0 {
            self.stats.total_attachments_count -= 1;
        }

        if author == &self.user_id {
            self.stats
                .user_attachments
                .retain(|id| id != &attachment_id);
            self.stats.user_has_attachments = !self.stats.user_attachments.is_empty();
        }

        self.stats.has_attachments = self.stats.total_attachments_count > 0;

        Ok(true)
    }
}
