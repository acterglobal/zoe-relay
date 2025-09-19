//! Comments manager for handling comments on any commentable object
//!
//! This module provides the CommentsManager type and related functionality
//! for managing comments and comment statistics on DGO objects.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::{MessageId, VerifyingKey};

use crate::digital_groups_organizer::{
    events::generic::AddCommentContent,
    indexing::{core::ModelParam, core::ObjectListIndex, keys::ExecuteReference, keys::IndexKey},
    models::core::DgoResult,
};

/// Statistics about comments on an object
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommentsStats {
    /// Whether this object has any comments
    pub has_comments: bool,
    /// Total number of comments
    pub total_comments_count: u32,
    /// Whether the current user has commented
    pub user_has_commented: bool,
    /// Comment IDs from the current user
    pub user_comments: Vec<MessageId>,
}

/// Manager for handling comments on any commentable object
#[derive(Debug, Clone)]
pub struct CommentsManager {
    /// The object being managed
    object_id: MessageId,
    /// Current statistics
    stats: CommentsStats,
    /// Current user
    user_id: VerifyingKey,
}

impl CommentsManager {
    /// Create a new comments manager for an object
    pub fn new(object_id: MessageId, user_id: VerifyingKey) -> Self {
        Self {
            object_id,
            stats: CommentsStats::default(),
            user_id,
        }
    }

    /// Create a comments manager with existing stats
    pub fn with_stats(object_id: MessageId, user_id: VerifyingKey, stats: CommentsStats) -> Self {
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
    pub fn stats(&self) -> &CommentsStats {
        &self.stats
    }

    /// Get the index key for comments on this object
    pub fn comments_index(&self) -> IndexKey {
        IndexKey::ObjectList(self.object_id, ObjectListIndex::Comments)
    }

    /// Get the storage key for comment statistics
    pub fn stats_key(&self) -> ExecuteReference {
        ExecuteReference::ModelParam(self.object_id, ModelParam::CommentsStats)
    }

    /// Add a comment to this object
    pub fn add_comment(&mut self, comment_id: MessageId, author: &VerifyingKey) -> DgoResult<bool> {
        self.stats.has_comments = true;
        self.stats.total_comments_count += 1;

        if author == &self.user_id {
            self.stats.user_has_commented = true;
            self.stats.user_comments.push(comment_id);
        }

        Ok(true)
    }

    /// Remove a comment from this object (for redaction)
    pub fn remove_comment(
        &mut self,
        comment_id: MessageId,
        author: &VerifyingKey,
    ) -> DgoResult<bool> {
        if self.stats.total_comments_count > 0 {
            self.stats.total_comments_count -= 1;
        }

        if author == &self.user_id {
            self.stats.user_comments.retain(|id| id != &comment_id);
            self.stats.user_has_commented = !self.stats.user_comments.is_empty();
        }

        self.stats.has_comments = self.stats.total_comments_count > 0;

        Ok(true)
    }

    /// Create a draft comment for this object
    pub fn create_comment_draft(&self, comment: String) -> AddCommentContent {
        AddCommentContent {
            comment,
            references: Vec::new(),
        }
    }

    /// Create a comment draft with references to other messages
    pub fn create_comment_draft_with_references(
        &self,
        comment: String,
        references: Vec<MessageId>,
    ) -> AddCommentContent {
        AddCommentContent {
            comment,
            references,
        }
    }
}
