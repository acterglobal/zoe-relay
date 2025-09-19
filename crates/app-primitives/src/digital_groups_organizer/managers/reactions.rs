//! Reactions manager for handling reactions on any reactable object
//!
//! This module provides the ReactionsManager type and related functionality
//! for managing reactions and reaction statistics on DGO objects.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zoe_wire_protocol::{MessageId, VerifyingKey};

use crate::digital_groups_organizer::{
    indexing::{core::ModelParam, core::ObjectListIndex, keys::ExecuteReference, keys::IndexKey},
    models::core::DgoResult,
};

/// Statistics about reactions on an object
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReactionStats {
    /// Whether this object has any reactions
    pub has_reactions: bool,
    /// Total number of reactions
    pub total_reactions_count: u32,
    /// Whether this object has like reactions specifically
    pub has_likes: bool,
    /// Total number of like reactions
    pub total_likes_count: u32,
    /// Whether the current user has reacted
    pub user_has_reacted: bool,
    /// Whether the current user has liked
    pub user_has_liked: bool,
    /// Reaction IDs from the current user
    pub user_reactions: Vec<MessageId>,
    /// Breakdown of reactions by type
    pub reaction_counts: HashMap<String, u32>,
}

/// Manager for handling reactions on any reactable object
#[derive(Debug, Clone)]
pub struct ReactionsManager {
    /// The object being managed
    object_id: MessageId,
    /// Current statistics
    stats: ReactionStats,
    /// Current user
    user_id: VerifyingKey,
}

impl ReactionsManager {
    /// Create a new reactions manager for an object
    pub fn new(object_id: MessageId, user_id: VerifyingKey) -> Self {
        Self {
            object_id,
            stats: ReactionStats::default(),
            user_id,
        }
    }

    /// Create a reactions manager with existing stats
    pub fn with_stats(object_id: MessageId, user_id: VerifyingKey, stats: ReactionStats) -> Self {
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
    pub fn stats(&self) -> &ReactionStats {
        &self.stats
    }

    /// Get the index key for reactions on this object
    pub fn reactions_index(&self) -> IndexKey {
        IndexKey::ObjectList(self.object_id, ObjectListIndex::Reactions)
    }

    /// Get the storage key for reaction statistics
    pub fn stats_key(&self) -> ExecuteReference {
        ExecuteReference::ModelParam(self.object_id, ModelParam::ReactionStats)
    }

    /// Add a reaction to this object
    pub fn add_reaction(
        &mut self,
        reaction_id: MessageId,
        reaction: &str,
        author: &VerifyingKey,
    ) -> DgoResult<bool> {
        self.stats.has_reactions = true;
        self.stats.total_reactions_count += 1;

        // Update reaction counts
        *self
            .stats
            .reaction_counts
            .entry(reaction.to_string())
            .or_insert(0) += 1;

        // Check if it's a like reaction (heart emoji)
        if reaction == "❤️" || reaction == "👍" {
            self.stats.has_likes = true;
            self.stats.total_likes_count += 1;

            if author == &self.user_id {
                self.stats.user_has_liked = true;
            }
        }

        if author == &self.user_id {
            self.stats.user_has_reacted = true;
            self.stats.user_reactions.push(reaction_id);
        }

        Ok(true)
    }

    /// Remove a reaction from this object (for redaction)
    pub fn remove_reaction(
        &mut self,
        reaction_id: MessageId,
        reaction: &str,
        author: &VerifyingKey,
    ) -> DgoResult<bool> {
        if self.stats.total_reactions_count > 0 {
            self.stats.total_reactions_count -= 1;
        }

        // Update reaction counts
        if let Some(count) = self.stats.reaction_counts.get_mut(reaction)
            && *count > 0
        {
            *count -= 1;
            if *count == 0 {
                self.stats.reaction_counts.remove(reaction);
            }
        }

        // Check if it was a like reaction
        if reaction == "❤️" || reaction == "👍" {
            if self.stats.total_likes_count > 0 {
                self.stats.total_likes_count -= 1;
            }
            self.stats.has_likes = self.stats.total_likes_count > 0;

            if author == &self.user_id {
                self.stats.user_has_liked = false;
            }
        }

        if author == &self.user_id {
            self.stats.user_reactions.retain(|id| id != &reaction_id);
            self.stats.user_has_reacted = !self.stats.user_reactions.is_empty();
        }

        self.stats.has_reactions = self.stats.total_reactions_count > 0;

        Ok(true)
    }
}
