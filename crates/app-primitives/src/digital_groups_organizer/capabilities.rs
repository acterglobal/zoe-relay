//! Capability system for Digital Groups Organizer
//!
//! This module defines the capabilities that DGO models can declare to enable
//! generic features like comments, attachments, reactions, etc.

use serde::{Deserialize, Serialize};

/// Capabilities that DGO models can declare to enable generic features
///
/// This system allows for flexible composition of features across different
/// object types. For example, both calendar events and tasks can be commentable,
/// but only calendar events might be RSVPable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DgoCapability {
    /// Objects that can receive comments
    Commentable,

    /// Objects that can have file attachments
    Attachmentable,

    /// Objects that can receive reactions (likes, emojis, etc.)
    Reactable,

    /// Objects that track read receipts
    ReadTracking,

    /// Objects that can receive RSVPs (calendar events, etc.)
    RSVPable,

    /// Objects that support explicit invitations
    Inviteable,

    /// Objects that can be pinned or featured
    Pinnable,

    /// Objects that support tagging/categorization
    Taggable,

    /// Objects that support due dates and reminders
    Schedulable,

    /// Objects that support assignment to users
    Assignable,

    /// Custom capability for application-specific features
    Custom(String),
}

impl DgoCapability {
    /// Check if this capability enables comments
    pub fn enables_comments(&self) -> bool {
        matches!(self, DgoCapability::Commentable)
    }

    /// Check if this capability enables attachments
    pub fn enables_attachments(&self) -> bool {
        matches!(self, DgoCapability::Attachmentable)
    }

    /// Check if this capability enables reactions
    pub fn enables_reactions(&self) -> bool {
        matches!(self, DgoCapability::Reactable)
    }

    /// Check if this capability enables read tracking
    pub fn enables_read_tracking(&self) -> bool {
        matches!(self, DgoCapability::ReadTracking)
    }

    /// Check if this capability enables RSVPs
    pub fn enables_rsvp(&self) -> bool {
        matches!(self, DgoCapability::RSVPable)
    }

    /// Check if this capability enables invitations
    pub fn enables_invitations(&self) -> bool {
        matches!(self, DgoCapability::Inviteable)
    }
}

/// A set of capabilities that a model declares
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    capabilities: Vec<DgoCapability>,
}

impl CapabilitySet {
    /// Create a new empty capability set
    pub fn new() -> Self {
        Self {
            capabilities: Vec::new(),
        }
    }

    /// Create a capability set with the given capabilities
    pub fn with_capabilities(capabilities: Vec<DgoCapability>) -> Self {
        Self { capabilities }
    }

    /// Add a capability to this set
    pub fn add(&mut self, capability: DgoCapability) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
    }

    /// Check if this set contains a specific capability
    pub fn contains(&self, capability: &DgoCapability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Get all capabilities in this set
    pub fn capabilities(&self) -> &[DgoCapability] {
        &self.capabilities
    }

    /// Check if this set enables comments
    pub fn enables_comments(&self) -> bool {
        self.contains(&DgoCapability::Commentable)
    }

    /// Check if this set enables attachments
    pub fn enables_attachments(&self) -> bool {
        self.contains(&DgoCapability::Attachmentable)
    }

    /// Check if this set enables reactions
    pub fn enables_reactions(&self) -> bool {
        self.contains(&DgoCapability::Reactable)
    }

    /// Check if this set enables read tracking
    pub fn enables_read_tracking(&self) -> bool {
        self.contains(&DgoCapability::ReadTracking)
    }

    /// Check if this set enables RSVPs
    pub fn enables_rsvp(&self) -> bool {
        self.contains(&DgoCapability::RSVPable)
    }

    /// Check if this set enables invitations
    pub fn enables_invitations(&self) -> bool {
        self.contains(&DgoCapability::Inviteable)
    }
}

impl From<Vec<DgoCapability>> for CapabilitySet {
    fn from(capabilities: Vec<DgoCapability>) -> Self {
        Self::with_capabilities(capabilities)
    }
}

impl From<&[DgoCapability]> for CapabilitySet {
    fn from(capabilities: &[DgoCapability]) -> Self {
        Self::with_capabilities(capabilities.to_vec())
    }
}
