//! # Digital Groups Organizer (DGO) - Event-Sourced Group Applications
//!
//! This module provides the core types and abstractions for building event-sourced
//! applications within encrypted groups. It's inspired by the Acter project but
//! redesigned for Zoe's encrypted group infrastructure with key improvements:
//!
//! ## Key Improvements over Acter
//!
//! 1. **Activity-First Design**: All changes are tracked as auditable activities
//! 2. **Permission-Aware State Transitions**: Permissions checked at application time  
//! 3. **Timeline Rewriting**: Support for out-of-order events and late arrivals
//! 4. **Group-Native**: Built for encrypted groups from the ground up
//!
//! ## Architecture
//!
//! ### Event-Sourced Models
//! All application objects (calendar events, tasks, text blocks, etc.) are represented
//! as event-sourced models that implement the [`DgoModel`] trait. State changes happen
//! through immutable events that are cryptographically signed and encrypted.
//!
//! ### Capability System  
//! Models declare capabilities (Commentable, Attachmentable, etc.) that enable
//! generic features to be composed flexibly across different object types.
//!
//! ### Manager Pattern
//! Generic features like comments, attachments, and reactions are handled by
//! managers that operate on any model with the appropriate capabilities.
//!
//! ## Core Types
//!
//! - [`models::core::DgoModel`]: Core trait for all application objects
//! - [`events::core::DgoActivityEvent`]: Forward-compatible enum for all activity events  
//! - [`capabilities::DgoCapability`]: Capabilities that models can declare
//! - [`models::core::ActivityMeta`]: Metadata for all activities (group_id, timestamp, actor, etc.)

pub mod capabilities;
pub mod events;
pub mod indexing;
pub mod managers;
pub mod models;

// Re-export key types for convenience
pub use events::core::{DgoActivityEvent, ObjectCore};
pub use models::core::{
    ActivityMeta, DgoModel, DgoModelError, DgoOperation, DgoResult, PermissionContext,
};
pub use models::permission_settings::DgoPermissionSettings;
pub use models::text_block::TextBlock;
