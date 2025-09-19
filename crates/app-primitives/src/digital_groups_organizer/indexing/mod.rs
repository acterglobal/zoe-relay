//! Indexing system for Digital Groups Organizer
//!
//! This module defines the indexing and referencing system for organizing
//! and querying DGO objects within encrypted groups. It's adapted from
//! Acter's system but uses GroupId (MessageId) instead of RoomId.
//!
//! ## Modules
//!
//! - [`core`] - Core index type definitions (SectionIndex, ObjectListIndex, etc.)
//! - [`keys`] - Index keys and execute references for storage and notifications

pub mod core;
pub mod keys;
