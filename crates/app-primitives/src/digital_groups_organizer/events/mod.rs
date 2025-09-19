//! Event types for the Digital Groups Organizer
//!
//! This module organizes all DGO event types into logical submodules:
//!
//! - [`core`] - Main event enum and shared data structures
//! - [`content`] - Text blocks and basic content events  
//! - [`calendar`] - Calendar events and RSVP management
//! - [`tasks`] - Task lists and task management events
//! - [`generic`] - Comments, reactions, and attachments
//! - [`admin`] - Administrative and redaction events

pub mod admin;
pub mod calendar;
pub mod content;
pub mod core;
pub mod generic;
pub mod tasks;
