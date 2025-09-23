//! # Zoe App Primitives: Core Types for Distributed Encrypted Applications
//!
//! This crate provides the foundational types and abstractions for building distributed,
//! encrypted applications using the Zoe protocol. It defines the core data structures,
//! events, and state management primitives that enable secure group communication,
//! file sharing, and identity management.

pub mod connection;
pub mod digital_groups_organizer;
pub mod extra;
pub mod file;
pub mod group;
pub mod identity;
pub mod invitation;
pub mod metadata;
pub mod protocol;
pub mod qr;
pub mod relay;
