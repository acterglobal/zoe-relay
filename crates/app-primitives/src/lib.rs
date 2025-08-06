//! # Zoe App Primitives
//!
//! Common types and primitives used across Zoe applications and protocols.
//! This crate contains the building blocks that are shared between different
//! layers of the Zoe ecosystem.

pub mod file_storage;
pub mod group;

pub use file_storage::*;
pub use group::*;
