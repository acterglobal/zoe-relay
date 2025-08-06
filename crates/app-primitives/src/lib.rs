//! # Zoe App Primitives
//!
//! Common types and primitives used across Zoe applications and protocols.
//! This crate contains the building blocks that are shared between different
//! layers of the Zoe ecosystem.

pub mod file;
pub mod group;

pub use file::{CompressionConfig, ConvergentEncryptionInfo, FileRef, Image};
pub use group::*;
