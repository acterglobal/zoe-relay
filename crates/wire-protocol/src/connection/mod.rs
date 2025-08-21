//! Connection utilities for the Zoe wire protocol
//!
//! This module provides TLS certificate generation and verification utilities
//! for different cryptographic algorithms used in transport security.

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

pub mod ed25519;

#[cfg(feature = "tls-ml-dsa-44")]
pub(super) mod ml_dsa;
