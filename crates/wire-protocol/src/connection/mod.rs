//! Connection utilities for the Zoe wire protocol
//!
//! This module provides TLS certificate generation and verification utilities
//! for different cryptographic algorithms used in transport security.

#[cfg(feature = "client")]
pub mod client;
pub mod ed25519;

#[cfg(feature = "tls-ml-dsa-44")]
pub mod ml_dsa;

// Re-export Ed25519 functions (default)
pub use ed25519::*;

// Re-export ML-DSA-44 functions when feature is enabled
#[cfg(feature = "tls-ml-dsa-44")]
pub use ml_dsa::*;
