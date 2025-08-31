//! # Zoe App Primitives: Core Types for Distributed Encrypted Applications
//!
//! This crate provides the foundational types and abstractions for building distributed,
//! encrypted applications using the Zoe protocol. It defines the core data structures,
//! events, and state management primitives that enable secure group communication,
//! file sharing, and identity management.
//!
//! ## 🏗️ Architecture Overview
//!
//! The crate is organized around several key architectural concepts:
//!
//! ### 📊 Event-Sourced State Management
//! Applications maintain state through immutable events that are cryptographically
//! signed and encrypted. This provides:
//! - **Auditability**: Complete history of all state changes
//! - **Consistency**: Deterministic state across all participants
//! - **Reliability**: State can be reconstructed from events
//! - **Security**: All changes are authenticated and encrypted
//!
//! ### 🔐 Encryption-First Design
//! All communication and data storage assumes hostile network conditions:
//! - End-to-end encryption using ChaCha20-Poly1305
//! - Cryptographic identity via Ed25519 signing keys
//! - Shared group encryption keys for scalable group communication
//! - Forward secrecy through key rotation capabilities
//!
//! ### 🎭 Multi-Layer Identity System
//! Supports complex identity scenarios through a three-layer model:
//! 1. **Cryptographic Identity** (VerifyingKeys): Authentication and authorization
//! 2. **Display Identity** (Aliases): Human-readable names and personas
//! 3. **Role-Based Access** (Permissions): Fine-grained capability control
//!
//! ### 📁 Structured Data Primitives
//! Provides typed data structures for common application needs:
//! - **Group Management**: Distributed team coordination and communication
//! - **File Handling**: Secure file storage, sharing, and metadata management
//! - **Identity Management**: User profiles, aliases, and display information
//! - **Metadata Systems**: Extensible, structured metadata for all data types
//!
//! ## 📦 Module Organization
//!
//! ### [`group`] - Distributed Group Management
//! Comprehensive system for managing encrypted, distributed groups:
//! - [`group::GroupState`]: Unified runtime state management
//! - [`group::GroupMembership`]: Advanced identity and alias management
//! - [`group::events`]: Events for group creation, updates, and member management
//! - [`group::states`]: State types and error handling
//!
//! Key features:
//! - Event-sourced group state with audit trails
//! - Multi-identity support (aliases, display names)
//! - Role-based permissions and access control
//! - Structured metadata system
//! - Dynamic membership with encryption-based access control
//!
//! ### [`mod@file`] - Secure File Management
//! Types for handling files in distributed, encrypted environments:
//! - File references with metadata and compression information
//! - Image handling with dimensions and format metadata
//! - Convergent encryption for deduplication
//! - Content-addressable storage integration
//!
//! ### [`identity`] - Identity and Display Name Management
//! Core types for managing user identities and display information:
//! - [`identity::IdentityRef`]: References to cryptographic or alias identities
//! - [`identity::IdentityType`]: Main identities vs aliases
//! - [`identity::IdentityInfo`]: Display names and metadata
//!
//! ### [`metadata`] - Structured Metadata System
//! Extensible metadata system supporting both structured and generic data:
//! - [`metadata::Metadata`]: Enum of typed metadata variants
//! - Type-safe handling of descriptions, images, key-value pairs
//! - Future extensibility for new metadata types
//!
//! ### [`relay`] - Network Configuration
//! Types for configuring connections to relay servers:
//! - [`relay::RelayEndpoint`]: Server connection information
//! - Discovery and connection management primitives
//!
//! ## 🚀 Quick Start Examples
//!
//! ### Creating and Managing a Group
//! ```rust
//! use zoe_app_primitives::{GroupState, GroupSettings, Metadata, events::roles::GroupRole};
//! use zoe_wire_protocol::KeyPair;
//! use blake3::Hash;
//!
//! // Generate cryptographic identity
//! let creator_key = KeyPair::generate(&mut rand::rngs::OsRng);
//! let creator_public_key = creator_key.public_key();
//!
//! // Define structured metadata
//! let metadata = vec![
//!     Metadata::Description("Development team coordination".to_string()),
//!     Metadata::Generic { key: "department".to_string(), value: "engineering".to_string() },
//! ];
//!
//! // Create group state
//! let group_state = GroupState::new(
//!     Hash::from([1u8; 32]),
//!     "Dev Team".to_string(),
//!     GroupSettings::default(),
//!     metadata,
//!     creator_public_key.clone(),
//!     1640995200,
//! );
//!
//! // Creator automatically becomes Owner
//! assert_eq!(
//!     group_state.get_member_role(&creator_public_key),
//!     Some(&GroupRole::Owner)
//! );
//! ```
//!
//! ### Working with Multiple Identities
//! ```rust
//! use zoe_app_primitives::{GroupMembership, IdentityRef, IdentityType};
//! use zoe_wire_protocol::KeyPair;
//!
//! let membership = GroupMembership::new();
//! let user_key = KeyPair::generate(&mut rand::rngs::OsRng).public_key();
//!
//! // Check available identities (currently returns empty set for compatibility)
//! let identities = membership.get_available_identities(&user_key);
//! // Note: Currently returns empty set during ML-DSA transition
//! assert!(identities.is_empty());
//!
//! // Check authorization for different identity types
//! let main_identity = IdentityRef::Key(user_key.clone());
//! assert!(membership.is_authorized(&user_key, &main_identity));
//! ```
//!
//! ### Handling Structured Metadata
//! ```rust
//! use zoe_app_primitives::{Metadata, GroupState, GroupSettings};
//! use zoe_wire_protocol::KeyPair;
//! use blake3::Hash;
//!
//! let creator = KeyPair::generate(&mut rand::rngs::OsRng).public_key();
//! let metadata = vec![
//!     Metadata::Description("Project discussion space".to_string()),
//!     Metadata::Generic { key: "project_id".to_string(), value: "proj_123".to_string() },
//!     Metadata::Generic { key: "classification".to_string(), value: "internal".to_string() },
//! ];
//!
//! let group = GroupState::new(
//!     Hash::from([1u8; 32]), "Project Team".to_string(),
//!     GroupSettings::default(), metadata, creator, 1000
//! );
//!
//! // Extract specific metadata types
//! assert_eq!(group.description(), Some("Project discussion space".to_string()));
//!
//! // Get all key-value metadata
//! let generic_meta = group.generic_metadata();
//! assert_eq!(generic_meta.get("project_id"), Some(&"proj_123".to_string()));
//! ```
//!
//! ## 🔧 Integration with Other Crates
//!
//! This crate is designed to integrate seamlessly with other parts of the Zoe ecosystem:
//!
//! - **[`zoe-wire-protocol`]**: Network communication and encryption
//! - **[`zoe-state-machine`]**: Higher-level state management and event processing
//! - **[`zoe-message-store`]**: Persistent storage for events and messages
//! - **[`zoe-client`]**: Application-level client implementations
//!
//! The types defined here serve as the interface contracts between these layers,
//! ensuring compatibility and consistency across the entire system.
//!
//! ## 🛡️ Security Considerations
//!
//! When using these primitives, keep in mind:
//!
//! - **Key Management**: Protect signing keys and encryption keys appropriately
//! - **Metadata Privacy**: Be careful about what information you put in metadata
//! - **Event Ordering**: Ensure events are applied in the correct chronological order
//! - **Permission Checking**: Always verify permissions before applying state changes
//! - **Validation**: Validate all inputs, especially those from network sources
//!
//! ## 📚 Further Reading
//!
//! For detailed information about specific components:
//! - [`group`] module documentation for group management concepts
//! - [`mod@file`] module documentation for file handling patterns
//! - Individual type documentation for specific API details
//!
//! For integration examples and higher-level usage:
//! - See the `examples/` directory in the workspace root
//! - Check the integration tests in `test/end2end/`
//! - Review the state machine crate for event processing patterns

pub mod connection;
pub mod file;
pub mod group;
pub mod identity;
pub mod metadata;
pub mod qr;
pub mod relay;

pub use connection::*;
pub use file::*;
pub use group::*;
pub use identity::*;
pub use metadata::*;
pub use qr::*;
pub use relay::*;
