//! # Connection Management and Protocol Negotiation
//!
//! This module provides TLS-based connection management with embedded protocol version
//! negotiation for the Zoe wire protocol. It implements a sophisticated handshake
//! mechanism that combines transport security with application-layer protocol compatibility.
//!
//! ## Architecture Overview
//!
//! The connection system uses **TLS with ALPN (Application Layer Protocol Negotiation)**
//! to establish secure connections while simultaneously negotiating protocol versions
//! using **semantic versioning (semver)** compatibility rules.
//!
//! ### Key Components
//!
//! - **TLS Transport Security**: Ed25519 or ML-DSA-44 based certificates
//! - **ALPN Protocol Negotiation**: Client advertises supported versions
//! - **Certificate-Embedded Versioning**: Server embeds negotiated version in certificate
//! - **Client-Side Validation**: Post-connection protocol compatibility verification
//!
//! ## Protocol Negotiation Flow
//!
//! ### 1. Client Connection Initiation
//!
//! ```text
//! Client → Server: TLS ClientHello + ALPN Extensions
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ ALPN Extensions (Postcard-Serialized Protocol Versions):       │
//! │ - [0x01, 0x02, 0x03, ...] → ProtocolVersion { V1, 1.2.3 }      │
//! │ - [0x01, 0x01, 0x01, ...] → ProtocolVersion { V1, 1.1.0 }      │
//! │ - [0x00, 0x00, 0x09, ...] → ProtocolVersion { V0, 0.9.5 }      │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### 2. Server Version Negotiation
//!
//! The server examines client versions against its requirements:
//!
//! ```rust
//! // Server configuration example
//! let server_config = ServerProtocolConfig::new(vec![
//!     (ProtocolVariant::V1, VersionReq::parse(">=1.2.0").unwrap()),
//!     (ProtocolVariant::V0, VersionReq::parse(">=0.8.0").unwrap()),
//! ]);
//! ```
//!
//! **Negotiation Logic:**
//! 1. **Deserialize ALPN protocols**: Server uses `postcard::from_bytes()` on each ALPN entry
//! 2. **Parse client versions**: Extract `ProtocolVersion` structs from binary data
//! 3. **Find highest compatible**: Server finds the **highest client version** that satisfies server requirements
//! 4. **Embed result**: If match found, embeds negotiated version in TLS certificate extension
//! 5. **Signal failure**: If no match, returns certificate with **empty protocol extension**
//!
//! ### 3. TLS Certificate Response
//!
//! **Success Case (Compatible Version Found):**
//! ```text
//! Server → Client: TLS Certificate + Extensions
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ X.509 Certificate Extension (OID: 1.3.6.1.4.1.99999.1):       │
//! │ [0x01, 0x02, 0x03, ...] → postcard::to_stdvec(&protocol_v1_2_3) │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Failure Case (No Compatible Version):**
//! ```text
//! Server → Client: TLS Certificate + Extensions
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ X.509 Certificate Extension (OID: 1.3.6.1.4.1.99999.1):       │
//! │ [] (Empty byte array - No compatible protocol found)            │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### 4. Client-Side Validation
//!
//! After TLS handshake completion, the client validates protocol compatibility:
//!
//! ```rust
//! use zoe_wire_protocol::version::{validate_server_protocol_support, ClientProtocolConfig};
//!
//! let client_config = ClientProtocolConfig::default();
//! match validate_server_protocol_support(&connection, &client_config) {
//!     Ok(negotiated_version) => {
//!         println!("✅ Protocol negotiated: {}", negotiated_version);
//!         // Proceed with application protocol
//!     }
//!     Err(ProtocolVersionError::ProtocolNotSupportedByServer) => {
//!         println!("❌ Server doesn't support any client protocol versions");
//!         // Handle incompatibility (e.g., upgrade client, contact admin)
//!     }
//!     Err(e) => {
//!         println!("❌ Protocol validation failed: {}", e);
//!     }
//! }
//! ```
//!
//! ## Error Handling and Debugging
//!
//! ### Protocol Mismatch Detection
//!
//! When the server cannot find a compatible protocol version:
//!
//! 1. **TLS handshake succeeds** (for better debugging)
//! 2. **Certificate contains empty protocol extension**
//! 3. **Client detects empty extension** during validation
//! 4. **Specific error raised**: `ProtocolNotSupportedByServer`
//!
//! This approach provides clear error messages instead of cryptic TLS failures:
//!
//! ```text
//! ❌ OLD: "peer doesn't support any known protocol"
//! ✅ NEW: "Protocol not supported by server: server returned empty ALPN list indicating no compatible protocol"
//! ```
//!
//! ### Debugging Protocol Issues
//!
//! Enable debug logging to see the negotiation process:
//!
//! ```bash
//! RUST_LOG=zoe_wire_protocol::connection=debug cargo run
//! ```
//!
//! **Example Debug Output:**
//! ```text
//! DEBUG zoe_wire_protocol::connection::ed25519: 📋 Client ALPN protocols: 3
//! DEBUG zoe_wire_protocol::connection::ed25519: ✅ Negotiated protocol version: V1(1.2.3)
//! INFO  zoe_wire_protocol::connection::client: ✅ Server Ed25519 identity verified via certificate
//! ```
//!
//! ## Supported Cryptographic Algorithms
//!
//! ### Ed25519 (Default)
//! - **Fast signature verification**
//! - **Small certificate size**
//! - **Wide compatibility**
//!
//! ### ML-DSA-44 (Post-Quantum)
//! - **Quantum-resistant signatures**
//! - **NIST standardized**
//! - **Future-proof security**
//!
//! ## Configuration Examples
//!
//! ### Server Configuration
//!
//! ```rust
//! use zoe_wire_protocol::version::{ServerProtocolConfig, ProtocolVariant};
//! use semver::VersionReq;
//!
//! // Strict server - only accepts recent versions
//! let strict_server = ServerProtocolConfig::new(vec![
//!     (ProtocolVariant::V1, VersionReq::parse(">=1.5.0").unwrap()),
//! ]);
//!
//! // Permissive server - accepts older versions
//! let permissive_server = ServerProtocolConfig::new(vec![
//!     (ProtocolVariant::V1, VersionReq::parse(">=1.0.0").unwrap()),
//!     (ProtocolVariant::V0, VersionReq::parse(">=0.5.0").unwrap()),
//! ]);
//! ```
//!
//! ### Client Configuration
//!
//! ```rust
//! use zoe_wire_protocol::version::{ClientProtocolConfig, ProtocolVersion, ProtocolVariant};
//! use semver::Version;
//!
//! // Client supporting multiple versions
//! let client_config = ClientProtocolConfig::new(vec![
//!     ProtocolVersion::new(ProtocolVariant::V1, Version::new(1, 3, 0)),
//!     ProtocolVersion::new(ProtocolVariant::V1, Version::new(1, 2, 0)),
//!     ProtocolVersion::new(ProtocolVariant::V0, Version::new(0, 9, 0)),
//! ]);
//! ```
//!
//! ## Security Considerations
//!
//! - **Certificate validation** ensures server identity
//! - **Protocol negotiation** prevents downgrade attacks
//! - **Version requirements** enforce minimum security standards
//! - **Embedded versioning** prevents protocol confusion attacks

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;
