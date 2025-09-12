//! # Protocol Version Negotiation
//!
//! This module provides semver-based protocol version negotiation with TLS certificate-embedded
//! version information. The Zoe protocol supports multiple variants for different use cases:
//!
//! - `zoer` - Relay protocol for server-mediated communication
//! - `zoep` - Peer-to-peer protocol for direct client communication  
//! - `zoem` - Mesh protocol for distributed network communication
//!
//! ## Protocol Negotiation Architecture
//!
//! The protocol negotiation system combines **TLS ALPN** with **certificate-embedded versioning**
//! to provide robust version compatibility checking with clear error reporting.
//!
//! ### Key Features
//!
//! - **Semantic Versioning**: Full semver compatibility rules (major.minor.patch)
//! - **Multiple Protocol Variants**: Support for different protocol types
//! - **Certificate-Embedded Negotiation**: Version information embedded in X.509 extensions
//! - **Clear Error Reporting**: Specific errors for different failure modes
//! - **Backward Compatibility**: Graceful handling of version mismatches
//!
//! ## ALPN Data Format
//!
//! Protocol versions are transmitted as **postcard-serialized `ProtocolVersion` structs**
//! in ALPN protocol fields, not as text strings. Each ALPN protocol entry contains
//! a binary-serialized `ProtocolVersion { variant, version }` structure.
//!
//! ## Version Compatibility Rules
//!
//! - **Major version**: Breaking changes, no backward compatibility
//! - **Minor version**: New features, backward compatible
//! - **Patch version**: Bug fixes, fully compatible (not included in ALPN)
//!
//! ## Protocol Negotiation Flow
//!
//! ### 1. Client Advertises Supported Versions
//!
//! ```rust
//! use zoe_wire_protocol::version::{ClientProtocolConfig, ProtocolVersion, ProtocolVariant};
//! use semver::Version;
//!
//! let client_config = ClientProtocolConfig::new(vec![
//!     ProtocolVersion::new(ProtocolVariant::V1, Version::new(1, 3, 0)),
//!     ProtocolVersion::new(ProtocolVariant::V1, Version::new(1, 2, 0)),
//!     ProtocolVersion::new(ProtocolVariant::V0, Version::new(0, 9, 0)),
//! ]);
//!
//! // Client sends these as postcard-serialized ALPN protocols during TLS handshake
//! let alpn_protocols: Vec<Vec<u8>> = client_config.alpn_protocols();
//! // Each Vec<u8> contains postcard::to_stdvec(&protocol_version).unwrap()
//! ```
//!
//! ### 2. Server Negotiates Compatible Version
//!
//! ```rust
//! use zoe_wire_protocol::version::{ServerProtocolConfig, ProtocolVariant};
//! use semver::VersionReq;
//!
//! let server_config = ServerProtocolConfig::new(vec![
//!     (ProtocolVariant::V1, VersionReq::parse(">=1.2.0").unwrap()),
//!     (ProtocolVariant::V0, VersionReq::parse(">=0.8.0").unwrap()),
//! ]);
//!
//! // Server finds highest compatible version
//! if let Some(negotiated) = server_config.negotiate_version(&client_config) {
//!     println!("✅ Negotiated: {}", negotiated);
//!     // Version embedded in TLS certificate
//! } else {
//!     println!("❌ No compatible version found");
//!     // Empty certificate extension sent
//! }
//! ```
//!
//! ### 3. Client Validates Post-Connection
//!
//! ```rust
//! use zoe_wire_protocol::version::{validate_server_protocol_support, ProtocolVersionError};
//!
//! match validate_server_protocol_support(&connection, &client_config) {
//!     Ok(version) => {
//!         println!("✅ Server supports: {}", version);
//!     }
//!     Err(ProtocolVersionError::ProtocolNotSupportedByServer) => {
//!         println!("❌ Server returned empty protocol extension");
//!         println!("   This means no client versions are supported by server");
//!     }
//!     Err(ProtocolVersionError::ProtocolMismatch) => {
//!         println!("❌ Server negotiated unsupported version");
//!     }
//!     Err(e) => {
//!         println!("❌ Validation error: {}", e);
//!     }
//! }
//! ```
//!
//! ## Error Handling
//!
//! The system provides specific error types for different failure scenarios:
//!
//! - [`ProtocolVersionError::ProtocolNotSupportedByServer`]: Server returned empty certificate extension
//! - [`ProtocolVersionError::ProtocolMismatch`]: Version negotiation disagreement
//! - [`ProtocolVersionError::NoAlpnData`]: Missing certificate or extension data
//! - [`ProtocolVersionError::InvalidAlpnData`]: Malformed protocol data
//!
//! ## Certificate Extension Format
//!
//! Protocol versions are embedded in X.509 certificate extensions:
//!
//! - **OID**: `1.3.6.1.4.1.99999.1` (Custom enterprise OID)
//! - **Format**: Postcard-serialized [`ProtocolVersion`] struct
//! - **Serialization**: `postcard::to_stdvec(&protocol_version)` → `Vec<u8>`
//! - **Deserialization**: `postcard::from_bytes::<ProtocolVersion>(&bytes)` → `ProtocolVersion`
//! - **Empty Extension**: `[]` (empty byte array) indicates no compatible protocol found
//!
//! ### Binary Format Details
//!
//! The postcard format is a compact, deterministic binary serialization:
//! - **Space-efficient**: Smaller than JSON or other text formats
//! - **Type-safe**: Preserves Rust type information
//! - **Deterministic**: Same struct always produces same bytes
//! - **Schema evolution**: Handles version compatibility gracefully
//!
//! ## Integration Examples
//!
//! ### Automatic Client Integration
//!
//! ```rust
//! use zoe_client::RelayClient;
//!
//! // RelayClient automatically performs protocol validation
//! match RelayClient::connect(server_addr, server_public_key).await {
//!     Ok(client) => {
//!         println!("✅ Connected with compatible protocol");
//!     }
//!     Err(ClientError::ProtocolError(msg)) => {
//!         println!("❌ Protocol incompatibility: {}", msg);
//!         // Handle version mismatch (upgrade client, contact admin, etc.)
//!     }
//!     Err(e) => {
//!         println!("❌ Connection error: {}", e);
//!     }
//! }
//! ```
//!
//! ### Manual Server Setup
//!
//! ```rust
//! use zoe_wire_protocol::connection::server::create_server_endpoint_with_protocols;
//! use zoe_wire_protocol::version::ServerProtocolConfig;
//!
//! let server_config = ServerProtocolConfig::new(vec![
//!     (ProtocolVariant::V1, VersionReq::parse(">=1.0.0").unwrap()),
//! ]);
//!
//! let server_endpoint = create_server_endpoint_with_protocols(
//!     "127.0.0.1:0",
//!     &server_keypair,
//!     server_config,
//! ).await?;
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

// Re-export semver types for use by other crates
pub use semver::{Version, VersionReq};

static DEFAULT_PROTOCOL_VERSION: &str = "0.1.0-dev.0";
static DEFAULT_PROTOCOL_VERSION_REQ: &str = ">=0.1.0-dev.0";

/// Protocol variants supported by the Zoe wire protocol
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum ProtocolVariant {
    /// Relay protocol for server-mediated communication
    Relay,
    /// Peer-to-peer protocol for direct client communication
    PeerToPeer,
    /// Mesh protocol for distributed network communication  
    Mesh,
    /// Not yet known variant
    Unknown(String),
}

impl From<String> for ProtocolVariant {
    fn from(value: String) -> Self {
        match value.as_str() {
            "zoer" => ProtocolVariant::Relay,
            "zoep" => ProtocolVariant::PeerToPeer,
            "zoem" => ProtocolVariant::Mesh,
            _ => ProtocolVariant::Unknown(value),
        }
    }
}

impl From<ProtocolVariant> for String {
    fn from(val: ProtocolVariant) -> Self {
        match val {
            ProtocolVariant::Relay => "zoer".to_string(),
            ProtocolVariant::PeerToPeer => "zoep".to_string(),
            ProtocolVariant::Mesh => "zoem".to_string(),
            ProtocolVariant::Unknown(value) => value,
        }
    }
}

impl ProtocolVariant {
    /// Get all supported protocol variants
    pub fn all_variants() -> Vec<Self> {
        vec![
            ProtocolVariant::Relay,
            ProtocolVariant::PeerToPeer,
            ProtocolVariant::Mesh,
        ]
    }
}

impl fmt::Display for ProtocolVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name: String = self.clone().into();
        write!(f, "{name}")
    }
}

/// Protocol version information combining variant and semantic version
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Protocol variant (zoer, zoep, zoem)
    pub variant: ProtocolVariant,
    /// Semantic version
    pub version: Version,
}

impl ProtocolVersion {
    /// Create a new protocol version
    pub fn new(variant: ProtocolVariant, version: Version) -> Self {
        Self { variant, version }
    }

    /// Create protocol version from major.minor version numbers
    pub fn new_simple(variant: ProtocolVariant, major: u64, minor: u64) -> Self {
        Self {
            variant,
            version: Version::new(major, minor, 0),
        }
    }

    /// Check if this version is compatible with a requirement
    pub fn is_compatible_with(&self, req: &VersionReq) -> bool {
        req.matches(&self.version)
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.variant, self.version)
    }
}

/// Client protocol configuration - defines what versions the client supports
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProtocolConfig(pub(crate) Vec<ProtocolVersion>);

impl ClientProtocolConfig {
    /// Create a new empty client protocol configuration
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn from_alpn_data<'a>(
        alpn_data: impl Iterator<Item = &'a [u8]>,
    ) -> Result<Self, postcard::Error> {
        let versions: Vec<ProtocolVersion> = alpn_data
            .filter_map(|v| postcard::from_bytes(v).ok())
            .collect();
        Ok(ClientProtocolConfig(versions))
    }
}

/// Server protocol configuration - defines what requirements the server has
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerProtocolConfig {
    /// Semver requirements for each variant that the server accepts
    pub variant_requirements: std::collections::BTreeMap<ProtocolVariant, VersionReq>,
}

impl ClientProtocolConfig {
    /// Add a current version for a protocol variant
    pub fn add_current_version(mut self, variant: ProtocolVariant, version: Version) -> Self {
        let protocol_version = ProtocolVersion::new(variant.clone(), version);
        self.0.push(protocol_version);
        self
    }

    /// Get ALPN protocol identifiers for TLS negotiation
    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        self.0
            .iter()
            .filter_map(|v| postcard::to_stdvec(v).ok())
            .collect()
    }

    /// Get all supported versions as a vector
    pub fn supported_versions(&self) -> Vec<ProtocolVersion> {
        self.0.clone()
    }

    /// Validate that client and server would negotiate to the same version
    /// This should be called by the client after receiving server's ALPN requirements
    pub fn validate_negotiation(
        &self,
        server_requirements: &ServerProtocolConfig,
    ) -> Option<ProtocolVersion> {
        // Use the same negotiate_version logic that the server uses
        let client_versions = self.supported_versions();
        server_requirements.negotiate_version(&client_versions)
    }

    /// Create default client configuration for relay protocol
    pub fn relay_default() -> Self {
        Self::new().add_current_version(
            ProtocolVariant::Relay,
            Version::parse(DEFAULT_PROTOCOL_VERSION).expect("Protocol version works"),
        )
    }
}

impl ServerProtocolConfig {
    /// Create a new server protocol configuration
    pub fn new() -> Self {
        Self {
            variant_requirements: std::collections::BTreeMap::new(),
        }
    }

    /// Add a semver requirement for a protocol variant
    pub fn add_variant_requirement(
        mut self,
        variant: ProtocolVariant,
        requirement: VersionReq,
    ) -> Self {
        self.variant_requirements.insert(variant, requirement);
        self
    }

    /// Get ALPN protocol identifiers for TLS negotiation
    /// Advertises the server's version requirements as serialized data
    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        // Serialize the entire ServerProtocolConfig so clients know what we accept
        if let Ok(serialized) = postcard::to_stdvec(self) {
            vec![serialized]
        } else {
            vec![]
        }
    }

    /// Check if client versions are acceptable and return the best match
    pub fn negotiate_version(
        &self,
        client_versions: &[ProtocolVersion],
    ) -> Option<ProtocolVersion> {
        // Check each client version against our requirements
        for client in client_versions {
            if let Some(requirement) = self.variant_requirements.get(&client.variant) {
                if requirement.matches(&client.version) {
                    return Some(client.clone());
                }
            }
        }
        None
    }

    /// Deserialize ServerProtocolConfig from ALPN data
    pub fn from_alpn_data(alpn_data: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(alpn_data)
    }

    /// Create default server configuration for relay protocol
    pub fn relay_default() -> Self {
        Self::new().add_variant_requirement(
            ProtocolVariant::Relay,
            VersionReq::parse(DEFAULT_PROTOCOL_VERSION_REQ).expect("Protocol version works"),
        )
    }
}

impl Default for ClientProtocolConfig {
    fn default() -> Self {
        Self::relay_default()
    }
}

impl Default for ServerProtocolConfig {
    fn default() -> Self {
        Self::relay_default()
    }
}

/// Validate that ALPN protocol negotiation succeeded
/// This should be called by the client after connecting to ensure a protocol was negotiated
pub fn validate_alpn_negotiation(
    connection: &quinn::Connection,
) -> Result<(), ProtocolVersionError> {
    // Check if ALPN negotiation resulted in a protocol
    match connection.handshake_data() {
        Some(handshake_data) => {
            if let Some(rustls_data) =
                handshake_data.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
            {
                if rustls_data.protocol.is_some() {
                    // ALPN negotiation succeeded - a protocol was selected
                    Ok(())
                } else {
                    // No protocol was negotiated
                    Err(ProtocolVersionError::ProtocolMismatch)
                }
            } else {
                // Couldn't access handshake data
                Err(ProtocolVersionError::NoAlpnData)
            }
        }
        None => {
            // No handshake data available
            Err(ProtocolVersionError::NoAlpnData)
        }
    }
}

/// Get the negotiated protocol from ALPN
/// Returns the raw ALPN protocol bytes that were negotiated
pub fn get_negotiated_protocol(connection: &quinn::Connection) -> Option<Vec<u8>> {
    if let Some(handshake_data) = connection.handshake_data() {
        if let Some(rustls_data) =
            handshake_data.downcast_ref::<quinn::crypto::rustls::HandshakeData>()
        {
            rustls_data.protocol.clone()
        } else {
            None
        }
    } else {
        None
    }
}

/// Validate protocol compatibility after TLS connection establishment
///
/// This function performs post-connection validation to ensure the server supports
/// the client's protocol versions. It examines the server's TLS certificate for
/// embedded protocol version information.
///
/// ## How It Works
///
/// 1. **Extracts server certificate** from the established TLS connection
/// 2. **Reads protocol extension** (OID: 1.3.6.1.4.1.99999.1) from certificate
/// 3. **Deserializes protocol version** from the extension data
/// 4. **Validates compatibility** against client's supported versions
///
/// ## Return Values
///
/// - `Ok(ProtocolVersion)`: Server supports a compatible protocol version
/// - `Err(ProtocolNotSupportedByServer)`: Server returned **empty extension** (no compatible versions)
/// - `Err(ProtocolMismatch)`: Server negotiated a version client doesn't support
/// - `Err(NoAlpnData)`: Missing certificate or extension data
/// - `Err(InvalidAlpnData)`: Malformed protocol data in certificate
///
/// ## Empty Extension Behavior
///
/// When the server cannot find any compatible protocol versions during negotiation,
/// it returns a certificate with an **empty protocol extension**. This is detected
/// by the client and results in `ProtocolNotSupportedByServer` error.
///
/// This approach provides much better debugging than failing the TLS handshake:
/// - TLS connection succeeds (can inspect certificates, logs, etc.)
/// - Clear error message indicates protocol incompatibility
/// - Distinguishes between TLS issues and protocol version issues
///
/// ## Example Usage
///
/// ```rust
/// use zoe_wire_protocol::version::{validate_server_protocol_support, ClientProtocolConfig};
///
/// let client_config = ClientProtocolConfig::default();
/// match validate_server_protocol_support(&connection, &client_config) {
///     Ok(negotiated_version) => {
///         println!("✅ Protocol negotiated: {}", negotiated_version);
///         // Proceed with application protocol
///     }
///     Err(ProtocolVersionError::ProtocolNotSupportedByServer) => {
///         eprintln!("❌ Server doesn't support any of our protocol versions");
///         eprintln!("   Client versions: {:?}", client_config.supported_versions());
///         eprintln!("   Consider upgrading client or contacting server admin");
///     }
///     Err(e) => {
///         eprintln!("❌ Protocol validation failed: {}", e);
///     }
/// }
/// ```
pub fn validate_server_protocol_support(
    connection: &quinn::Connection,
    client_config: &ClientProtocolConfig,
) -> Result<ProtocolVersion, ProtocolVersionError> {
    // Get the peer certificates
    let Some(peer_certs) = connection.peer_identity() else {
        return Err(ProtocolVersionError::NoAlpnData);
    };

    let Some(rustls_certs) = peer_certs.downcast_ref::<Vec<rustls::pki_types::CertificateDer>>()
    else {
        return Err(ProtocolVersionError::NoAlpnData);
    };

    let Some(cert) = rustls_certs.first() else {
        return Err(ProtocolVersionError::NoAlpnData);
    };

    // Extract the protocol version from the certificate
    // This will contain either the negotiated version or the "no-protocol" marker
    let cert_protocol_version = extract_protocol_version_from_cert(cert)?;
    // Check if thi
    // Verify this version is one the client actually supports
    let client_versions = client_config.supported_versions();
    if !client_versions.contains(&cert_protocol_version) {
        return Err(ProtocolVersionError::ProtocolMismatch);
    }

    Ok(cert_protocol_version)
}

/// Extract protocol version from certificate extension
/// This reads the custom extension that contains the negotiated protocol version
fn extract_protocol_version_from_cert(
    cert_der: &rustls::pki_types::CertificateDer,
) -> Result<ProtocolVersion, ProtocolVersionError> {
    use x509_parser::prelude::*;

    // Parse the certificate
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|_| ProtocolVersionError::InvalidAlpnData)?;

    // Look for our custom extension (OID: 1.3.6.1.4.1.99999.1)
    let extensions = cert.extensions();
    let mut found_extension = false;
    for ext in extensions {
        if ext.oid.to_string() == "1.3.6.1.4.1.99999.1" {
            found_extension = true;
            // Found our protocol version extension
            if let Ok(protocol_version) = postcard::from_bytes::<ProtocolVersion>(ext.value) {
                return Ok(protocol_version);
            }
        }
    }
    if found_extension {
        // found but not any valid format - empty or invalid
        Err(ProtocolVersionError::ProtocolNotSupportedByServer)
    } else {
        Err(ProtocolVersionError::InvalidAlpnData)
    }
}

/// Validate that client and server negotiated to a compatible version
/// This performs a full validation that both sides would agree on the same version
pub fn validate_version_compatibility(
    connection: &quinn::Connection,
    client_config: &ClientProtocolConfig,
) -> Result<ProtocolVersion, ProtocolVersionError> {
    // First check that ALPN negotiation succeeded
    validate_alpn_negotiation(connection)?;

    // Get the negotiated protocol (should be one of the client's versions)
    if let Some(negotiated_protocol) = get_negotiated_protocol(connection) {
        // Try to deserialize as a ProtocolVersion (client's version)
        if let Ok(negotiated_version) =
            postcard::from_bytes::<ProtocolVersion>(&negotiated_protocol)
        {
            // Verify this version is one the client actually supports
            let client_versions = client_config.supported_versions();
            if client_versions.contains(&negotiated_version) {
                Ok(negotiated_version)
            } else {
                Err(ProtocolVersionError::ProtocolMismatch)
            }
        } else {
            Err(ProtocolVersionError::InvalidAlpnData)
        }
    } else {
        Err(ProtocolVersionError::NoAlpnData)
    }
}

/// Errors that can occur during protocol version negotiation
#[derive(Debug, thiserror::Error)]
pub enum ProtocolVersionError {
    #[error("No compatible protocol version found")]
    NoCompatibleVersion,
    #[error("Protocol version {0} below minimum requirement {1}")]
    VersionTooOld(Version, Version),
    #[error("No ALPN data found in connection")]
    NoAlpnData,
    #[error("Invalid ALPN data format")]
    InvalidAlpnData,
    #[error("Protocol mismatch: client and server could not agree on a protocol version")]
    ProtocolMismatch,
    #[error("Protocol not supported by server: server returned empty ALPN list indicating no compatible protocol")]
    ProtocolNotSupportedByServer,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_protocol_config_alpn_protocols() {
        let client_config = ClientProtocolConfig::new()
            .add_current_version(ProtocolVariant::Relay, Version::new(1, 0, 0))
            .add_current_version(ProtocolVariant::PeerToPeer, Version::new(1, 1, 0));

        let alpn_protocols = client_config.alpn_protocols();
        assert_eq!(alpn_protocols.len(), 2);

        // Verify we can deserialize back to ProtocolVersion
        // Note: BTreeMap ordering means Relay comes before PeerToPeer
        let first_version: ProtocolVersion = postcard::from_bytes(&alpn_protocols[0]).unwrap();
        let second_version: ProtocolVersion = postcard::from_bytes(&alpn_protocols[1]).unwrap();

        // Check that we have both variants (order may vary due to BTreeMap)
        let variants = [&first_version.variant, &second_version.variant];
        assert!(variants.contains(&&ProtocolVariant::Relay));
        assert!(variants.contains(&&ProtocolVariant::PeerToPeer));
    }

    #[test]
    fn test_server_protocol_negotiation() {
        let server_config = ServerProtocolConfig::new().add_variant_requirement(
            ProtocolVariant::Relay,
            VersionReq::parse(">=1.0.0").unwrap(),
        );

        let client_versions = vec![ProtocolVersion::new_simple(ProtocolVariant::Relay, 1, 2)];

        let negotiated = server_config.negotiate_version(&client_versions).unwrap();
        assert_eq!(negotiated.variant, ProtocolVariant::Relay);
        // Should use the client's version (1.2) since it meets server requirements
        assert_eq!(negotiated.version.major, 1);
        assert_eq!(negotiated.version.minor, 2);
    }

    #[test]
    fn test_server_protocol_minimum_version_rejection() {
        let server_config = ServerProtocolConfig::new().add_variant_requirement(
            ProtocolVariant::Relay,
            VersionReq::parse(">=1.5.0").unwrap(),
        );

        // Client version too old
        let client_versions = vec![ProtocolVersion::new_simple(ProtocolVariant::Relay, 1, 0)];
        assert!(server_config.negotiate_version(&client_versions).is_none());

        // Client version meets minimum
        let client_versions = vec![ProtocolVersion::new_simple(ProtocolVariant::Relay, 1, 6)];
        assert!(server_config.negotiate_version(&client_versions).is_some());
    }

    #[test]
    fn test_default_configurations() {
        let client_config = ClientProtocolConfig::relay_default();
        let supported_versions = client_config.supported_versions();
        assert_eq!(supported_versions.len(), 1);
        assert_eq!(supported_versions[0].variant, ProtocolVariant::Relay);

        let server_config = ServerProtocolConfig::relay_default();
        assert_eq!(server_config.variant_requirements.len(), 1);
        assert!(server_config
            .variant_requirements
            .contains_key(&ProtocolVariant::Relay));
    }

    #[test]
    fn test_protocol_variant_serialization() {
        // Test serialization roundtrip
        let variants = vec![
            ProtocolVariant::Relay,
            ProtocolVariant::PeerToPeer,
            ProtocolVariant::Mesh,
            ProtocolVariant::Unknown("custom-protocol".to_string()),
        ];

        for variant in variants {
            let serialized = postcard::to_stdvec(&variant).unwrap();
            let deserialized: ProtocolVariant = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(variant, deserialized);
        }
    }

    #[test]
    fn test_protocol_version_serialization() {
        let version = ProtocolVersion::new_simple(ProtocolVariant::Relay, 1, 2);
        let serialized = postcard::to_stdvec(&version).unwrap();
        let deserialized: ProtocolVersion = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(version, deserialized);
    }

    #[test]
    fn test_server_selects_from_client_versions() {
        // Server accepts relay 1.0+
        let server_config = ServerProtocolConfig::new().add_variant_requirement(
            ProtocolVariant::Relay,
            VersionReq::parse(">=1.0.0").unwrap(),
        );

        // Client offers relay 1.0 and p2p 2.0
        let client_versions = vec![
            ProtocolVersion::new_simple(ProtocolVariant::Relay, 1, 0),
            ProtocolVersion::new_simple(ProtocolVariant::PeerToPeer, 2, 0),
        ];

        // Server should select relay 1.0 (client's version, meets minimum)
        let negotiated = server_config.negotiate_version(&client_versions).unwrap();
        assert_eq!(negotiated.variant, ProtocolVariant::Relay);
        assert_eq!(negotiated.version.major, 1);
        assert_eq!(negotiated.version.minor, 0);
    }

    #[test]
    fn test_client_version_too_old() {
        // Server requires relay 1.5+
        let server_config = ServerProtocolConfig::new().add_variant_requirement(
            ProtocolVariant::Relay,
            VersionReq::parse(">=1.5.0").unwrap(),
        );

        // Client only offers relay 1.0
        let client_versions = vec![ProtocolVersion::new_simple(ProtocolVariant::Relay, 1, 0)];

        // Should fail - client version too old
        assert!(server_config.negotiate_version(&client_versions).is_none());
    }

    #[test]
    fn test_alpn_serialization_roundtrip() {
        // Test that we can serialize and deserialize protocol configs for ALPN
        let server_config = ServerProtocolConfig::new()
            .add_variant_requirement(
                ProtocolVariant::Relay,
                VersionReq::parse(">=1.0.0").unwrap(),
            )
            .add_variant_requirement(
                ProtocolVariant::PeerToPeer,
                VersionReq::parse(">=2.0.0").unwrap(),
            );

        let client_config = ClientProtocolConfig::new()
            .add_current_version(ProtocolVariant::Relay, Version::new(1, 2, 0))
            .add_current_version(ProtocolVariant::PeerToPeer, Version::new(2, 1, 0));

        // Test server ALPN serialization
        let server_alpn = server_config.alpn_protocols();
        assert_eq!(server_alpn.len(), 1); // Server sends one serialized config

        let deserialized_server = ServerProtocolConfig::from_alpn_data(&server_alpn[0]).unwrap();
        assert_eq!(deserialized_server.variant_requirements.len(), 2);

        // Test client ALPN serialization
        let client_alpn = client_config.alpn_protocols();
        assert_eq!(client_alpn.len(), 2); // Client sends individual versions

        // Verify client versions can be deserialized
        for alpn_data in &client_alpn {
            let version: ProtocolVersion = postcard::from_bytes(alpn_data).unwrap();
            assert!(matches!(
                version.variant,
                ProtocolVariant::Relay | ProtocolVariant::PeerToPeer
            ));
        }
    }

    #[test]
    fn test_client_validation_logic() {
        let server_config = ServerProtocolConfig::new().add_variant_requirement(
            ProtocolVariant::Relay,
            VersionReq::parse(">=1.0.0").unwrap(),
        );

        let client_config = ClientProtocolConfig::new()
            .add_current_version(ProtocolVariant::Relay, Version::new(1, 2, 0));

        // Test that client can validate against server requirements
        let negotiated = client_config.validate_negotiation(&server_config).unwrap();
        assert_eq!(negotiated.variant, ProtocolVariant::Relay);
        assert_eq!(negotiated.version.major, 1);
        assert_eq!(negotiated.version.minor, 2);

        // Test incompatible case
        let incompatible_client = ClientProtocolConfig::new()
            .add_current_version(ProtocolVariant::PeerToPeer, Version::new(1, 0, 0));

        assert!(incompatible_client
            .validate_negotiation(&server_config)
            .is_none());
    }
}
