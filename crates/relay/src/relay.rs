//! # Zoe Relay
//!
//! A clean, minimal QUIC relay server with ed25519 bi-directional authentication for service routing.
//!
//! ## Features
//!
//! - **QUIC Transport**: High-performance transport with TLS 1.3 and ed25519 identity verification
//! - **Service Routing**: Routes connections to different services based on a u8 service identifier
//! - **Bi-directional Streams**: Full duplex communication between client and server
//! - **Ed25519 Authentication**: Client identity verification via embedded public keys in certificates
//! - **Trait-based Design**: Clean abstraction for implementing service handlers
//!
//! ## Architecture
//!
//! The relay accepts QUIC connections, authenticates clients via ed25519 keys, reads the first byte
//! of the stream to determine the service type, and routes the connection to the appropriate service handler:
//!
//! ```text
//! Client → QUIC Connection → ed25519 Auth → Read Service ID (u8) → Route to Service
//!    ↓           ↓                ↓              ↓                    ↓
//! Certificate  TLS 1.3        Extract Key    First Byte        ServiceRouter::create_service
//! ```
//!
//! ## Usage
//!
//! ### Implementing a Service Router
//!
//! ```rust
//! use zoe_relay::{RelayServer, ServiceRouter};
//! use ed25519_dalek::SigningKey;
//! use std::net::SocketAddr;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let addr: SocketAddr = "127.0.0.1:4433".parse()?;
//! let server_key = SigningKey::generate(&mut rand::thread_rng());
//! let router = MyServiceRouter; // Your ServiceRouter implementation
//!
//! let server = RelayServer::new(addr, server_key, router)?;
//! println!("🚀 Relay server running on {}", addr);
//! server.run().await?;
//! # Ok(())
//! # }
//! # use async_trait::async_trait;
//! # struct MyServiceRouter;
//! # struct MyService;
//! # #[derive(Debug, thiserror::Error)]
//! # enum MyError {
//! #     #[error("Service error")]
//! #     ServiceError,
//! # }
//! # #[async_trait]
//! # impl ServiceRouter for MyServiceRouter {
//! #     type Error = MyError;
//! #     type ServiceId = u8;
//! #     type Service = MyService;
//! #     async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> { Ok(service_id) }
//! #     async fn create_service(&self, _: &Self::ServiceId, _: &zoe_relay::ConnectionInfo, _: zoe_relay::StreamPair) -> Result<Self::Service, Self::Error> { Ok(MyService) }
//! # }
//! # #[async_trait]
//! # impl zoe_relay::Service for MyService {
//! #     type Error = MyError;
//! #     async fn run(self) -> Result<(), Self::Error> { Ok(()) }
//! # }
//! ```
//!
//! For detailed service routing examples, see the [`router`](crate::router) module documentation.
//!
//! ## Transport Details
//!
//! ### QUIC with Ed25519 Authentication
//!
//! - **QUIC Protocol**: Multiplexed, encrypted transport with connection-level authentication
//! - **TLS 1.3**: Latest TLS with ed25519-derived certificates
//! - **Client Authentication**: Client identity verification via ed25519 keys embedded in certificates
//! - **Certificate Embedding**: Public keys embedded in X.509 certificate extensions
//!
//! ### Server Protocol Flow
//!
//! 1. **Connection Establishment**: Client connects via QUIC with ed25519 certificate
//! 2. **Mutual Authentication**: Server and client verify each other's ed25519 certificates
//! 3. **Connection Handling**: Server extracts client public key and connection metadata
//! 4. **Service Delegation**: Hands over streams and client info to the [`ServiceRouter`]
//!
//! ## Security Model
//!
//! ### Authentication Flow
//!
//! 1. **Certificate Generation**: Ed25519 keys embedded in deterministic self-signed certificates
//! 2. **QUIC Handshake**: TLS authentication with client certificate verification
//! 3. **Key Extraction**: Server extracts client's ed25519 public key from certificate
//! 4. **Service Routing**: Authenticated client streams are routed to appropriate services
//!
//! ### Identity and Trust
//!
//! - **Certificate-based**: Client identity is embedded in the certificate
//! - **Key-based identity**: Identity is the ed25519 public key itself
//! - **Connection-scoped**: Authentication valid for entire QUIC connection lifetime
//! - **Service-agnostic**: Authentication happens once, all services trust the identity

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};
use zoe_wire_protocol::{
    extract_ed25519_from_cert, generate_deterministic_cert_from_ed25519, CryptoError,
    ZoeClientCertVerifier,
};

use crate::{Service, ServiceError, ServiceRouter};

/// Information about an authenticated connection
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// The ed25519 public key of the connected client
    pub client_public_key: VerifyingKey,
    /// The remote address of the client
    pub remote_address: SocketAddr,
    /// Timestamp when the connection was established
    pub connected_at: std::time::SystemTime,
}

/// A pair of streams for bi-directional communication
#[derive(Debug)]
pub struct StreamPair {
    /// Stream for receiving data from the client
    pub recv: RecvStream,
    /// Stream for sending data to the client
    pub send: SendStream,
}

impl StreamPair {
    pub async fn send_ack(&mut self) -> Result<()> {
        self.send.write_u8(1).await?;
        Ok(())
    }
}

/// Main relay server that accepts QUIC connections with ed25519 authentication
pub struct RelayServer<R: ServiceRouter> {
    pub endpoint: Endpoint,
    server_key: SigningKey,
    router: Arc<R>,
}

impl<R: ServiceRouter + 'static> RelayServer<R> {
    /// Create a new relay server
    ///
    /// # Arguments
    /// * `addr` - The address to bind the server to
    /// * `server_key` - The ed25519 signing key for server identity
    /// * `router` - The service router implementation
    pub fn new(addr: SocketAddr, server_key: SigningKey, router: R) -> Result<Self> {
        let endpoint = create_server_endpoint(addr, &server_key)?;

        Ok(Self {
            endpoint,
            server_key,
            router: Arc::new(router),
        })
    }

    /// Run the relay server, accepting and handling connections
    pub async fn run(self) -> Result<()> {
        info!(
            "🚀 Relay server starting on {}",
            self.endpoint.local_addr()?
        );
        info!(
            "🔑 Server public key: {}",
            hex::encode(self.server_key.verifying_key().to_bytes())
        );

        while let Some(conn) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);

            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        if let Err(e) = Self::handle_connection(connection, router).await {
                            error!("Connection handling failed: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Connection failed: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    /// Handle a single QUIC connection
    async fn handle_connection(connection: Connection, router: Arc<R>) -> Result<()> {
        let remote_addr = connection.remote_address();
        info!("🔗 New connection from {}", remote_addr);

        // Extract client's ed25519 key from the connection certificate
        let client_public_key = match extract_client_ed25519_key(&connection) {
            Ok(key) => key,
            Err(error) => {
                error!(?error, "Failed to extract client public key");
                connection.close(0u32.into(), b"Missing ed25519 key in client certificate");
                return Ok(());
            }
        };

        info!(
            "🔑 Client public key: {}",
            hex::encode(client_public_key.to_bytes())
        );

        // Create connection info
        let connection_info = ConnectionInfo {
            client_public_key,
            remote_address: remote_addr,
            connected_at: std::time::SystemTime::now(),
        };

        // Accept the bi-directional streams
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let service_id = recv.read_u8().await?;
            info!(
                ?client_public_key,
                ?remote_addr,
                "📋 Service ID: {}",
                service_id
            );
            let service_id = match router.parse_service_id(service_id).await {
                Ok(service_id) => service_id,
                Err(error) => {
                    error!(?error, "Invalid service ID: {}", service_id);
                    send.write_u8(ServiceError::UnknownService.as_u8()).await?; // we immediately close this stream with unknown service id
                    continue;
                }
            };

            let streams = StreamPair { recv, send };
            let service = match router
                .create_service(&service_id, &connection_info, streams)
                .await
            {
                Ok(service) => service,
                Err(error) => {
                    error!(?error, "Failed to create service: {:?}", service_id);
                    // server error
                    // send.write_u8(ServiceError::ServiceCreationError as u8).await?; // we immediately close this stream with unknown service id
                    continue;
                }
            };
            tokio::spawn(async move {
                if let Err(e) = service.run().await {
                    error!("Service failed: {}", e);
                } else {
                    info!("Service ended");
                }
            });
        }

        Ok(())
    }
}

/// Extract the client's ed25519 public key from the QUIC connection
fn extract_client_ed25519_key(connection: &Connection) -> Result<VerifyingKey, CryptoError> {
    // Try to get peer certificate from the connection
    if let Some(identity) = connection.peer_identity() {
        if let Ok(cert_chain) = identity.downcast::<Vec<rustls::pki_types::CertificateDer>>() {
            if !cert_chain.is_empty() {
                // Extract ed25519 key from the first certificate if available
                return extract_ed25519_from_cert(&cert_chain[0]);
            }
        }
    }

    Err(CryptoError::Ed25519KeyNotFound)
}

/// Create a QUIC server endpoint with ed25519-derived TLS certificate
fn create_server_endpoint(addr: SocketAddr, server_key: &SigningKey) -> Result<Endpoint> {
    use quinn::ServerConfig;
    use std::sync::Arc;

    info!("🚀 Creating relay server endpoint on {}", addr);
    info!(
        "🔑 Server public key: {}",
        hex::encode(server_key.verifying_key().to_bytes())
    );

    // Generate TLS certificate from ed25519 key using wire protocol utility
    let (certs, private_key) = generate_deterministic_cert_from_ed25519(server_key, "localhost")
        .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

    // Create QUIC server config with client certificate verification required
    let rustls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(ZoeClientCertVerifier::new()))
        .with_single_cert(certs, private_key)?;

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?,
    ));

    let endpoint = Endpoint::server(server_config, addr)?;
    info!("✅ Server endpoint ready on {}", addr);

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Simple test router for unit tests
    #[derive(Clone)]
    struct TestRouter {
        handle_called: Arc<AtomicBool>,
        expected_service_id: u8,
    }

    impl TestRouter {
        fn new(expected_service_id: u8) -> Self {
            Self {
                handle_called: Arc::new(AtomicBool::new(false)),
                expected_service_id,
            }
        }

        #[allow(dead_code)]
        fn was_called(&self) -> bool {
            self.handle_called.load(Ordering::SeqCst)
        }
    }

    #[derive(Debug, thiserror::Error)]
    enum TestError {
        #[error("Test error: {0}")]
        #[allow(dead_code)]
        Generic(String),
    }

    #[async_trait::async_trait]
    impl Service for TestRouter {
        type Error = TestError;
        async fn run(self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl ServiceRouter for TestRouter {
        type Error = TestError;
        type ServiceId = u8;
        type Service = TestRouter;

        async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> {
            Ok(service_id)
        }

        async fn create_service(
            &self,
            service_id: &Self::ServiceId,
            _connection_info: &ConnectionInfo,
            _streams: StreamPair,
        ) -> Result<Self::Service, Self::Error> {
            assert_eq!(service_id, &self.expected_service_id);
            self.handle_called.store(true, Ordering::SeqCst);
            Ok(self.clone())
        }
    }

    #[test]
    fn test_connection_info_creation() {
        let key_bytes = [1u8; 32];
        let public_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        let addr = "127.0.0.1:8080".parse().unwrap();
        let now = std::time::SystemTime::now();

        let info = ConnectionInfo {
            client_public_key: public_key,
            remote_address: addr,
            connected_at: now,
        };

        assert_eq!(info.client_public_key.to_bytes(), key_bytes);
        assert_eq!(info.remote_address, addr);
        assert!(info.connected_at <= std::time::SystemTime::now());
    }

    #[tokio::test]
    async fn test_relay_server_creation() {
        let addr = "127.0.0.1:0".parse().unwrap();
        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let router = TestRouter::new(1);

        let server = RelayServer::new(addr, server_key, router);
        if let Err(e) = &server {
            println!("Server creation failed: {}", e);
        }
        assert!(server.is_ok());
    }

    // Note: Full ServiceRouter testing is done in integration tests
    // where we have real Quinn streams to work with
}
