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
//! let server_keypair = generate_ml_dsa_44_keypair_for_tls();
//! let router = MyServiceRouter; // Your ServiceRouter implementation
//!
//! let server = RelayServer::new(addr, server_keypair, router)?;
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
use quinn::{Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};
use zoe_wire_protocol::{
    connection::server::create_server_endpoint, StreamPair, TransportPrivateKey,
};
// ML-DSA-44 imports (only available with tls-ml-dsa-44 feature)
#[cfg(feature = "tls-ml-dsa-44")]
use ml_dsa::VerifyingKey;

use crate::{Service, ServiceError, ServiceRouter};

/// Information about an authenticated connection
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    /// Set of ML-DSA public keys verified during challenge handshake (message authentication)
    pub verified_keys: std::collections::BTreeSet<Vec<u8>>,
    /// The remote address of the client
    pub remote_address: SocketAddr,
    /// Timestamp when the connection was established
    pub connected_at: std::time::SystemTime,
}

impl ConnectionInfo {
    /// Check if a specific ML-DSA public key has been verified for this connection
    pub fn has_verified_ml_dsa_key(&self, public_key: &[u8]) -> bool {
        self.verified_keys.contains(public_key)
    }

    /// Get the number of verified ML-DSA keys for this connection
    pub fn verified_key_count(&self) -> usize {
        self.verified_keys.len()
    }
}

/// Main relay server that accepts QUIC connections with transport authentication
pub struct RelayServer<R: ServiceRouter> {
    pub endpoint: Endpoint,
    server_keypair: TransportPrivateKey,
    router: Arc<R>,
}

impl<R: ServiceRouter + 'static> RelayServer<R> {
    /// Create a new relay server
    ///
    /// # Arguments
    /// * `addr` - The address to bind the server to
    /// * `server_keypair` - The server keypair for transport security (Ed25519 or ML-DSA-44)
    /// * `router` - The service router implementation
    pub fn new(addr: SocketAddr, server_keypair: TransportPrivateKey, router: R) -> Result<Self> {
        let endpoint = create_server_endpoint(addr, &server_keypair)?;

        Ok(Self {
            endpoint,
            server_keypair,
            router: Arc::new(router),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    /// Run the relay server, accepting and handling connections
    pub async fn run(self) -> Result<()> {
        info!(
            "🚀 Relay server starting on {}",
            self.endpoint.local_addr()?
        );
        let server_identity = self.server_keypair.public_key();
        info!(
            "🔑 Server identity: {} ({})",
            server_identity,
            server_identity.algorithm()
        );

        while let Some(conn) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);
            let server_keypair = self.server_keypair.clone();

            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        if let Err(e) =
                            Self::handle_connection(connection, router, server_keypair).await
                        {
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
    async fn handle_connection(
        connection: Connection,
        router: Arc<R>,
        server_keypair: TransportPrivateKey,
    ) -> Result<()> {
        let remote_addr = connection.remote_address();
        info!("🔗 New connection from {}", remote_addr);

        // Perform ML-DSA challenge-response handshake
        let (send, recv) = match connection.open_bi().await {
            Ok((send, recv)) => (send, recv),
            Err(e) => {
                error!("Failed to accept handshake stream: {}", e);
                connection.close(0u32.into(), b"Failed to accept handshake stream");
                return Ok(());
            }
        };

        tracing::trace!("🔗 Handshake streams accepted");

        // Get the server's keypair for the handshake (message layer authentication)
        let server_challenge_keypair = match &server_keypair {
            TransportPrivateKey::Ed25519 { signing_key } => {
                zoe_wire_protocol::KeyPair::Ed25519(Box::new(signing_key.clone()))
            }
            #[cfg(feature = "tls-ml-dsa-44")]
            TransportPrivateKey::MlDsa44 { keypair } => {
                // Use the same ML-DSA-44 key for both transport and message authentication
                zoe_wire_protocol::KeyPair::MlDsa44(Box::new(keypair.clone()))
            }
        };

        // Perform the actual challenge handshake
        let verified_keys = match crate::challenge::perform_multi_challenge_handshake(
            send,
            recv,
            &server_challenge_keypair, // Use the server's keypair for challenge
        )
        .await
        {
            Ok(keys) => {
                info!(
                    "✅ ML-DSA handshake successful, verified {} keys",
                    keys.len()
                );
                keys
            }
            Err(e) => {
                error!("❌ ML-DSA handshake failed: {}", e);
                connection.close(0u32.into(), b"ML-DSA handshake failed");
                return Ok(());
            }
        };

        // Create connection info with verified ML-DSA keys
        let connection_info = ConnectionInfo {
            verified_keys,
            remote_address: remote_addr,
            connected_at: std::time::SystemTime::now(),
        };

        info!(
            "🔐 Connection established with {} verified ML-DSA keys",
            connection_info.verified_key_count()
        );

        // Accept the bi-directional streams for services
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            let service_id = recv.read_u8().await?;
            info!(?remote_addr, "📋 Service ID: {}", service_id);
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

    // E-2-E-Test over quinn

    use anyhow::Result;

    use crate::Service;
    use crate::{ConnectionInfo, ServiceRouter};

    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Notify;
    /// Echo service that echoes back everything it receives
    struct EchoService {
        connection_info: ConnectionInfo,
        streams: StreamPair,
        connections_handled: Arc<Notify>,
    }

    impl EchoService {
        fn new(
            connection_info: ConnectionInfo,
            streams: StreamPair,
            connections_handled: Arc<Notify>,
        ) -> Self {
            Self {
                connection_info,
                streams,
                connections_handled,
            }
        }
    }

    #[derive(Clone)]
    struct EchoServiceRouter {
        connections_handled: Arc<Notify>,
    }

    impl EchoServiceRouter {
        fn new() -> Self {
            Self {
                connections_handled: Arc::new(Notify::new()),
            }
        }

        fn connection_notify(&self) -> Arc<Notify> {
            self.connections_handled.clone()
        }
    }
    #[async_trait::async_trait]
    impl ServiceRouter for EchoServiceRouter {
        type Error = TestError;
        type ServiceId = u8;
        type Service = EchoService;

        async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> {
            Ok(service_id)
        }

        async fn create_service(
            &self,
            service_id: &Self::ServiceId,
            connection_info: &ConnectionInfo,
            streams: StreamPair,
        ) -> Result<Self::Service, Self::Error> {
            if service_id != &1 {
                return Err(TestError::Generic("Unknown service".to_string()));
            }
            Ok(EchoService::new(
                connection_info.clone(),
                streams,
                self.connections_handled.clone(),
            ))
        }
    }

    #[async_trait::async_trait]
    impl Service for EchoService {
        type Error = TestError;
        async fn run(self) -> Result<(), Self::Error> {
            let Self {
                connection_info,
                mut streams,
                connections_handled,
            } = self;
            println!(
                "🔗 Echo service handling connection with {} verified keys",
                connection_info.verified_keys.len(),
            );

            // Echo everything back
            let mut buffer = [0u8; 1024];
            loop {
                match streams.recv.read(&mut buffer).await {
                    Ok(Some(n)) => {
                        if n == 0 {
                            // Connection closed
                            println!("📪 Client disconnected");
                            break;
                        }
                        let data = &buffer[..n];
                        println!(
                            "📨 Echoing {} bytes: {:?}",
                            n,
                            String::from_utf8_lossy(data)
                        );

                        // Echo the data back
                        streams
                            .send
                            .write_all(data)
                            .await
                            .map_err(|e| TestError::Generic(format!("Write error: {e}")))?;
                        streams
                            .send
                            .flush()
                            .await
                            .map_err(|e| TestError::Generic(format!("Flush error: {e}")))?;
                    }
                    Ok(None) => {
                        println!("📪 Stream ended");
                        break;
                    }
                    Err(e) => {
                        println!("❌ Read error: {e}");
                        break;
                    }
                }
            }

            // Notify that we handled a connection
            connections_handled.notify_one();
            Ok(())
        }
    }
}
