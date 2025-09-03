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
//! use zoe_wire_protocol::KeyPair;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let addr: SocketAddr = "127.0.0.1:4433".parse()?;
//! let server_keypair = KeyPair::generate_ml_dsa44(&mut rand::rngs::OsRng);
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
//! #     async fn create_service(&self, _: &Self::ServiceId, _: &zoe_relay::ConnectionInfo, _: zoe_wire_protocol::StreamPair) -> Result<Self::Service, Self::Error> { Ok(MyService) }
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
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf};
use zoe_blob_store::{BlobServiceImpl, BlobStoreError};
use zoe_message_store::RedisMessageStorage;
use zoe_wire_protocol::{ConnectionInfo, CryptoError, VerifyingKey};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};
use zoe_wire_protocol::{connection::server::create_server_endpoint, KeyPair, StreamPair};

use crate::{RelayServiceRouter, Service, ServiceError, ServiceRouter};

#[derive(Debug, thiserror::Error)]
pub enum RelayServerBuilderError {
    #[error("Blob directory not set")]
    BlobDirNotSet,

    #[error("Blob service error: {0}")]
    BlobServiceError(BlobStoreError),

    #[error("Redis URL not set")]
    RedisUrlNotSet,

    #[error("Redis message storage error: {0}")]
    RedisMessageStorageError(zoe_message_store::MessageStoreError),

    #[error("Relay server error: {0}")]
    RelayServerError(RelayServerError),
}

#[derive(Default)]
pub struct RelayServerBuilder {
    server_keypair: Option<KeyPair>,
    address: Option<SocketAddr>,
    redis_url: Option<String>,
    blob_dir: Option<PathBuf>,
}

impl RelayServerBuilder {
    pub fn server_keypair(mut self, server_keypair: KeyPair) -> Self {
        self.server_keypair = Some(server_keypair);
        self
    }

    pub fn address(mut self, address: SocketAddr) -> Self {
        self.address = Some(address);
        self
    }

    pub fn redis_url(mut self, redis_url: String) -> Self {
        self.redis_url = Some(redis_url);
        self
    }

    pub fn blob_dir(mut self, blob_dir: PathBuf) -> Self {
        self.blob_dir = Some(blob_dir);
        self
    }

    async fn create_default_router(&self) -> Result<RelayServiceRouter, RelayServerBuilderError> {
        let Some(blob_dir) = &self.blob_dir else {
            return Err(RelayServerBuilderError::BlobDirNotSet);
        };
        let Some(redis_url) = &self.redis_url else {
            return Err(RelayServerBuilderError::RedisUrlNotSet);
        };

        let blob_service = BlobServiceImpl::new(blob_dir.clone())
            .await
            .map_err(RelayServerBuilderError::BlobServiceError)?;
        let message_service = RedisMessageStorage::new(redis_url.clone())
            .await
            .map_err(RelayServerBuilderError::RedisMessageStorageError)?;
        Ok(RelayServiceRouter::new(blob_service, message_service))
    }

    pub async fn build(self) -> Result<RelayServer<RelayServiceRouter>, RelayServerBuilderError> {
        let router = self.create_default_router().await?;
        self.build_with_router(router).await
    }

    pub async fn build_with_router<R: ServiceRouter + Send + Sync + 'static>(
        self,
        router: R,
    ) -> Result<RelayServer<R>, RelayServerBuilderError> {
        let address = self.address.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0)));
        let server_keypair = self
            .server_keypair
            .unwrap_or(KeyPair::generate_ed25519(&mut rand::rngs::OsRng));

        RelayServer::new(address, server_keypair, router)
            .map_err(RelayServerBuilderError::RelayServerError)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayServerError {
    #[error("Crypto error: {0}")]
    CryptoError(CryptoError),
}

/// Main relay server that accepts QUIC connections with transport authentication
pub struct RelayServer<R: ServiceRouter> {
    pub endpoint: Endpoint,
    server_keypair: Arc<KeyPair>,
    router: Arc<R>,
}

impl<R: ServiceRouter + 'static> RelayServer<R> {
    pub fn builder() -> RelayServerBuilder {
        RelayServerBuilder::default()
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.server_keypair.public_key()
    }

    /// Create a new relay server
    ///
    /// # Arguments
    /// * `addr` - The address to bind the server to
    /// * `server_keypair` - The server keypair for transport security (Ed25519 or ML-DSA-44)
    /// * `router` - The service router implementation
    pub fn new(
        addr: SocketAddr,
        server_keypair: KeyPair,
        router: R,
    ) -> Result<Self, RelayServerError> {
        let server_keypair = Arc::new(server_keypair);
        let endpoint =
            create_server_endpoint(addr, &server_keypair).map_err(RelayServerError::CryptoError)?;

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
        debug!(address = ?self.endpoint.local_addr()?,
            "Relay server starting",
        );
        let server_identity = self.server_keypair.public_key();
        debug!(
            server_identity = ?server_identity,
            "Server identity:",
        );

        while let Some(conn) = self.endpoint.accept().await {
            let router = Arc::clone(&self.router);
            let server_keypair = Arc::clone(&self.server_keypair);

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
        server_keypair: Arc<KeyPair>,
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

        // Perform the actual challenge handshake
        let verified_keys = match crate::challenge::perform_multi_challenge_handshake(
            send,
            recv,
            server_keypair.as_ref(), // Use the server's keypair for challenge
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

        // TODO: Extract client public key from TLS certificate
        // For now, using a placeholder key - this should be extracted from the client's TLS certificate
        let placeholder_transport_key = server_keypair.public_key(); // Temporary placeholder

        // Create connection info with verified keys
        let connection_info = ConnectionInfo::with_verified_keys(
            placeholder_transport_key,
            verified_keys,
            remote_addr,
        );

        info!(
            "🔐 Connection established with {} verified keys",
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

pub type FullRelayServer = RelayServer<RelayServiceRouter>;
