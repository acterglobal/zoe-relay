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
use tarpc::tokio_serde;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info};
use zoe_wire_protocol::{
    extract_ed25519_from_cert, generate_deterministic_cert_from_ed25519, CryptoError,
    ZoeClientCertVerifier,
};

use crate::{services::rpc::PostcardFormat, Service, ServiceError, ServiceRouter};

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

type WrappedStream = FramedRead<RecvStream, LengthDelimitedCodec>;
type WrappedSink = FramedWrite<SendStream, LengthDelimitedCodec>;

// only dealing with one half of the IO
type SerStream<I> = tokio_serde::Framed<WrappedStream, I, I, PostcardFormat>;
type DeSink<I> = tokio_serde::Framed<WrappedSink, I, I, PostcardFormat>;

impl StreamPair {
    pub async fn send_ack(&mut self) -> std::io::Result<()> {
        self.send.write_u8(1).await
    }

    pub fn unpack_transports<S, D>(self) -> (SerStream<S>, DeSink<D>) {
        let StreamPair { recv, send } = self;
        let wrapped_recv = FramedRead::new(recv, LengthDelimitedCodec::new());
        let wrapped_send = FramedWrite::new(send, LengthDelimitedCodec::new());
        let ser_stream = tokio_serde::Framed::new(wrapped_recv, PostcardFormat);
        let de_sink = tokio_serde::Framed::new(wrapped_send, PostcardFormat);
        (ser_stream, de_sink)
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
            println!("Server creation failed: {e}");
        }
        assert!(server.is_ok());
    }

    // E-2-E-Test over quinn

    use anyhow::Result;
    use ed25519_dalek::SigningKey;
    use futures::future::join;

    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Notify;
    use tokio::time::{timeout, Duration};
    use crate::Service;
    use crate::{ConnectionInfo, RelayServer, ServiceRouter, StreamPair};
    use zoe_wire_protocol::{
        generate_deterministic_cert_from_ed25519, AcceptSpecificServerCertVerifier,
    };
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
                "🔗 Echo service handling connection from client: {}",
                hex::encode(connection_info.client_public_key.to_bytes()),
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

    /// A simple QUIC client for testing
    struct TestClient {
        client_key: SigningKey,
    }

    impl TestClient {
        fn new() -> Self {
            Self {
                client_key: SigningKey::generate(&mut rand::thread_rng()),
            }
        }

        async fn connect_and_test(
            &self,
            server_addr: SocketAddr,
            server_public_key: &SigningKey,
        ) -> Result<()> {
            // Create client endpoint
            let client_endpoint = self.create_client_endpoint(server_public_key)?;

            // Connect to server
            let connection = client_endpoint.connect(server_addr, "localhost")?.await?;

            // Open bidirectional stream
            let (mut send, mut recv) = connection.open_bi().await?;

            // Send service ID (1 for echo service)
            send.write_u8(1).await?;

            // Send test message
            let test_message = b"Hello, Echo Server!";
            send.write_all(test_message).await?;
            send.flush().await?;

            // Read echoed response
            let mut response = vec![0u8; test_message.len()];
            recv.read_exact(&mut response).await?;

            // Verify echo
            assert_eq!(response, test_message);
            println!(
                "✅ Echo test successful! Received: {}",
                String::from_utf8_lossy(&response)
            );

            // Close the connection gracefully
            connection.close(0u32.into(), b"test complete");

            Ok(())
        }

        fn create_client_endpoint(&self, server_public_key: &SigningKey) -> Result<quinn::Endpoint> {
            use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Endpoint};
            use rustls::ClientConfig as RustlsClientConfig;
            use std::sync::Arc;

            // Generate client certificate for mutual TLS
            let (client_certs, client_key) =
                generate_deterministic_cert_from_ed25519(&self.client_key, "client")?;

            // Create custom certificate verifier that accepts our server
            let verifier = AcceptSpecificServerCertVerifier::new(server_public_key.verifying_key());

            // Create client config with client certificate for mutual TLS
            let crypto = RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(client_certs, client_key)?;

            let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));

            let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
            endpoint.set_default_client_config(client_config);

            Ok(endpoint)
        }
    }

    #[tokio::test]
    async fn test_echo_service_integration() -> Result<()> {
        // Initialize tracing for better debugging
        let _ = tracing_subscriber::fmt::try_init();

        // Generate server key
        let server_key = SigningKey::generate(&mut rand::thread_rng());
        println!(
            "🔑 Server key: {}",
            hex::encode(server_key.verifying_key().to_bytes())
        );

        // Create echo service
        let echo_service = EchoServiceRouter::new();
        let connection_notify = echo_service.connection_notify();

        // Start server on random port
        let server_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let server = RelayServer::new(server_addr, server_key.clone(), echo_service)?;

        // Get the actual bound address
        let actual_addr = server.endpoint.local_addr()?;
        println!("🚀 Server started on {actual_addr}");

        // Create client
        let client = TestClient::new();
        println!(
            "🔑 Client key: {}",
            hex::encode(client.client_key.verifying_key().to_bytes())
        );

        // Spawn server in background
        let server_handle = tokio::spawn(async move { server.run().await });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client test
        let client_task = timeout(Duration::from_secs(10), async {
            client.connect_and_test(actual_addr, &server_key).await
        });

        let connection_wait_task = timeout(Duration::from_secs(10), async {
            // Wait for connection to be handled
            connection_notify.notified().await;
            println!("✅ Connection was handled by echo service");
        });

        // Run client test and wait for connection handling
        let (client_result, _) = join(client_task, connection_wait_task).await;

        // Check client result
        match client_result {
            Ok(Ok(())) => println!("✅ Client test successful"),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow::anyhow!("Client test timed out")),
        }

        // Stop the server
        server_handle.abort();

        println!("🎉 Integration test completed successfully!");
        Ok(())
    }

    #[tokio::test]
    async fn test_service_id_routing() -> Result<()> {
        // Test that a specific service ID is properly routed
        use std::sync::atomic::{AtomicU8, Ordering};

        struct SingleService {
            streams: StreamPair,
            service_id: u8,
        }

        #[async_trait::async_trait]
        impl Service for SingleService {
            type Error = TestError;
            async fn run(self) -> Result<(), Self::Error> {
                let Self {
                    mut streams,
                    service_id,
                } = self;
                // Echo back the service ID
                streams
                    .send
                    .write_u8(service_id)
                    .await
                    .map_err(|e| TestError::Generic(format!("Write error: {e}")))?;
                streams
                    .send
                    .flush()
                    .await
                    .map_err(|e| TestError::Generic(format!("Flush error: {e}")))?;

                // Give client time to read the response before closing
                tokio::time::sleep(Duration::from_millis(100)).await;

                Ok(())
            }
        }

        struct SingleServiceRouter {
            received_service_id: AtomicU8,
        }

        impl SingleServiceRouter {
            fn new() -> Self {
                Self {
                    received_service_id: AtomicU8::new(0),
                }
            }
        }

        #[async_trait::async_trait]
        impl ServiceRouter for SingleServiceRouter {
            type Error = TestError;
            type ServiceId = u8;
            type Service = SingleService;

            async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> {
                Ok(service_id)
            }

            async fn create_service(
                &self,
                service_id: &Self::ServiceId,
                _connection_info: &ConnectionInfo,
                streams: StreamPair,
            ) -> Result<Self::Service, Self::Error> {
                self.received_service_id
                    .store(*service_id, Ordering::SeqCst);
                Ok(SingleService {
                    streams,
                    service_id: *service_id,
                })
            }
        }

        let server_key = SigningKey::generate(&mut rand::thread_rng());
        let router = SingleServiceRouter::new();

        let server_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let server = RelayServer::new(server_addr, server_key.clone(), router)?;
        let actual_addr = server.endpoint.local_addr()?;

        let client = TestClient::new();
        let test_service_id = 42u8;

        // Spawn server in background
        let server_handle = tokio::spawn(async move { server.run().await });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Run client test with timeout
        let client_result = timeout(Duration::from_secs(5), async {
            let client_endpoint = client.create_client_endpoint(&server_key)?;
            let connection = client_endpoint.connect(actual_addr, "localhost")?.await?;
            let (mut send, mut recv) = connection.open_bi().await?;

            // Send service ID
            send.write_u8(test_service_id).await?;
            send.flush().await?;

            // Read response
            let response = recv.read_u8().await?;
            assert_eq!(response, test_service_id);

            connection.close(0u32.into(), b"test complete");
            Result::<(), anyhow::Error>::Ok(())
        })
        .await;

        // Stop the server
        server_handle.abort();

        match client_result {
            Ok(Ok(())) => println!("✅ Client test successful"),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow::anyhow!("Client test timed out")),
        }

        println!("✅ Service ID routing test completed successfully!");
        Ok(())
    }

}
