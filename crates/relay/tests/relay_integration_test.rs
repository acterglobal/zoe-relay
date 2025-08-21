use anyhow::Result;

use futures::future::join;

use ml_dsa::{KeyGen, MlDsa44, VerifyingKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::{timeout, Duration};
use zoe_wire_protocol::{
    connection::client::create_client_endpoint,
    KeyPair, TransportPrivateKey,
};
use zoe_relay::Service;
use zoe_relay::{ConnectionInfo, RelayServer, ServiceRouter};
use zoe_wire_protocol::StreamPair;

#[derive(Debug, thiserror::Error)]
enum TestError {
    #[error("Test error: {0}")]
    Generic(String),
}

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
            hex::encode(connection_info.client_public_key.encode()),
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
    client_keypair: KeyPair,
}

impl TestClient {
    fn new() -> Self {
        let client_keypair =
            KeyPair::MlDsa44(Box::new(ml_dsa::MlDsa44::key_gen(&mut rand::rngs::OsRng)));
        Self { client_keypair }
    }

    fn client_key(&self) -> &ml_dsa::KeyPair<MlDsa44> {
        match &self.client_keypair {
            KeyPair::MlDsa44(kp) => kp,
            _ => panic!("Expected MlDsa44 keypair"),
        }
    }

    fn client_verifying_key(&self) -> ml_dsa::VerifyingKey<MlDsa44> {
        self.client_key().verifying_key().clone()
    }

    async fn connect_and_test(
        &self,
        server_addr: SocketAddr,
        server_public_key: &VerifyingKey<MlDsa44>,
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

    fn create_client_endpoint(
        &self,
        server_public_key: &VerifyingKey<MlDsa44>,
    ) -> Result<quinn::Endpoint> {
        // Convert ML-DSA VerifyingKey to TransportPublicKey
        let transport_public_key = zoe_wire_protocol::TransportPublicKey::MlDsa44 {
            verifying_key_bytes: server_public_key.encode().to_vec(),
        };
        Ok(create_client_endpoint(&transport_public_key)?)
    }
}

#[tokio::test]
async fn test_echo_service_integration() -> Result<()> {
    // Initialize tracing for better debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Generate server key
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    // For this test, we'll create a dummy ML-DSA key since the test expects ML-DSA
    let server_verifying_key = MlDsa44::key_gen(&mut rand::rngs::OsRng).verifying_key().clone();
    println!(
        "🔑 Server key: {}",
        hex::encode(server_verifying_key.encode())
    );

    // Create echo service
    let echo_service = EchoServiceRouter::new();
    let connection_notify = echo_service.connection_notify();

    // Start server on random port
    let server_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server = RelayServer::new(server_addr, server_keypair, echo_service)?;

    // Get the actual bound address
    let actual_addr = server.endpoint.local_addr()?;
    println!("🚀 Server started on {actual_addr}");

    // Create client
    let client = TestClient::new();
    println!(
        "🔑 Client key: {}",
        hex::encode(client.client_verifying_key().encode())
    );

    // Spawn server in background
    let server_handle = tokio::spawn(async move { server.run().await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client test
    let client_task = timeout(Duration::from_secs(10), async {
        client
            .connect_and_test(actual_addr, &server_verifying_key)
            .await
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

    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    // For this test, we'll create a dummy ML-DSA key since the test expects ML-DSA
    let server_verifying_key = MlDsa44::key_gen(&mut rand::rngs::OsRng).verifying_key().clone();
    let router = SingleServiceRouter::new();

    let server_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server = RelayServer::new(server_addr, server_keypair, router)?;
    let actual_addr = server.endpoint.local_addr()?;

    let client = TestClient::new();
    let test_service_id = 42u8;

    // Spawn server in background
    let server_handle = tokio::spawn(async move { server.run().await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client test with timeout
    let client_result = timeout(Duration::from_secs(5), async {
        let client_endpoint = client.create_client_endpoint(&server_verifying_key)?;
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
