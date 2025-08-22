use anyhow::Result;

use futures::future::join;

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::{timeout, Duration};
use zoe_relay::Service;
use zoe_relay::{ConnectionInfo, RelayServer, ServiceRouter};
use zoe_wire_protocol::StreamPair;
use zoe_wire_protocol::TransportPrivateKey;

// Initialize crypto provider for Rustls
fn init_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install crypto provider");
    });
}

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

#[tokio::test]
async fn test_echo_service_integration() -> Result<()> {
    // Initialize Rustls crypto provider before any TLS operations
    init_crypto_provider();

    // Initialize tracing for better debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Use the new infrastructure approach with proper key generation
    let server_keypair = TransportPrivateKey::default(); // Ed25519 by default
    let server_public_key = server_keypair.public_key();

    println!(
        "🔑 Server public key: {}",
        hex::encode(server_public_key.encode())
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

    // Generate client keypair using proper wire protocol infrastructure
    let client_keypair = zoe_wire_protocol::generate_keypair(&mut rand::rngs::OsRng);
    println!(
        "🔑 Client public key: {}",
        hex::encode(client_keypair.public_key().encode())
    );

    // Spawn server in background
    let server_handle = tokio::spawn(async move { server.run().await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run client test with proper protocol setup using helper functions
    let client_task = timeout(Duration::from_secs(10), async {
        // Use the new helper function for complete connection setup
        let (connection, _version, _verified_count, _warnings) =
            zoe_e2e_tests::multi_client_infra::create_authenticated_connection(
                actual_addr,
                &server_public_key,
                &[&client_keypair],
            )
            .await?;

        // Now test the echo service functionality
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send service ID (1 for echo service)
        send.write_u8(1).await?;

        // Send test message
        let test_message = b"Hello, Echo Server with Protocol!";
        send.write_all(test_message).await?;
        send.flush().await?;

        // Read echoed response
        let mut response = vec![0u8; test_message.len()];
        recv.read_exact(&mut response).await?;

        // Verify echo
        if response != test_message {
            return Err(anyhow::anyhow!(
                "Echo response mismatch: expected {:?}, got {:?}",
                String::from_utf8_lossy(test_message),
                String::from_utf8_lossy(&response)
            ));
        }

        println!(
            "✅ Echo test successful! Received: {}",
            String::from_utf8_lossy(&response)
        );

        // Close the connection gracefully
        connection.close(0u32.into(), b"test complete");

        Result::<(), anyhow::Error>::Ok(())
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

    println!("🎉 Echo service integration test with version negotiation and challenge protocol completed successfully!");
    Ok(())
}

#[tokio::test]
async fn test_service_id_routing() -> Result<()> {
    // Initialize Rustls crypto provider before any TLS operations
    init_crypto_provider();

    // Test that a specific service ID is properly routed using the new multi-client infrastructure
    use std::sync::atomic::{AtomicU8, Ordering};
    use zoe_wire_protocol::generate_keypair;

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

    // Use the new infrastructure approach with proper key generation
    let server_keypair = TransportPrivateKey::default(); // Ed25519 by default
    let server_public_key = server_keypair.public_key();
    let router = SingleServiceRouter::new();

    let server_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let server = RelayServer::new(server_addr, server_keypair, router)?;
    let actual_addr = server.endpoint.local_addr()?;

    let test_service_id = 42u8;

    // Spawn server in background
    let server_handle = tokio::spawn(async move { server.run().await });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client using the proper wire protocol infrastructure
    let client_keypair = generate_keypair(&mut rand::rngs::OsRng);

    // Run client test with timeout using helper functions
    let client_result = timeout(Duration::from_secs(10), async {
        // Use the new helper function for complete connection setup
        let (connection, _version, _verified_count, _warnings) =
            zoe_e2e_tests::multi_client_infra::create_authenticated_connection(
                actual_addr,
                &server_public_key,
                &[&client_keypair],
            )
            .await?;

        // Now test the service ID routing
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
        Ok(Ok(())) => {
            println!("✅ Client test successful");
            println!(
                "✅ Service ID {} was correctly routed (verified by echo response)",
                test_service_id
            );
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(anyhow::anyhow!("Client test timed out")),
    }

    println!("✅ Service ID routing test with version negotiation and challenge protocol completed successfully!");
    Ok(())
}
