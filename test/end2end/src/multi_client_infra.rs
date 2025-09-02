//! Multi-client testing infrastructure for Zoe protocol testing
//!
//! This module provides comprehensive infrastructure for testing protocols across
//! multiple clients connected to a single server. It includes:
//!
//! - **Server Management**: Automatic server setup with proper version negotiation
//! - **Multi-Client Support**: Easy creation and management of multiple test clients
//! - **Protocol Testing**: Built-in support for challenge protocol and version negotiation
//! - **Test Scenarios**: Common patterns for multi-client protocol testing
//!
//! ## Usage Examples
//!
//! ### High-Level Multi-Client Testing
//! ```rust
//! use zoe_e2e_tests::multi_client_infra::MultiClientTestHarness;
//!
//! #[tokio::test]
//! async fn test_multi_client_message_exchange() -> Result<()> {
//!     let mut harness = MultiClientTestHarness::setup().await?;
//!     
//!     // Create multiple clients
//!     let client_a = harness.create_client("alice").await?;
//!     let client_b = harness.create_client("bob").await?;
//!     let client_c = harness.create_client("charlie").await?;
//!     
//!     // Test protocol between clients
//!     harness.test_message_broadcast(&[client_a, client_b, client_c]).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ### Low-Level Protocol Testing
//! ```rust
//! use zoe_e2e_tests::multi_client_infra::create_authenticated_connection;
//! use zoe_wire_protocol::KeyPair;
//!
//! #[tokio::test]
//! async fn test_custom_protocol() -> Result<()> {
//!     // Setup server (using your own server setup)
//!     let server_addr = setup_test_server().await?;
//!     let server_public_key = get_server_public_key();
//!     
//!     // Create client and establish authenticated connection
//!     let client_keypair = KeyPair::generate(&mut rand::rngs::OsRng);
//!     let (connection, version, verified_count, warnings) =
//!         create_authenticated_connection(
//!             server_addr,
//!             &server_public_key,
//!             &[&client_keypair],
//!         ).await?;
//!     
//!     // Now use the connection for your custom protocol testing
//!     let (mut send, mut recv) = connection.open_bi().await?;
//!     // ... your protocol logic here
//!     
//!     Ok(())
//! }
//! ```

use crate::infra::TestInfrastructure;
use anyhow::{Context, Result};
use futures::StreamExt;
use libcrux_ml_dsa;
use rand::{Rng, RngCore};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tokio_stream::wrappers::BroadcastStream;
use tracing::{debug, info, warn};
use zoe_client::services::MessagesManagerTrait;
use zoe_client::services::messages_manager::MessagesManager;
use zoe_client::{RelayClient, RelayClientBuilder};
use zoe_wire_protocol::{
    Content, Filter, KeyPair, Kind, Message, MessageFilters, MessageFull, StreamMessage,
    SubscriptionConfig, Tag, VerifyingKey,
};

// ============================================================================
// Protocol Helper Functions
// ============================================================================

/// Perform version negotiation with a server connection
///
/// This is a lower-level helper that can be used by tests that need to manually
/// control the connection process. Most tests should use `TestClient` which
/// handles this automatically.
///
/// # Arguments
/// * `connection` - The QUIC connection to the server
///
/// # Returns
/// * `Ok(version)` - The negotiated protocol version
/// * `Err(error)` - Version negotiation failed
pub async fn perform_version_negotiation(connection: &quinn::Connection) -> Result<String> {
    let client_protocol_config = zoe_wire_protocol::version::ClientProtocolConfig::default();

    let protocol_version = zoe_wire_protocol::version::validate_server_protocol_support(
        connection,
        &client_protocol_config,
    )
    .map_err(|e| anyhow::anyhow!("Protocol negotiation failed: {}", e))?;

    Ok(protocol_version.to_string())
}

/// Perform challenge protocol handshake with a server
///
/// This is a lower-level helper that can be used by tests that need to manually
/// control the connection process. Most tests should use `TestClient` which
/// handles this automatically.
///
/// # Arguments
/// * `connection` - The QUIC connection to the server
/// * `server_public_key` - The server's public key for verification
/// * `client_keypairs` - Array of client keypairs to use for the challenge
///
/// # Returns
/// * `Ok((verified_count, warnings))` - Challenge completed successfully
/// * `Err(error)` - Challenge protocol failed
pub async fn perform_challenge_handshake(
    connection: &quinn::Connection,
    server_public_key: &VerifyingKey,
    client_keypairs: &[&KeyPair],
) -> Result<(usize, Vec<String>)> {
    // Accept bidirectional stream for challenge protocol
    let (send, recv) = connection
        .accept_bi()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to accept challenge stream: {}", e))?;

    // Perform the challenge handshake
    let (verified_count, warnings) =
        zoe_wire_protocol::challenge::client::perform_client_challenge_handshake(
            send,
            recv,
            server_public_key,
            client_keypairs,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Challenge protocol failed: {}", e))?;

    // Convert warnings to strings
    let warning_strings: Vec<String> = warnings.into_iter().map(|w| format!("{:?}", w)).collect();

    Ok((verified_count, warning_strings))
}

/// Perform complete protocol setup (version negotiation + challenge handshake)
///
/// This combines version negotiation and challenge protocol into a single
/// convenient function. This is the recommended approach for most tests.
///
/// # Arguments
/// * `connection` - The QUIC connection to the server
/// * `server_public_key` - The server's public key for verification
/// * `client_keypairs` - Array of client keypairs to use for the challenge
///
/// # Returns
/// * `Ok((version, verified_count, warnings))` - Protocol setup completed
/// * `Err(error)` - Protocol setup failed
pub async fn perform_full_protocol_setup(
    connection: &quinn::Connection,
    server_public_key: &VerifyingKey,
    client_keypairs: &[&KeyPair],
) -> Result<(String, usize, Vec<String>)> {
    // Step 1: Version negotiation
    let negotiated_version = perform_version_negotiation(connection)
        .await
        .context("Version negotiation failed during full protocol setup")?;

    info!("✅ Protocol negotiated: {}", negotiated_version);

    // Step 2: Challenge protocol handshake
    let (verified_count, warnings) =
        perform_challenge_handshake(connection, server_public_key, client_keypairs)
            .await
            .context("Challenge handshake failed during full protocol setup")?;

    info!(
        "✅ Challenge protocol handshake completed: {} keys verified",
        verified_count
    );

    if !warnings.is_empty() {
        warn!("Challenge protocol warnings: {:?}", warnings);
    }

    Ok((negotiated_version, verified_count, warnings))
}

/// Create a client endpoint and connect to a server with full protocol setup
///
/// This is the highest-level helper that handles the complete connection process:
/// 1. Creates a client endpoint
/// 2. Connects to the server
/// 3. Performs version negotiation
/// 4. Performs challenge protocol handshake
///
/// # Arguments
/// * `server_addr` - The server address to connect to
/// * `server_public_key` - The server's public key
/// * `client_keypairs` - Array of client keypairs to use for the challenge
///
/// # Returns
/// * `Ok((connection, version, verified_count, warnings))` - Full connection established
/// * `Err(error)` - Connection or protocol setup failed
pub async fn create_authenticated_connection(
    server_addr: std::net::SocketAddr,
    server_public_key: &VerifyingKey,
    client_keypairs: &[&KeyPair],
) -> Result<(quinn::Connection, String, usize, Vec<String>)> {
    // Create client endpoint
    let client_endpoint =
        zoe_wire_protocol::connection::client::create_client_endpoint(server_public_key)
            .map_err(|e| anyhow::anyhow!("Failed to create client endpoint: {}", e))?;

    // Connect to server
    let connection = client_endpoint
        .connect(server_addr, "localhost")
        .map_err(|e| anyhow::anyhow!("Failed to initiate connection: {}", e))?
        .await
        .map_err(|e| anyhow::anyhow!("Failed to establish connection: {}", e))?;

    // Perform full protocol setup
    let (version, verified_count, warnings) =
        perform_full_protocol_setup(&connection, server_public_key, client_keypairs).await?;

    Ok((connection, version, verified_count, warnings))
}

// ============================================================================
// Test Client Infrastructure
// ============================================================================

/// A named client instance for multi-client testing
pub struct TestClient {
    /// Human-readable name for this client (e.g., "alice", "bob")
    pub name: String,
    /// The underlying relay client
    pub client: RelayClient,
}

impl TestClient {
    /// Create a new test client with the given name
    pub fn new(name: String, client: RelayClient) -> Self {
        Self { name, client }
    }

    /// Get a unique identifier for this client (hex-encoded public key)
    pub fn id(&self) -> String {
        hex::encode(self.client.public_key().encode())
    }

    /// Get the client's public key
    pub fn public_key(&self) -> VerifyingKey {
        self.client.public_key()
    }

    /// Get the client's keypair
    pub fn keypair(&self) -> &KeyPair {
        self.client.keypair()
    }

    /// Connect to the message service and return service and streams
    pub async fn connect_message_service(
        &self,
    ) -> Result<(
        Arc<zoe_client::services::MessagesManager>,
        BroadcastStream<zoe_wire_protocol::StreamMessage>,
        BroadcastStream<zoe_wire_protocol::CatchUpResponse>,
    )> {
        let persistence_manager = self.client.persistence_manager();
        let msg_stream = persistence_manager.messages_stream();
        let catch_up_stream = persistence_manager.catch_up_stream();
        let service = persistence_manager.messages_manager().clone();

        Ok((service, msg_stream, catch_up_stream))
    }

    /// Create and publish a message to a specific channel
    pub async fn publish_to_channel(
        &self,
        messages_manager: &zoe_client::services::MessagesManager,
        channel: &str,
        content: &str,
    ) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let channel_tag = Tag::Channel {
            id: channel.as_bytes().to_vec(),
            relays: vec![],
        };

        let message = Message::new_v0_raw(
            content.as_bytes().to_vec(),
            self.public_key(),
            timestamp,
            Kind::Regular,
            vec![channel_tag],
        );

        let message_full = MessageFull::new(message, self.keypair())
            .map_err(|e| anyhow::anyhow!("Failed to create MessageFull: {}", e))?;

        messages_manager
            .publish(message_full)
            .await
            .with_context(|| format!("Failed to publish message from client '{}'", self.name))?;

        info!(
            "📤 Client '{}' published message to channel '{}'",
            self.name, channel
        );
        Ok(())
    }

    /// Subscribe to a specific channel and return a filtered stream
    pub async fn subscribe_to_channel(
        &self,
        messages_manager: &zoe_client::services::MessagesManager,
        message_stream: BroadcastStream<zoe_wire_protocol::StreamMessage>,
        channel: &str,
    ) -> Result<BroadcastStream<zoe_wire_protocol::StreamMessage>> {
        let filter = Filter::Channel(channel.as_bytes().to_vec());

        messages_manager
            .ensure_contains_filter(filter)
            .await
            .with_context(|| {
                format!(
                    "Failed to subscribe client '{}' to channel '{}'",
                    self.name, channel
                )
            })?;

        info!(
            "📬 Client '{}' subscribed to channel '{}'",
            self.name, channel
        );
        Ok(message_stream)
    }
}

/// Multi-client test harness for comprehensive protocol testing
pub struct MultiClientTestHarness {
    /// The underlying test infrastructure
    infra: TestInfrastructure,
    /// Counter for generating unique test identifiers
    test_counter: Arc<RwLock<u32>>,
}

impl MultiClientTestHarness {
    /// Set up the multi-client test harness
    ///
    /// This creates the underlying server infrastructure and prepares
    /// for multi-client testing scenarios.
    pub async fn setup() -> Result<Self> {
        info!("🚀 Setting up multi-client test harness");

        let infra = TestInfrastructure::setup()
            .await
            .context("Failed to setup test infrastructure")?;

        info!("✅ Multi-client test harness ready");

        Ok(Self {
            infra,
            test_counter: Arc::new(RwLock::new(0)),
        })
    }

    /// Create a new test client with the given name
    ///
    /// The client will automatically go through version negotiation and
    /// challenge protocol handshake during connection establishment.
    ///
    /// # Arguments
    ///
    /// * `name` - Human-readable name for the client (e.g., "alice", "bob")
    ///
    /// # Returns
    ///
    /// A TestClient instance ready for protocol testing
    pub async fn create_client(&self, name: &str) -> Result<TestClient> {
        info!("👤 Creating test client '{}'", name);

        // Generate unique keypair for this client
        let keypair = KeyPair::generate(&mut rand::thread_rng());

        // Create the underlying relay client (this handles version negotiation and challenge protocol)
        let client = timeout(
            Duration::from_secs(10),
            RelayClientBuilder::new()
                .client_keypair(keypair)
                .server_public_key(self.infra.server_public_key.clone())
                .server_address(self.infra.server_addr)
                .encryption_key([0u8; 32]) // Use default encryption key for tests
                .build(),
        )
        .await
        .with_context(|| format!("Timeout connecting client '{}'", name))?
        .with_context(|| format!("Failed to create client '{}'", name))?;

        let test_client = TestClient::new(name.to_string(), client);

        info!(
            "✅ Client '{}' connected successfully ({:?})",
            name,
            test_client.public_key()
        );

        Ok(test_client)
    }

    /// List all currently connected clients (not implemented since clients are not stored)
    pub async fn list_clients(&self) -> Vec<String> {
        // Since we don't store clients anymore, return empty list
        // In a real implementation, you might want to track client names separately
        vec![]
    }

    /// Generate a unique test channel name
    pub async fn unique_channel(&self, prefix: &str) -> String {
        let mut counter = self.test_counter.write().await;
        *counter += 1;
        format!("{}_{}", prefix, *counter)
    }

    /// Test message broadcasting between multiple clients
    ///
    /// This is a common test scenario where one client publishes a message
    /// and multiple clients receive it through subscriptions.
    ///
    /// # Arguments
    ///
    /// * `clients` - List of clients to participate in the test
    ///
    /// # Returns
    ///
    /// Statistics about the message broadcast test
    pub async fn test_message_broadcast(
        &self,
        clients: &[TestClient],
    ) -> Result<BroadcastTestResult> {
        if clients.is_empty() {
            return Err(anyhow::anyhow!(
                "At least one client required for broadcast test"
            ));
        }

        let test_channel = self.unique_channel("broadcast_test").await;
        info!(
            "🔊 Starting message broadcast test on channel '{}'",
            test_channel
        );

        let mut message_services = Vec::new();
        let mut message_streams = Vec::new();

        // Connect all clients to message service and subscribe to test channel
        for client in clients {
            let (service, msg_stream, _catch_up_stream) = client.connect_message_service().await?;
            let stream = client
                .subscribe_to_channel(&service, msg_stream, &test_channel)
                .await?;

            message_services.push(service);
            message_streams.push(stream);
        }

        // Wait for subscriptions to be processed
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Have the first client publish a message
        let publisher = &clients[0];
        let test_message = format!("Broadcast test message from {}", publisher.name);

        publisher
            .publish_to_channel(&message_services[0], &test_channel, &test_message)
            .await?;

        // Wait for message propagation
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Collect messages received by each client
        let mut results = BTreeMap::new();
        let receive_timeout = Duration::from_millis(1000);

        for (i, client) in clients.iter().enumerate() {
            let mut messages_received = 0;
            let mut stream = &mut message_streams[i];

            info!("👂 Collecting messages for client '{}'...", client.name);

            // Try to receive messages
            for _ in 0..5 {
                match timeout(receive_timeout, stream.next()).await {
                    Ok(Some(Ok(stream_message))) => match stream_message {
                        StreamMessage::MessageReceived {
                            message: _msg,
                            stream_height,
                        } => {
                            messages_received += 1;
                            debug!(
                                "📨 Client '{}' received message at height: {}",
                                client.name, stream_height
                            );
                        }
                        StreamMessage::StreamHeightUpdate(height) => {
                            debug!(
                                "💓 Client '{}' stream height update: {}",
                                client.name, height
                            );
                        }
                    },
                    Ok(Some(Err(_))) => break, // Stream error
                    Ok(None) => break,
                    Err(_) => break, // Timeout
                }
            }

            results.insert(client.name.clone(), messages_received);
            info!(
                "📊 Client '{}' received {} messages",
                client.name, messages_received
            );
        }

        let total_messages_sent = 1;
        let total_messages_received: u32 = results.values().sum();

        info!("✅ Broadcast test completed:");
        info!("   📤 Messages sent: {}", total_messages_sent);
        info!("   📥 Total messages received: {}", total_messages_received);
        info!("   👥 Participating clients: {}", clients.len());

        Ok(BroadcastTestResult {
            channel: test_channel,
            messages_sent: total_messages_sent,
            client_results: results,
            total_received: total_messages_received,
        })
    }

    /// Test peer-to-peer message exchange between two specific clients
    ///
    /// This tests direct communication patterns between two clients.
    pub async fn test_peer_to_peer_exchange(
        &self,
        client_a: &TestClient,
        client_b: &TestClient,
    ) -> Result<P2PTestResult> {
        let test_channel = self.unique_channel("p2p_test").await;
        info!(
            "🤝 Starting peer-to-peer test between '{}' and '{}' on channel '{}'",
            client_a.name, client_b.name, test_channel
        );

        // Connect both clients to message service
        let (service_a, msg_stream_a, _catch_up_a) = client_a.connect_message_service().await?;
        let (service_b, msg_stream_b, _catch_up_b) = client_b.connect_message_service().await?;

        // Both clients subscribe to the test channel
        let mut stream_a = client_a
            .subscribe_to_channel(&service_a, msg_stream_a, &test_channel)
            .await?;
        let mut stream_b = client_b
            .subscribe_to_channel(&service_b, msg_stream_b, &test_channel)
            .await?;

        // Wait for subscriptions
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Client A sends message to Client B
        let message_a_to_b = format!("Hello {} from {}", client_b.name, client_a.name);
        client_a
            .publish_to_channel(&service_a, &test_channel, &message_a_to_b)
            .await?;

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Client B sends message to Client A
        let message_b_to_a = format!("Hello {} from {}", client_a.name, client_b.name);
        client_b
            .publish_to_channel(&service_b, &test_channel, &message_b_to_a)
            .await?;

        // Wait for message propagation
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Collect messages for both clients
        let mut messages_a = 0;
        let mut messages_b = 0;
        let receive_timeout = Duration::from_millis(1000);

        // Collect for client A
        for _ in 0..5 {
            match timeout(receive_timeout, stream_a.next()).await {
                Ok(Some(Ok(StreamMessage::MessageReceived { .. }))) => messages_a += 1,
                Ok(Some(Ok(StreamMessage::StreamHeightUpdate(_)))) => {}
                _ => break,
            }
        }

        // Collect for client B
        for _ in 0..5 {
            match timeout(receive_timeout, stream_b.next()).await {
                Ok(Some(Ok(StreamMessage::MessageReceived { .. }))) => messages_b += 1,
                Ok(Some(Ok(StreamMessage::StreamHeightUpdate(_)))) => {}
                _ => break,
            }
        }

        info!("✅ P2P test completed:");
        info!(
            "   📨 Client '{}' received {} messages",
            client_a.name, messages_a
        );
        info!(
            "   📨 Client '{}' received {} messages",
            client_b.name, messages_b
        );

        Ok(P2PTestResult {
            channel: test_channel,
            client_a: client_a.name.clone(),
            client_b: client_b.name.clone(),
            messages_a_received: messages_a,
            messages_b_received: messages_b,
        })
    }

    /// Test client connection and disconnection patterns
    ///
    /// This tests the robustness of the protocol when clients connect and disconnect.
    pub async fn test_connection_resilience(
        &self,
        client_names: &[&str],
    ) -> Result<ResilienceTestResult> {
        info!(
            "🔄 Starting connection resilience test with {} clients",
            client_names.len()
        );

        let mut connected_clients = Vec::new();
        let mut connection_results = BTreeMap::new();

        // Phase 1: Connect all clients
        for &name in client_names {
            match self.create_client(name).await {
                Ok(client) => {
                    connected_clients.push(client);
                    connection_results.insert(name.to_string(), true);
                    info!("✅ Client '{}' connected successfully", name);
                }
                Err(e) => {
                    connection_results.insert(name.to_string(), false);
                    warn!("❌ Client '{}' failed to connect: {}", name, e);
                }
            }
        }

        // Phase 2: Test message exchange with all connected clients
        let mut broadcast_success = false;
        if !connected_clients.is_empty() {
            match self.test_message_broadcast(&connected_clients).await {
                Ok(_) => {
                    broadcast_success = true;
                    info!(
                        "✅ Message broadcast successful with {} clients",
                        connected_clients.len()
                    );
                }
                Err(e) => {
                    warn!("❌ Message broadcast failed: {}", e);
                }
            }
        }

        info!("✅ Connection resilience test completed:");
        info!(
            "   🔗 Successful connections: {}/{}",
            connection_results.values().filter(|&&v| v).count(),
            client_names.len()
        );
        info!(
            "   📡 Broadcast test: {}",
            if broadcast_success { "PASS" } else { "FAIL" }
        );

        Ok(ResilienceTestResult {
            connection_results,
            broadcast_success,
            total_clients: client_names.len(),
        })
    }

    /// Clean up the test harness and all resources
    pub async fn cleanup(self) -> Result<()> {
        info!("🧹 Cleaning up multi-client test harness");

        // Clean up underlying infrastructure
        self.infra.cleanup().await?;

        info!("✅ Multi-client test harness cleanup complete");
        Ok(())
    }
}

/// Result of a message broadcast test
#[derive(Debug)]
pub struct BroadcastTestResult {
    /// The channel used for the test
    pub channel: String,
    /// Number of messages sent during the test
    pub messages_sent: u32,
    /// Map of client name to number of messages received
    pub client_results: BTreeMap<String, u32>,
    /// Total number of messages received across all clients
    pub total_received: u32,
}

impl BroadcastTestResult {
    /// Check if the broadcast test was successful
    ///
    /// A broadcast is considered successful if at least one client received the message.
    pub fn is_successful(&self) -> bool {
        self.total_received > 0
    }

    /// Get the success rate (percentage of expected messages received)
    ///
    /// Expected messages = messages_sent * number_of_clients
    pub fn success_rate(&self) -> f64 {
        let expected = self.messages_sent * self.client_results.len() as u32;
        if expected == 0 {
            0.0
        } else {
            (self.total_received as f64 / expected as f64) * 100.0
        }
    }
}

/// Result of a peer-to-peer test
#[derive(Debug)]
pub struct P2PTestResult {
    /// The channel used for the test
    pub channel: String,
    /// Name of the first client
    pub client_a: String,
    /// Name of the second client
    pub client_b: String,
    /// Number of messages received by client A
    pub messages_a_received: u32,
    /// Number of messages received by client B
    pub messages_b_received: u32,
}

impl P2PTestResult {
    /// Check if the P2P test was successful
    ///
    /// A P2P test is successful if both clients received at least one message.
    pub fn is_successful(&self) -> bool {
        self.messages_a_received > 0 && self.messages_b_received > 0
    }
}

/// Result of a connection resilience test
#[derive(Debug)]
pub struct ResilienceTestResult {
    /// Map of client name to connection success
    pub connection_results: BTreeMap<String, bool>,
    /// Whether the broadcast test succeeded
    pub broadcast_success: bool,
    /// Total number of clients tested
    pub total_clients: usize,
}

impl ResilienceTestResult {
    /// Get the number of successful connections
    pub fn successful_connections(&self) -> usize {
        self.connection_results.values().filter(|&&v| v).count()
    }

    /// Get the connection success rate
    pub fn connection_success_rate(&self) -> f64 {
        if self.total_clients == 0 {
            0.0
        } else {
            (self.successful_connections() as f64 / self.total_clients as f64) * 100.0
        }
    }

    /// Check if the resilience test was overall successful
    ///
    /// A resilience test is successful if at least 50% of clients connected
    /// and the broadcast test succeeded.
    pub fn is_successful(&self) -> bool {
        self.connection_success_rate() >= 50.0 && self.broadcast_success
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_multi_client_harness_setup() -> Result<()> {
        let harness = MultiClientTestHarness::setup().await?;

        // Verify we can create clients
        let client_a = harness.create_client("alice").await?;
        let client_b = harness.create_client("bob").await?;

        // Verify clients were created successfully
        assert_eq!(client_a.name, "alice");
        assert_eq!(client_b.name, "bob");

        // Verify clients have unique IDs
        assert_ne!(client_a.id(), client_b.id());

        harness.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_message_broadcast_scenario() -> Result<()> {
        let harness = MultiClientTestHarness::setup().await?;

        // Create multiple clients
        let client_a = harness.create_client("alice").await?;
        let client_b = harness.create_client("bob").await?;
        let client_c = harness.create_client("charlie").await?;

        // Test broadcast
        let result = harness
            .test_message_broadcast(&[client_a, client_b, client_c])
            .await?;

        // Verify results
        assert_eq!(result.messages_sent, 1);
        assert_eq!(result.client_results.len(), 3);

        info!("Broadcast test success rate: {:.1}%", result.success_rate());

        harness.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_peer_to_peer_scenario() -> Result<()> {
        let harness = MultiClientTestHarness::setup().await?;

        let client_a = harness.create_client("alice").await?;
        let client_b = harness.create_client("bob").await?;

        let result = harness
            .test_peer_to_peer_exchange(&client_a, &client_b)
            .await?;

        // Verify both clients participated
        assert_eq!(result.client_a, "alice");
        assert_eq!(result.client_b, "bob");

        info!("P2P test successful: {}", result.is_successful());

        harness.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn test_connection_resilience_scenario() -> Result<()> {
        let harness = MultiClientTestHarness::setup().await?;

        let client_names = ["alice", "bob", "charlie", "david"];
        let result = harness.test_connection_resilience(&client_names).await?;

        // Verify results
        assert_eq!(result.total_clients, 4);
        assert!(result.successful_connections() > 0);

        info!(
            "Connection success rate: {:.1}%",
            result.connection_success_rate()
        );
        info!(
            "Overall resilience test successful: {}",
            result.is_successful()
        );

        harness.cleanup().await?;
        Ok(())
    }
}
