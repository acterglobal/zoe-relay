//! End-to-end test for tarpc echo service using TarpcOverMessages transport
//!
//! This test validates that:
//! 1. A tarpc echo service can be defined using #[tarpc::service]
//! 2. TarpcOverMessagesServer/Client can bridge tarpc over encrypted messages
//! 3. Responses are correctly routed back through request correlation
//! 4. The complete roundtrip works end-to-end with proper tarpc patterns

use crate::infra::TestInfrastructure;
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use futures::StreamExt;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tarpc::server::{BaseChannel, Channel};
use tokio::time::timeout;
use tracing::info;
use zoe_client::{
    RpcRequestListener, RpcResponseListener, TarpcOverMessagesClient, TarpcOverMessagesServer,
};
use zoe_wire_protocol::{MessageFilters, SubscriptionConfig};

/// Information about the echo service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// Echo service using tarpc service definition
#[tarpc::service]
pub trait EchoService {
    /// Echo a message back to the caller
    async fn echo(message: String) -> String;

    /// Get service information
    async fn get_info() -> ServiceInfo;

    /// Perform a simple calculation
    async fn add_numbers(a: i32, b: i32) -> i32;
}

// tarpc generates request/response types automatically - no wrapper needed!

/// Echo service implementation that implements the tarpc trait
#[derive(Clone)]
pub struct EchoServiceImpl {
    name: String,
    start_time: std::time::Instant,
}

impl EchoServiceImpl {
    pub fn new(name: String) -> Self {
        Self {
            name,
            start_time: std::time::Instant::now(),
        }
    }
}

impl EchoService for EchoServiceImpl {
    async fn echo(self, _context: tarpc::context::Context, message: String) -> String {
        info!("🔄 Echo service received: '{}'", message);
        format!("Echo: {message}")
    }

    async fn get_info(self, _context: tarpc::context::Context) -> ServiceInfo {
        info!("ℹ️ Echo service info requested");
        ServiceInfo {
            name: self.name.clone(),
            version: "1.0.0".to_string(),
            uptime_seconds: self.start_time.elapsed().as_secs(),
        }
    }

    async fn add_numbers(self, _context: tarpc::context::Context, a: i32, b: i32) -> i32 {
        info!("🧮 Adding {} + {}", a, b);
        a + b
    }
}

/// Test tarpc echo service using TarpcOverMessages transport
#[tokio::test]
async fn test_tarpc_echo_service_end_to_end() -> Result<()> {
    let infra = TestInfrastructure::setup().await?;

    // Create two clients with different keys - one for service, one for client
    let service_key = SigningKey::generate(&mut OsRng);
    let rpc_key = SigningKey::generate(&mut OsRng);

    let service_client = zoe_client::RelayClient::new(
        service_key.clone(),
        infra.server_public_key,
        infra.server_addr,
    )
    .await?;

    let rpc_client =
        zoe_client::RelayClient::new(rpc_key.clone(), infra.server_public_key, infra.server_addr)
            .await?;

    info!("🎯 Created service and client connections");

    // Connect both clients to message services
    let (service_messages, service_stream) = service_client
        .connect_message_service()
        .await
        .context("Failed to connect service to message service")?;

    let (client_messages, client_stream) = rpc_client
        .connect_message_service()
        .await
        .context("Failed to connect client to message service")?;

    info!("✅ Both clients connected to message services");

    // Set up subscriptions for both clients to receive messages targeted at them
    let service_subscription = SubscriptionConfig {
        filters: MessageFilters {
            authors: None,
            channels: None,
            events: None,
            users: Some(vec![service_key.verifying_key().to_bytes().to_vec()]),
        },
        since: None,
        limit: None,
    };

    let _service_sub_id = service_messages
        .subscribe(service_subscription)
        .await
        .context("Failed to subscribe service to targeted messages")?;

    let client_subscription = SubscriptionConfig {
        filters: MessageFilters {
            authors: None,
            channels: None,
            events: None,
            users: Some(vec![rpc_key.verifying_key().to_bytes().to_vec()]),
        },
        since: None,
        limit: None,
    };

    let _client_sub_id = client_messages
        .subscribe(client_subscription)
        .await
        .context("Failed to subscribe client to targeted messages")?;

    info!("📬 Both clients subscribed to messages targeted at them");

    // Wait for subscriptions to be processed
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create RPC listeners for the service and client
    let service_request_listener = RpcRequestListener::new(service_key.clone(), service_stream);
    let client_response_listener = RpcResponseListener::new(rpc_key.clone(), client_stream);

    info!("🔧 Created RPC listeners");

    // Create tarpc echo server using TarpcOverMessagesServer
    let echo_server = TarpcOverMessagesServer::new(
        service_request_listener,
        service_key.clone(),
        service_messages,
        move |transport| {
            let service = EchoServiceImpl::new("TestTarpcEchoService".to_string());
            let channel = BaseChannel::with_defaults(transport);

            tokio::spawn(async move {
                channel
                    .execute(service.serve())
                    .for_each(|response| async move {
                        tokio::spawn(response);
                    })
                    .await;
                Ok(())
            })
        },
    );

    info!("🚀 Created tarpc echo server");

    // Create tarpc echo client using TarpcOverMessagesClient
    let echo_client = TarpcOverMessagesClient::new(
        client_response_listener,
        rpc_key.clone(),
        client_messages,
        service_key.verifying_key(),
        move |transport| EchoServiceClient::new(Default::default(), transport).spawn(),
    );

    info!("📱 Created tarpc echo client");

    // Give the services a moment to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test 1: Simple echo (real tarpc style!)
    info!("🧪 Testing tarpc echo functionality...");
    let echo_response = timeout(
        Duration::from_secs(10),
        echo_client.echo(tarpc::context::current(), "Hello, tarpc World!".to_string()),
    )
    .await
    .context("tarpc Echo call timed out")?
    .context("tarpc Echo call failed")?;

    assert_eq!(echo_response, "Echo: Hello, tarpc World!");
    info!("✅ tarpc Echo test passed: {}", echo_response);

    // Test 2: Service info (real tarpc style!)
    info!("🧪 Testing tarpc service info retrieval...");
    let info_response = timeout(
        Duration::from_secs(10),
        echo_client.get_info(tarpc::context::current()),
    )
    .await
    .context("tarpc Get info call timed out")?
    .context("tarpc Get info call failed")?;

    assert_eq!(info_response.name, "TestTarpcEchoService");
    assert_eq!(info_response.version, "1.0.0");
    info!("✅ tarpc Service info test passed: {:?}", info_response);

    // Test 3: Addition calculation (real tarpc style!)
    info!("🧪 Testing tarpc calculation functionality...");
    let add_response = timeout(
        Duration::from_secs(10),
        echo_client.add_numbers(tarpc::context::current(), 42, 13),
    )
    .await
    .context("tarpc Add numbers call timed out")?
    .context("tarpc Add numbers call failed")?;

    assert_eq!(add_response, 55);
    info!("✅ tarpc Addition test passed: 42 + 13 = {}", add_response);

    // Test 4: Multiple concurrent requests (real tarpc style!)
    info!("🧪 Testing concurrent tarpc requests...");
    let mut handles = Vec::new();

    for i in 0..3 {
        let client = echo_client.clone();
        let test_message = format!("Concurrent tarpc message #{i}");

        let handle =
            tokio::spawn(async move { client.echo(tarpc::context::current(), test_message).await });
        handles.push((i, handle));
    }

    for (i, handle) in handles {
        let result = timeout(Duration::from_secs(10), handle).await???;
        assert_eq!(result, format!("Echo: Concurrent tarpc message #{i}"));
        info!("✅ Concurrent tarpc request #{i} passed");
    }

    info!("🎉 All tarpc echo service tests passed!");
    info!("   ✅ Real tarpc Echo functionality works over encrypted messages");
    info!("   ✅ Real tarpc Service info retrieval works");
    info!("   ✅ Real tarpc Calculation functionality works");
    info!("   ✅ Real tarpc Concurrent requests work");
    info!("   🚀 Real tarpc over encrypted message transport is working end-to-end!");

    // Cleanup
    echo_server.abort();
    echo_client.abort();

    Ok(())
}
