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
use forward_compatible_enum::ForwardCompatibleEnum;
use futures::{StreamExt, pin_mut};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tarpc::{
    ClientMessage, Request,
    server::{BaseChannel, Channel},
};
use tokio::time::timeout;
use tracing::info;
use zoe_client::{
    RpcMessageListener, TarpcOverMessagesClient, TarpcOverMessagesServer, rpc_transport::RpcMessage,
};
use zoe_wire_protocol::{MessageFilters, SubscriptionConfig};

/// Information about the echo service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub version: String,
    pub uptime_seconds: u64,
}

// Legacy version for testing
/// Echo service using tarpc service definition
#[tarpc::service]
pub trait EchoServiceV0 {
    /// Echo a message back to the caller
    async fn echo(message: String) -> String;

    /// Get service information
    async fn get_info() -> ServiceInfo;

    /// Perform a simple calculation
    async fn add_numbers(a: i32, b: i32) -> i32;
}
/// Echo service using tarpc service definition but is a newer service
#[tarpc::service]
pub trait EchoServiceV1 {
    /// Echo a message back to the caller
    async fn echo(message: String) -> String;

    /// Get service information
    async fn get_info() -> ServiceInfo;

    /// Perform a simple calculation
    async fn add_numbers(a: i32, b: i32) -> i32;

    // THis is the new feature. Important here: internally tarpc uses an enum and
    // that is ordered. So for simple backwards comptabile chnages, we  *must* add
    // the new features _at the end_ of the trait and keep all other signatures
    // exactly how they were.

    /// hello world variant
    async fn hello(name: String) -> String;
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

impl EchoServiceV1 for EchoServiceImpl {
    async fn echo(self, _context: tarpc::context::Context, message: String) -> String {
        info!("🔄 Echo service received: '{}'", message);
        format!("Echo: {message}")
    }

    async fn hello(self, _context: tarpc::context::Context, name: String) -> String {
        info!("👋 Hello service received: '{}'", name);
        format!("Hello, {name}!")
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

#[derive(Debug, ForwardCompatibleEnum)]
pub enum EchoServiceRequestInner {
    #[discriminant(0)]
    V0(EchoServiceV0Request),
    #[discriminant(1)]
    V1(EchoServiceV1Request),
    Unknown {
        discriminant: u32,
        data: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EchoServiceRequest(ClientMessage<EchoServiceRequestInner>);

impl EchoServiceRequest {
    pub fn unwrap_message(self) -> Option<ClientMessage<EchoServiceV1Request>> {
        match self.0 {
            ClientMessage::Cancel {
                request_id,
                trace_context,
            } => Some(ClientMessage::Cancel {
                request_id,
                trace_context,
            }),
            ClientMessage::Request(Request {
                message: EchoServiceRequestInner::V1(request),
                context,
                id,
            }) => Some(ClientMessage::Request(Request {
                message: request,
                context,
                id,
            })),
            ClientMessage::Request(Request {
                message: EchoServiceRequestInner::V0(request),
                context,
                id,
            }) => {
                let new_message = match request {
                    EchoServiceV0Request::Echo { message } => {
                        EchoServiceV1Request::Echo { message }
                    }
                    EchoServiceV0Request::GetInfo {} => EchoServiceV1Request::GetInfo {},
                    EchoServiceV0Request::AddNumbers { a, b } => EchoServiceV1Request::AddNumbers {
                        a,
                        b,
                    },
                }; // we rewrite that into the v1 request
                Some(ClientMessage::Request(Request {
                    message: new_message,
                    context,
                    id,
                }))
            }
            _ => None, // we don't support anything else
        }
    }
}

/// Test tarpc echo service using TarpcOverMessages transport
#[tokio::test]
async fn test_tarpc_echo_service_end_to_end() -> Result<()> {
    let infra = TestInfrastructure::setup().await?;

    // Create two clients with different keys - one for service, one for client
    let service_key = SigningKey::generate(&mut OsRng);
    let rpc_key_v0 = SigningKey::generate(&mut OsRng);
    let rpc_key_v1 = SigningKey::generate(&mut OsRng);

    let service_client = zoe_client::RelayClient::new(
        service_key.clone(),
        infra.server_public_key,
        infra.server_addr,
    )
    .await?;

    let rpc_client_v0 = zoe_client::RelayClient::new(
        rpc_key_v0.clone(),
        infra.server_public_key,
        infra.server_addr,
    )
    .await?;

    let rpc_client_v1 = zoe_client::RelayClient::new(
        rpc_key_v1.clone(),
        infra.server_public_key,
        infra.server_addr,
    )
    .await?;

    info!("🎯 Created service and client connections");

    // Connect both clients to message services
    let (service_messages, service_stream) = service_client
        .connect_message_service()
        .await
        .context("Failed to connect service to message service")?;

    let (client_messages_v0, client_stream_v0) = rpc_client_v0
        .connect_message_service()
        .await
        .context("Failed to connect client to message service")?;

    let (client_messages_v1, client_stream_v1) = rpc_client_v1
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

    let client_subscription_v0 = SubscriptionConfig {
        filters: MessageFilters {
            authors: None,
            channels: None,
            events: None,
            users: Some(vec![rpc_key_v0.verifying_key().to_bytes().to_vec()]),
        },
        since: None,
        limit: None,
    };

    let _client_sub_id = client_messages_v0
        .subscribe(client_subscription_v0)
        .await
        .context("Failed to subscribe client to targeted messages")?;

    let client_subscription_v1 = SubscriptionConfig {
        filters: MessageFilters {
            authors: None,
            channels: None,
            events: None,
            users: Some(vec![rpc_key_v1.verifying_key().to_bytes().to_vec()]),
        },
        since: None,
        limit: None,
    };

    let _client_sub_id = client_messages_v1
        .subscribe(client_subscription_v1)
        .await
        .context("Failed to subscribe client to targeted messages")?;

    info!("📬 alll clients subscribed to messages targeted at them");

    // Wait for subscriptions to be processed
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create RPC listeners for the service and client
    let service_request_stream =
        RpcMessageListener::<EchoServiceRequest>::new(service_key.clone(), service_stream);
    let service_request_listener = Box::pin(service_request_stream.filter_map(|msg| async move {
        let RpcMessage { content, header } = msg;
        content
            .unwrap_message()
            .map(|c| RpcMessage { content: c, header })
    }));

    info!("🔧 Created RPC server listeners");

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

    let client_response_listener = RpcMessageListener::new(rpc_key_v0.clone(), client_stream_v0);

    // Create tarpc echo client using TarpcOverMessagesClient
    let echo_client_v0 = TarpcOverMessagesClient::new_with_mapper(
        client_response_listener,
        rpc_key_v0.clone(),
        client_messages_v0,
        service_key.verifying_key(),
        move |transport| EchoServiceV0Client::new(Default::default(), transport).spawn(),
        |rpc_message| match rpc_message {
            ClientMessage::Request(Request {
                message,
                context,
                id,
            }) => ClientMessage::Request(Request {
                message: EchoServiceRequestInner::V0(message),
                context,
                id,
            }),
            ClientMessage::Cancel {
                request_id,
                trace_context,
            } => ClientMessage::Cancel {
                request_id,
                trace_context,
            },
            _ => panic!("Expected Request or Cancel, got {rpc_message:?}"),
        },
    );

    info!("📱 Created tarpc echo client v0");

    let client_response_listener = RpcMessageListener::new(rpc_key_v1.clone(), client_stream_v1);

    // Create tarpc echo client using TarpcOverMessagesClient
    let echo_client_v1 = TarpcOverMessagesClient::new_with_mapper(
        client_response_listener,
        rpc_key_v1.clone(),
        client_messages_v1,
        service_key.verifying_key(),
        move |transport| EchoServiceV1Client::new(Default::default(), transport).spawn(),
        |rpc_message| match rpc_message {
            ClientMessage::Request(Request {
                message,
                context,
                id,
            }) => ClientMessage::Request(Request {
                message: EchoServiceRequestInner::V1(message),
                context,
                id,
            }),
            ClientMessage::Cancel {
                request_id,
                trace_context,
            } => ClientMessage::Cancel {
                request_id,
                trace_context,
            },
            _ => panic!("Expected Request or Cancel, got {rpc_message:?}"),
        },
    );

    info!("📱 Created tarpc echo client v0");

    // Give the services a moment to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test 1: Simple echo (real tarpc style!)
    info!("🧪 Testing tarpc echo functionality...");
    let echo_response = timeout(
        Duration::from_secs(10),
        echo_client_v0.echo(tarpc::context::current(), "Hello, tarpc World!".to_string()),
    )
    .await
    .context("tarpc Echo call timed out")?
    .context("tarpc Echo call failed")?;
    assert_eq!(echo_response, "Echo: Hello, tarpc World!");
    info!("✅ tarpc Echo test passed: {}", echo_response);

    let echo_response = timeout(
        Duration::from_secs(10),
        echo_client_v1.echo(tarpc::context::current(), "Hello, from v1!".to_string()),
    )
    .await
    .context("tarpc Echo call timed out")?
    .context("tarpc Echo call failed")?;

    assert_eq!(echo_response, "Echo: Hello, from v1!");
    info!("✅ tarpc Echo test passed: {}", echo_response);

    info!("✅ tarpc Hello v1 test passed: {}", echo_response);

    let echo_response = timeout(
        Duration::from_secs(10),
        echo_client_v1.hello(tarpc::context::current(), "John".to_string()),
    )
    .await
    .context("tarpc Echo call timed out")?
    .context("tarpc Echo call failed")?;

    assert_eq!(echo_response, "Hello, John!");
    info!("✅ tarpc Hello v1 test passed: {}", echo_response);

    // Test 2: Service info (real tarpc style!)
    info!("🧪 Testing tarpc service info retrieval...");
    let info_response = timeout(
        Duration::from_secs(10),
        echo_client_v0.get_info(tarpc::context::current()),
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
        echo_client_v0.add_numbers(tarpc::context::current(), 42, 13),
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
        let client = echo_client_v0.clone();
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
    echo_client_v0.abort();

    Ok(())
}
