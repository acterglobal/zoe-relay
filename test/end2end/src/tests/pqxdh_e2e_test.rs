//! End-to-end tests for PQXDH protocol using multi-client infrastructure
//!
//! This module tests the complete PQXDH protocol flow:
//! 1. Service provider publishes an inbox
//! 2. Client discovers and connects to the inbox
//! 3. Client sends a message over the established session
//! 4. Service provider receives and echoes the message back
//! 5. Client receives and verifies the echoed message

use crate::multi_client_infra::{MultiClientTestHarness, TestClient};
use anyhow::{Context, Result};
use futures::StreamExt;
use serial_test::serial;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};
use zoe_client::pqxdh::{PqxdhError, PqxdhProtocolHandler};
use zoe_client::services::messages_manager::MessagesManager;
use zoe_wire_protocol::{KeyPair, PqxdhInboxProtocol};

#[tokio::test]
#[serial]
async fn test_pqxdh_simple_echo_e2e() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    let _ = env_logger::try_init();
    info!("🚀 Starting PQXDH echo service end-to-end test");

    // Setup test infrastructure with two clients
    let harness = MultiClientTestHarness::setup().await?;
    let alice = harness.create_client("alice").await?;
    let bob = harness.create_client("bob").await?;

    info!("👥 Created clients: Alice (service provider) and Bob (client)");

    // Create MessagesManagers for both clients
    let alice_manager = create_messages_manager(&alice).await?;
    let bob_manager = create_messages_manager(&bob).await?;

    info!("📡 Created MessagesManagers for both clients");

    // Alice sets up as service provider
    let mut alice_handler = alice
        .client
        .session_manager()
        .await
        .pqxdh_handler(PqxdhInboxProtocol::EchoService)
        .await?;

    // Alice publishes her service inbox
    let inbox_tag = alice_handler.publish_service(false).await?;

    info!("📮 Alice published PQXDH inbox with tag: {:?}", inbox_tag);

    // Alice starts listening for incoming client connections BEFORE Bob connects
    let mut alice_inbox_stream = Box::pin(alice_handler.inbox_stream::<String>().await?);

    info!("👂 Alice is now listening on the inbox");

    // Give Alice's service a moment to be fully published and discoverable
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Bob sets up as client
    let mut bob_handler = bob
        .client
        .session_manager()
        .await
        .pqxdh_handler(PqxdhInboxProtocol::EchoService)
        .await?;

    // Bob connects to Alice's service
    let initial_message = "Hello Alice!".to_string();
    let alice_public_key = alice.public_key();
    let (bob_session_id, mut bob_responses) = bob_handler
        .connect_to_service::<String, String>(&alice_public_key, &initial_message)
        .await?;
    let mut bob_response_stream = Box::pin(bob_responses);

    info!(
        "🤝 Bob connected to Alice's service and sent: '{}'",
        initial_message
    );

    // Alice receives Bob's initial message
    let (alice_session_id, received_message) =
        timeout(Duration::from_secs(5), alice_inbox_stream.next())
            .await
            .unwrap()
            .unwrap();

    info!(
        "📨 Alice received message from session {:?}: '{}'",
        alice_session_id, received_message
    );

    // Verify Alice received the correct message
    assert_eq!(
        received_message, initial_message,
        "Alice should receive Bob's initial message"
    );

    // Alice echoes the message back
    let echo_message = format!("Echo: {received_message}");
    alice_handler
        .send_message(&alice_session_id, &echo_message)
        .await
        .unwrap();

    info!("📤 Alice sent echo message: '{}'", echo_message);

    // Bob receives Alice's echo response
    let response = timeout(Duration::from_secs(5), bob_response_stream.next())
        .await
        .unwrap()
        .unwrap();

    info!("📨 Bob received response: '{}'", response);

    // Verify Bob received the correct echo
    assert_eq!(
        response, echo_message,
        "Bob should receive the echoed message from Alice"
    );

    // Test additional message exchange
    let follow_up_message = "How are you?".to_string();

    bob_handler
        .send_message(&bob_session_id, &follow_up_message)
        .await
        .unwrap();

    info!("📤 Bob sent follow-up message: '{}'", follow_up_message);

    let mut alice_listen_stream = Box::pin(
        alice_handler
            .listen_for_messages::<String>(alice_session_id, true)
            .await?,
    );

    // Alice receives the follow-up message
    let received_follow_up = timeout(Duration::from_secs(5), alice_listen_stream.next())
        .await
        .unwrap()
        .unwrap();

    info!("📨 Alice received follow-up '{}'", received_follow_up);

    assert_eq!(
        received_follow_up, follow_up_message,
        "Alice should receive Bob's follow-up message"
    );

    // Alice echoes the follow-up message
    let echo_follow_up = format!("Echo: {received_follow_up}");
    alice_handler
        .send_message(&alice_session_id, &echo_follow_up)
        .await
        .unwrap();

    info!("📤 Alice sent follow-up echo: '{}'", echo_follow_up);

    // Bob receives the follow-up echo
    let follow_up_response = timeout(Duration::from_secs(5), bob_response_stream.next())
        .await
        .unwrap()
        .unwrap();

    info!(
        "📨 Bob received follow-up response: '{}'",
        follow_up_response
    );

    // Verify the follow-up echo is correct
    assert_eq!(
        follow_up_response, echo_follow_up,
        "Bob should receive the echoed follow-up message"
    );

    info!("✅ PQXDH echo service test completed successfully!");
    info!("   - Session established between Alice and Bob");
    info!(
        "   - Initial message: '{}' -> Echo: '{}'",
        initial_message, echo_message
    );
    info!(
        "   - Follow-up message: '{}' -> Echo: '{}'",
        follow_up_message, echo_follow_up
    );

    // Cleanup
    harness.cleanup().await?;

    Ok(())
}

/// Test PQXDH error handling scenarios
#[tokio::test]
#[serial]
async fn test_pqxdh_error_scenarios() -> Result<()> {
    info!("🚀 Starting PQXDH error handling test");

    let harness = MultiClientTestHarness::setup().await?;
    let alice = harness.create_client("alice").await?;
    let bob = harness.create_client("bob").await?;

    let alice_manager = create_messages_manager(&alice).await?;
    let bob_manager = create_messages_manager(&bob).await?;

    // Test 1: Connecting to non-existent service
    let mut bob_handler = PqxdhProtocolHandler::new(
        Arc::new(bob_manager),
        Arc::new(KeyPair::generate(&mut rand::thread_rng())),
        PqxdhInboxProtocol::EchoService,
    );

    // Try to connect to Alice before she publishes a service
    let alice_public_key = alice.public_key();
    let hello_message = "Hello".to_string();
    let result = bob_handler
        .connect_to_service::<String, String>(&alice_public_key, &hello_message)
        .await;

    match result {
        Err(PqxdhError::InboxNotFound) => {
            info!(
                "✅ Correctly received InboxNotFound error when connecting to non-existent service"
            );
        }
        Err(e) => {
            warn!("❌ Expected InboxNotFound error, got: {:?}", e);
            return Err(anyhow::anyhow!(
                "Expected InboxNotFound error, got: {:?}",
                e
            ));
        }
        Ok(_) => {
            return Err(anyhow::anyhow!(
                "Expected error when connecting to non-existent service"
            ));
        }
    }

    // Test 2: Double service publication
    let mut alice_handler = PqxdhProtocolHandler::new(
        Arc::new(alice_manager),
        Arc::new(KeyPair::generate(&mut rand::thread_rng())),
        PqxdhInboxProtocol::EchoService,
    );

    // First publication should succeed
    alice_handler
        .publish_service(false)
        .await
        .context("First service publication should succeed")?;

    // Second publication without force_overwrite should fail
    let result = alice_handler.publish_service(false).await;
    match result {
        Err(PqxdhError::InboxAlreadyPublished) => {
            info!("✅ Correctly received InboxAlreadyPublished error on duplicate publication");
        }
        Err(e) => {
            warn!("❌ Expected InboxAlreadyPublished error, got: {:?}", e);
            return Err(anyhow::anyhow!(
                "Expected InboxAlreadyPublished error, got: {:?}",
                e
            ));
        }
        Ok(_) => {
            return Err(anyhow::anyhow!(
                "Expected error on duplicate service publication"
            ));
        }
    }

    // Test 3: Force overwrite should succeed
    alice_handler
        .publish_service(true)
        .await
        .context("Service publication with force_overwrite should succeed")?;

    info!("✅ Service publication with force_overwrite succeeded");

    info!("✅ PQXDH error handling test completed successfully!");

    harness.cleanup().await?;
    Ok(())
}

/// Helper function to create a MessagesManager from a TestClient
async fn create_messages_manager(client: &TestClient) -> Result<MessagesManager> {
    MessagesManager::builder()
        .autosubscribe(true)
        .build(client.client.connection())
        .await
        .context("Failed to create MessagesManager")
}
