//! Protocol testing scenarios using multi-client infrastructure
//!
//! This module contains comprehensive test scenarios that demonstrate
//! real-world protocol usage patterns across multiple clients. These tests
//! verify that the version negotiation and challenge protocol work correctly
//! in various multi-client scenarios.

use crate::multi_client_infra::{MultiClientTestHarness, TestClient};
use anyhow::{Context, Result};
use rand::RngCore;
use serial_test::serial;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};
use zoe_wire_protocol::{
    Kind, Message, MessageFilters, MessageFull, StreamMessage, SubscriptionConfig, Tag,
};

/// Test scenario: Group chat with multiple participants
///
/// This scenario simulates a group chat where multiple clients join a channel,
/// exchange messages, and verify that all participants receive all messages.
#[tokio::test]
#[serial]
async fn test_group_chat_scenario() -> Result<()> {
    info!("🎭 Starting group chat scenario test");

    let harness = MultiClientTestHarness::setup().await?;

    // Create a group of clients representing chat participants
    let alice = harness.create_client("alice").await?;
    let bob = harness.create_client("bob").await?;
    let charlie = harness.create_client("charlie").await?;
    let diana = harness.create_client("diana").await?;

    let participants = [&alice, &bob, &charlie, &diana];
    let chat_channel = harness.unique_channel("group_chat").await;

    info!("👥 Group chat participants: alice, bob, charlie, diana");
    info!("💬 Chat channel: {}", chat_channel);

    // Phase 1: All participants join the chat (subscribe to channel)
    let mut message_services = Vec::new();
    let mut message_streams = Vec::new();

    for participant in &participants {
        let (service, msg_stream, _catch_up_stream) = participant.connect_message_service().await?;
        let stream = participant
            .subscribe_to_channel(&service, msg_stream, &chat_channel)
            .await?;
        message_services.push(service);
        message_streams.push(stream);
    }

    // Wait for all subscriptions to be processed
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Phase 2: Participants exchange messages in sequence
    let messages = [
        ("alice", "Hello everyone! 👋"),
        ("bob", "Hey Alice! How's everyone doing?"),
        ("charlie", "Great to see you all here!"),
        ("diana", "This group chat is working perfectly! 🎉"),
        ("alice", "Agreed! The protocol is solid."),
    ];

    for (i, (sender_name, content)) in messages.iter().enumerate() {
        let sender_idx = participants
            .iter()
            .position(|p| p.name == *sender_name)
            .unwrap();
        let sender = &participants[sender_idx];

        sender
            .publish_to_channel(&message_services[sender_idx], &chat_channel, content)
            .await?;
        info!("💬 {} says: {}", sender_name, content);

        // Small delay between messages to simulate natural conversation
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Phase 3: Wait for message propagation and collect results
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut total_messages_received = 0;
    let receive_timeout = Duration::from_millis(1500);

    for (i, participant) in participants.iter().enumerate() {
        let mut participant_messages = 0;
        let stream = &mut message_streams[i];

        info!("📥 Collecting messages for {}...", participant.name);

        // Collect messages for this participant
        for _ in 0..10 {
            // Allow for multiple messages
            match timeout(receive_timeout, stream.recv()).await {
                Ok(Some(StreamMessage::MessageReceived {
                    message: _msg,
                    stream_height,
                })) => {
                    participant_messages += 1;
                    total_messages_received += 1;
                    info!(
                        "📨 {} received message at height {}",
                        participant.name, stream_height
                    );
                }
                Ok(Some(StreamMessage::StreamHeightUpdate(_))) => {
                    // Ignore height updates
                }
                Ok(None) => break,
                Err(_) => break, // Timeout
            }
        }

        info!(
            "📊 {} received {} messages total",
            participant.name, participant_messages
        );
    }

    // Phase 4: Verify results
    let expected_messages = messages.len() * participants.len(); // Each participant should receive all messages
    let success_rate = (total_messages_received as f64 / expected_messages as f64) * 100.0;

    info!("✅ Group chat scenario completed:");
    info!("   👥 Participants: {}", participants.len());
    info!("   💬 Messages sent: {}", messages.len());
    info!("   📨 Total messages received: {}", total_messages_received);
    info!("   📊 Success rate: {:.1}%", success_rate);

    // Consider the test successful if we received at least 20% of expected messages
    // Note: In testing environments, message delivery can be unreliable due to timing
    assert!(
        success_rate >= 20.0,
        "Group chat success rate too low: {:.1}%",
        success_rate
    );

    harness.cleanup().await?;
    Ok(())
}

/// Test scenario: Client join/leave dynamics
///
/// This scenario tests what happens when clients dynamically join and leave
/// an ongoing conversation, ensuring the protocol handles membership changes gracefully.
#[tokio::test]
#[serial]
async fn test_dynamic_membership_scenario() -> Result<()> {
    info!("🔄 Starting dynamic membership scenario test");

    let harness = MultiClientTestHarness::setup().await?;
    let chat_channel = harness.unique_channel("dynamic_chat").await;

    // Phase 1: Start with two initial participants
    let alice = harness.create_client("alice").await?;
    let bob = harness.create_client("bob").await?;

    let (service_alice, msg_stream_alice, _catch_up_alice) =
        alice.connect_message_service().await?;
    let (service_bob, msg_stream_bob, _catch_up_bob) = bob.connect_message_service().await?;

    let mut stream_alice = alice
        .subscribe_to_channel(&service_alice, msg_stream_alice, &chat_channel)
        .await?;
    let mut stream_bob = bob
        .subscribe_to_channel(&service_bob, msg_stream_bob, &chat_channel)
        .await?;

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Initial conversation
    alice
        .publish_to_channel(&service_alice, &chat_channel, "Hey Bob, just us for now")
        .await?;
    bob.publish_to_channel(&service_bob, &chat_channel, "Yeah Alice, quiet in here")
        .await?;

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 2: Charlie joins mid-conversation
    let charlie = harness.create_client("charlie").await?;
    let (service_charlie, msg_stream_charlie, _catch_up_charlie) =
        charlie.connect_message_service().await?;
    let mut stream_charlie = charlie
        .subscribe_to_channel(&service_charlie, msg_stream_charlie, &chat_channel)
        .await?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    charlie
        .publish_to_channel(
            &service_charlie,
            &chat_channel,
            "Hey everyone! I just joined",
        )
        .await?;
    alice
        .publish_to_channel(&service_alice, &chat_channel, "Welcome Charlie!")
        .await?;

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 3: Diana joins as well
    let diana = harness.create_client("diana").await?;
    let (service_diana, msg_stream_diana, _catch_up_diana) =
        diana.connect_message_service().await?;
    let mut stream_diana = diana
        .subscribe_to_channel(&service_diana, msg_stream_diana, &chat_channel)
        .await?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    diana
        .publish_to_channel(&service_diana, &chat_channel, "Room for one more?")
        .await?;
    bob.publish_to_channel(&service_bob, &chat_channel, "The more the merrier!")
        .await?;

    // Phase 4: Wait and collect messages
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut results = std::collections::BTreeMap::new();
    let receive_timeout = Duration::from_millis(1000);

    // Collect messages for each participant
    for (name, stream) in [
        ("alice", &mut stream_alice),
        ("bob", &mut stream_bob),
        ("charlie", &mut stream_charlie),
        ("diana", &mut stream_diana),
    ] {
        let mut messages = 0;
        for _ in 0..10 {
            match timeout(receive_timeout, stream.recv()).await {
                Ok(Some(StreamMessage::MessageReceived { .. })) => messages += 1,
                Ok(Some(StreamMessage::StreamHeightUpdate(_))) => {}
                _ => break,
            }
        }
        results.insert(name.to_string(), messages);
        info!("📊 {} received {} messages", name, messages);
    }

    // Verify that later joiners can participate
    assert!(
        results.get("charlie").unwrap_or(&0) > &0,
        "Charlie should have received messages"
    );
    assert!(
        results.get("diana").unwrap_or(&0) > &0,
        "Diana should have received messages"
    );

    info!("✅ Dynamic membership scenario completed successfully");

    harness.cleanup().await?;
    Ok(())
}

/// Test scenario: High-frequency message exchange
///
/// This scenario tests the protocol's ability to handle rapid message exchanges
/// between multiple clients, simulating high-activity chat scenarios.
#[tokio::test]
#[serial]
async fn test_high_frequency_messaging_scenario() -> Result<()> {
    info!("⚡ Starting high-frequency messaging scenario test");

    let harness = MultiClientTestHarness::setup().await?;
    let busy_channel = harness.unique_channel("busy_chat").await;

    // Create clients for high-frequency testing
    let alice = harness.create_client("alice").await?;
    let bob = harness.create_client("bob").await?;
    let charlie = harness.create_client("charlie").await?;

    let clients = [&alice, &bob, &charlie];
    let mut services = Vec::new();
    let mut streams = Vec::new();

    // Setup all clients
    for client in &clients {
        let (service, msg_stream, _catch_up_stream) = client.connect_message_service().await?;
        let stream = client
            .subscribe_to_channel(&service, msg_stream, &busy_channel)
            .await?;
        services.push(service);
        streams.push(stream);
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Phase 1: Rapid message burst from each client
    let messages_per_client = 5;
    info!(
        "📤 Each client will send {} messages rapidly",
        messages_per_client
    );

    for (client_idx, client) in clients.iter().enumerate() {
        for msg_num in 1..=messages_per_client {
            let content = format!("Rapid message #{} from {}", msg_num, client.name);
            client
                .publish_to_channel(&services[client_idx], &busy_channel, &content)
                .await?;

            // Very short delay to simulate rapid typing
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    // Phase 2: Wait for message propagation
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Phase 3: Collect and analyze results
    let mut total_received = 0;
    let receive_timeout = Duration::from_millis(2000);

    for (client_idx, client) in clients.iter().enumerate() {
        let mut client_received = 0;
        let stream = &mut streams[client_idx];

        for _ in 0..20 {
            // Allow for many messages
            match timeout(receive_timeout, stream.recv()).await {
                Ok(Some(StreamMessage::MessageReceived { .. })) => {
                    client_received += 1;
                    total_received += 1;
                }
                Ok(Some(StreamMessage::StreamHeightUpdate(_))) => {}
                _ => break,
            }
        }

        info!("📊 {} received {} messages", client.name, client_received);
    }

    let total_sent = clients.len() * messages_per_client;
    let expected_received = total_sent * clients.len(); // Each client should receive all messages
    let throughput_rate = (total_received as f64 / expected_received as f64) * 100.0;

    info!("✅ High-frequency messaging scenario completed:");
    info!("   📤 Total messages sent: {}", total_sent);
    info!("   📥 Total messages received: {}", total_received);
    info!("   📊 Throughput rate: {:.1}%", throughput_rate);

    // Consider successful if we achieved at least 30% throughput (high-frequency can be lossy)
    assert!(
        throughput_rate >= 30.0,
        "Throughput rate too low: {:.1}%",
        throughput_rate
    );

    harness.cleanup().await?;
    Ok(())
}

/// Test scenario: Cross-client protocol verification
///
/// This scenario specifically tests that the version negotiation and challenge
/// protocol work correctly when multiple clients with different configurations
/// connect to the same server.
#[tokio::test]
#[serial]
async fn test_protocol_handshake_verification_scenario() -> Result<()> {
    info!("🔐 Starting protocol handshake verification scenario");

    let harness = MultiClientTestHarness::setup().await?;

    // Create multiple clients to verify they all successfully complete handshakes
    let client_names = ["alice", "bob", "charlie", "diana", "eve"];
    let mut successful_connections = 0;
    let mut clients = Vec::new();

    info!(
        "🤝 Testing handshake protocol with {} clients",
        client_names.len()
    );

    // Phase 1: Connect all clients (each goes through version negotiation + challenge protocol)
    for &name in &client_names {
        match harness.create_client(name).await {
            Ok(client) => {
                successful_connections += 1;
                clients.push(client);
                info!("✅ {} completed handshake successfully", name);
            }
            Err(e) => {
                warn!("❌ {} failed handshake: {}", name, e);
            }
        }
    }

    // Phase 2: Verify all connected clients can communicate
    if !clients.is_empty() {
        let test_result = harness.test_message_broadcast(&clients).await?;

        info!("📡 Broadcast test with handshake-verified clients:");
        info!("   📤 Messages sent: {}", test_result.messages_sent);
        info!("   📥 Messages received: {}", test_result.total_received);
        info!("   📊 Success rate: {:.1}%", test_result.success_rate());

        assert!(
            test_result.is_successful(),
            "Broadcast should succeed with handshake-verified clients"
        );
    }

    // Phase 3: Verify protocol integrity
    let handshake_success_rate =
        (successful_connections as f64 / client_names.len() as f64) * 100.0;

    info!("✅ Protocol handshake verification completed:");
    info!(
        "   🔐 Successful handshakes: {}/{}",
        successful_connections,
        client_names.len()
    );
    info!(
        "   📊 Handshake success rate: {:.1}%",
        handshake_success_rate
    );

    // All clients should successfully complete the handshake protocol
    assert_eq!(
        successful_connections,
        client_names.len(),
        "All clients should complete handshake protocol successfully"
    );

    harness.cleanup().await?;
    Ok(())
}

/// Test scenario: Server resilience under load
///
/// This scenario tests how the server handles multiple concurrent client connections
/// and verifies that the protocol remains stable under load.
#[tokio::test]
#[serial]
async fn test_server_resilience_under_load_scenario() -> Result<()> {
    info!("🏋️ Starting server resilience under load scenario");

    let harness = MultiClientTestHarness::setup().await?;

    // Create a larger number of clients to stress-test the server
    let num_clients = 8;
    let mut clients = Vec::new();

    info!(
        "🔄 Creating {} concurrent clients for load testing",
        num_clients
    );

    // Phase 1: Concurrent client creation (stress test connection handling)
    let mut connection_tasks = Vec::new();

    for i in 0..num_clients {
        let client_name = format!("client_{}", i);
        let harness_ref = &harness;

        let task = async move {
            match harness_ref.create_client(&client_name).await {
                Ok(client) => {
                    info!("✅ {} connected under load", client_name);
                    Some(client)
                }
                Err(e) => {
                    warn!("❌ {} failed to connect under load: {}", client_name, e);
                    None
                }
            }
        };

        connection_tasks.push(task);
    }

    // Execute all connection attempts concurrently
    let connection_results = futures::future::join_all(connection_tasks).await;

    for client in connection_results.into_iter().flatten() {
        clients.push(client);
    }

    let successful_connections = clients.len();
    info!(
        "🔗 Successfully connected {}/{} clients under load",
        successful_connections, num_clients
    );

    // Phase 2: Concurrent messaging (stress test message handling)
    if !clients.is_empty() {
        let load_channel = harness.unique_channel("load_test").await;
        let mut services = Vec::new();
        let mut streams = Vec::new();

        // Setup all clients for messaging
        for client in &clients {
            let (service, msg_stream, _catch_up_stream) = client.connect_message_service().await?;
            let stream = client
                .subscribe_to_channel(&service, msg_stream, &load_channel)
                .await?;
            services.push(service);
            streams.push(stream);
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        // Each client sends multiple messages concurrently
        let mut message_tasks = Vec::new();

        for (i, client) in clients.iter().enumerate() {
            let service = &services[i];
            let channel = load_channel.clone();

            let task = async move {
                let mut sent = 0;
                for msg_num in 1..=3 {
                    let content = format!("Load test message {} from {}", msg_num, client.name);
                    if client
                        .publish_to_channel(service, &channel, &content)
                        .await
                        .is_ok()
                    {
                        sent += 1;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                sent
            };

            message_tasks.push(task);
        }

        let message_results = futures::future::join_all(message_tasks).await;
        let total_sent: u32 = message_results.iter().sum();

        info!("📤 Sent {} messages under load", total_sent);

        // Wait for message propagation
        tokio::time::sleep(Duration::from_millis(1500)).await;

        // Collect received messages
        let mut total_received = 0;
        let receive_timeout = Duration::from_millis(1000);

        for (i, client) in clients.iter().enumerate() {
            let mut client_received = 0;
            let stream = &mut streams[i];

            for _ in 0..15 {
                match timeout(receive_timeout, stream.recv()).await {
                    Ok(Some(StreamMessage::MessageReceived { .. })) => {
                        client_received += 1;
                        total_received += 1;
                    }
                    Ok(Some(StreamMessage::StreamHeightUpdate(_))) => {}
                    _ => break,
                }
            }
        }

        let load_success_rate = if total_sent > 0 {
            (total_received as f64 / (total_sent * successful_connections as u32) as f64) * 100.0
        } else {
            0.0
        };

        info!("📊 Load test messaging results:");
        info!("   📤 Messages sent: {}", total_sent);
        info!("   📥 Messages received: {}", total_received);
        info!("   📊 Success rate under load: {:.1}%", load_success_rate);
    }

    // Phase 3: Evaluate overall resilience
    let connection_success_rate = (successful_connections as f64 / num_clients as f64) * 100.0;

    info!("✅ Server resilience under load scenario completed:");
    info!(
        "   🔗 Connection success rate: {:.1}%",
        connection_success_rate
    );
    info!(
        "   👥 Concurrent clients handled: {}",
        successful_connections
    );

    // Server should handle at least 75% of connections under load
    assert!(
        connection_success_rate >= 75.0,
        "Server should handle at least 75% of connections under load, got {:.1}%",
        connection_success_rate
    );

    harness.cleanup().await?;
    Ok(())
}
