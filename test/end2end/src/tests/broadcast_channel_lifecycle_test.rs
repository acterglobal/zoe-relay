//! Test for broadcast channel lifecycle issues in MessagesManager
//!
//! This test specifically targets the broadcast channel receiver dropping issue
//! that causes "Stream message send failed (receiver may be dropped): channel closed" warnings.

use anyhow::{Context, Result};
use futures::StreamExt;
use serial_test::serial;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};
use zoe_client::services::MessagesManager;
use zoe_wire_protocol::{Filter, Kind, Message, MessageFull, Tag};

use crate::infra::TestInfrastructure;

/// Test that demonstrates the broadcast channel receiver dropping issue
#[tokio::test]
#[serial]
async fn test_broadcast_channel_receiver_lifecycle_issue() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    info!("🧪 Testing broadcast channel receiver lifecycle issue");

    // Setup test infrastructure
    let infra = TestInfrastructure::setup().await?;
    let client = infra.create_client().await?;

    // Create a MessagesManager
    let messages_manager = MessagesManager::builder()
        .autosubscribe(true)
        .build(client.connection())
        .await?;

    info!("📡 Created MessagesManager");

    // Create a test filter
    let test_tag = Tag::Channel {
        id: b"test_channel".to_vec(),
        relays: vec![],
    };
    let test_filter = Filter::from(test_tag.clone());

    // Ensure the filter is subscribed
    messages_manager
        .ensure_contains_filter(test_filter.clone())
        .await?;

    info!("🔍 Subscribed to filter: {:?}", test_filter);

    // STEP 1: Create a filtered stream but DON'T poll it immediately
    // This simulates the problematic pattern where streams are created but not immediately used
    let filtered_stream = messages_manager
        .clone()
        .filtered_messages_stream(test_filter.clone());

    info!("📺 Created filtered stream (but not polling yet)");

    // STEP 2: Wait a moment to let any background tasks settle
    tokio::time::sleep(Duration::from_millis(100)).await;

    // STEP 3: Publish a message that should match the filter
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let test_message_raw = Message::new_v0_raw(
        b"Test message for broadcast channel lifecycle".to_vec(),
        client.public_key(),
        timestamp,
        Kind::Ephemeral(60),
        vec![test_tag],
    );

    let test_message = MessageFull::new(test_message_raw, client.keypair())?;

    info!("📤 Publishing test message");
    let publish_result = messages_manager.publish(test_message.clone()).await?;
    info!("✅ Message published with result: {:?}", publish_result);

    // STEP 4: Wait a moment for message propagation
    tokio::time::sleep(Duration::from_millis(500)).await;

    // STEP 5: NOW try to poll the stream (this should fail due to receiver being dropped)
    info!("📺 Now attempting to poll the filtered stream...");

    let mut filtered_stream = Box::pin(filtered_stream);
    let result = timeout(Duration::from_secs(5), filtered_stream.next()).await;

    match result {
        Ok(Some(received_message)) => {
            info!(
                "✅ Successfully received message: {}",
                hex::encode(received_message.id().as_bytes())
            );
            // This would be the ideal case, but we expect it to fail due to the broadcast channel issue
        }
        Ok(None) => {
            warn!("❌ Stream ended unexpectedly (no message received)");
            return Err(anyhow::anyhow!(
                "Stream ended without receiving message - this demonstrates the broadcast channel lifecycle issue"
            ));
        }
        Err(_) => {
            warn!(
                "❌ Timeout waiting for message (likely due to broadcast channel receiver being dropped)"
            );
            return Err(anyhow::anyhow!(
                "Timeout receiving message - this demonstrates the broadcast channel lifecycle issue"
            ));
        }
    }

    // Cleanup
    infra.cleanup().await?;
    Ok(())
}

/// Test that demonstrates the correct pattern - polling stream immediately
#[tokio::test]
#[serial]
async fn test_broadcast_channel_correct_usage_pattern() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    info!("🧪 Testing correct broadcast channel usage pattern");

    // Setup test infrastructure
    let infra = TestInfrastructure::setup().await?;
    let client = infra.create_client().await?;

    // Create a MessagesManager
    let messages_manager = MessagesManager::builder()
        .autosubscribe(true)
        .build(client.connection())
        .await?;

    info!("📡 Created MessagesManager");

    // Create a test filter
    let test_tag = Tag::Channel {
        id: b"test_channel_correct".to_vec(),
        relays: vec![],
    };
    let test_filter = Filter::from(test_tag.clone());

    // Ensure the filter is subscribed
    messages_manager
        .ensure_contains_filter(test_filter.clone())
        .await?;

    info!("🔍 Subscribed to filter: {:?}", test_filter);

    // CORRECT PATTERN: Create stream and immediately start polling it
    let filtered_stream = messages_manager
        .clone()
        .filtered_messages_stream(test_filter.clone());
    let mut filtered_stream = Box::pin(filtered_stream);

    // Start polling in the background
    let stream_task = {
        let mut stream = filtered_stream;
        tokio::spawn(async move {
            if let Some(message) = stream.next().await {
                info!(
                    "✅ Background task received message: {}",
                    hex::encode(message.id().as_bytes())
                );
                Some(message)
            } else {
                warn!("❌ Background task: stream ended");
                None
            }
        })
    };

    info!("📺 Created filtered stream and started polling immediately");

    // Wait a moment to ensure the stream is actively polling
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publish a message that should match the filter
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let test_message_raw = Message::new_v0_raw(
        b"Test message for correct pattern".to_vec(),
        client.public_key(),
        timestamp,
        Kind::Ephemeral(60),
        vec![test_tag],
    );

    let test_message = MessageFull::new(test_message_raw, client.keypair())?;

    info!("📤 Publishing test message");
    let publish_result = messages_manager.publish(test_message.clone()).await?;
    info!("✅ Message published with result: {:?}", publish_result);

    // Wait for the background task to receive the message
    let result = timeout(Duration::from_secs(5), stream_task).await;

    match result {
        Ok(Ok(Some(received_message))) => {
            info!(
                "✅ Successfully received message via correct pattern: {}",
                hex::encode(received_message.id().as_bytes())
            );
        }
        Ok(Ok(None)) => {
            return Err(anyhow::anyhow!("Stream ended without receiving message"));
        }
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("Background task failed: {}", e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Timeout waiting for background task"));
        }
    }

    // Cleanup
    infra.cleanup().await?;
    Ok(())
}

/// Test that demonstrates multiple receivers and the dropping behavior
#[tokio::test]
#[serial]
async fn test_broadcast_channel_multiple_receivers() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();
    info!("🧪 Testing broadcast channel with multiple receivers");

    // Setup test infrastructure
    let infra = TestInfrastructure::setup().await?;
    let client = infra.create_client().await?;

    // Create a MessagesManager with a small buffer to trigger dropping more easily
    let messages_manager = MessagesManager::builder()
        .buffer_size(10) // Small buffer to trigger lagging behavior
        .autosubscribe(true)
        .build(client.connection())
        .await?;

    info!("📡 Created MessagesManager with small buffer size");

    // Create a test filter
    let test_tag = Tag::Channel {
        id: b"test_channel_multi".to_vec(),
        relays: vec![],
    };
    let test_filter = Filter::from(test_tag.clone());

    // Ensure the filter is subscribed
    messages_manager
        .ensure_contains_filter(test_filter.clone())
        .await?;

    info!("🔍 Subscribed to filter: {:?}", test_filter);

    // Create multiple streams - some actively polling, some not
    let active_stream = messages_manager
        .clone()
        .filtered_messages_stream(test_filter.clone());
    let inactive_stream1 = messages_manager
        .clone()
        .filtered_messages_stream(test_filter.clone());
    let inactive_stream2 = messages_manager
        .clone()
        .filtered_messages_stream(test_filter.clone());

    // Start polling only the active stream
    let mut active_stream = Box::pin(active_stream);
    let active_task = tokio::spawn(async move {
        let mut received_count = 0;
        while let Some(message) = active_stream.next().await {
            received_count += 1;
            info!(
                "✅ Active stream received message {}: {}",
                received_count,
                hex::encode(message.id().as_bytes())
            );
            if received_count >= 5 {
                break;
            }
        }
        received_count
    });

    info!("📺 Created 3 streams: 1 active, 2 inactive");

    // Wait a moment
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publish multiple messages rapidly to trigger buffer overflow
    for i in 0..15 {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let test_message_raw = Message::new_v0_raw(
            format!("Test message {i} for multi-receiver test").into_bytes(),
            client.public_key(),
            timestamp,
            Kind::Ephemeral(60),
            vec![test_tag.clone()],
        );

        let test_message = MessageFull::new(test_message_raw, client.keypair())?;

        messages_manager.publish(test_message).await?;

        // Small delay between messages
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    info!("📤 Published 15 messages rapidly");

    // Wait for active stream to receive messages
    let received_count = timeout(Duration::from_secs(10), active_task).await??;
    info!("✅ Active stream received {} messages", received_count);

    // Now try to poll the inactive streams (these should have missed messages)
    info!("📺 Now attempting to poll inactive streams...");

    let mut inactive_stream1 = Box::pin(inactive_stream1);
    let mut inactive_stream2 = Box::pin(inactive_stream2);

    let inactive1_result = timeout(Duration::from_secs(2), inactive_stream1.next()).await;
    let inactive2_result = timeout(Duration::from_secs(2), inactive_stream2.next()).await;

    match (inactive1_result, inactive2_result) {
        (Ok(Some(_)), Ok(Some(_))) => {
            info!(
                "⚠️ Inactive streams unexpectedly received messages (buffer might be larger than expected)"
            );
        }
        _ => {
            info!(
                "❌ Inactive streams timed out or ended (demonstrating the broadcast channel lifecycle issue)"
            );
        }
    }

    // Cleanup
    infra.cleanup().await?;
    Ok(())
}
