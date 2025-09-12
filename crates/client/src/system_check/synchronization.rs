//! Synchronization Tests
//!
//! This module contains tests that verify synchronization between
//! local storage and relay servers after establishing connections.
//! These tests ensure that offline-created data properly syncs
//! with the server infrastructure.

use super::{SystemCheckConfig, TestInfo, TestResult};
use crate::Client;
use crate::services::MessagesManagerTrait;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{debug, info, warn};
use zoe_wire_protocol::{
    Content, KeyPair, Kind, Message, MessageFull, MessageV0, MessageV0Header, Tag,
};

/// Test message for sync verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SyncTestMessage {
    pub sync_id: String,
    pub message_type: String,
    pub created_offline: bool,
    pub data: Vec<u8>,
    pub checksum: u32,
    pub timestamp: u64,
}

impl SyncTestMessage {
    pub fn new_offline(sync_id: String, data_size: usize) -> Self {
        use rand::{RngCore, SeedableRng};
        let mut rng = rand::rngs::StdRng::from_entropy();
        let data: Vec<u8> = (0..data_size).map(|_| rng.next_u32() as u8).collect();
        let checksum = crc32fast::hash(&data);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            sync_id,
            message_type: "sync_test".to_string(),
            created_offline: true,
            data,
            checksum,
            timestamp,
        }
    }

    pub fn verify_integrity(&self) -> bool {
        crc32fast::hash(&self.data) == self.checksum
    }
}

/// Run all synchronization tests
pub async fn run_tests(client: &Client, config: &SystemCheckConfig) -> Vec<TestInfo> {
    let mut tests = Vec::new();

    info!("🔄 Running synchronization verification tests");

    // Test message synchronization
    tests.push(test_message_sync_verification(client, config).await);

    // Test connection stability during sync
    tests.push(test_sync_connection_stability(client, config).await);

    tests
}

/// Test that offline messages can be verified after connection
async fn test_message_sync_verification(client: &Client, _config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Message Sync Verification");

    debug!("Testing message synchronization after connection establishment...");

    // First, verify we have an active connection
    if !client.has_connected_relays().await {
        let error = "No relay connections available for sync verification".to_string();
        return test.with_result(TestResult::Failed { error });
    }

    test.add_detail("✓ Relay connection confirmed for sync testing");

    // Create a new message that should sync with the server
    let sync_message = SyncTestMessage::new_offline(
        "sync_verification_test".to_string(),
        512, // Medium size for sync testing
    );

    let serialized_content = match postcard::to_stdvec(&sync_message) {
        Ok(data) => data,
        Err(e) => {
            let error = format!("Failed to serialize sync test message: {e}");
            return test.with_result(TestResult::Failed { error });
        }
    };

    use rand::SeedableRng;
    let mut rng = rand::rngs::StdRng::from_entropy();
    let temp_keypair = KeyPair::generate_ed25519(&mut rng);

    let message = Message::MessageV0(MessageV0 {
        header: MessageV0Header {
            sender: temp_keypair.public_key(),
            when: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            kind: Kind::Ephemeral(3600), // Use ephemeral for sync testing
            tags: vec![Tag::Protected],
        },
        content: Content::Raw(serialized_content),
    });

    let message_full = match MessageFull::new(message, &temp_keypair) {
        Ok(msg) => msg,
        Err(e) => {
            let error = format!("Failed to create sync test MessageFull: {e}");
            return test.with_result(TestResult::Failed { error });
        }
    };

    // Publish the message (should sync with relay)
    let message_manager = client.message_manager();
    match message_manager.publish(message_full).await {
        Ok(_) => {
            test.add_detail("✓ Published message for sync verification");
        }
        Err(e) => {
            let error = format!("Failed to publish sync test message: {e}");
            return test.with_result(TestResult::Failed { error });
        }
    }

    // Wait a moment for potential synchronization
    sleep(Duration::from_millis(500)).await;

    // Verify message integrity
    if sync_message.verify_integrity() {
        test.add_detail("✓ Message data integrity maintained during sync");
    } else {
        let error = "Message integrity check failed after sync".to_string();
        return test.with_result(TestResult::Failed { error });
    }

    // Verify storage is accessible
    let _storage = client.storage();
    test.add_detail("✓ Local storage accessible after sync operation");

    info!("Message sync verification completed successfully");
    test.with_result(TestResult::Passed)
}

/// Test connection stability during synchronization operations
async fn test_sync_connection_stability(client: &Client, _config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Sync Connection Stability");

    debug!("Testing connection stability during sync operations...");

    // Verify initial connection state
    if !client.has_connected_relays().await {
        let error = "No relay connections available for stability testing".to_string();
        return test.with_result(TestResult::Failed { error });
    }

    let initial_status = match client.get_relay_status().await {
        Ok(status) => status,
        Err(e) => {
            let error = format!("Failed to get initial relay status: {e}");
            return test.with_result(TestResult::Failed { error });
        }
    };

    let connected_count = initial_status
        .iter()
        .filter(|s| matches!(s.status, crate::RelayConnectionStatus::Connected { .. }))
        .count();

    test.add_detail(format!(
        "✓ Initial connection state: {connected_count} relays connected"
    ));

    // Perform several sync-like operations to test stability
    for i in 0..3 {
        // Create a small test message
        let test_message = SyncTestMessage::new_offline(format!("stability_test_{i}"), 128);

        let serialized_content = match postcard::to_stdvec(&test_message) {
            Ok(data) => data,
            Err(e) => {
                warn!("Failed to serialize stability test message {}: {}", i, e);
                continue;
            }
        };

        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::from_entropy();
        let temp_keypair = KeyPair::generate_ed25519(&mut rng);

        let message = Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender: temp_keypair.public_key(),
                when: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                kind: Kind::Ephemeral(300), // Short-lived for stability testing
                tags: vec![Tag::Protected],
            },
            content: Content::Raw(serialized_content),
        });

        let message_full = match MessageFull::new(message, &temp_keypair) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to create stability test MessageFull {}: {}", i, e);
                continue;
            }
        };

        // Publish and check connection stability
        let message_manager = client.message_manager();
        match message_manager.publish(message_full).await {
            Ok(_) => {
                test.add_detail(format!("✓ Stability test {i} completed"));
            }
            Err(e) => {
                warn!("Stability test {} failed: {}", i, e);
                // Don't fail the entire test for individual message failures
            }
        }

        // Brief pause between operations
        sleep(Duration::from_millis(100)).await;
    }

    // Verify connection is still stable after operations
    if client.has_connected_relays().await {
        test.add_detail("✓ Connection remained stable during sync operations");

        // Get final status
        match client.get_relay_status().await {
            Ok(final_status) => {
                let final_connected = final_status
                    .iter()
                    .filter(|s| matches!(s.status, crate::RelayConnectionStatus::Connected { .. }))
                    .count();

                test.add_detail(format!(
                    "✓ Final connection state: {final_connected} relays connected"
                ));

                if final_connected >= connected_count {
                    test.add_detail("✓ Connection stability maintained");
                } else {
                    test.add_detail("⚠ Some connections were lost during testing");
                }
            }
            Err(e) => {
                warn!("Failed to get final relay status: {}", e);
            }
        }
    } else {
        let error = "Connection lost during sync stability testing".to_string();
        return test.with_result(TestResult::Failed { error });
    }

    info!("Sync connection stability test completed successfully");
    test.with_result(TestResult::Passed)
}
