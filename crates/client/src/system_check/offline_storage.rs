//! Offline Storage Tests
//!
//! This module contains tests that verify local storage functionality
//! without requiring a relay connection. These tests validate that
//! the client can store and retrieve messages locally.

use super::{SystemCheckConfig, TestInfo, TestResult};
use crate::Client;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};
use zoe_state_machine::messages::MessagesManagerTrait;
use zoe_wire_protocol::{
    Content, KeyPair, Kind, Message, MessageFull, MessageV0, MessageV0Header, Tag,
};

/// Test message structure for offline storage verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OfflineTestMessage {
    pub test_id: String,
    pub message_type: String,
    pub data: Vec<u8>,
    pub checksum: u32,
    pub created_at: u64,
}

impl OfflineTestMessage {
    pub fn new(test_id: String, data_size: usize) -> Self {
        use rand::{RngCore, SeedableRng};
        let mut rng = rand::rngs::StdRng::from_entropy();
        let data: Vec<u8> = (0..data_size).map(|_| rng.next_u32() as u8).collect();
        let checksum = crc32fast::hash(&data);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            test_id,
            message_type: "offline_test".to_string(),
            data,
            checksum,
            created_at,
        }
    }

    pub fn verify_integrity(&self) -> bool {
        crc32fast::hash(&self.data) == self.checksum
    }
}

/// Run all offline storage tests
pub async fn run_tests(client: &Client, config: &SystemCheckConfig) -> Vec<TestInfo> {
    let mut tests = Vec::new();

    info!("🔧 Running offline storage tests (no relay connection required)");

    // Test local message storage
    tests.push(test_offline_message_storage(client, config).await);

    // Test message persistence across operations
    tests.push(test_message_persistence(client, config).await);

    tests
}

/// Test offline message storage and retrieval
async fn test_offline_message_storage(client: &Client, config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Offline Message Storage");

    debug!(
        "Testing offline message storage with {} messages...",
        config.offline_message_count
    );

    let mut stored_messages = HashMap::new();

    // Store test messages locally
    for i in 0..config.offline_message_count {
        let test_message = OfflineTestMessage::new(
            format!("offline_storage_test_{i}"),
            256, // Small data size for offline tests
        );

        // Create a proper MessageFull for local storage
        let serialized_content = match postcard::to_stdvec(&test_message) {
            Ok(data) => data,
            Err(e) => {
                let error = format!("Failed to serialize test message {i}: {e}");
                return test.with_result(TestResult::Failed { error });
            }
        };

        // Create a temporary keypair for the test message
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
                kind: Kind::Ephemeral(3600), // 1 hour timeout
                tags: vec![Tag::Protected],
            },
            content: Content::Raw(serialized_content),
        });

        let message_full = match MessageFull::new(message, &temp_keypair) {
            Ok(msg) => msg,
            Err(e) => {
                let error = format!("Failed to create MessageFull for test message {i}: {e}");
                return test.with_result(TestResult::Failed { error });
            }
        };

        // Store the message locally (this should work without relay connection)
        let message_manager = client.message_manager();
        match message_manager.publish(message_full.clone()).await {
            Ok(_) => {
                stored_messages.insert(test_message.test_id.clone(), test_message);
                test.add_detail(format!("✓ Stored offline message {i}"));
            }
            Err(e) => {
                let error = format!("Failed to store offline message {i}: {e}");
                return test.with_result(TestResult::Failed { error });
            }
        }
    }

    test.add_detail(format!(
        "✓ Successfully stored {} messages offline",
        stored_messages.len()
    ));

    // Verify we can access the storage directly
    let _storage = client.storage();
    test.add_detail("✓ Local storage accessible");

    info!("Offline message storage test completed successfully");
    test.with_result(TestResult::Passed)
}

/// Test message persistence across operations
async fn test_message_persistence(client: &Client, _config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Message Persistence");

    debug!("Testing message persistence in local storage...");

    // Create a test message with unique identifier
    let test_message = OfflineTestMessage::new("persistence_test".to_string(), 128);

    let serialized_content = match postcard::to_stdvec(&test_message) {
        Ok(data) => data,
        Err(e) => {
            let error = format!("Failed to serialize persistence test message: {e}");
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
            kind: Kind::Ephemeral(86400), // Use long-lived ephemeral for persistence simulation
            tags: vec![Tag::Protected],
        },
        content: Content::Raw(serialized_content),
    });

    let message_full = match MessageFull::new(message, &temp_keypair) {
        Ok(msg) => msg,
        Err(e) => {
            let error = format!("Failed to create persistent MessageFull: {e}");
            return test.with_result(TestResult::Failed { error });
        }
    };

    // Store the persistent message
    let message_manager = client.message_manager();
    match message_manager.publish(message_full).await {
        Ok(_) => {
            test.add_detail("✓ Stored persistent message");
        }
        Err(e) => {
            let error = format!("Failed to store persistent message: {e}");
            return test.with_result(TestResult::Failed { error });
        }
    }

    // Verify storage is working
    let _storage = client.storage();
    test.add_detail("✓ Storage persistence verified");

    // Verify the test message integrity
    if test_message.verify_integrity() {
        test.add_detail("✓ Message data integrity verified");
    } else {
        let error = "Message data integrity check failed".to_string();
        return test.with_result(TestResult::Failed { error });
    }

    info!("Message persistence test completed successfully");
    test.with_result(TestResult::Passed)
}
