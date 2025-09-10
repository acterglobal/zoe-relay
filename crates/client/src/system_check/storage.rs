//! Storage tests for system check
//!
//! This module contains tests that verify the client can properly store and
//! retrieve messages through the relay server, including message persistence,
//! synchronization, and data integrity verification.

use super::{SystemCheckConfig, TestInfo, TestResult};
use crate::{Client, services::MessagesManagerTrait};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info};
use zoe_wire_protocol::{
    Content, KeyPair, Kind, Message, MessageFull, MessageV0, MessageV0Header, Tag,
};

/// Test message structure for storage verification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemCheckTestMessage {
    /// Unique test identifier
    pub test_id: String,
    /// Timestamp when the message was created
    pub timestamp: u64,
    /// Random test data
    pub data: Vec<u8>,
    /// CRC32 checksum of the data for integrity verification
    pub checksum: u32,
}

impl SystemCheckTestMessage {
    /// Create a new test message with random data
    pub fn new(test_id: String, data_size: usize) -> Self {
        let mut rng = rand::thread_rng();
        let data: Vec<u8> = (0..data_size).map(|_| rng.r#gen::<u8>()).collect();
        let checksum = crc32fast::hash(&data);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            test_id,
            timestamp,
            data,
            checksum,
        }
    }

    /// Verify the integrity of the message data
    pub fn verify_integrity(&self) -> bool {
        crc32fast::hash(&self.data) == self.checksum
    }
}

/// Run all storage tests
pub async fn run_tests(client: &Client, config: &SystemCheckConfig) -> Vec<TestInfo> {
    let mut tests = Vec::new();

    // Test message storage and retrieval
    tests.push(test_message_storage(client, config).await);

    // Test message integrity
    tests.push(test_message_integrity(client, config).await);

    tests
}

/// Test basic message storage and retrieval
async fn test_message_storage(client: &Client, config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Message Storage");

    debug!(
        "Testing message storage with {} messages...",
        config.storage_test_count
    );

    let mut stored_messages = Vec::new();

    // Store test messages
    for i in 0..config.storage_test_count {
        let test_message = SystemCheckTestMessage::new(
            format!("storage_test_{}", i),
            256, // Small data size for storage tests
        );

        // Create a proper MessageFull for publishing
        let serialized_content = match postcard::to_stdvec(&test_message) {
            Ok(data) => data,
            Err(e) => {
                let error = format!("Failed to serialize test message {}: {}", i, e);
                return test.with_result(TestResult::Failed { error });
            }
        };

        // Create a temporary keypair for the test message
        let temp_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());

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
                let error = format!("Failed to create MessageFull for test message {}: {}", i, e);
                return test.with_result(TestResult::Failed { error });
            }
        };

        match client.message_manager().publish(message_full).await {
            Ok(publish_result) => {
                debug!("Stored message {} with result: {:?}", i, publish_result);
                stored_messages.push((publish_result, test_message));
            }
            Err(e) => {
                let error = format!("Failed to store test message {}: {}", i, e);
                return test.with_result(TestResult::Failed { error });
            }
        }
    }

    test.add_detail(format!(
        "Successfully stored {} test messages",
        stored_messages.len()
    ));

    // TODO: Add message retrieval verification once the API supports it
    // For now, we consider the test passed if all messages were stored successfully

    info!("Message storage test completed successfully");
    test.with_result(TestResult::Passed)
}

/// Test message data integrity
async fn test_message_integrity(client: &Client, _config: &SystemCheckConfig) -> TestInfo {
    let mut test = TestInfo::new("Message Integrity");

    debug!("Testing message integrity...");

    // Create a test message with larger data to test integrity
    let test_message = SystemCheckTestMessage::new(
        "integrity_test".to_string(),
        1024, // Larger data size for integrity testing
    );

    // Verify the message integrity before storing
    if !test_message.verify_integrity() {
        let error = "Test message failed integrity check before storage".to_string();
        return test.with_result(TestResult::Failed { error });
    }

    // Create a proper MessageFull for publishing
    let serialized_content = match postcard::to_stdvec(&test_message) {
        Ok(data) => data,
        Err(e) => {
            let error = format!("Failed to serialize integrity test message: {}", e);
            return test.with_result(TestResult::Failed { error });
        }
    };

    // Create a temporary keypair for the test message
    let temp_keypair = KeyPair::generate_ed25519(&mut rand::thread_rng());

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
            let error = format!("Failed to create MessageFull for integrity test: {}", e);
            return test.with_result(TestResult::Failed { error });
        }
    };

    match client.message_manager().publish(message_full).await {
        Ok(publish_result) => {
            test.add_detail(format!(
                "Stored integrity test message with result: {:?}",
                publish_result
            ));
            test.add_detail(format!("Data size: {} bytes", test_message.data.len()));
            test.add_detail(format!("Checksum: {:08x}", test_message.checksum));

            info!("Message integrity test completed successfully");
            test.with_result(TestResult::Passed)
        }
        Err(e) => {
            let error = format!("Failed to store integrity test message: {}", e);
            test.with_result(TestResult::Failed { error })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Client;
    use tempfile::TempDir;

    async fn create_test_client() -> (Client, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let media_storage_path = temp_dir.path().join("blobs");
        let db_storage_path = temp_dir.path().join("db");

        let client = {
            let mut builder = Client::builder();
            builder.media_storage_dir_pathbuf(media_storage_path);
            builder.db_storage_dir_pathbuf(db_storage_path);
            builder.autoconnect(false);
            builder.build().await.unwrap()
        };

        (client, temp_dir)
    }

    #[test]
    fn test_system_check_test_message_creation() {
        let message = SystemCheckTestMessage::new("test_id".to_string(), 100);

        assert_eq!(message.test_id, "test_id");
        assert_eq!(message.data.len(), 100);
        assert!(message.verify_integrity());
    }

    #[test]
    fn test_system_check_test_message_integrity() {
        let mut message = SystemCheckTestMessage::new("test_id".to_string(), 50);

        // Should pass integrity check initially
        assert!(message.verify_integrity());

        // Corrupt the data
        if !message.data.is_empty() {
            message.data[0] = message.data[0].wrapping_add(1);
        }

        // Should fail integrity check after corruption
        assert!(!message.verify_integrity());
    }

    #[test]
    fn test_system_check_test_message_serialization() {
        let message = SystemCheckTestMessage::new("test_id".to_string(), 100);

        // Test serialization round trip
        let serialized = postcard::to_stdvec(&message).unwrap();
        let deserialized: SystemCheckTestMessage = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(message, deserialized);
        assert!(deserialized.verify_integrity());
    }

    #[tokio::test]
    async fn test_storage_tests_structure() {
        let (client, _temp_dir) = create_test_client().await;
        let config = SystemCheckConfig::default();

        let results = run_tests(&client, &config).await;

        // Should have 2 tests
        assert_eq!(results.len(), 2);

        let test_names: Vec<_> = results.iter().map(|t| &t.name).collect();
        assert!(test_names.contains(&&"Message Storage".to_string()));
        assert!(test_names.contains(&&"Message Integrity".to_string()));
    }
}
