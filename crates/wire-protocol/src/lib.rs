pub mod auth;
pub mod blob;
pub mod crypto;
pub mod model;
pub mod protocol;
pub mod relay; // Existing wire protocol models
pub mod streaming;
pub mod wire; // Message streaming protocol

pub use auth::*;
pub use blob::*;
pub use crypto::*;
pub use model::*;
pub use protocol::*;
pub use relay::*; // Re-export existing wire protocol types
pub use streaming::*; // Re-export streaming protocol types
pub use wire::*;

// Re-export Blake3 Hash type for use in other crates
pub use blake3::Hash;

use serde::{Deserialize, Serialize};

/// The main protocol message type - generic over content type T
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + for<'a> serde::Deserialize<'a> + Clone + PartialEq + Send + Sync")]
pub enum ProtocolMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    // Authentication flow for dynamic per-operation challenges
    AuthChallenge {
        nonce: String,
        timestamp: u64,
    },
    AuthResponse {
        nonce: String,
        timestamp: u64,
        signature: Vec<u8>,
    },
    AuthProof {
        signature: Vec<u8>,
        nonce: String,
        timestamp: u64,
    },
    AuthSuccess {
        session_token: String,
    },
    AuthFailure {
        reason: String,
    },

    // Message operations
    Message {
        content: Box<T>,
    },
    MessageResponse {
        message_id: String,
        success: bool,
    },

    // Health and control
    HealthCheck,
    HealthResponse {
        status: String,
        timestamp: u64,
    },

    // Error responses
    Error {
        message: String,
    },
}

impl<T> From<T> for ProtocolMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    fn from(value: T) -> Self {
        Box::new(value).into()
    }
}

impl<T> From<Box<T>> for ProtocolMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    fn from(value: Box<T>) -> Self {
        ProtocolMessage::Message { content: value }
    }
}

/// Common content types for convenience
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileContent {
    pub filename: String,
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use test_case::test_case;

    // ========================================
    // UNIT TESTS - Protocol Message Creation
    // ========================================

    #[test]
    fn unit_protocol_creation() {
        let content = "Hello World".to_string();
        let message: ProtocolMessage<String> = content.into();

        match message {
            ProtocolMessage::Message { content } => {
                assert_eq!(content.as_str(), "Hello World");
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn unit_protocol_serialization() {
        let content = vec![1u8, 2, 3, 4];
        let message: ProtocolMessage<Vec<u8>> = content.into();

        // Test postcard serialization
        let serialized_bytes =
            postcard::to_allocvec(&message).expect("Postcard serialization failed");
        let deserialized: ProtocolMessage<Vec<u8>> =
            postcard::from_bytes(&serialized_bytes).expect("Postcard deserialization failed");

        assert_eq!(message, deserialized);
    }

    #[test_case("test".to_string(); "text_content")]
    #[test_case("another message".to_string(); "another_text_content")]
    fn unit_protocol_text_content_types(content: String) {
        let message: ProtocolMessage<String> = content.into();

        // Ensure it serializes and deserializes correctly
        let serialized_bytes = postcard::to_allocvec(&message).unwrap();
        let deserialized: ProtocolMessage<String> =
            postcard::from_bytes(&serialized_bytes).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn unit_protocol_binary_content() {
        let content = vec![1u8, 2, 3];
        let message: ProtocolMessage<Vec<u8>> = content.into();

        let serialized_bytes = postcard::to_allocvec(&message).unwrap();
        let deserialized: ProtocolMessage<Vec<u8>> =
            postcard::from_bytes(&serialized_bytes).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn unit_protocol_file_content() {
        let content = FileContent {
            filename: "test.txt".to_string(),
            data: vec![4, 5, 6],
        };
        let message: ProtocolMessage<FileContent> = content.into();

        let serialized_bytes = postcard::to_allocvec(&message).unwrap();
        let deserialized: ProtocolMessage<FileContent> =
            postcard::from_bytes(&serialized_bytes).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn unit_protocol_health_check() {
        let health: ProtocolMessage<String> = ProtocolMessage::HealthCheck;
        let response: ProtocolMessage<String> = ProtocolMessage::HealthResponse {
            status: "OK".to_string(),
            timestamp: 1234567890,
        };

        // Test serialization of health messages
        let health_bytes = postcard::to_allocvec(&health).unwrap();
        let response_bytes = postcard::to_allocvec(&response).unwrap();

        let health_deser: ProtocolMessage<String> = postcard::from_bytes(&health_bytes).unwrap();
        let response_deser: ProtocolMessage<String> =
            postcard::from_bytes(&response_bytes).unwrap();

        assert_eq!(health, health_deser);
        assert_eq!(response, response_deser);
    }

    #[test]
    fn unit_protocol_error_handling() {
        let error_msg: ProtocolMessage<String> = ProtocolMessage::Error {
            message: "Test error".to_string(),
        };

        let serialized_bytes = postcard::to_allocvec(&error_msg).unwrap();
        let deserialized: ProtocolMessage<String> =
            postcard::from_bytes(&serialized_bytes).unwrap();

        assert_eq!(error_msg, deserialized);
    }

    #[test]
    fn protocol_message_postcard_serialization_works() {
        let message: ProtocolMessage<String> = "test message".to_string().into();

        // Postcard serialization should work with our current approach
        let serialized_bytes = postcard::to_allocvec(&message).unwrap();
        let deserialized: ProtocolMessage<String> =
            postcard::from_bytes(&serialized_bytes).unwrap();
        assert_eq!(message, deserialized);

        // Verify the postcard serialization is more compact than JSON would be
        assert!(serialized_bytes.len() < 100); // Should be much smaller than JSON
    }

    #[test]
    fn protocol_message_postcard_works_now() {
        // Test the actual message type that was previously causing issues
        let message: ProtocolMessage<String> = "hello by ben".to_string().into();

        // PostCard serialization now works with our implementation approach
        let serialized =
            postcard::to_allocvec(&message).expect("Postcard serialization should work");

        // Deserialization should also work
        let result: ProtocolMessage<String> =
            postcard::from_bytes(&serialized).expect("Postcard deserialization should work");

        assert_eq!(message, result);

        // PostCard is now working properly with our ProtocolMessage
        println!("PostCard works great with ProtocolMessage!");
    }

    // ========================================
    // UNIT TESTS - Authentication Types
    // ========================================

    #[test]
    fn unit_auth_challenge_creation() {
        let challenge = AuthChallenge {
            nonce: "test-nonce-12345".to_string(),
            timestamp: 1234567890,
            issued_at: std::time::SystemTime::now(),
        };

        assert_eq!(challenge.nonce, "test-nonce-12345");
        assert_eq!(challenge.timestamp, 1234567890);
        assert!(challenge.issued_at <= std::time::SystemTime::now());
    }

    #[test]
    fn unit_auth_challenge_serialization() {
        let challenge = AuthChallenge {
            nonce: "uuid-test-nonce".to_string(),
            timestamp: 9999999999,
            issued_at: std::time::SystemTime::now(),
        };

        // Test postcard serialization
        let serialized_bytes = postcard::to_allocvec(&challenge).unwrap();
        let postcard_deser: AuthChallenge = postcard::from_bytes(&serialized_bytes).unwrap();
        assert_eq!(challenge.nonce, postcard_deser.nonce);
        assert_eq!(challenge.timestamp, postcard_deser.timestamp);
    }

    #[test]
    fn unit_dynamic_session_creation() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let session = DynamicSession::new(verifying_key);

        assert_eq!(session.client_ed25519_key, verifying_key);
        assert_eq!(session.successful_challenges, 0);
        assert_eq!(session.failed_challenges, 0);
        assert!(session.current_challenge.is_none());
        assert!(session.last_successful_challenge.is_none());
    }

    // ========================================
    // UNIT TESTS - Generic Protocol Messages
    // ========================================

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct CustomContent {
        message: String,
        priority: u8,
        metadata: std::collections::HashMap<String, String>,
    }

    #[test]
    fn unit_protocol_generic_custom_content() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("author".to_string(), "test-user".to_string());
        metadata.insert("version".to_string(), "1.0.0".to_string());

        let custom_content = CustomContent {
            message: "Custom protocol message".to_string(),
            priority: 5,
            metadata,
        };

        let protocol_message: ProtocolMessage<CustomContent> = custom_content.clone().into();

        // Test serialization
        let serialized_bytes = postcard::to_allocvec(&protocol_message).unwrap();
        let deserialized: ProtocolMessage<CustomContent> =
            postcard::from_bytes(&serialized_bytes).unwrap();

        assert_eq!(protocol_message, deserialized);

        // Verify content
        match deserialized {
            ProtocolMessage::Message { content } => {
                assert_eq!(content.message, "Custom protocol message");
                assert_eq!(content.priority, 5);
                assert_eq!(
                    content.metadata.get("author"),
                    Some(&"test-user".to_string())
                );
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn unit_protocol_generic_health_responses() {
        // Health checks can work with any generic type since they don't use the content
        let health_check: ProtocolMessage<u32> = ProtocolMessage::HealthCheck;
        let health_response: ProtocolMessage<CustomContent> = ProtocolMessage::HealthResponse {
            status: "Healthy".to_string(),
            timestamp: 9876543210,
        };

        // Serialize both with different generic types
        let check_bytes = postcard::to_allocvec(&health_check).unwrap();
        let response_bytes = postcard::to_allocvec(&health_response).unwrap();

        // Deserialize with matching types
        let check_deser: ProtocolMessage<u32> = postcard::from_bytes(&check_bytes).unwrap();
        let response_deser: ProtocolMessage<CustomContent> =
            postcard::from_bytes(&response_bytes).unwrap();

        assert_eq!(health_check, check_deser);
        assert_eq!(health_response, response_deser);
    }
}
