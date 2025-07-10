pub mod auth;
pub mod crypto;
pub mod protocol;
pub mod relay;
pub mod model; // Existing wire protocol models

pub use auth::*;
pub use crypto::*;
pub use protocol::*;
pub use relay::*;
pub use model::*; // Re-export existing wire protocol types

// Re-export Blake3 Hash type for use in other crates
pub use blake3::Hash;

use serde::{Deserialize, Serialize};

/// The main protocol message type - generic over content type T
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", bound = "T: Serialize + for<'a> serde::Deserialize<'a> + Clone + PartialEq + Send + Sync")]
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
        content: T,
        session_token: Option<String>,
    },
    MessageFull {
        message: MessageFull<T>,
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
    Error { message: String },
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
        let message = ProtocolMessage::Message {
            content,
            session_token: Some("test-token".to_string()),
        };
        
        match message {
            ProtocolMessage::Message { content, session_token } => {
                assert_eq!(session_token, Some("test-token".to_string()));
                assert_eq!(content, "Hello World");
            }
            _ => panic!("Wrong message type"),
        }
    }
    
    #[test]
    fn unit_protocol_serialization() {
        let content = vec![1u8, 2, 3, 4];
        let message = ProtocolMessage::Message {
            content,
            session_token: Some("binary-session".to_string()),
        };
        
        // Test JSON serialization
        let json_str = serde_json::to_string(&message).expect("JSON serialization failed");
        let deserialized: ProtocolMessage<Vec<u8>> = serde_json::from_str(&json_str)
            .expect("JSON deserialization failed");
        
        assert_eq!(message, deserialized);
    }
    
    #[test_case("test".to_string(); "text_content")]
    #[test_case("another message".to_string(); "another_text_content")]
    fn unit_protocol_text_content_types(content: String) {
        let message = ProtocolMessage::Message {
            content,
            session_token: None,
        };
        
        // Ensure it serializes and deserializes correctly
        let json_str = serde_json::to_string(&message).unwrap();
        let deserialized: ProtocolMessage<String> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn unit_protocol_binary_content() {
        let content = vec![1u8, 2, 3];
        let message = ProtocolMessage::Message {
            content,
            session_token: None,
        };
        
        let json_str = serde_json::to_string(&message).unwrap();
        let deserialized: ProtocolMessage<Vec<u8>> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(message, deserialized);
    }

    #[test]
    fn unit_protocol_file_content() {
        let content = FileContent {
            filename: "test.txt".to_string(),
            data: vec![4, 5, 6],
        };
        let message = ProtocolMessage::Message {
            content,
            session_token: None,
        };
        
        let json_str = serde_json::to_string(&message).unwrap();
        let deserialized: ProtocolMessage<FileContent> = serde_json::from_str(&json_str).unwrap();
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
        let health_json = serde_json::to_string(&health).unwrap();
        let response_json = serde_json::to_string(&response).unwrap();
        
        let health_deser: ProtocolMessage<String> = serde_json::from_str(&health_json).unwrap();
        let response_deser: ProtocolMessage<String> = serde_json::from_str(&response_json).unwrap();
        
        assert_eq!(health, health_deser);
        assert_eq!(response, response_deser);
    }
    
    #[test]
    fn unit_protocol_error_handling() {
        let error_msg: ProtocolMessage<String> = ProtocolMessage::Error {
            message: "Test error".to_string(),
        };
        
        let json_str = serde_json::to_string(&error_msg).unwrap();
        let deserialized: ProtocolMessage<String> = serde_json::from_str(&json_str).unwrap();
        
        assert_eq!(error_msg, deserialized);
    }
    
    #[test]
    fn protocol_message_json_serialization_works() {
        let message = ProtocolMessage::Message {
            content: "test message".to_string(),
            session_token: Some("token123".to_string()),
        };
        
        // JSON serialization should work with serde tagging
        let json_str = serde_json::to_string(&message).unwrap();
        let deserialized: ProtocolMessage<String> = serde_json::from_str(&json_str).unwrap();
        assert_eq!(message, deserialized);
        
        // Verify the JSON contains the type tag
        assert!(json_str.contains(r#""type":"Message""#));
    }
    
    #[test]
    fn protocol_message_postcard_limitation_documented() {
        // Test the actual message type that was causing issues
        let message = ProtocolMessage::Message {
            content: "hello by ben".to_string(),
            session_token: None,
        };
        
        // PostCard serialization may work for simple cases but fails for complex ones
        // The issue occurs with the serde tagging when deserializing
        let serialized = postcard::to_allocvec(&message);
        
        if let Ok(bytes) = serialized {
            // The real issue is during deserialization with tagged enums
            let result = postcard::from_bytes::<ProtocolMessage<String>>(&bytes);
            
            // This is where the "This is a feature that PostCard will never implement" error occurs
            // PostCard doesn't support serde's externally tagged enums
            if let Err(e) = result {
                let error_msg = format!("{}", e);
                // Document the limitation - this is the error we encountered
                println!("PostCard limitation: {}", error_msg);
                assert!(error_msg.contains("never implement") || error_msg.contains("not supported"));
            } else {
                // Sometimes it might work for simple cases, but the limitation exists
                // The key point is documented: use JSON for ProtocolMessage types
                println!("PostCard may work for simple cases but has limitations with serde tagging");
            }
        }
        
        // JSON works fine with tagged enums - this is what we use in examples
        let json_str = serde_json::to_string(&message).unwrap();
        let _deserialized: ProtocolMessage<String> = serde_json::from_str(&json_str).unwrap();
        
        // Verify the JSON contains the type tag
        assert!(json_str.contains(r#""type":"Message""#));
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
        
        // Test JSON serialization
        let json_str = serde_json::to_string(&challenge).unwrap();
        let json_deser: AuthChallenge = serde_json::from_str(&json_str).unwrap();
        assert_eq!(challenge.nonce, json_deser.nonce);
        assert_eq!(challenge.timestamp, json_deser.timestamp);
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
        
        let protocol_message = ProtocolMessage::Message {
            content: custom_content.clone(),
            session_token: Some("custom-session-token".to_string()),
        };
        
        // Test serialization
        let json_str = serde_json::to_string(&protocol_message).unwrap();
        let deserialized: ProtocolMessage<CustomContent> = serde_json::from_str(&json_str).unwrap();
        
        assert_eq!(protocol_message, deserialized);
        
        // Verify content
        match deserialized {
            ProtocolMessage::Message { content, session_token } => {
                assert_eq!(content.message, "Custom protocol message");
                assert_eq!(content.priority, 5);
                assert_eq!(content.metadata.get("author"), Some(&"test-user".to_string()));
                assert_eq!(session_token, Some("custom-session-token".to_string()));
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
        let check_json = serde_json::to_string(&health_check).unwrap();
        let response_json = serde_json::to_string(&health_response).unwrap();
        
        // Deserialize with matching types
        let check_deser: ProtocolMessage<u32> = serde_json::from_str(&check_json).unwrap();
        let response_deser: ProtocolMessage<CustomContent> = serde_json::from_str(&response_json).unwrap();
        
        assert_eq!(health_check, check_deser);
        assert_eq!(health_response, response_deser);
    }
}
