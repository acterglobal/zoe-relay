use forward_compatible_enum::ForwardCompatibleEnum;
use serde::{Serialize, de::DeserializeOwned};
use std::collections::HashMap;

/// Simulates a real-world message envelope with generic payload
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(
    serde_serialize = "T: Serialize",
    serde_deserialize = "T: DeserializeOwned"
)]
pub enum MessageEnvelope<T> {
    #[discriminant(1)]
    UserMessage {
        sender: String,
        recipient: String,
        payload: T,
        timestamp: u64,
    },

    #[discriminant(2)]
    SystemNotification { level: String, content: T },

    #[discriminant(3)]
    BulkData(Vec<T>),

    /// Unknown message type for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Test different payload types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ChatMessage {
    pub text: String,
    pub attachments: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct StatusUpdate {
    pub status: String,
    pub metadata: HashMap<String, String>,
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_real_world_chat_message() {
        let chat = ChatMessage {
            text: "Hello, world!".to_string(),
            attachments: vec!["image.png".to_string(), "doc.pdf".to_string()],
        };

        let envelope = MessageEnvelope::UserMessage {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            payload: chat.clone(),
            timestamp: 1234567890,
        };

        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let recovered: MessageEnvelope<ChatMessage> = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(envelope, recovered);

        // Verify the payload is correctly preserved
        if let MessageEnvelope::UserMessage { payload, .. } = recovered {
            assert_eq!(payload.text, "Hello, world!");
            assert_eq!(payload.attachments.len(), 2);
        } else {
            panic!("Expected UserMessage variant");
        }
    }

    #[test]
    fn test_system_notification_with_status() {
        let status = StatusUpdate {
            status: "online".to_string(),
            metadata: {
                let mut map = HashMap::new();
                map.insert("last_seen".to_string(), "2024-01-01".to_string());
                map.insert("location".to_string(), "office".to_string());
                map
            },
        };

        let envelope = MessageEnvelope::SystemNotification {
            level: "info".to_string(),
            content: status.clone(),
        };

        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let recovered: MessageEnvelope<StatusUpdate> = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(envelope, recovered);
    }

    #[test]
    fn test_bulk_data_handling() {
        let messages = vec![
            ChatMessage {
                text: "Message 1".to_string(),
                attachments: vec![],
            },
            ChatMessage {
                text: "Message 2".to_string(),
                attachments: vec!["file.txt".to_string()],
            },
            ChatMessage {
                text: "Message 3".to_string(),
                attachments: vec!["img1.jpg".to_string(), "img2.jpg".to_string()],
            },
        ];

        let envelope = MessageEnvelope::BulkData(messages.clone());

        let bytes = postcard::to_stdvec(&envelope).unwrap();
        let recovered: MessageEnvelope<ChatMessage> = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(envelope, recovered);

        if let MessageEnvelope::BulkData(recovered_messages) = recovered {
            assert_eq!(recovered_messages.len(), 3);
            assert_eq!(recovered_messages[0].text, "Message 1");
            assert_eq!(recovered_messages[1].attachments.len(), 1);
            assert_eq!(recovered_messages[2].attachments.len(), 2);
        } else {
            panic!("Expected BulkData variant");
        }
    }

    #[test]
    fn test_cross_type_unknown_preservation() {
        // Simulate receiving a message with a future payload type that we don't understand
        let future_payload_data =
            postcard::to_stdvec(&("future_field", 42u64, vec![1u8, 2u8, 3u8])).unwrap();

        let unknown_envelope: MessageEnvelope<ChatMessage> = MessageEnvelope::Unknown {
            discriminant: 999,
            data: future_payload_data.clone(),
        };

        // Should preserve the unknown data perfectly
        let bytes = postcard::to_stdvec(&unknown_envelope).unwrap();
        let recovered: MessageEnvelope<ChatMessage> = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(unknown_envelope, recovered);

        // Should be able to extract the original future payload
        if let MessageEnvelope::Unknown { discriminant, data } = recovered {
            assert_eq!(discriminant, 999);
            assert_eq!(data, future_payload_data);

            // Could potentially deserialize as a different type in the future
            let (field, num, vec): (String, u64, Vec<u8>) = postcard::from_bytes(&data).unwrap();
            assert_eq!(field, "future_field");
            assert_eq!(num, 42);
            assert_eq!(vec, vec![1u8, 2u8, 3u8]);
        } else {
            panic!("Expected Unknown variant");
        }
    }

    #[test]
    fn test_mixed_payload_types_in_sequence() {
        // Test that we can have different concrete instantiations in the same test
        let chat_envelope = MessageEnvelope::UserMessage {
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            payload: ChatMessage {
                text: "Hello".to_string(),
                attachments: vec![],
            },
            timestamp: 1000,
        };

        let status_envelope = MessageEnvelope::SystemNotification {
            level: "warning".to_string(),
            content: StatusUpdate {
                status: "away".to_string(),
                metadata: HashMap::new(),
            },
        };

        // Serialize both
        let chat_bytes = postcard::to_stdvec(&chat_envelope).unwrap();
        let status_bytes = postcard::to_stdvec(&status_envelope).unwrap();

        // Deserialize with correct types
        let recovered_chat: MessageEnvelope<ChatMessage> =
            postcard::from_bytes(&chat_bytes).unwrap();
        let recovered_status: MessageEnvelope<StatusUpdate> =
            postcard::from_bytes(&status_bytes).unwrap();

        assert_eq!(chat_envelope, recovered_chat);
        assert_eq!(status_envelope, recovered_status);
    }

    #[test]
    fn test_wire_format_compatibility() {
        // Test that the wire format is consistent regardless of bounds
        let envelope = MessageEnvelope::SystemNotification {
            level: "debug".to_string(),
            content: "simple string".to_string(),
        };

        let bytes = postcard::to_stdvec(&envelope).unwrap();

        // Should be deserializable as the same logical structure
        let recovered: MessageEnvelope<String> = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(envelope, recovered);

        // The discriminant should be preserved correctly
        let (discriminant, _): (u32, Vec<u8>) = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(discriminant, 2); // SystemNotification discriminant
    }
}
