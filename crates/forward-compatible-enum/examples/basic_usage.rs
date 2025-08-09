//! Basic usage example of ForwardCompatibleEnum
//!
//! This example demonstrates how to use the ForwardCompatibleEnum derive macro
//! to create enums that can handle unknown variants gracefully.

use forward_compatible_enum::ForwardCompatibleEnum;

/// A message type that can evolve over time without breaking compatibility
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum Message {
    /// A simple text message
    #[discriminant(1)]
    Text(String),

    /// An image with optional caption
    #[discriminant(2)]
    Image {
        url: String,
        caption: Option<String>,
    },

    /// A file attachment
    #[discriminant(3)]
    File {
        name: String,
        size: u64,
        mime_type: String,
    },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// A user status that might gain new states in the future
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
#[forward_compatible(unknown_variant = "UnknownStatus")]
pub enum UserStatus {
    #[discriminant(0)]
    Offline,

    #[discriminant(1)]
    Online,

    #[discriminant(2)]
    Away { since: u64 },

    #[discriminant(3)]
    Busy { message: Option<String> },

    /// Unknown variant for forward compatibility
    UnknownStatus { discriminant: u32, data: Vec<u8> },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Forward Compatible Enum Example ===\n");

    // Create some messages
    let messages = [
        Message::Text("Hello, world!".to_string()),
        Message::Image {
            url: "https://example.com/sunset.jpg".to_string(),
            caption: Some("Beautiful sunset".to_string()),
        },
        Message::File {
            name: "document.pdf".to_string(),
            size: 1_024_000,
            mime_type: "application/pdf".to_string(),
        },
    ];

    // Serialize and deserialize each message
    for (i, message) in messages.iter().enumerate() {
        println!("Message {}: {:?}", i + 1, message);

        // Serialize with postcard
        let serialized = postcard::to_stdvec(message)?;
        println!("  Serialized: {} bytes", serialized.len());

        // Deserialize back
        let deserialized: Message = postcard::from_bytes(&serialized)?;
        println!("  Round-trip successful: {}", message == &deserialized);

        println!();
    }

    // Demonstrate unknown variant handling
    println!("=== Unknown Variant Handling ===\n");

    // Simulate data from a newer version with unknown discriminant
    let future_message = Message::Unknown {
        discriminant: 999,
        data: postcard::to_stdvec(&("Future message type", 42u32))?,
    };

    println!("Future message: {future_message:?}");

    // This can be serialized and deserialized without loss
    let serialized = postcard::to_stdvec(&future_message)?;
    let recovered: Message = postcard::from_bytes(&serialized)?;

    println!("Future message preserved: {}", future_message == recovered);

    // Show how applications can handle unknown variants
    match recovered {
        Message::Text(text) => println!("Handling text: {text}"),
        Message::Image { url, .. } => println!("Handling image: {url}"),
        Message::File { name, .. } => println!("Handling file: {name}"),
        Message::Unknown { discriminant, .. } => {
            println!("Unknown message type {discriminant} - ignoring or logging");
        }
    }

    println!("\n=== Custom Unknown Variant Name ===\n");

    // Demonstrate custom unknown variant name
    let status = UserStatus::UnknownStatus {
        discriminant: 100,
        data: vec![1, 2, 3, 4],
    };

    println!("Unknown status: {status:?}");

    let serialized = postcard::to_stdvec(&status)?;
    let recovered: UserStatus = postcard::from_bytes(&serialized)?;
    println!("Status preserved: {}", status == recovered);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let message = Message::Text("test".to_string());
        let bytes = postcard::to_stdvec(&message).unwrap();
        let recovered: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(message, recovered);
    }

    #[test]
    fn test_unknown_variant_handling() {
        let unknown = Message::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3],
        };

        let bytes = postcard::to_stdvec(&unknown).unwrap();
        let recovered: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(unknown, recovered);
    }

    #[test]
    fn test_custom_unknown_variant() {
        let status = UserStatus::UnknownStatus {
            discriminant: 50,
            data: vec![4, 5, 6],
        };

        let bytes = postcard::to_stdvec(&status).unwrap();
        let recovered: UserStatus = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(status, recovered);
    }
}
