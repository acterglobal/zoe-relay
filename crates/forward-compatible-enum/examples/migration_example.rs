//! Migration example showing how to evolve enums over time
//!
//! This example demonstrates how to safely add new variants to an enum
//! while maintaining compatibility with existing deployments.

use forward_compatible_enum::ForwardCompatibleEnum;

/// Version 1.0 of a notification enum
/// This represents the initial release
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum NotificationV1 {
    #[discriminant(1)]
    Email { recipient: String, subject: String },

    #[discriminant(2)]
    SMS { phone: String, message: String },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Version 2.0 of the notification enum
/// Added push notifications - new discriminant = 3
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum NotificationV2 {
    #[discriminant(1)]
    Email { recipient: String, subject: String },

    #[discriminant(2)]
    SMS { phone: String, message: String },

    // New in v2.0!
    #[discriminant(3)]
    Push {
        device_id: String,
        title: String,
        body: String,
    },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

/// Version 3.0 of the notification enum
/// Added webhook notifications and enhanced push notifications
#[derive(Debug, Clone, PartialEq, Eq, ForwardCompatibleEnum)]
pub enum NotificationV3 {
    #[discriminant(1)]
    Email { recipient: String, subject: String },

    #[discriminant(2)]
    SMS { phone: String, message: String },

    #[discriminant(3)]
    Push {
        device_id: String,
        title: String,
        body: String,
    },

    // New in v3.0!
    #[discriminant(4)]
    Webhook { url: String, payload: String },

    #[discriminant(5)]
    EnhancedPush {
        device_id: String,
        title: String,
        body: String,
        badge_count: Option<u32>,
        sound: Option<String>,
    },

    /// Unknown variant for forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Forward Compatible Enum Migration Example ===\n");

    // Simulate v1.0 client creating notifications
    let v1_notifications = [
        NotificationV1::Email {
            recipient: "user@example.com".to_string(),
            subject: "Welcome!".to_string(),
        },
        NotificationV1::SMS {
            phone: "+1234567890".to_string(),
            message: "Hello!".to_string(),
        },
    ];

    println!("=== V1.0 Client Data ===");
    for (i, notification) in v1_notifications.iter().enumerate() {
        println!("V1 Notification {}: {:?}", i + 1, notification);

        // Serialize as v1.0 would
        let bytes = postcard::to_stdvec(notification)?;

        // V2.0 client can read v1.0 data perfectly
        let as_v2: NotificationV2 = postcard::from_bytes(&bytes)?;
        println!("  Read by V2: {as_v2:?}");

        // V3.0 client can also read v1.0 data perfectly
        let as_v3: NotificationV3 = postcard::from_bytes(&bytes)?;
        println!("  Read by V3: {as_v3:?}");

        println!();
    }

    // Simulate v2.0 client creating new push notification
    println!("=== V2.0 Client Data ===");
    let v2_push = NotificationV2::Push {
        device_id: "device123".to_string(),
        title: "New Message".to_string(),
        body: "You have a new message!".to_string(),
    };

    println!("V2 Push Notification: {v2_push:?}");
    let v2_bytes = postcard::to_stdvec(&v2_push)?;

    // V1.0 client receives this data - it becomes unknown
    let v1_view: NotificationV1 = postcard::from_bytes(&v2_bytes)?;
    println!("V1 client sees: {v1_view:?}");

    // V1.0 client can handle unknown variants gracefully
    match v1_view {
        NotificationV1::Email { .. } => println!("  V1: Handling email"),
        NotificationV1::SMS { .. } => println!("  V1: Handling SMS"),
        NotificationV1::Unknown { discriminant, .. } => {
            println!("  V1: Unknown notification type {discriminant}, logging and ignoring");
        }
    }

    // V3.0 client can read v2.0 data perfectly
    let v3_view: NotificationV3 = postcard::from_bytes(&v2_bytes)?;
    println!("V3 client sees: {v3_view:?}");

    println!("\n=== V3.0 Client Data ===");
    let v3_notifications = [
        NotificationV3::Webhook {
            url: "https://api.example.com/webhook".to_string(),
            payload: r#"{"event": "notification"}"#.to_string(),
        },
        NotificationV3::EnhancedPush {
            device_id: "device456".to_string(),
            title: "Breaking News".to_string(),
            body: "Important update available!".to_string(),
            badge_count: Some(5),
            sound: Some("alert.wav".to_string()),
        },
    ];

    for (i, notification) in v3_notifications.iter().enumerate() {
        println!("V3 Notification {}: {:?}", i + 1, notification);
        let bytes = postcard::to_stdvec(notification)?;

        // V1.0 and V2.0 clients see these as unknown
        let v1_view: NotificationV1 = postcard::from_bytes(&bytes)?;
        let v2_view: NotificationV2 = postcard::from_bytes(&bytes)?;

        println!("  V1 sees: {:?}", extract_discriminant_v1(&v1_view));
        println!("  V2 sees: {:?}", extract_discriminant_v2(&v2_view));

        println!();
    }

    println!("=== Round-trip Compatibility ===");

    // Demonstrate that unknown data is preserved perfectly
    let v3_enhanced = NotificationV3::EnhancedPush {
        device_id: "device789".to_string(),
        title: "Test".to_string(),
        body: "Testing round-trip".to_string(),
        badge_count: Some(3),
        sound: None,
    };

    let bytes = postcard::to_stdvec(&v3_enhanced)?;

    // V1 client receives and forwards the data
    let v1_unknown: NotificationV1 = postcard::from_bytes(&bytes)?;
    let v1_forwarded_bytes = postcard::to_stdvec(&v1_unknown)?;

    // V3 client receives the forwarded data
    let v3_recovered: NotificationV3 = postcard::from_bytes(&v1_forwarded_bytes)?;

    println!("Original V3:  {v3_enhanced:?}");
    println!("After V1 hop: {v3_recovered:?}");
    println!("Data preserved: {}", v3_enhanced == v3_recovered);

    Ok(())
}

fn extract_discriminant_v1(notification: &NotificationV1) -> String {
    match notification {
        NotificationV1::Email { .. } => "Email".to_string(),
        NotificationV1::SMS { .. } => "SMS".to_string(),
        NotificationV1::Unknown { discriminant, .. } => format!("Unknown({discriminant})"),
    }
}

fn extract_discriminant_v2(notification: &NotificationV2) -> String {
    match notification {
        NotificationV2::Email { .. } => "Email".to_string(),
        NotificationV2::SMS { .. } => "SMS".to_string(),
        NotificationV2::Push { .. } => "Push".to_string(),
        NotificationV2::Unknown { discriminant, .. } => format!("Unknown({discriminant})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v1_to_v2_compatibility() {
        let v1_email = NotificationV1::Email {
            recipient: "test@example.com".to_string(),
            subject: "Test".to_string(),
        };

        let bytes = postcard::to_stdvec(&v1_email).unwrap();
        let v2_view: NotificationV2 = postcard::from_bytes(&bytes).unwrap();

        match v2_view {
            NotificationV2::Email { recipient, subject } => {
                assert_eq!(recipient, "test@example.com");
                assert_eq!(subject, "Test");
            }
            _ => panic!("Expected Email variant"),
        }
    }

    #[test]
    fn test_v2_to_v1_unknown_handling() {
        let v2_push = NotificationV2::Push {
            device_id: "device123".to_string(),
            title: "Test".to_string(),
            body: "Test message".to_string(),
        };

        let bytes = postcard::to_stdvec(&v2_push).unwrap();
        let v1_view: NotificationV1 = postcard::from_bytes(&bytes).unwrap();

        match v1_view {
            NotificationV1::Unknown { discriminant, .. } => {
                assert_eq!(discriminant, 3); // Push discriminant
            }
            _ => panic!("Expected Unknown variant"),
        }
    }

    #[test]
    fn test_round_trip_preservation() {
        let v3_webhook = NotificationV3::Webhook {
            url: "https://test.com".to_string(),
            payload: "test".to_string(),
        };

        // V3 -> bytes -> V1 -> bytes -> V3
        let bytes1 = postcard::to_stdvec(&v3_webhook).unwrap();
        let v1_view: NotificationV1 = postcard::from_bytes(&bytes1).unwrap();
        let bytes2 = postcard::to_stdvec(&v1_view).unwrap();
        let v3_recovered: NotificationV3 = postcard::from_bytes(&bytes2).unwrap();

        assert_eq!(v3_webhook, v3_recovered);
    }
}
