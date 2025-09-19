//! Calendar-related event types for scheduling and RSVP management
//!
//! This module contains event types for creating and managing calendar events,
//! including location information and RSVP responses.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

/// Content for creating a calendar event
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateCalendarEventContent {
    /// Title of the event
    pub title: String,
    /// Optional description (HTML formatted)
    #[serde(default)]
    pub description: Option<String>,
    /// Optional icon (emoji)
    #[serde(default)]
    pub icon: Option<String>,
    /// Optional parent object (for threading/nesting)
    #[serde(default)]
    pub parent_id: Option<MessageId>,
    /// Event start time (Unix timestamp in UTC)
    pub utc_start_time: u64,
    /// Event end time (Unix timestamp in UTC)
    pub utc_end_time: u64,
    /// Event location information (supports multiple locations for hybrid events)
    #[serde(default)]
    pub locations: Vec<EventLocation>,
    /// Whether this is an all-day event
    #[serde(default)]
    pub all_day: bool,
}

/// Individual calendar event update operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CalendarEventUpdate {
    /// Update the title
    Title(String),
    /// Update the description
    Description(String),
    /// Clear the description
    ClearDescription,
    /// Update the icon
    Icon(String),
    /// Clear the icon
    ClearIcon,
    /// Update the parent relationship
    ParentId(MessageId),
    /// Clear the parent relationship
    ClearParentId,
    /// Update the start time
    UtcStartTime(u64),
    /// Update the end time
    UtcEndTime(u64),
    /// Replace all locations with a new list
    SetLocations(Vec<EventLocation>),
    /// Add a location to the list
    AddLocation(EventLocation),
    /// Clear all locations
    ClearLocations,
    /// Update the all-day flag
    AllDay(bool),
}

/// Content for updating a calendar event - vector of specific updates
pub type UpdateCalendarEventContent = Vec<CalendarEventUpdate>;

/// Event Location - distinguishes between physical and virtual locations
///
/// Modeled after Acter's EventLocation enum to properly handle different
/// location types with appropriate fields for each.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventLocation {
    /// Physical location with address and coordinates
    Physical {
        /// Optional name of this location
        #[serde(default)]
        name: Option<String>,

        /// Further description of this location (HTML formatted)
        #[serde(default)]
        description: Option<String>,

        /// Alternative icon to show with this location (emoji)
        #[serde(default)]
        icon: Option<String>,

        /// A `geo:` URI RFC5870 for the location coordinates
        #[serde(default)]
        coordinates: Option<String>,

        /// Physical locations can also have a website
        #[serde(default)]
        uri: Option<String>,

        /// Optional address of this physical location
        #[serde(default)]
        address: Option<String>,

        /// Optional notes about this location
        #[serde(default)]
        notes: Option<String>,
    },
    /// Virtual location with URI and connection details
    Virtual {
        /// Optional name of this virtual location
        #[serde(default)]
        name: Option<String>,

        /// Further description for virtual location (HTML formatted)
        #[serde(default)]
        description: Option<String>,

        /// Alternative icon to show with this location (emoji)
        #[serde(default)]
        icon: Option<String>,

        /// URI to this virtual location (required for virtual)
        uri: String,

        /// Optional notes about this virtual location
        #[serde(default)]
        notes: Option<String>,
    },
}

/// RSVP response options
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RsvpResponse {
    /// Will attend
    Yes,
    /// Will not attend
    No,
    /// Might attend
    Maybe,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to test postcard serialization round-trip
    fn test_postcard_roundtrip<T>(value: &T) -> postcard::Result<()>
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let serialized = postcard::to_stdvec(value)?;
        let deserialized: T = postcard::from_bytes(&serialized)?;
        assert_eq!(*value, deserialized);
        Ok(())
    }

    #[test]
    fn test_create_calendar_event_content_postcard() {
        let content = CreateCalendarEventContent {
            title: "Annual Conference".to_string(),
            description: Some(
                "Our yearly tech conference with <b>amazing</b> speakers".to_string(),
            ),
            icon: Some("🎤".to_string()),
            parent_id: None,
            utc_start_time: 1703001600, // 2023-12-19 12:00:00 UTC
            utc_end_time: 1703088000,   // 2023-12-20 12:00:00 UTC (24 hours later)
            locations: vec![EventLocation::Physical {
                name: Some("Convention Center".to_string()),
                description: Some("Main auditorium".to_string()),
                icon: Some("🏢".to_string()),
                coordinates: Some("geo:37.7749,-122.4194".to_string()),
                uri: Some("https://conventioncenter.com".to_string()),
                address: Some("123 Conference Ave, San Francisco, CA 94102".to_string()),
                notes: Some("Parking available on-site".to_string()),
            }],
            all_day: false,
        };

        test_postcard_roundtrip(&content)
            .expect("CreateCalendarEventContent should serialize/deserialize");
    }

    #[test]
    fn test_create_calendar_event_virtual_postcard() {
        let content = CreateCalendarEventContent {
            title: "Team Standup".to_string(),
            description: Some("Daily team synchronization".to_string()),
            icon: Some("👥".to_string()),
            parent_id: None,
            utc_start_time: 1703001600,
            utc_end_time: 1703003400, // 30 minutes later
            locations: vec![EventLocation::Virtual {
                name: Some("Zoom Room".to_string()),
                description: Some("Daily standup meeting".to_string()),
                icon: Some("💻".to_string()),
                uri: "https://zoom.us/j/123456789".to_string(),
                notes: Some("Password: standup2023".to_string()),
            }],
            all_day: false,
        };

        test_postcard_roundtrip(&content)
            .expect("Virtual CreateCalendarEventContent should serialize/deserialize");
    }

    #[test]
    fn test_create_calendar_event_all_day_postcard() {
        let content = CreateCalendarEventContent {
            title: "Company Holiday".to_string(),
            description: None,
            icon: Some("🎉".to_string()),
            parent_id: None,
            utc_start_time: 1703001600,
            utc_end_time: 1703088000,
            locations: vec![],
            all_day: true,
        };

        test_postcard_roundtrip(&content)
            .expect("All-day CreateCalendarEventContent should serialize/deserialize");
    }

    #[test]
    fn test_update_calendar_event_content_postcard() {
        let content = vec![
            CalendarEventUpdate::Title("Updated Conference Title".to_string()),
            CalendarEventUpdate::Description("Updated description with new details".to_string()),
            CalendarEventUpdate::UtcStartTime(1703005200), // New start time
            CalendarEventUpdate::UtcEndTime(1703091600),   // New end time
            CalendarEventUpdate::SetLocations(vec![EventLocation::Virtual {
                name: Some("Online Conference".to_string()),
                description: Some("Moved to virtual due to weather".to_string()),
                icon: Some("🌐".to_string()),
                uri: "https://conference.example.com/live".to_string(),
                notes: Some("Check email for access details".to_string()),
            }]),
            CalendarEventUpdate::AllDay(false),
        ];

        test_postcard_roundtrip(&content)
            .expect("UpdateCalendarEventContent should serialize/deserialize");
    }

    #[test]
    fn test_event_location_physical_postcard() {
        let location = EventLocation::Physical {
            name: Some("Central Park".to_string()),
            description: Some("Beautiful park in Manhattan".to_string()),
            icon: Some("🌳".to_string()),
            coordinates: Some("geo:40.7829,-73.9654".to_string()),
            uri: Some("https://centralparknyc.org".to_string()),
            address: Some("Central Park, New York, NY 10024".to_string()),
            notes: Some("Meet at the main entrance".to_string()),
        };

        test_postcard_roundtrip(&location)
            .expect("Physical EventLocation should serialize/deserialize");
    }

    #[test]
    fn test_event_location_virtual_postcard() {
        let location = EventLocation::Virtual {
            name: Some("Discord Server".to_string()),
            description: Some("Community gaming session".to_string()),
            icon: Some("🎮".to_string()),
            uri: "https://discord.gg/abcd1234".to_string(),
            notes: Some("Voice channel #general".to_string()),
        };

        test_postcard_roundtrip(&location)
            .expect("Virtual EventLocation should serialize/deserialize");
    }

    #[test]
    fn test_rsvp_response_postcard() {
        test_postcard_roundtrip(&RsvpResponse::Yes)
            .expect("RsvpResponse::Yes should serialize/deserialize");
        test_postcard_roundtrip(&RsvpResponse::No)
            .expect("RsvpResponse::No should serialize/deserialize");
        test_postcard_roundtrip(&RsvpResponse::Maybe)
            .expect("RsvpResponse::Maybe should serialize/deserialize");
    }

    #[test]
    fn test_update_efficiency_single_field() {
        // Test that updating just one field is very compact
        let single_update = vec![CalendarEventUpdate::Title("New Title".to_string())];
        let serialized = postcard::to_stdvec(&single_update).expect("Should serialize");

        // With Vec<UpdateEnum>, we only serialize what we're actually updating
        // This should be much smaller than a struct with 8 Option fields
        assert!(
            serialized.len() < 50,
            "Single field update should be compact, got {} bytes",
            serialized.len()
        );

        test_postcard_roundtrip(&single_update)
            .expect("Single field update should serialize/deserialize");
    }

    #[test]
    fn test_update_efficiency_multiple_fields() {
        // Test that updating multiple fields is still efficient
        let multi_update = vec![
            CalendarEventUpdate::Title("Updated Title".to_string()),
            CalendarEventUpdate::AllDay(true),
            CalendarEventUpdate::UtcStartTime(1703001600),
        ];
        let serialized = postcard::to_stdvec(&multi_update).expect("Should serialize");

        // Even with multiple updates, we only pay for what we use
        println!("Multi-field update size: {} bytes", serialized.len());

        test_postcard_roundtrip(&multi_update)
            .expect("Multi-field update should serialize/deserialize");
    }

    #[test]
    fn test_update_clear_variants_postcard() {
        // Test that clear variants work correctly
        let clear_updates = vec![
            CalendarEventUpdate::Title("New Title".to_string()),
            CalendarEventUpdate::ClearDescription, // Clear description
            CalendarEventUpdate::ClearIcon,        // Clear icon
            CalendarEventUpdate::ClearLocations,   // Clear all locations
        ];
        let serialized = postcard::to_stdvec(&clear_updates).expect("Should serialize");

        // Clear variants should be very compact (just the discriminant)
        println!("Clear variants update size: {} bytes", serialized.len());

        test_postcard_roundtrip(&clear_updates)
            .expect("Clear variants should serialize/deserialize");
    }

    #[test]
    fn test_multiple_locations_and_list_management() {
        // Test creating an event with multiple locations (hybrid event)
        let hybrid_event = CreateCalendarEventContent {
            title: "Hybrid Conference".to_string(),
            description: Some("Available both in-person and online".to_string()),
            icon: Some("🌐".to_string()),
            parent_id: None,
            utc_start_time: 1703001600,
            utc_end_time: 1703088000,
            locations: vec![
                EventLocation::Physical {
                    name: Some("Main Auditorium".to_string()),
                    description: Some("In-person venue".to_string()),
                    icon: Some("🏢".to_string()),
                    coordinates: Some("geo:37.7749,-122.4194".to_string()),
                    uri: Some("https://venue.com".to_string()),
                    address: Some("123 Conference St, SF, CA".to_string()),
                    notes: Some("Parking available".to_string()),
                },
                EventLocation::Virtual {
                    name: Some("Live Stream".to_string()),
                    description: Some("Online participation".to_string()),
                    icon: Some("💻".to_string()),
                    uri: "https://stream.example.com/live".to_string(),
                    notes: Some("Registration required".to_string()),
                },
            ],
            all_day: false,
        };

        test_postcard_roundtrip(&hybrid_event)
            .expect("Hybrid event with multiple locations should serialize/deserialize");

        // Test list management operations
        let location_updates = vec![
            // Set new locations list (replaces all)
            CalendarEventUpdate::SetLocations(vec![EventLocation::Virtual {
                name: Some("Backup Stream".to_string()),
                description: Some("Alternative online venue".to_string()),
                icon: Some("🔄".to_string()),
                uri: "https://backup.example.com/live".to_string(),
                notes: Some("Use if main stream fails".to_string()),
            }]),
            // Add another location to the list
            CalendarEventUpdate::AddLocation(EventLocation::Physical {
                name: Some("Overflow Room".to_string()),
                description: Some("Additional capacity".to_string()),
                icon: Some("📺".to_string()),
                coordinates: Some("geo:37.7849,-122.4094".to_string()),
                uri: None,
                address: Some("456 Overflow Ave, SF, CA".to_string()),
                notes: Some("Live video feed from main auditorium".to_string()),
            }),
            // Clear all locations
            CalendarEventUpdate::ClearLocations,
        ];

        test_postcard_roundtrip(&location_updates)
            .expect("Location list management updates should serialize/deserialize");
    }
}
