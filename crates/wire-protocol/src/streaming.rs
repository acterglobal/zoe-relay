use blake3::Hash;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use tarpc::{ClientMessage, Response};

use crate::{MessageFull, StoreKey};

/// Message filtering criteria for querying stored messages
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MessageFilters {
    pub authors: Option<Vec<Vec<u8>>>,
    pub channels: Option<Vec<Vec<u8>>>,
    pub events: Option<Vec<Vec<u8>>>,
    pub users: Option<Vec<Vec<u8>>>,
}

/// Generic filter field identifier
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FilterField {
    Author,
    Channel,
    Event,
    User,
}

/// Generic filter operations that work on any field
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FilterOperation {
    /// Add values to a specific filter field
    Add {
        field: FilterField,
        values: Vec<Vec<u8>>,
    },

    /// Remove values from a specific filter field
    Remove {
        field: FilterField,
        values: Vec<Vec<u8>>,
    },

    /// Replace all values in a specific filter field
    Replace {
        field: FilterField,
        values: Vec<Vec<u8>>,
    },

    /// Clear a specific filter field (set to None)
    Clear { field: FilterField },

    /// Replace the entire filter set (forces restart - use sparingly)
    ReplaceAll(MessageFilters),
}

impl FilterOperation {
    /// Add channels to the filter
    pub fn add_channels(channels: Vec<Vec<u8>>) -> Self {
        Self::Add {
            field: FilterField::Channel,
            values: channels,
        }
    }

    /// Remove channels from the filter
    pub fn remove_channels(channels: Vec<Vec<u8>>) -> Self {
        Self::Remove {
            field: FilterField::Channel,
            values: channels,
        }
    }

    /// Add authors to the filter
    pub fn add_authors(authors: Vec<Vec<u8>>) -> Self {
        Self::Add {
            field: FilterField::Author,
            values: authors,
        }
    }

    /// Remove authors from the filter
    pub fn remove_authors(authors: Vec<Vec<u8>>) -> Self {
        Self::Remove {
            field: FilterField::Author,
            values: authors,
        }
    }

    /// Add events to the filter
    pub fn add_events(events: Vec<Vec<u8>>) -> Self {
        Self::Add {
            field: FilterField::Event,
            values: events,
        }
    }

    /// Add users to the filter
    pub fn add_users(users: Vec<Vec<u8>>) -> Self {
        Self::Add {
            field: FilterField::User,
            values: users,
        }
    }

    /// Remove events from the filter
    pub fn remove_events(events: Vec<Vec<u8>>) -> Self {
        Self::Remove {
            field: FilterField::Event,
            values: events,
        }
    }

    /// Remove users from the filter
    pub fn remove_users(users: Vec<Vec<u8>>) -> Self {
        Self::Remove {
            field: FilterField::User,
            values: users,
        }
    }

    /// Clear all channels
    pub fn clear_channels() -> Self {
        Self::Clear {
            field: FilterField::Channel,
        }
    }

    /// Replace all channels
    pub fn replace_channels(channels: Vec<Vec<u8>>) -> Self {
        Self::Replace {
            field: FilterField::Channel,
            values: channels,
        }
    }

    /// Clear all authors
    pub fn clear_authors() -> Self {
        Self::Clear {
            field: FilterField::Author,
        }
    }

    /// Clear all events
    pub fn clear_events() -> Self {
        Self::Clear {
            field: FilterField::Event,
        }
    }

    /// Clear all users
    pub fn clear_users() -> Self {
        Self::Clear {
            field: FilterField::User,
        }
    }

    /// Replace all events
    pub fn replace_events(events: Vec<Vec<u8>>) -> Self {
        Self::Replace {
            field: FilterField::Event,
            values: events,
        }
    }

    /// Replace all authors
    pub fn replace_authors(authors: Vec<Vec<u8>>) -> Self {
        Self::Replace {
            field: FilterField::Author,
            values: authors,
        }
    }

    /// Replace all users
    pub fn replace_users(users: Vec<Vec<u8>>) -> Self {
        Self::Replace {
            field: FilterField::User,
            values: users,
        }
    }
}

impl MessageFilters {
    pub fn is_empty(&self) -> bool {
        self.authors.is_none()
            && self.channels.is_none()
            && self.events.is_none()
            && self.users.is_none()
    }

    /// Apply a generic filter operation to this filter set
    pub fn apply_operation(&mut self, operation: &FilterOperation) {
        match operation {
            FilterOperation::Add { field, values } => {
                let target_field = self.get_field_mut(field);
                let field_vec = target_field.get_or_insert_with(Vec::new);

                for value in values {
                    if !field_vec.contains(value) {
                        field_vec.push(value.clone());
                    }
                }
            }

            FilterOperation::Remove { field, values } => {
                if let Some(field_vec) = self.get_field_mut(field).as_mut() {
                    field_vec.retain(|existing| !values.contains(existing));

                    // Clean up empty vectors
                    if field_vec.is_empty() {
                        *self.get_field_mut(field) = None;
                    }
                }
            }

            FilterOperation::Replace { field, values } => {
                let target_field = self.get_field_mut(field);
                if values.is_empty() {
                    *target_field = None;
                } else {
                    *target_field = Some(values.clone());
                }
            }

            FilterOperation::Clear { field } => {
                *self.get_field_mut(field) = None;
            }

            FilterOperation::ReplaceAll(new_filters) => {
                *self = new_filters.clone();
            }
        }
    }

    /// Get a mutable reference to the specified filter field
    fn get_field_mut(&mut self, field: &FilterField) -> &mut Option<Vec<Vec<u8>>> {
        match field {
            FilterField::Author => &mut self.authors,
            FilterField::Channel => &mut self.channels,
            FilterField::Event => &mut self.events,
            FilterField::User => &mut self.users,
        }
    }

    /// Get an immutable reference to the specified filter field
    pub fn get_field(&self, field: &FilterField) -> &Option<Vec<Vec<u8>>> {
        match field {
            FilterField::Author => &self.authors,
            FilterField::Channel => &self.channels,
            FilterField::Event => &self.events,
            FilterField::User => &self.users,
        }
    }
}

/// Messages sent over the streaming protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamMessage {
    /// A new message received that matches our filter
    MessageReceived {
        /// Blake3 hash of the message
        message: MessageFull,
        /// Redis stream position
        stream_height: String,
    },
    /// We have just received a stream height update
    /// but our filter didn't apply here
    /// Indicator that we are live now and we have
    /// received all messages up to this point this
    /// server knows about
    StreamHeightUpdate(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    pub filters: MessageFilters,
    pub since: Option<String>,
    pub limit: Option<usize>,
}
/// Message store service for message interaction operations
#[tarpc::service]
pub trait MessageService {
    // async fn subscribe(config: SubscriptionConfig) -> Result<(), MessageError>;
    async fn publish(message: MessageFull) -> Result<Option<String>, MessageError>;
    async fn message(id: Hash) -> Result<Option<MessageFull>, MessageError>;
    async fn user_data(
        author: VerifyingKey,
        storage_key: StoreKey,
    ) -> Result<Option<MessageFull>, MessageError>;
}

/// Result type for message operations
pub type MessageResult<T> = Result<T, MessageError>;

/// Error types for blob operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum MessageError {
    #[error("Message not found: {hash}")]
    NotFound { hash: String },

    #[error("Invalid message hash: {hash}")]
    InvalidHash { hash: String },

    #[error("Storage error: {message}")]
    StorageError { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("IO error: {message}")]
    IoError { message: String },

    #[error("Internal server error: {message}")]
    InternalError { message: String },
}

/// Generic filter update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterUpdateRequest {
    pub operations: Vec<FilterOperation>,
}

/// Generic catch-up request for historical messages of any filter field type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchUpRequest {
    pub filter_field: FilterField, // What type of filter (Channel, Author, Event, User)
    pub filter_value: Vec<u8>,     // The ID/value to catch up on
    pub since: Option<String>,     // Redis stream ID
    pub max_messages: Option<usize>,
    pub request_id: String, // For tracking response
}

impl CatchUpRequest {
    /// Convenience constructor for channel catch-up
    pub fn for_channel(
        channel_id: Vec<u8>,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: String,
    ) -> Self {
        Self {
            filter_field: FilterField::Channel,
            filter_value: channel_id,
            since,
            max_messages,
            request_id,
        }
    }

    /// Convenience constructor for author catch-up
    pub fn for_author(
        author_id: Vec<u8>,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: String,
    ) -> Self {
        Self {
            filter_field: FilterField::Author,
            filter_value: author_id,
            since,
            max_messages,
            request_id,
        }
    }

    /// Convenience constructor for event catch-up
    pub fn for_event(
        event_id: Vec<u8>,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: String,
    ) -> Self {
        Self {
            filter_field: FilterField::Event,
            filter_value: event_id,
            since,
            max_messages,
            request_id,
        }
    }

    /// Convenience constructor for user catch-up
    pub fn for_user(
        user_id: Vec<u8>,
        since: Option<String>,
        max_messages: Option<usize>,
        request_id: String,
    ) -> Self {
        Self {
            filter_field: FilterField::User,
            filter_value: user_id,
            since,
            max_messages,
            request_id,
        }
    }
}

/// Catch-up response with historical messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatchUpResponse {
    pub request_id: String,
    pub filter_field: FilterField, // What type of filter was requested
    pub filter_value: Vec<u8>,     // The ID/value that was caught up on
    pub messages: Vec<MessageFull>,
    pub is_complete: bool,          // False if more batches coming
    pub next_since: Option<String>, // For pagination
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessagesServiceRequestWrap {
    /// Initial subscription setup
    Subscribe(SubscriptionConfig),

    /// Live filter updates (no stream restart)
    UpdateFilters(FilterUpdateRequest),

    /// Parallel catch-up request for historical messages
    CatchUp(CatchUpRequest),

    /// RPC request forwarding
    RpcRequest(ClientMessage<MessageServiceRequest>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageServiceResponseWrap {
    /// Streaming messages (live or historical)
    StreamMessage(StreamMessage),

    /// Catch-up response with batched historical messages
    CatchUpResponse(CatchUpResponse),

    /// Filter update acknowledgment
    FilterUpdateAck,

    /// RPC response forwarding
    RpcResponse(Response<MessageServiceResponse>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_field_enum() {
        // Test that FilterField variants are properly defined
        let author = FilterField::Author;
        let channel = FilterField::Channel;
        let event = FilterField::Event;
        let user = FilterField::User;

        // Test Debug formatting
        assert_eq!(format!("{author:?}"), "Author");
        assert_eq!(format!("{channel:?}"), "Channel");
        assert_eq!(format!("{event:?}"), "Event");
        assert_eq!(format!("{user:?}"), "User");

        // Test PartialEq
        assert_eq!(FilterField::Author, FilterField::Author);
        assert_ne!(FilterField::Author, FilterField::Channel);
    }

    #[test]
    fn test_message_filters_default() {
        let filters = MessageFilters::default();
        assert!(filters.is_empty());
        assert!(filters.authors.is_none());
        assert!(filters.channels.is_none());
        assert!(filters.events.is_none());
        assert!(filters.users.is_none());
    }

    #[test]
    fn test_message_filters_is_empty() {
        let mut filters = MessageFilters::default();
        assert!(filters.is_empty());

        // Add some channels
        filters.channels = Some(vec![b"general".to_vec()]);
        assert!(!filters.is_empty());

        // Clear channels but add authors
        filters.channels = None;
        filters.authors = Some(vec![b"alice".to_vec()]);
        assert!(!filters.is_empty());

        // Clear all
        filters.authors = None;
        assert!(filters.is_empty());
    }

    #[test]
    fn test_get_field_operations() {
        let mut filters = MessageFilters {
            authors: Some(vec![b"alice".to_vec()]),
            channels: Some(vec![b"general".to_vec()]),
            events: Some(vec![b"important".to_vec()]),
            users: Some(vec![b"user1".to_vec()]),
        };

        // Test get_field (immutable)
        assert_eq!(
            filters.get_field(&FilterField::Author),
            &Some(vec![b"alice".to_vec()])
        );
        assert_eq!(
            filters.get_field(&FilterField::Channel),
            &Some(vec![b"general".to_vec()])
        );
        assert_eq!(
            filters.get_field(&FilterField::Event),
            &Some(vec![b"important".to_vec()])
        );
        assert_eq!(
            filters.get_field(&FilterField::User),
            &Some(vec![b"user1".to_vec()])
        );

        // Test get_field_mut (mutable)
        *filters.get_field_mut(&FilterField::Author) = Some(vec![b"bob".to_vec()]);
        assert_eq!(filters.authors, Some(vec![b"bob".to_vec()]));
    }

    #[test]
    fn test_filter_operation_convenience_constructors() {
        let channels = vec![b"general".to_vec(), b"tech".to_vec()];
        let authors = vec![b"alice".to_vec()];
        let events = vec![b"important".to_vec()];
        let users = vec![b"user1".to_vec()];

        // Test add operations
        let add_channels = FilterOperation::add_channels(channels.clone());
        match add_channels {
            FilterOperation::Add { field, values } => {
                assert_eq!(field, FilterField::Channel);
                assert_eq!(values, channels);
            }
            _ => panic!("Expected Add operation"),
        }

        let add_authors = FilterOperation::add_authors(authors.clone());
        match add_authors {
            FilterOperation::Add { field, values } => {
                assert_eq!(field, FilterField::Author);
                assert_eq!(values, authors);
            }
            _ => panic!("Expected Add operation"),
        }

        let add_events = FilterOperation::add_events(events.clone());
        match add_events {
            FilterOperation::Add { field, values } => {
                assert_eq!(field, FilterField::Event);
                assert_eq!(values, events);
            }
            _ => panic!("Expected Add operation"),
        }

        let add_users = FilterOperation::add_users(users.clone());
        match add_users {
            FilterOperation::Add { field, values } => {
                assert_eq!(field, FilterField::User);
                assert_eq!(values, users);
            }
            _ => panic!("Expected Add operation"),
        }

        // Test remove operations
        let remove_channels = FilterOperation::remove_channels(channels.clone());
        match remove_channels {
            FilterOperation::Remove { field, values } => {
                assert_eq!(field, FilterField::Channel);
                assert_eq!(values, channels);
            }
            _ => panic!("Expected Remove operation"),
        }

        let remove_authors = FilterOperation::remove_authors(authors.clone());
        match remove_authors {
            FilterOperation::Remove { field, values } => {
                assert_eq!(field, FilterField::Author);
                assert_eq!(values, authors);
            }
            _ => panic!("Expected Remove operation"),
        }

        // Test replace operations
        let replace_channels = FilterOperation::replace_channels(channels.clone());
        match replace_channels {
            FilterOperation::Replace { field, values } => {
                assert_eq!(field, FilterField::Channel);
                assert_eq!(values, channels);
            }
            _ => panic!("Expected Replace operation"),
        }

        let replace_events = FilterOperation::replace_events(events.clone());
        match replace_events {
            FilterOperation::Replace { field, values } => {
                assert_eq!(field, FilterField::Event);
                assert_eq!(values, events);
            }
            _ => panic!("Expected Replace operation"),
        }

        let replace_authors = FilterOperation::replace_authors(authors.clone());
        match replace_authors {
            FilterOperation::Replace { field, values } => {
                assert_eq!(field, FilterField::Author);
                assert_eq!(values, authors);
            }
            _ => panic!("Expected Replace operation"),
        }

        let replace_users = FilterOperation::replace_users(users.clone());
        match replace_users {
            FilterOperation::Replace { field, values } => {
                assert_eq!(field, FilterField::User);
                assert_eq!(values, users);
            }
            _ => panic!("Expected Replace operation"),
        }

        // Test clear operations
        let clear_channels = FilterOperation::clear_channels();
        match clear_channels {
            FilterOperation::Clear { field } => {
                assert_eq!(field, FilterField::Channel);
            }
            _ => panic!("Expected Clear operation"),
        }

        let clear_authors = FilterOperation::clear_authors();
        match clear_authors {
            FilterOperation::Clear { field } => {
                assert_eq!(field, FilterField::Author);
            }
            _ => panic!("Expected Clear operation"),
        }

        let clear_events = FilterOperation::clear_events();
        match clear_events {
            FilterOperation::Clear { field } => {
                assert_eq!(field, FilterField::Event);
            }
            _ => panic!("Expected Clear operation"),
        }

        let clear_users = FilterOperation::clear_users();
        match clear_users {
            FilterOperation::Clear { field } => {
                assert_eq!(field, FilterField::User);
            }
            _ => panic!("Expected Clear operation"),
        }
    }

    #[test]
    fn test_apply_operation_add() {
        let mut filters = MessageFilters::default();

        // Test adding channels
        let add_channels =
            FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]);
        filters.apply_operation(&add_channels);
        assert_eq!(
            filters.channels,
            Some(vec![b"general".to_vec(), b"tech".to_vec()])
        );

        // Test adding more channels (should not duplicate)
        let add_more_channels = FilterOperation::add_channels(vec![
            b"general".to_vec(), // duplicate
            b"random".to_vec(),  // new
        ]);
        filters.apply_operation(&add_more_channels);
        assert_eq!(
            filters.channels,
            Some(vec![
                b"general".to_vec(),
                b"tech".to_vec(),
                b"random".to_vec()
            ])
        );

        // Test adding authors
        let add_authors = FilterOperation::add_authors(vec![b"alice".to_vec()]);
        filters.apply_operation(&add_authors);
        assert_eq!(filters.authors, Some(vec![b"alice".to_vec()]));
    }

    #[test]
    fn test_apply_operation_remove() {
        let mut filters = MessageFilters {
            channels: Some(vec![
                b"general".to_vec(),
                b"tech".to_vec(),
                b"random".to_vec(),
            ]),
            authors: Some(vec![b"alice".to_vec(), b"bob".to_vec()]),
            events: None,
            users: None,
        };

        // Test removing some channels
        let remove_channels = FilterOperation::remove_channels(vec![b"tech".to_vec()]);
        filters.apply_operation(&remove_channels);
        assert_eq!(
            filters.channels,
            Some(vec![b"general".to_vec(), b"random".to_vec()])
        );

        // Test removing all remaining channels
        let remove_all_channels =
            FilterOperation::remove_channels(vec![b"general".to_vec(), b"random".to_vec()]);
        filters.apply_operation(&remove_all_channels);
        assert_eq!(filters.channels, None); // Should be None when empty

        // Test removing from authors
        let remove_authors = FilterOperation::remove_authors(vec![b"alice".to_vec()]);
        filters.apply_operation(&remove_authors);
        assert_eq!(filters.authors, Some(vec![b"bob".to_vec()]));

        // Test removing from non-existent field (should be no-op)
        let remove_events = FilterOperation::remove_events(vec![b"nonexistent".to_vec()]);
        filters.apply_operation(&remove_events);
        assert_eq!(filters.events, None);
    }

    #[test]
    fn test_apply_operation_replace() {
        let mut filters = MessageFilters {
            channels: Some(vec![b"old1".to_vec(), b"old2".to_vec()]),
            authors: Some(vec![b"alice".to_vec()]),
            events: None,
            users: None,
        };

        // Test replacing channels
        let replace_channels = FilterOperation::replace_channels(vec![
            b"new1".to_vec(),
            b"new2".to_vec(),
            b"new3".to_vec(),
        ]);
        filters.apply_operation(&replace_channels);
        assert_eq!(
            filters.channels,
            Some(vec![b"new1".to_vec(), b"new2".to_vec(), b"new3".to_vec()])
        );

        // Test replacing with empty vector (should set to None)
        let replace_empty = FilterOperation::replace_authors(vec![]);
        filters.apply_operation(&replace_empty);
        assert_eq!(filters.authors, None);

        // Test replacing a None field
        let replace_events = FilterOperation::replace_events(vec![b"important".to_vec()]);
        filters.apply_operation(&replace_events);
        assert_eq!(filters.events, Some(vec![b"important".to_vec()]));
    }

    #[test]
    fn test_apply_operation_clear() {
        let mut filters = MessageFilters {
            channels: Some(vec![b"general".to_vec()]),
            authors: Some(vec![b"alice".to_vec()]),
            events: Some(vec![b"important".to_vec()]),
            users: Some(vec![b"user1".to_vec()]),
        };

        // Test clearing channels
        let clear_channels = FilterOperation::clear_channels();
        filters.apply_operation(&clear_channels);
        assert_eq!(filters.channels, None);

        // Test clearing authors
        let clear_authors = FilterOperation::clear_authors();
        filters.apply_operation(&clear_authors);
        assert_eq!(filters.authors, None);

        // Test clearing events
        let clear_events = FilterOperation::clear_events();
        filters.apply_operation(&clear_events);
        assert_eq!(filters.events, None);

        // Test clearing users
        let clear_users = FilterOperation::clear_users();
        filters.apply_operation(&clear_users);
        assert_eq!(filters.users, None);

        // Now filter should be empty
        assert!(filters.is_empty());
    }

    #[test]
    fn test_apply_operation_replace_all() {
        let mut filters = MessageFilters {
            channels: Some(vec![b"old".to_vec()]),
            authors: Some(vec![b"old_author".to_vec()]),
            events: None,
            users: None,
        };

        let new_filters = MessageFilters {
            channels: Some(vec![b"new_channel".to_vec()]),
            authors: None,
            events: Some(vec![b"new_event".to_vec()]),
            users: Some(vec![b"new_user".to_vec()]),
        };

        let replace_all = FilterOperation::ReplaceAll(new_filters.clone());
        filters.apply_operation(&replace_all);

        assert_eq!(filters, new_filters);
    }

    #[test]
    fn test_atomic_multi_operation_scenario() {
        let mut filters = MessageFilters::default();

        // Simulate atomic application of multiple operations
        let operations = vec![
            FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]),
            FilterOperation::add_authors(vec![b"alice".to_vec()]),
            FilterOperation::add_events(vec![b"important".to_vec()]),
            FilterOperation::add_users(vec![b"user1".to_vec()]),
        ];

        for operation in &operations {
            filters.apply_operation(operation);
        }

        assert_eq!(
            filters.channels,
            Some(vec![b"general".to_vec(), b"tech".to_vec()])
        );
        assert_eq!(filters.authors, Some(vec![b"alice".to_vec()]));
        assert_eq!(filters.events, Some(vec![b"important".to_vec()]));
        assert_eq!(filters.users, Some(vec![b"user1".to_vec()]));
    }

    #[test]
    fn test_duplicate_prevention() {
        let mut filters = MessageFilters::default();

        // Add the same channel multiple times
        filters.apply_operation(&FilterOperation::add_channels(vec![b"general".to_vec()]));
        filters.apply_operation(&FilterOperation::add_channels(vec![b"general".to_vec()]));
        filters.apply_operation(&FilterOperation::add_channels(vec![b"general".to_vec()]));

        // Should only have one instance
        assert_eq!(filters.channels, Some(vec![b"general".to_vec()]));
    }

    #[test]
    fn test_complex_filter_manipulation() {
        let mut filters = MessageFilters::default();

        // Start with some initial data
        filters.apply_operation(&FilterOperation::add_channels(vec![
            b"general".to_vec(),
            b"tech".to_vec(),
            b"random".to_vec(),
        ]));
        filters.apply_operation(&FilterOperation::add_authors(vec![
            b"alice".to_vec(),
            b"bob".to_vec(),
            b"charlie".to_vec(),
        ]));

        // Remove some items
        filters.apply_operation(&FilterOperation::remove_channels(vec![b"random".to_vec()]));
        filters.apply_operation(&FilterOperation::remove_authors(vec![b"charlie".to_vec()]));

        // Add some new items
        filters.apply_operation(&FilterOperation::add_channels(vec![b"urgent".to_vec()]));
        filters.apply_operation(&FilterOperation::add_events(vec![b"important".to_vec()]));

        // Verify final state
        assert_eq!(
            filters.channels,
            Some(vec![
                b"general".to_vec(),
                b"tech".to_vec(),
                b"urgent".to_vec()
            ])
        );
        assert_eq!(
            filters.authors,
            Some(vec![b"alice".to_vec(), b"bob".to_vec()])
        );
        assert_eq!(filters.events, Some(vec![b"important".to_vec()]));
        assert_eq!(filters.users, None);
    }

    #[test]
    fn test_filter_update_request() {
        let operations = vec![
            FilterOperation::add_channels(vec![b"general".to_vec()]),
            FilterOperation::remove_authors(vec![b"spammer".to_vec()]),
            FilterOperation::add_events(vec![b"important".to_vec()]),
        ];

        let filter_request = FilterUpdateRequest {
            operations: operations.clone(),
        };

        assert_eq!(filter_request.operations.len(), 3);
        assert_eq!(filter_request.operations, operations);

        // Test that the request can be applied
        let mut filters = MessageFilters::default();
        for operation in &filter_request.operations {
            filters.apply_operation(operation);
        }

        assert_eq!(filters.channels, Some(vec![b"general".to_vec()]));
        assert_eq!(filters.authors, None); // Remove from empty has no effect
        assert_eq!(filters.events, Some(vec![b"important".to_vec()]));
    }

    #[test]
    fn test_edge_cases() {
        let mut filters = MessageFilters::default();

        // Test empty values in operations
        filters.apply_operation(&FilterOperation::add_channels(vec![]));
        assert_eq!(filters.channels, Some(vec![])); // Empty add creates empty vector

        // Test replace with empty values
        filters.channels = Some(vec![b"existing".to_vec()]);
        filters.apply_operation(&FilterOperation::replace_channels(vec![]));
        assert_eq!(filters.channels, None); // Empty replace should clear

        // Test removing non-existent values
        filters.channels = Some(vec![b"general".to_vec()]);
        filters.apply_operation(&FilterOperation::remove_channels(vec![
            b"nonexistent".to_vec()
        ]));
        assert_eq!(filters.channels, Some(vec![b"general".to_vec()])); // Should be unchanged

        // Test clearing already empty field
        filters.authors = None;
        filters.apply_operation(&FilterOperation::clear_authors());
        assert_eq!(filters.authors, None); // Should remain None

        // Test adding to existing empty field
        filters.channels = Some(vec![]);
        filters.apply_operation(&FilterOperation::add_channels(vec![b"new".to_vec()]));
        assert_eq!(filters.channels, Some(vec![b"new".to_vec()])); // Should add to empty

        // Test removing all items results in None
        filters.channels = Some(vec![b"channel1".to_vec(), b"channel2".to_vec()]);
        filters.apply_operation(&FilterOperation::remove_channels(vec![
            b"channel1".to_vec(),
            b"channel2".to_vec(),
        ]));
        assert_eq!(filters.channels, None); // Empty after remove should be None
    }

    #[test]
    fn test_message_filters_equality() {
        let filters1 = MessageFilters {
            channels: Some(vec![b"general".to_vec()]),
            authors: Some(vec![b"alice".to_vec()]),
            events: None,
            users: None,
        };

        let filters2 = MessageFilters {
            channels: Some(vec![b"general".to_vec()]),
            authors: Some(vec![b"alice".to_vec()]),
            events: None,
            users: None,
        };

        let filters3 = MessageFilters {
            channels: Some(vec![b"tech".to_vec()]),
            authors: Some(vec![b"alice".to_vec()]),
            events: None,
            users: None,
        };

        assert_eq!(filters1, filters2);
        assert_ne!(filters1, filters3);
    }

    #[test]
    fn test_subscription_config() {
        let filters = MessageFilters {
            channels: Some(vec![b"general".to_vec()]),
            authors: None,
            events: None,
            users: None,
        };

        let config = SubscriptionConfig {
            filters: filters.clone(),
            since: Some("1234-0".to_string()),
            limit: Some(100),
        };

        assert_eq!(config.filters, filters);
        assert_eq!(config.since, Some("1234-0".to_string()));
        assert_eq!(config.limit, Some(100));
    }

    #[test]
    fn test_generic_catchup_request() {
        // Test channel catch-up
        let channel_request = CatchUpRequest::for_channel(
            b"general".to_vec(),
            Some("1234-0".to_string()),
            Some(50),
            "req123".to_string(),
        );

        assert_eq!(channel_request.filter_field, FilterField::Channel);
        assert_eq!(channel_request.filter_value, b"general".to_vec());
        assert_eq!(channel_request.since, Some("1234-0".to_string()));
        assert_eq!(channel_request.max_messages, Some(50));
        assert_eq!(channel_request.request_id, "req123");

        // Test author catch-up
        let author_request = CatchUpRequest::for_author(
            b"alice".to_vec(),
            None,
            Some(100),
            "author-req456".to_string(),
        );

        assert_eq!(author_request.filter_field, FilterField::Author);
        assert_eq!(author_request.filter_value, b"alice".to_vec());
        assert_eq!(author_request.since, None);
        assert_eq!(author_request.max_messages, Some(100));
        assert_eq!(author_request.request_id, "author-req456");

        // Test event catch-up
        let event_request = CatchUpRequest::for_event(
            b"urgent".to_vec(),
            Some("5678-1".to_string()),
            None,
            "event-req789".to_string(),
        );

        assert_eq!(event_request.filter_field, FilterField::Event);
        assert_eq!(event_request.filter_value, b"urgent".to_vec());
        assert_eq!(event_request.since, Some("5678-1".to_string()));
        assert_eq!(event_request.max_messages, None);
        assert_eq!(event_request.request_id, "event-req789");

        // Test user catch-up
        let user_request = CatchUpRequest::for_user(
            b"user123".to_vec(),
            Some("9999-0".to_string()),
            Some(25),
            "user-req101".to_string(),
        );

        assert_eq!(user_request.filter_field, FilterField::User);
        assert_eq!(user_request.filter_value, b"user123".to_vec());
        assert_eq!(user_request.since, Some("9999-0".to_string()));
        assert_eq!(user_request.max_messages, Some(25));
        assert_eq!(user_request.request_id, "user-req101");
    }

    #[test]
    fn test_catchup_response() {
        let response = CatchUpResponse {
            request_id: "req123".to_string(),
            filter_field: FilterField::Channel,
            filter_value: b"general".to_vec(),
            messages: vec![], // Empty for test
            is_complete: true,
            next_since: Some("1234-1".to_string()),
        };

        assert_eq!(response.request_id, "req123");
        assert_eq!(response.filter_field, FilterField::Channel);
        assert_eq!(response.filter_value, b"general".to_vec());
        assert!(response.is_complete);
        assert_eq!(response.next_since, Some("1234-1".to_string()));
    }

    #[test]
    fn test_filter_operation_equality() {
        // Test that FilterOperation properly implements PartialEq
        let op1 = FilterOperation::add_channels(vec![b"general".to_vec()]);
        let op2 = FilterOperation::add_channels(vec![b"general".to_vec()]);
        let op3 = FilterOperation::add_channels(vec![b"tech".to_vec()]);
        let op4 = FilterOperation::add_authors(vec![b"general".to_vec()]);

        assert_eq!(op1, op2);
        assert_ne!(op1, op3); // Different values
        assert_ne!(op1, op4); // Different operation type

        // Test complex operations
        let operations1 = vec![
            FilterOperation::add_channels(vec![b"general".to_vec()]),
            FilterOperation::remove_authors(vec![b"spammer".to_vec()]),
        ];
        let operations2 = vec![
            FilterOperation::add_channels(vec![b"general".to_vec()]),
            FilterOperation::remove_authors(vec![b"spammer".to_vec()]),
        ];

        assert_eq!(operations1, operations2);
    }

    #[test]
    fn test_all_remove_operations() {
        // Test that all remove operations work correctly
        let mut filters = MessageFilters {
            channels: Some(vec![b"general".to_vec(), b"tech".to_vec()]),
            authors: Some(vec![b"alice".to_vec(), b"bob".to_vec()]),
            events: Some(vec![b"important".to_vec(), b"urgent".to_vec()]),
            users: Some(vec![b"user1".to_vec(), b"user2".to_vec()]),
        };

        // Test remove_events
        filters.apply_operation(&FilterOperation::remove_events(vec![b"urgent".to_vec()]));
        assert_eq!(filters.events, Some(vec![b"important".to_vec()]));

        // Test remove_users
        filters.apply_operation(&FilterOperation::remove_users(vec![b"user1".to_vec()]));
        assert_eq!(filters.users, Some(vec![b"user2".to_vec()]));

        // Remove all remaining events
        filters.apply_operation(&FilterOperation::remove_events(vec![b"important".to_vec()]));
        assert_eq!(filters.events, None);

        // Remove all remaining users
        filters.apply_operation(&FilterOperation::remove_users(vec![b"user2".to_vec()]));
        assert_eq!(filters.users, None);
    }
}
