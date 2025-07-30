use serde::{Deserialize, Serialize};

use crate::MessageFull;

/// Message filtering criteria for querying stored messages
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageFilters {
    pub authors: Option<Vec<Vec<u8>>>,
    pub channels: Option<Vec<Vec<u8>>>,
    pub events: Option<Vec<Vec<u8>>>,
    pub users: Option<Vec<Vec<u8>>>,
}

impl MessageFilters {
    pub fn is_empty(&self) -> bool {
        self.authors.is_none()
            && self.channels.is_none()
            && self.events.is_none()
            && self.users.is_none()
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
    filters: MessageFilters,
    since: Option<String>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagesServiceRequest {
    Subscribe(SubscriptionConfig),
    Publish(MessageFull),
}
