use serde::{Deserialize, Serialize};

use crate::MessageFull;

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
    StreamHeightUpdate(String),
}

/// Request to start a message stream over a dedicated QUIC stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRequest {
    /// Message filtering criteria
    pub filters: crate::MessageFilters,
    /// Start streaming from this message ID (optional but recommended)
    pub since: Option<String>,
}

impl StreamRequest {
    pub fn new(filters: crate::MessageFilters) -> Self {
        Self {
            filters,
            since: None,
        }
    }

    pub fn with_since(mut self, since: String) -> Self {
        self.since = Some(since);
        self
    }
}
