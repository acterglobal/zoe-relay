use serde::{Deserialize, Serialize};

/// Request to start a message stream over a dedicated QUIC stream
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamRequest {
    /// Message filtering criteria
    pub filters: crate::MessageFilters,
    /// Start streaming from this message ID (optional)
    pub since: Option<String>,
    /// Maximum number of messages per batch (optional)
    pub limit: Option<usize>,
    /// Keep streaming for new messages (don't stop after initial batch)
    pub follow: bool,
}

/// Messages sent over the streaming protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamingMessage {
    /// A new message received from the storage
    MessageReceived {
        /// Blake3 hash of the message
        message_id: String,
        /// Redis stream position
        stream_position: String,
        /// Serialized MessageFull data
        message_data: Vec<u8>,
    },
    /// Stream has ended (no more messages)
    StreamEnd,
    /// Error occurred in streaming
    StreamError(String),
    /// Heartbeat to keep connection alive
    Heartbeat,
    /// Batch boundary marker (indicates end of current batch)
    BatchEnd,
}

/// Response to stream request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamResponse {
    /// Stream started successfully
    StreamStarted,
    /// Stream request was rejected
    StreamRejected(String),
}

/// Protocol message that can be either a stream request or streaming message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StreamProtocolMessage {
    /// Initial request to start streaming
    Request(StreamRequest),
    /// Response to stream request
    Response(StreamResponse),
    /// Streaming message
    Message(StreamingMessage),
}

impl StreamRequest {
    pub fn new(filters: crate::MessageFilters) -> Self {
        Self {
            filters,
            since: None,
            limit: None,
            follow: false,
        }
    }

    pub fn with_since(mut self, since: String) -> Self {
        self.since = Some(since);
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_follow(mut self, follow: bool) -> Self {
        self.follow = follow;
        self
    }
}

impl StreamingMessage {
    pub fn new_message(message_id: String, stream_position: String, message_data: Vec<u8>) -> Self {
        Self::MessageReceived {
            message_id,
            stream_position,
            message_data,
        }
    }

    pub fn error(message: String) -> Self {
        Self::StreamError(message)
    }

    pub fn end() -> Self {
        Self::StreamEnd
    }

    pub fn heartbeat() -> Self {
        Self::Heartbeat
    }

    pub fn batch_end() -> Self {
        Self::BatchEnd
    }
}
