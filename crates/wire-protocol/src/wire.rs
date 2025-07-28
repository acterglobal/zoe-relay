use serde::{Deserialize, Serialize};

use crate::StreamMessage;

/// Wrapped enum for different message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServerWireMessage<R> {
    /// Streaming protocol message
    Stream(StreamMessage),
    /// RPC message that goes to tarpc
    Rpc(R),
}
