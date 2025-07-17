use serde::{Deserialize, Serialize};

use crate::StreamMessage;

/// Wrapped enum for different message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + for<'a> Deserialize<'a>, R: Serialize + for<'a> Deserialize<'a>")]
pub enum ServerWireMessage<R, T>
where
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    /// Streaming protocol message
    Stream(StreamMessage<T>),
    /// RPC message that goes to tarpc
    Rpc(R),
}
