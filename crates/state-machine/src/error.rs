use thiserror::Error;
use zoe_wire_protocol::MessageFullError;

use crate::state::GroupSessionError;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Error, Debug)]
pub enum GroupError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] ed25519_dalek::SignatureError),

    #[error("Wire protocol error: {0}")]
    WireProtocol(#[from] zoe_wire_protocol::MessageError),

    #[error("Group not found: {0}")]
    GroupNotFound(String),

    #[error("Member not found in group: {member} in {group}")]
    MemberNotFound { member: String, group: String },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Invalid event: {0}")]
    InvalidEvent(String),

    #[error("State transition error: {0}")]
    StateTransition(String),

    #[error("Invalid group configuration: {0}")]
    InvalidGroupConfig(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Group Session error: {0}")]
    SessionError(#[from] GroupSessionError),

    #[error("Message full error: {0}")]
    MessageFullError(#[from] MessageFullError),
}

pub type GroupResult<T> = Result<T, GroupError>;
