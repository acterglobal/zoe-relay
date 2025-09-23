use thiserror::Error;
use tracing::error;

/// Error type for PQXDH protocol operations
///
/// This error type wraps all possible errors that can occur during PQXDH
/// protocol operations, providing structured error handling with proper
/// error context and conversion from underlying error types.
///
/// ## Error Categories
///
/// ### Connection and Service Errors
/// - [`InboxNotFound`](PqxdhError::InboxNotFound): Service provider inbox not available
/// - [`ServiceNotPublished`](PqxdhError::ServiceNotPublished): Service must be published first
/// - [`NoInboxSubscription`](PqxdhError::NoInboxSubscription): Missing inbox subscription
/// - [`InboxAlreadyPublished`](PqxdhError::InboxAlreadyPublished): Inbox already exists
///
/// ### Session Management Errors  
/// - [`SessionNotFound`](PqxdhError::SessionNotFound): No active session for given ID
/// - [`InvalidSender`](PqxdhError::InvalidSender): Message from wrong sender (security issue)
/// - [`NotInitialMessage`](PqxdhError::NotInitialMessage): Expected initial PQXDH message
///
/// ### Cryptographic Errors
/// - [`Crypto`](PqxdhError::Crypto): General cryptographic operation failures
/// - [`KeyGeneration`](PqxdhError::KeyGeneration): Key generation failures
/// - [`PqxdhProtocol`](PqxdhError::PqxdhProtocol): Wire protocol PQXDH errors
///
/// ### Message and Data Errors
/// - [`InvalidContentType`](PqxdhError::InvalidContentType): Wrong message content type
/// - [`NotPqxdhMessage`](PqxdhError::NotPqxdhMessage): Expected PQXDH encrypted message
/// - [`NoContent`](PqxdhError::NoContent): Message missing content
/// - [`MessageCreation`](PqxdhError::MessageCreation): Failed to create message
///
/// ### Infrastructure Errors
/// - [`Rpc`](PqxdhError::Rpc): RPC communication failures
/// - [`MessagesService`](PqxdhError::MessagesService): Message service errors
/// - [`Serialization`](PqxdhError::Serialization): Postcard serialization errors
/// - [`SystemTime`](PqxdhError::SystemTime): System time errors
#[derive(Error, Debug)]
pub enum PqxdhError {
    #[error("Inbox not found for service provider")]
    InboxNotFound,

    #[error("No content found in inbox message")]
    NoContent,

    #[error("Serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),

    #[error("Message creation failed: {0}")]
    MessageCreation(String),

    #[error("RPC error: {0}")]
    Rpc(#[from] tarpc::client::RpcError),

    #[error("Messages service error: {0}")]
    MessagesService(#[from] crate::ClientError),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Session not found for session ID")]
    SessionNotFound,

    #[error("Invalid message content type")]
    InvalidContentType,

    #[error("No private keys available")]
    NoPrivateKeys,

    #[error("No inbox available")]
    NoInbox,

    #[error("Not an initial PQXDH message")]
    NotInitialMessage,

    #[error("Message not from session sender - potentially compromised")]
    InvalidSender,

    #[error("Not a PQXDH encrypted message")]
    NotPqxdhMessage,

    #[error("Inbox already published, use force_overwrite to overwrite")]
    InboxAlreadyPublished,

    #[error("Must call publish_service() before listening for clients")]
    ServiceNotPublished,

    #[error("No inbox subscription found - did you call publish_service()?")]
    NoInboxSubscription,

    #[error("PQXDH key generation failed: {0}")]
    KeyGeneration(String),

    #[error("PQXDH protocol error: {0}")]
    PqxdhProtocol(#[from] zoe_wire_protocol::inbox::pqxdh::PqxdhError),

    #[error("Message service error: {0}")]
    MessageService(#[from] zoe_wire_protocol::MessageError),
}

/// Result type for PQXDH protocol operations
pub type Result<T> = std::result::Result<T, PqxdhError>;

// Conversion from MessagesManagerError to PqxdhError
impl From<zoe_state_machine::messages::MessagesManagerError> for PqxdhError {
    fn from(err: zoe_state_machine::messages::MessagesManagerError) -> Self {
        PqxdhError::MessageCreation(err.to_string())
    }
}
