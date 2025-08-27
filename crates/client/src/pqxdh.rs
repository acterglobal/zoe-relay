//! Post-Quantum Extended Diffie-Hellman (PQXDH) Protocol Implementation
//!
//! This module provides a complete, high-level implementation of the PQXDH protocol
//! for secure, post-quantum resistant communication. It includes both client and
//! service provider functionality with automatic session management.
//!
//! ## Core Components
//!
//! ### 1. Inbox Management
//! - **Publishing**: Service providers can publish PQXDH inboxes to advertise their availability
//! - **Discovery**: Clients can discover and fetch service provider inboxes
//! - **Privacy**: Uses type-safe protocols and deterministic serialization with postcard
//!
//! ### 2. Session Establishment
//! - **Initiation**: Clients can establish secure sessions with service providers
//! - **Privacy-Preserving**: Uses randomized channel IDs for unlinkable communication
//! - **Post-Quantum Security**: Leverages PQXDH for quantum-resistant key exchange
//!
//! ### 3. Message Communication
//! - **Session Messages**: Encrypted communication over established sessions
//! - **Channel Management**: Automatic subscription handling for session channels
//! - **Sequence Numbers**: Built-in replay protection with sequence numbering
//!
//! ### 4. State Management
//! - **Persistence**: Serializable state for application restarts
//! - **Session Tracking**: Automatic management of multiple concurrent sessions
//! - **Key Management**: Secure handling of private keys and prekey bundles
//!
//! ## Usage Patterns
//!
//! ### Service Provider Pattern
//! ```rust,no_run
//! # use zoe_client::pqxdh::*;
//! # use zoe_wire_protocol::*;
//! # use futures::StreamExt;
//! # async fn example() -> Result<()> {
//! # let messages_manager = todo!();
//! # let keypair = todo!();
//! // 1. Create handler and publish service
//! let mut handler = PqxdhProtocolHandler::new(
//!     &messages_manager,
//!     &keypair,
//!     PqxdhInboxProtocol::EchoService
//! );
//! handler.publish_service(false).await?;
//!
//! // 2. Listen for incoming client connections
//! let mut inbox_stream = Box::pin(handler.inbox_stream::<String>().await?);
//! while let Some((session_id, message)) = inbox_stream.next().await {
//!     // Handle client messages
//!     println!("Received from {:?}: {}", session_id, message);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Client Pattern
//! ```rust,no_run
//! # use zoe_client::pqxdh::*;
//! # use zoe_wire_protocol::*;
//! # use futures::StreamExt;
//! # async fn example() -> Result<()> {
//! # let messages_manager = todo!();
//! # let keypair = todo!();
//! # let service_key = todo!();
//! # let session_id = [0u8; 32]; // Session ID obtained from connection
//! # let initial_message = "hello".to_string();
//! // 1. Create handler and connect to service
//! let mut handler = PqxdhProtocolHandler::new(
//!     &messages_manager,
//!     &keypair,
//!     PqxdhInboxProtocol::EchoService
//! );
//! let mut response_stream = Box::pin(handler.connect_to_service::<String, String>(
//!     &service_key,
//!     &initial_message
//! ).await?);
//!
//! // 2. Send additional messages using session ID
//! handler.send_message(&session_id, &"follow up message".to_string()).await?;
//!
//! // 3. Listen for responses
//! while let Some(response) = response_stream.next().await {
//!     println!("Received response: {}", response);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Features
//!
//! - **Post-Quantum Resistance**: Uses CRYSTALS-Kyber for key encapsulation
//! - **Forward Secrecy**: Each session uses emphemeral keys
//! - **Replay Protection**: Sequence numbers prevent message replay attacks
//! - **Unlinkability**: Randomized channel IDs prevent traffic analysis
//! - **Authentication**: All messages are cryptographically signed
//!
//! ## Error Handling
//!
//! This module uses a custom [`PqxdhError`] type that provides structured error handling
//! for all PQXDH operations. The error type includes specific variants for different
//! failure modes:
//!
//! - **Connection Errors**: `InboxNotFound`, `ServiceNotPublished`, `NoInboxSubscription`
//! - **Session Errors**: `SessionNotFound`, `InvalidSender`, `NotInitialMessage`
//! - **Cryptographic Errors**: `Crypto`, `KeyGeneration`, `PqxdhProtocol`
//! - **Message Errors**: `InvalidContentType`, `NotPqxdhMessage`, `MessageCreation`
//! - **Infrastructure Errors**: `Rpc`, `MessagesService`, `Serialization`
//!
//! ### Error Handling Example
//! ```rust,no_run
//! # use zoe_client::pqxdh::*;
//! # async fn example() -> Result<()> {
//! # let mut handler: PqxdhProtocolHandler = todo!();
//! match handler.publish_service(false).await {
//!     Ok(tag) => println!("Service published with tag: {:?}", tag),
//!     Err(PqxdhError::InboxAlreadyPublished) => {
//!         println!("Service already published, use force_overwrite=true");
//!     }
//!     Err(PqxdhError::KeyGeneration(msg)) => {
//!         eprintln!("Failed to generate keys: {}", msg);
//!     }
//!     Err(e) => eprintln!("Unexpected error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Serialization
//!
//! All data structures use `postcard` for efficient binary serialization,
//! providing compact wire formats and deterministic encoding for cryptographic
//! operations. This ensures compatibility with the project's binary-first
//! architecture and optimal network efficiency.

use crate::MessagesService;
use futures::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{error, warn};
use zoe_wire_protocol::{Content, Filter, PqxdhEncryptedContent};
use zoe_wire_protocol::{
    Kind, Message, MessageFull, PqxdhInboxProtocol, StoreKey, Tag, VerifyingKey,
    inbox::pqxdh::{
        InboxType, PqxdhInbox, PqxdhInitialPayload, PqxdhSharedSecret,
        encrypt_pqxdh_session_message, generate_pqxdh_prekeys, pqxdh_initiate,
    },
    keys::Id as KeyId,
};

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

async fn fetch_pqxdh_inbox<T: for<'de> Deserialize<'de>>(
    messages_service: &MessagesService,
    provider_key: &VerifyingKey,
    protocol: PqxdhInboxProtocol,
) -> Result<(T, Tag)> {
    let provider_user_id = *provider_key.id();
    let store_key = StoreKey::PqxdhInbox(protocol);

    let user_data_result = messages_service
        .user_data(tarpc::context::current(), provider_user_id, store_key)
        .await?;

    let Some(message_full) = user_data_result? else {
        return Err(PqxdhError::InboxNotFound);
    };

    let Some(content_bytes) = message_full.raw_content() else {
        return Err(PqxdhError::NoContent);
    };

    let inbox_data: T = postcard::from_bytes(content_bytes)?;

    Ok((inbox_data, Tag::from(&message_full)))
}

type PqxdhSessionId = [u8; 32];

/// A PQXDH session for secure communication
///
/// This struct represents an established PQXDH session between two parties.
/// It contains the shared cryptographic material and state needed to encrypt
/// and decrypt messages within the session.
///
/// ## Key Features
/// - **Shared Secret**: Cryptographic material derived from PQXDH key exchange
/// - **Sequence Numbers**: Monotonic counter for replay protection
/// - **Channel ID**: Randomized identifier for unlinkable communication
/// - **Serializable**: Can be persisted and restored across application restarts
///
/// ## Security Properties
/// - Forward secrecy through emphemeral key material
/// - Replay protection via sequence numbering
/// - Unlinkability through randomized channel identifiers
/// - Post-quantum resistance via CRYSTALS-Kyber
#[derive(Serialize, Deserialize)]
struct PqxdhSession {
    shared_secret: PqxdhSharedSecret,
    /// Current sequence number for this session (stored as u64 for serialization)
    sequence_number: u64,
    /// Randomized channel ID for session messages (provides unlinkability)
    session_channel_id: PqxdhSessionId,
    /// The key of the sender of the messages
    sender_key: VerifyingKey,
}

impl PqxdhSession {
    /// Get the channel tag for this session (for subscribing to session messages)
    pub fn channel_tag(&self) -> Tag {
        Tag::Channel {
            id: self.session_channel_id.to_vec(),
            relays: vec![],
        }
    }

    /// Get the channel ID as bytes (for filtering)
    pub fn channel_id(&self) -> &PqxdhSessionId {
        &self.session_channel_id
    }

    /// Initiates a PQXDH session with a target user using an already loaded inbox
    ///
    /// This method performs the PQXDH key exchange protocol to establish a secure
    /// session with another party. It generates emphemeral keys, performs the key
    /// exchange, and sends the initial message to the target.
    ///
    /// # Arguments
    /// * `messages_service` - The messages service for publishing the initial message
    /// * `client_keypair` - The initiator's keypair for authentication
    /// * `inbox` - The target's PQXDH inbox containing prekey bundles
    /// * `target_tags` - Tags to route the initial message to the target
    /// * `initial_payload` - User data to include in the initial message
    ///
    /// # Returns
    /// Returns the established PQXDH session ready for secure communication.
    ///
    /// # Security Notes
    /// - Uses randomized channel IDs for unlinkable communication
    /// - Provides forward secrecy through emphemeral key material
    /// - Includes replay protection via sequence numbering
    pub async fn initiate<T: Serialize>(
        messages_service: &MessagesService,
        client_keypair: &zoe_wire_protocol::KeyPair,
        inbox: &PqxdhInbox,
        target_tags: Vec<Tag>,
        initial_payload: &T,
    ) -> Result<Self> {
        // Extract the prekey bundle from the inbox
        let prekey_bundle = &inbox.pqxdh_prekeys;

        // Generate randomized channel ID for session messages
        let mut rng = rand::thread_rng();
        let mut session_channel_id = PqxdhSessionId::default();
        rng.fill_bytes(&mut session_channel_id);

        // Serialize the initial payload
        let user_payload_bytes = postcard::to_stdvec(initial_payload)?;

        // Create the combined initial payload with channel ID
        let initial_payload_struct = PqxdhInitialPayload {
            user_payload: user_payload_bytes,
            session_channel_id,
        };

        let combined_payload_bytes = postcard::to_stdvec(&initial_payload_struct)?;

        // Initiate PQXDH
        let (initial_message, shared_secret) = pqxdh_initiate(
            client_keypair,
            prekey_bundle,
            &combined_payload_bytes,
            &mut rng,
        )
        .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_message);

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            Content::PqxdhEncrypted(pqxdh_content),
            client_keypair.public_key(),
            timestamp,
            Kind::Emphemeral(0),
            target_tags,
        );

        let message_full = MessageFull::new(message, client_keypair).map_err(|e| {
            PqxdhError::MessageCreation(format!("Failed to create initial message: {}", e))
        })?;

        // The initial message will be routed using its derived tag (Tag::Event with message ID)
        // This is automatically created by Tag::from(&MessageFull)

        messages_service
            .publish(tarpc::context::current(), message_full)
            .await??;

        Ok(Self {
            shared_secret,
            sequence_number: 1,
            session_channel_id,
            sender_key: client_keypair.public_key().clone(),
        })
    }

    /// Get the next sequence number and increment the internal counter
    pub fn next_sequence_number(&mut self) -> u64 {
        let current = self.sequence_number;
        self.sequence_number += 1;
        current
    }

    /// Sends a message in an established PQXDH session
    ///
    /// This method encrypts and sends a message over an already established PQXDH session.
    /// The message is encrypted using the session's shared secret and includes sequence
    /// numbering for replay protection.
    ///
    /// # Arguments
    /// * `messages_service` - The messages service for publishing the encrypted message
    /// * `client_keypair` - The sender's keypair for message authentication
    /// * `payload` - The user data to encrypt and send
    ///
    /// # Security Features
    /// - Messages are encrypted with the session's shared secret
    /// - Sequence numbers prevent replay attacks
    /// - Messages are sent to the session's private channel ID
    /// - Each message uses fresh randomness for encryption
    pub async fn send_message<T: Serialize>(
        &mut self,
        messages_service: &MessagesService,
        client_keypair: &zoe_wire_protocol::KeyPair,
        payload: &T,
        kind: Kind,
    ) -> Result<()> {

        // Serialize the payload
        let payload_bytes = postcard::to_stdvec(payload)?;

        // Encrypt as session message
        let sequence = self.next_sequence_number();
        let mut rng = rand::thread_rng();
        let session_message =
            encrypt_pqxdh_session_message(&self.shared_secret, &payload_bytes, sequence, &mut rng)
                .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        // Send the session message
        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Session(session_message);

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            Content::PqxdhEncrypted(pqxdh_content),
            client_keypair.public_key(),
            timestamp,
            kind,
            vec![Tag::Channel {
                id: self.session_channel_id.to_vec(),
                relays: vec![],
            }],
        );

        let message_full = MessageFull::new(message, client_keypair).map_err(|e| {
            PqxdhError::MessageCreation(format!("Failed to create session message: {}", e))
        })?;

        messages_service
            .publish(tarpc::context::current(), message_full)
            .await??;

        Ok(())
    }
    


    /// Sends a message in an established PQXDH session
    ///
    /// This method encrypts and sends a message over an already established PQXDH session.
    /// The message is encrypted using the session's shared secret and includes sequence
    /// numbering for replay protection.
    ///
    /// # Arguments
    /// * `messages_service` - The messages service for publishing the encrypted message
    /// * `client_keypair` - The sender's keypair for message authentication
    /// * `payload` - The user data to encrypt and send
    ///
    /// # Security Features
    /// - Messages are encrypted with the session's shared secret
    /// - Sequence numbers prevent replay attacks
    /// - Messages are sent to the session's private channel ID
    /// - Each message uses fresh randomness for encryption
    pub async fn send_emphemeral_message<T: Serialize>(
        &mut self,
        messages_service: &MessagesService,
        client_keypair: &zoe_wire_protocol::KeyPair,
        payload: &T,
        timeout: u32
    ) -> Result<()> {
        self.send_message(messages_service, client_keypair, payload, Kind::Emphemeral(timeout)).await
    }

    /// Extracts user payload from a PQXDH initial message (for responders)
    ///
    /// This helper function extracts the actual user payload from the decrypted initial
    /// message. The initial message contains both the user data and the session channel ID
    /// wrapped in a `PqxdhInitialPayload` structure.
    ///
    /// # Arguments
    /// * `decrypted_payload` - The decrypted bytes from the initial PQXDH message
    ///
    /// # Returns
    /// Returns a tuple of `(user_payload, session_channel_id)` where:
    /// - `user_payload` is the deserialized user data
    /// - `session_channel_id` is the randomized channel ID for the session
    ///
    /// # Usage
    /// This is typically called by service providers after decrypting an initial
    /// PQXDH message to extract both the user's data and the channel ID needed
    /// for ongoing session communication.
    pub fn extract_initial_payload<R: for<'de> Deserialize<'de>>(
        decrypted_payload: &[u8],
    ) -> Result<(R, PqxdhSessionId)> {
        // Deserialize the PqxdhInitialPayload structure
        let initial_payload: PqxdhInitialPayload = postcard::from_bytes(decrypted_payload)?;
        // Deserialize the user payload
        let user_payload: R = postcard::from_bytes(&initial_payload.user_payload)?;
        Ok((user_payload, initial_payload.session_channel_id))
    }

    /// Creates a PQXDH session from an established shared secret and channel ID (for responders)
    ///
    /// This constructor is used by service providers to create a session after successfully
    /// processing an initial PQXDH message. It initializes the session with the derived
    /// shared secret and the channel ID extracted from the initial message.
    ///
    /// # Arguments
    /// * `shared_secret` - The cryptographic material derived from PQXDH key exchange
    /// * `session_channel_id` - The randomized channel ID for this session
    ///
    /// # Returns
    /// Returns a new `PqxdhSession` ready for encrypting and decrypting messages
    ///
    /// # Usage
    /// Typically called after `extract_initial_payload()` to create a session
    /// that can be used for ongoing communication with the client.
    pub fn from_shared_secret(
        shared_secret: PqxdhSharedSecret,
        session_channel_id: PqxdhSessionId,
        sender_key: VerifyingKey,
    ) -> Self {
        Self {
            shared_secret,
            sequence_number: 1,
            session_channel_id,
            sender_key,
        }
    }
}

/// Serializable state for a PQXDH protocol handler
///
/// This structure contains all the persistent state needed to restore a
/// `PqxdhProtocolHandler` across application restarts. It excludes runtime
/// dependencies like the messages manager and client keypair, focusing only
/// on the cryptographic and session state that needs to be preserved.
///
/// ## Persistence Strategy
/// This state can be serialized with `postcard` and stored in a database or file
/// system. When the application restarts, this state can be loaded and used to
/// reconstruct a fully functional protocol handler.
///
/// ## State Components
/// - **Protocol**: The specific PQXDH protocol variant being used
/// - **Sessions**: Active sessions keyed by target user ID
/// - **Inbox Tag**: The published inbox tag (for service providers)
/// - **Private Keys**: Cryptographic keys for responding to initial messages
#[derive(Serialize, Deserialize)]
pub struct PqxdhProtocolState {
    /// The PQXDH protocol variant being used
    protocol: PqxdhInboxProtocol,
    /// Active sessions keyed by target user ID
    sessions: BTreeMap<KeyId, PqxdhSession>,
    inbox_tag: Option<Tag>,
    inbox: Option<PqxdhInbox>,
    /// Private keys for responding to initial messages (if we're a service provider)
    private_keys: Option<zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys>,
}

impl PqxdhProtocolState {
    /// Creates a new empty protocol state
    ///
    /// Initializes a new protocol state with the specified protocol variant.
    /// All other fields are set to their default empty values.
    ///
    /// # Arguments
    /// * `protocol` - The PQXDH protocol variant to use
    pub fn new(protocol: PqxdhInboxProtocol) -> Self {
        Self {
            protocol,
            sessions: BTreeMap::new(),
            inbox_tag: None,
            private_keys: None,
            inbox: None,
        }
    }
}

/// A complete PQXDH protocol handler that encapsulates all session management,
/// key observation, subscription handling, and message routing logic.
///
/// This provides a high-level abstraction over the entire PQXDH workflow with
/// automatic state management and persistence support. It can operate in two modes:
///
/// ## Service Provider Mode
/// - Publishes a PQXDH inbox for clients to discover
/// - Listens for incoming client connections
/// - Manages multiple concurrent client sessions
/// - Handles initial message decryption and session establishment
///
/// ## Client Mode  
/// - Discovers and connects to service provider inboxes
/// - Establishes secure sessions with service providers
/// - Sends messages over established sessions
/// - Manages session state and channel subscriptions
///
/// ## Key Features
/// - **State Persistence**: All state can be serialized and restored across restarts
/// - **Automatic Subscriptions**: Handles message routing and channel management
/// - **Session Management**: Tracks multiple concurrent sessions by user ID
/// - **Privacy Preserving**: Uses randomized channel IDs and derived tags
/// - **Type Safety**: Generic over message payload types with compile-time safety
pub struct PqxdhProtocolHandler<'a> {
    messages_manager: &'a crate::services::MessagesManager,
    client_keypair: &'a zoe_wire_protocol::KeyPair,
    /// Persistent state that can be serialized and restored
    state: Arc<RwLock<PqxdhProtocolState>>,
}

impl<'a> PqxdhProtocolHandler<'a> {
    /// Creates a new protocol handler for a specific PQXDH protocol
    ///
    /// This creates a fresh handler with empty state that can be used either as:
    /// - **Service Provider**: Call `publish_service()` then use `inbox_stream()`
    /// - **Client**: Call `connect_to_service()` then `send_message()`
    ///
    /// # Arguments
    /// * `messages_manager` - The messages manager to use for message operations
    /// * `client_keypair` - The client's keypair for signing and encryption
    /// * `protocol` - The specific PQXDH protocol variant to use
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use zoe_wire_protocol::*;
    /// # async fn example() -> Result<()> {
    /// # let messages_manager = todo!();
    /// # let keypair = todo!();
    /// let handler = PqxdhProtocolHandler::new(
    ///     &messages_manager,
    ///     &keypair,
    ///     PqxdhInboxProtocol::EchoService
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        messages_manager: &'a crate::services::MessagesManager,
        client_keypair: &'a zoe_wire_protocol::KeyPair,
        protocol: PqxdhInboxProtocol,
    ) -> Self {
        Self {
            messages_manager,
            client_keypair,
            state: Arc::new(RwLock::new(PqxdhProtocolState::new(protocol))),
        }
    }

    /// Creates a protocol handler from existing serialized state
    ///
    /// This allows restoring a handler across application restarts by loading
    /// previously serialized state from a database or file. All sessions and
    /// cryptographic state will be restored to their previous state.
    ///
    /// # Arguments
    /// * `messages_manager` - The messages manager to use for message operations
    /// * `client_keypair` - The client's keypair for signing and encryption
    /// * `state` - Previously serialized protocol state
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use zoe_wire_protocol::*;
    /// # async fn example() -> Result<()> {
    /// # let messages_manager = todo!();
    /// # let keypair = todo!();
    /// // Load state from storage
    /// let saved_state: PqxdhProtocolState = load_from_database()?;
    ///
    /// // Restore handler with previous state
    /// let handler = PqxdhProtocolHandler::from_state(
    ///     &messages_manager,
    ///     &keypair,
    ///     saved_state
    /// );
    /// # Ok(())
    /// # }
    /// # fn load_from_database() -> Result<PqxdhProtocolState> { todo!() }
    /// ```
    pub fn from_state(
        messages_manager: &'a crate::services::MessagesManager,
        client_keypair: &'a zoe_wire_protocol::KeyPair,
        state: PqxdhProtocolState,
    ) -> Self {
        Self {
            messages_manager,
            client_keypair,
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Publishes a service inbox for this protocol (SERVICE PROVIDERS ONLY)
    ///
    /// This makes the current client discoverable as a service provider for the given protocol.
    /// It generates fresh prekey bundles, publishes the inbox to the message store, and sets up
    /// the necessary subscriptions for receiving client connections.
    ///
    /// Only call this if you want to provide a service that others can connect to.
    /// After calling this, use `inbox_stream()` to listen for incoming client messages.
    ///
    /// # Arguments
    /// * `force_overwrite` - If true, overwrites any existing published inbox
    ///
    /// # Returns
    /// Returns the `Tag` of the published inbox
    ///
    /// # Errors
    /// Returns an error if an inbox is already published and `force_overwrite` is false,
    /// or if the publishing process fails.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// // Publish service for clients to discover
    /// let inbox_tag = handler.publish_service(false).await?;
    /// println!("Service published with tag: {:?}", inbox_tag);
    ///
    /// // Now listen for client connections
    /// let mut inbox_stream = Box::pin(handler.inbox_stream::<String>().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn publish_service(&mut self, force_overwrite: bool) -> Result<Tag> {
        let (inbox_tag, protocol) = {
            let state = self.state.read().await;
            (state.inbox_tag.clone(), state.protocol.clone())
        };

        if inbox_tag.is_some() && !force_overwrite {
            return Err(PqxdhError::InboxAlreadyPublished);
        }

        // Generate prekey bundle with private keys
        let (prekey_bundle, private_keys) =
            create_pqxdh_prekey_bundle_with_private_keys(self.client_keypair, 5)?;

        // Create inbox
        let inbox = PqxdhInbox::new(
            InboxType::Public,
            prekey_bundle,
            Some(1024), // Max message size
            None,       // No expiration
        );

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Create storage message for the PQXDH inbox
        let inbox_message = Message::new_v0(
            Content::Raw(postcard::to_stdvec(&inbox)?),
            self.client_keypair.public_key(),
            timestamp,
            Kind::Store(StoreKey::PqxdhInbox(protocol)),
            vec![],
        );

        let inbox_message_full =
            MessageFull::new(inbox_message, self.client_keypair).map_err(|e| {
                PqxdhError::MessageCreation(format!(
                    "Failed to create MessageFull for inbox: {}",
                    e
                ))
            })?;

        let target_tag = Tag::from(&inbox_message_full);

        // Publish the inbox
        self.messages_manager.publish(inbox_message_full).await?;

        {
            let mut state = self.state.write().await;
            state.private_keys = Some(private_keys);
            state.inbox_tag = Some(target_tag.clone());
            state.inbox = Some(inbox);
        }

        Ok(target_tag)
    }

    /// Connects to a service provider's inbox (CLIENTS ONLY)
    ///
    /// This discovers the target service provider's inbox and establishes a secure PQXDH session.
    /// It performs the full PQXDH key exchange protocol and sets up the necessary subscriptions
    /// for receiving responses from the service.
    ///
    /// Use this when you want to connect to a service as a client.
    /// After calling this, use `send_message()` to send additional messages to the service.
    ///
    /// # Arguments
    /// * `target_service_key` - The public key of the service provider to connect to
    /// * `initial_message` - The first message to send as part of the connection
    ///
    /// # Returns
    /// Returns a stream of messages from the service provider
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// # let service_key = todo!();
    /// // Connect to service and send initial message
    /// let mut response_stream = Box::pin(handler.connect_to_service::<String, String>(
    ///     &service_key,
    ///     &"Hello, service!".to_string()
    /// ).await?);
    ///
    /// // Listen for responses
    /// while let Some(message) = response_stream.next().await {
    ///     // Handle service responses
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_to_service<O, I>(
        &mut self,
        target_service_key: &VerifyingKey,
        initial_message: &O,
    ) -> Result<impl futures::Stream<Item = I> + 'a>
    where
        O: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
        I: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let protocol = {
            let state = self.state.read().await;
            state.protocol.clone()
        };
        // Discover inbox
        let (inbox, inbox_tag) = fetch_pqxdh_inbox(
            self.messages_manager.messages_service(),
            target_service_key,
            protocol,
        )
        .await?;

        // Establish session
        let session = PqxdhSession::initiate(
            self.messages_manager.messages_service(),
            self.client_keypair,
            &inbox,
            vec![inbox_tag],
            initial_message,
        )
        .await?;

        // Store session
        let session_id = *session.channel_id();
        let channel_tag = Tag::Channel {
            id: session_id.to_vec(),
            relays: vec![],
        };

        {
            let mut state = self.state.write().await;
            if state.sessions.insert(session_id, session).is_some() {
                warn!("overwriting existing pqxdh session. Shouldn't happen");
            }
        }

        let state = self.state.clone();

        // Subscribe to the session channel for responses

        let stream = self
            .messages_manager
            .catch_up_and_subscribe((&channel_tag).into(), None)
            .await?
            .filter_map(move |message_full| {
                let state = state.clone();
                async move {
                    Self::on_regular_message::<I>(&state, &message_full, &session_id)
                        .await
                        .inspect_err(|e| {
                            error!(
                                msg_id = hex::encode(message_full.id().as_bytes()),
                                "error processing inbox message: {e}"
                            );
                        })
                        .ok()
                }
            });

        Ok(stream)
    }

    /// Sends a message to an established session (CLIENTS ONLY)
    ///
    /// Use this to send additional messages after calling `connect_to_service()`.
    /// The message will be encrypted and sent over the established secure PQXDH session
    /// using the session's private channel.
    ///
    /// # Arguments
    /// * `session_id` - The session ID of the established PQXDH session
    /// * `message` - The message payload to encrypt and send
    ///
    /// # Errors
    /// Returns an error if no active session exists with the given session ID
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// # let service_key = todo!();
    /// # let session_id = [0u8; 32]; // Session ID from established connection
    /// // First establish connection
    /// let _stream = handler.connect_to_service::<String, String>(&service_key, &"initial".to_string()).await?;
    ///
    /// // Send follow-up messages using session ID
    /// handler.send_message(&session_id, &"follow-up message".to_string()).await?;
    /// handler.send_message(&session_id, &"another message".to_string()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_message<T>(&self, session_id: &PqxdhSessionId, message: &T) -> Result<()>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let mut state = self.state.write().await;
        let Some(session) = state.sessions.get_mut(session_id) else {
            return Err(PqxdhError::SessionNotFound);
        };

        session
            .send_message(
                self.messages_manager.messages_service(),
                self.client_keypair,
                message,
                Kind::Regular,
            )
            .await
    }

    pub async fn send_emphemeral_message<T>(&self, session_id: &PqxdhSessionId, message: &T, timeout: u32) -> Result<()>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let mut state = self.state.write().await;
        let Some(session) = state.sessions.get_mut(session_id) else {
            return Err(PqxdhError::SessionNotFound);
        };

        session
            .send_emphemeral_message(
                self.messages_manager.messages_service(),
                self.client_keypair,
                message,
                timeout,
            )
            .await
    }

    /// Creates a stream of messages that arrive to our inbox (SERVICE PROVIDERS ONLY)
    ///
    /// This method returns a stream of incoming messages from clients who are connecting
    /// to or communicating with this service. The stream includes both initial PQXDH
    /// messages (new client connections) and session messages (ongoing communication).
    ///
    /// # Returns
    /// Returns a stream of `(PqxdhSessionId, T)` tuples where:
    /// - `PqxdhSessionId` is the session ID for the client connection
    /// - `T` is the deserialized message payload from the client
    ///
    /// # Errors
    /// Returns an error if `publish_service()` has not been called first
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// // First publish the service
    /// handler.publish_service(false).await?;
    ///
    /// // Then listen for client messages
    /// let mut inbox_stream = Box::pin(handler.inbox_stream::<String>().await?);
    /// while let Some((session_id, message)) = inbox_stream.next().await {
    ///     println!("Received message from session {:?}: {}", session_id, message);
    ///     
    ///     // Echo the message back to the client
    ///     handler.send_message(&session_id, &format!("Echo: {}", message)).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn inbox_stream<T>(&self) -> Result<impl futures::Stream<Item = (PqxdhSessionId, T)>>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let inbox_tag = {
            let state = self.state.read().await;
            if state.private_keys.is_none() {
                return Err(PqxdhError::ServiceNotPublished);
            }

            let Some(inbox_tag) = &state.inbox_tag else {
                return Err(PqxdhError::NoInboxSubscription);
            };
            inbox_tag.clone()
        };

        self.messages_manager.ensure_contains_filter(Filter::from(inbox_tag.clone())).await?;

        let stream = self
            .messages_manager
            .filtered_messages_stream(Filter::from(inbox_tag));

        let state = self.state.clone();
        

        let stream = stream.filter_map(move |message_full| {
            let state = state.clone();
            async move {
                Self::on_incoming_inbox_message::<T>(&state, &message_full)
                    .await
                    .inspect_err(|e| {
                        error!(
                            msg_id = hex::encode(message_full.id().as_bytes()),
                            "error processing inbox message: {e}"
                        );
                    })
                    .ok()
            }
        });

        Ok(stream)
    }
}

impl PqxdhProtocolHandler<'_> {
    async fn on_incoming_inbox_message<T>(
        state: &Arc<RwLock<PqxdhProtocolState>>,
        message_full: &MessageFull,
    ) -> Result<(PqxdhSessionId, T)>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let msg_id_hex = hex::encode(message_full.id().as_bytes());
        let Some(pqxdh_content) = message_full.content().as_pqxdh_encrypted() else {
            warn!(
                msg_id = msg_id_hex,
                "not the proper content type on message"
            );
            return Err(PqxdhError::InvalidContentType);
        };

        let (private_keys, prekey_bundle) = {
            let state = state.read().await;

            let Some(private_keys) = state.private_keys.clone() else {
                error!(msg_id = msg_id_hex, "no private keys");
                return Err(PqxdhError::NoPrivateKeys);
            };
            let Some(ref inbox) = state.inbox else {
                error!(msg_id = msg_id_hex, "no inbox");
                return Err(PqxdhError::NoInbox);
            };
            (private_keys, inbox.pqxdh_prekeys.clone())
        };

        let initial_msg = match pqxdh_content {
            zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_msg) => initial_msg,
            _ => {
                warn!(
                    msg_id = msg_id_hex,
                    "not an inbox initial message. ignoring incoming message."
                );
                return Err(PqxdhError::NotInitialMessage);
            }
        };

        let (decrypted_payload, shared_secret) =
            zoe_wire_protocol::inbox::pqxdh::pqxdh_crypto::pqxdh_respond(
                initial_msg,
                &private_keys,
                &prekey_bundle,
            )
            .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        // Extract user payload
        let (user_request, session_channel_id) =
            PqxdhSession::extract_initial_payload::<T>(&decrypted_payload)?;

        // Create session
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_channel_id,
            message_full.author().clone(),
        );

        {
            let mut state = state.write().await;
            if state.sessions.insert(session_channel_id, session).is_some() {
                warn!("overwriting existing pqxdh session. Shouldn't happen");
            }
        }

        Ok((session_channel_id, user_request))
    }

    async fn on_regular_message<T>(
        state: &Arc<RwLock<PqxdhProtocolState>>,
        message_full: &MessageFull,
        session_id: &PqxdhSessionId,
    ) -> Result<T>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let (author_id, shared_secret) = {
            let state = state.read().await;
            let Some(session) = state.sessions.get(session_id) else {
                return Err(PqxdhError::SessionNotFound);
            };
            (session.sender_key.clone(), session.shared_secret.clone())
        };

        if &author_id != message_full.author() {
            return Err(PqxdhError::InvalidSender);
        };

        let Some(PqxdhEncryptedContent::Session(pqxdh_content)) =
            message_full.content().as_pqxdh_encrypted()
        else {
            return Err(PqxdhError::NotPqxdhMessage);
        };

        let decrypted_bytes =
            zoe_wire_protocol::inbox::pqxdh::pqxdh_crypto::decrypt_pqxdh_session_message(
                &shared_secret,
                pqxdh_content,
            )
            .map_err(|e| PqxdhError::Crypto(e.to_string()))?;
        Ok(postcard::from_bytes(&decrypted_bytes)?)
    }
}

pub(crate) fn create_pqxdh_prekey_bundle_with_private_keys(
    identity_keypair: &zoe_wire_protocol::KeyPair,
    num_one_time_keys: usize,
) -> Result<(
    zoe_wire_protocol::inbox::pqxdh::PqxdhPrekeyBundle,
    zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys,
)> {
    let mut rng = rand::thread_rng();
    generate_pqxdh_prekeys(identity_keypair, num_one_time_keys, &mut rng)
        .map_err(|e| PqxdhError::KeyGeneration(format!("Failed to generate PQXDH prekeys: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_wire_protocol::KeyPair;

    #[test]
    fn test_pqxdh_session_serialization() {
        // Create a test session
        let shared_secret = PqxdhSharedSecret {
            shared_key: [42u8; 32],
            consumed_one_time_key_ids: vec!["key1".to_string(), "key2".to_string()],
        };
        let session_channel_id = [1u8; 32];

        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_channel_id,
            keypair.public_key(),
        );

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&session).expect("Failed to serialize session");
        let deserialized: PqxdhSession =
            postcard::from_bytes(&serialized).expect("Failed to deserialize session");

        // Verify the data is preserved
        assert_eq!(
            session.shared_secret.shared_key,
            deserialized.shared_secret.shared_key
        );
        assert_eq!(
            session.shared_secret.consumed_one_time_key_ids,
            deserialized.shared_secret.consumed_one_time_key_ids
        );
        assert_eq!(session.sequence_number, deserialized.sequence_number);
        assert_eq!(session.session_channel_id, deserialized.session_channel_id);
    }

    #[test]
    fn test_pqxdh_protocol_state_serialization() {
        let protocol = PqxdhInboxProtocol::EchoService;
        let mut state = PqxdhProtocolState::new(protocol.clone());

        // Add some test data
        state.inbox_tag = Some(Tag::Channel {
            id: vec![1, 2, 3, 4],
            relays: vec![],
        });

        let target_id: KeyId = [1u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [99u8; 32],
            consumed_one_time_key_ids: vec!["consumed_key".to_string()],
        };
        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let session =
            PqxdhSession::from_shared_secret(shared_secret, [5u8; 32], keypair.public_key());
        state.sessions.insert(target_id, session);

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&state).expect("Failed to serialize state");
        let deserialized: PqxdhProtocolState =
            postcard::from_bytes(&serialized).expect("Failed to deserialize state");

        // Verify the data is preserved
        assert_eq!(state.protocol, deserialized.protocol);
        assert_eq!(state.inbox_tag, deserialized.inbox_tag);
        assert_eq!(state.sessions.len(), deserialized.sessions.len());

        // Verify session data
        let original_session = &state.sessions[&target_id];
        let deserialized_session = &deserialized.sessions[&target_id];
        assert_eq!(
            original_session.shared_secret.shared_key,
            deserialized_session.shared_secret.shared_key
        );
        assert_eq!(
            original_session.sequence_number,
            deserialized_session.sequence_number
        );
        assert_eq!(
            original_session.session_channel_id,
            deserialized_session.session_channel_id
        );
    }

    #[test]
    fn test_pqxdh_private_keys_serialization() -> Result<()> {
        // Generate test keypair with random data
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        // Generate prekey bundle with private keys (creates random keys)
        let (_prekey_bundle, private_keys) =
            create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3)?;

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&private_keys)?;
        let deserialized: zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys =
            postcard::from_bytes(&serialized)?;

        // Verify the data is preserved by comparing the keys directly (now that serde works)
        // We can't use PartialEq on StaticSecret, so we compare the bytes
        assert_eq!(
            private_keys.signed_prekey_private.to_bytes(),
            deserialized.signed_prekey_private.to_bytes()
        );
        assert_eq!(
            private_keys.one_time_prekey_privates.len(),
            deserialized.one_time_prekey_privates.len()
        );
        assert_eq!(
            private_keys.pq_signed_prekey_private,
            deserialized.pq_signed_prekey_private
        );
        assert_eq!(
            private_keys.pq_one_time_prekey_privates,
            deserialized.pq_one_time_prekey_privates
        );

        // Verify one-time keys (should be random and different each time)
        for (key_id, original_key) in &private_keys.one_time_prekey_privates {
            let deserialized_key = &deserialized.one_time_prekey_privates[key_id];
            assert_eq!(original_key.to_bytes(), deserialized_key.to_bytes());
        }

        // Verify that keys are actually random by generating another set
        let (_prekey_bundle2, private_keys2) =
            create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3)?;
        assert_ne!(
            private_keys.signed_prekey_private.to_bytes(),
            private_keys2.signed_prekey_private.to_bytes(),
            "Keys should be randomly generated and different"
        );

        Ok(())
    }
}
