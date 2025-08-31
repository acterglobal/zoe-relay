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
use eyeball::{AsyncLock, ObservableWriteGuard, SharedObservable};
use futures::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

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
/// - **Session Channel IDs**: A hash of the session channel id prefix and the target key, provides unlinkability
/// - **Serializable**: Can be persisted and restored across application restarts
///
/// ## Security Properties
/// - Forward secrecy through emphemeral key material
/// - Replay protection via sequence numbering
/// - Unlinkability through randomized channel identifiers
/// - Post-quantum resistance via CRYSTALS-Kyber
#[derive(Serialize, Deserialize, Clone)]
struct PqxdhSession {
    shared_secret: PqxdhSharedSecret,
    /// Current sequence number for this session (stored as u64 for serialization)
    sequence_number: u64,
    /// The channel Id we are listening for, derived from the session channel id prefix
    my_session_channel_id: PqxdhSessionId,
    /// The session id channel they will be listening to, derived from the session channel id prefix
    their_session_channel_id: PqxdhSessionId,
    /// The key of the sender of the messages
    their_key: VerifyingKey,
}

impl PqxdhSession {
    /// Get the channel they are listening for
    pub fn publish_channel_tag(&self) -> Tag {
        Tag::Channel {
            id: self.their_session_channel_id.to_vec(),
            relays: vec![],
        }
    }

    /// Get the channel tag we want to be listening for
    pub fn listening_channel_tag(&self) -> Tag {
        Tag::Channel {
            id: self.my_session_channel_id.to_vec(),
            relays: vec![],
        }
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
    pub fn gen_next_message<T: Serialize>(
        &mut self,
        client_keypair: &zoe_wire_protocol::KeyPair,
        payload: &T,
        kind: Kind,
    ) -> Result<MessageFull> {
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
            vec![self.publish_channel_tag()],
        );

        MessageFull::new(message, client_keypair).map_err(|e| {
            PqxdhError::MessageCreation(format!("Failed to create session message: {}", e))
        })
    }

    /// Creates a PQXDH session from an established shared secret and channel ID (for responders)
    ///
    /// This constructor is used by service providers to create a session after successfully
    /// processing an initial PQXDH message. It initializes the session with the derived
    /// shared secret and the channel ID extracted from the initial message.
    ///
    /// # Arguments
    /// * `shared_secret` - The cryptographic material derived from PQXDH key exchange
    /// * `my_session_channel_id` - The channel ID we are listening for
    /// * `their_session_channel_id` - The channel ID they are listening for
    /// * `sender_key` - The public key of the sender of the initial message
    ///
    /// # Returns
    /// Returns a new `PqxdhSession` ready for encrypting and decrypting messages
    ///
    /// # Usage
    /// Typically called after `extract_initial_payload()` to create a session
    /// that can be used for ongoing communication with the client.
    pub fn from_shared_secret(
        shared_secret: PqxdhSharedSecret,
        my_session_channel_id: PqxdhSessionId,
        their_session_channel_id: PqxdhSessionId,
        their_key: VerifyingKey,
    ) -> Self {
        Self {
            shared_secret,
            sequence_number: 1,
            my_session_channel_id,
            their_session_channel_id,
            their_key,
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
#[derive(Serialize, Deserialize, Clone)]
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
/// - **State Observation**: Observable state changes via broadcast channels for reactive programming
/// - **Automatic Subscriptions**: Handles message routing and channel management
/// - **Session Management**: Tracks multiple concurrent sessions by user ID
/// - **Privacy Preserving**: Uses randomized channel IDs and derived tags
/// - **Type Safety**: Generic over message payload types with compile-time safety
pub struct PqxdhProtocolHandler<'a, T: crate::services::MessagesManagerTrait> {
    messages_manager: &'a T,
    client_keypair: &'a zoe_wire_protocol::KeyPair,
    /// Observable state that can be subscribed to for reactive programming
    state: SharedObservable<PqxdhProtocolState, AsyncLock>,
}

impl<'a, T: crate::services::MessagesManagerTrait> PqxdhProtocolHandler<'a, T> {
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
        messages_manager: &'a T,
        client_keypair: &'a zoe_wire_protocol::KeyPair,
        protocol: PqxdhInboxProtocol,
    ) -> Self {
        let initial_state = PqxdhProtocolState::new(protocol);
        let state = SharedObservable::new_async(initial_state);

        Self {
            messages_manager,
            client_keypair,
            state,
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
        messages_manager: &'a T,
        client_keypair: &'a zoe_wire_protocol::KeyPair,
        state: PqxdhProtocolState,
    ) -> Self {
        let state = SharedObservable::new_async(state);

        Self {
            messages_manager,
            client_keypair,
            state,
        }
    }

    /// Subscribe to state changes for reactive programming
    ///
    /// This method returns a broadcast receiver that can be used to observe changes to the
    /// protocol handler's internal state. This is useful for building reactive UIs
    /// or implementing state-dependent logic that needs to respond to changes in
    /// session state, inbox status, or other protocol state.
    ///
    /// # Returns
    /// Returns a `broadcast::Receiver<PqxdhProtocolState>` that receives state updates
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let handler: PqxdhProtocolHandler = todo!();
    /// // Subscribe to state changes
    /// let mut state_receiver = handler.subscribe_to_state();
    ///
    /// // Get current state
    /// let current_state = handler.current_state();
    /// println!("Current sessions: {}", current_state.sessions.len());
    ///
    /// // Watch for state changes
    /// let mut state_stream = state_receiver.subscribe();
    /// while let Some(new_state) = state_stream.next().await {
    ///     println!("State updated! Sessions: {}", new_state.sessions.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn subscribe_to_state(&self) -> eyeball::Subscriber<PqxdhProtocolState, AsyncLock> {
        self.state.subscribe().await
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
            let current_state = self.state.get().await;
            (
                current_state.inbox_tag.clone(),
                current_state.protocol.clone(),
            )
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

        // Update state and notify observers
        {
            let mut state = self.state.write().await;
            ObservableWriteGuard::update(&mut state, |state| {
                state.private_keys = Some(private_keys);
                state.inbox_tag = Some(target_tag.clone());
                state.inbox = Some(inbox);
            });
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
    ) -> Result<(PqxdhSessionId, impl futures::Stream<Item = I> + 'a)>
    where
        O: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
        I: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let protocol = self.state.get().await.protocol.clone();
        // Discover inbox
        let (inbox, inbox_tag) = self.fetch_pqxdh_inbox(target_service_key, protocol).await?;

        // Establish session
        let session = self
            .initiate_session(
                target_service_key.clone(),
                &inbox,
                vec![inbox_tag],
                initial_message,
            )
            .await?;

        let my_session_id = session.my_session_channel_id;

        // Update state and notify observers
        {
            let mut state = self.state.write().await;
            ObservableWriteGuard::update(&mut state, |state| {
                if state.sessions.insert(my_session_id, session).is_some() {
                    warn!("overwriting existing pqxdh session. Shouldn't happen");
                }
            });
        }

        Ok((
            my_session_id,
            self.listen_for_messages(my_session_id, true).await?,
        ))
    }

    pub async fn listen_for_messages<I>(
        &self,
        my_session_id: PqxdhSessionId,
        catch_up: bool,
    ) -> Result<impl futures::Stream<Item = I> + 'a>
    where
        I: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let listening_tag = {
            let state = self.state.get().await;
            let Some(session) = state.sessions.get(&my_session_id) else {
                return Err(PqxdhError::SessionNotFound);
            };
            session.listening_channel_tag()
        };

        // Subscribe to the session channel for responses
        let stream: std::pin::Pin<Box<dyn futures::Stream<Item = Box<MessageFull>> + Send>> =
            if catch_up {
                self.messages_manager
                    .catch_up_and_subscribe((&listening_tag).into(), None)
                    .await?
            } else {
                self.messages_manager
                    .ensure_contains_filter(Filter::from(listening_tag.clone()))
                    .await?;
                self.messages_manager
                    .filtered_messages_stream(Filter::from(listening_tag))
            };

        let state_for_stream = self.state.clone();

        Ok(stream.filter_map(move |message_full| {
            let my_session_id = my_session_id;
            let state = state_for_stream.clone();
            async move {
                tracing::debug!(
                    "🔄 PQXDH handler received message: {}",
                    hex::encode(message_full.id().as_bytes())
                );
                Self::on_regular_message::<I>(&state, &message_full, &my_session_id)
                    .await
                    .inspect_err(|e| {
                        error!(
                            msg_id = hex::encode(message_full.id().as_bytes()),
                            "error processing inbox message: {e}"
                        );
                    })
                    .inspect(|_result| {
                        tracing::debug!(
                            "✅ PQXDH handler successfully processed message: {}",
                            hex::encode(message_full.id().as_bytes())
                        );
                    })
                    .ok()
            }
        }))
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
    pub async fn send_message<U>(&self, session_id: &PqxdhSessionId, message: &U) -> Result<()>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        self.send_message_inner(session_id, message, Kind::Regular)
            .await
    }

    pub async fn send_emphemeral_message<U>(
        &self,
        session_id: &PqxdhSessionId,
        message: &U,
        timeout: u32,
    ) -> Result<()>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        self.send_message_inner(session_id, message, Kind::Emphemeral(timeout))
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
    pub async fn inbox_stream<U>(&self) -> Result<impl futures::Stream<Item = (PqxdhSessionId, U)>>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let inbox_tag = {
            let current_state = self.state.get().await;
            if current_state.private_keys.is_none() {
                return Err(PqxdhError::ServiceNotPublished);
            };

            let Some(inbox_tag) = &current_state.inbox_tag else {
                return Err(PqxdhError::NoInboxSubscription);
            };
            inbox_tag.clone()
        };

        self.messages_manager
            .ensure_contains_filter(Filter::from(inbox_tag.clone()))
            .await?;

        let stream = self
            .messages_manager
            .filtered_messages_stream(Filter::from(inbox_tag));

        let state = self.state.clone();
        let my_public_key = self.client_keypair.public_key().clone();

        let stream = stream.filter_map(move |message_full| {
            let state = state.clone();
            let my_public_key = my_public_key.clone();
            async move {
                Self::on_incoming_inbox_message::<U>(&state, &my_public_key, &message_full)
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

// Internal functions

impl<T: crate::services::MessagesManagerTrait> PqxdhProtocolHandler<'_, T> {
    /// Fetch a PQXDH inbox using the trait method
    async fn fetch_pqxdh_inbox<U: for<'de> Deserialize<'de>>(
        &self,
        provider_key: &VerifyingKey,
        protocol: PqxdhInboxProtocol,
    ) -> Result<(U, Tag)> {
        let provider_user_id = *provider_key.id();
        let store_key = StoreKey::PqxdhInbox(protocol);

        let Some(message_full) = self
            .messages_manager
            .user_data(provider_user_id, store_key)
            .await?
        else {
            return Err(PqxdhError::InboxNotFound);
        };

        let Some(content_bytes) = message_full.raw_content() else {
            return Err(PqxdhError::NoContent);
        };

        let inbox_data: U = postcard::from_bytes(content_bytes)?;

        Ok((inbox_data, Tag::from(&message_full)))
    }

    /// Initiates a PQXDH session with a target user using an already loaded inbox
    async fn initiate_session<U: Serialize>(
        &self,
        target_public_key: VerifyingKey,
        inbox: &PqxdhInbox,
        target_tags: Vec<Tag>,
        initial_payload: &U,
    ) -> Result<PqxdhSession> {
        // Extract the prekey bundle from the inbox
        let prekey_bundle = &inbox.pqxdh_prekeys;

        // Generate randomized channel ID for session messages
        let mut rng = rand::thread_rng();
        let mut session_channel_id_prefix = PqxdhSessionId::default();
        rng.fill_bytes(&mut session_channel_id_prefix);

        let their_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(target_public_key.id().as_ref());
            hasher.finalize()
        };

        let my_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(self.client_keypair.public_key().id().as_ref());
            hasher.finalize()
        };

        // Create the combined initial payload with channel ID
        let initial_payload_struct = PqxdhInitialPayload {
            user_payload: initial_payload,
            session_channel_id_prefix,
        };

        let combined_payload_bytes = postcard::to_stdvec(&initial_payload_struct)?;

        // Initiate PQXDH
        let (initial_message, shared_secret) = pqxdh_initiate(
            self.client_keypair,
            prekey_bundle,
            &combined_payload_bytes,
            &mut rng,
        )
        .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_message);

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            Content::PqxdhEncrypted(pqxdh_content),
            self.client_keypair.public_key(),
            timestamp,
            Kind::Emphemeral(0),
            target_tags,
        );

        let message_full = MessageFull::new(message, self.client_keypair).map_err(|e| {
            PqxdhError::MessageCreation(format!("Failed to create initial message: {}", e))
        })?;

        // The initial message will be routed using its derived tag (Tag::Event with message ID)
        // This is automatically created by Tag::from(&MessageFull)

        self.messages_manager.publish(message_full).await?;

        Ok(PqxdhSession {
            shared_secret,
            sequence_number: 1,
            my_session_channel_id: my_session_channel_id.into(),
            their_session_channel_id: their_session_channel_id.into(),
            their_key: target_public_key,
        })
    }

    async fn on_incoming_inbox_message<U>(
        state: &SharedObservable<PqxdhProtocolState, AsyncLock>,
        my_public_key: &VerifyingKey,
        message_full: &MessageFull,
    ) -> Result<(PqxdhSessionId, U)>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
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
            let current_state = state.get().await;
            let Some(private_keys) = current_state.private_keys else {
                error!(msg_id = msg_id_hex, "no private keys");
                return Err(PqxdhError::NoPrivateKeys);
            };
            let Some(ref inbox) = current_state.inbox else {
                error!(msg_id = msg_id_hex, "no inbox");
                return Err(PqxdhError::NoInbox);
            };
            (private_keys.clone(), inbox.pqxdh_prekeys.clone())
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

        // Deserialize the PqxdhInitialPayload structure with the user payload type
        let initial_payload: PqxdhInitialPayload<U> = postcard::from_bytes(&decrypted_payload)?;

        let PqxdhInitialPayload {
            user_payload: user_message,
            session_channel_id_prefix,
        } = initial_payload;

        let my_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(my_public_key.id().as_ref());
            hasher.finalize().into()
        };

        let their_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(message_full.author().id().as_ref());
            hasher.finalize().into()
        };

        // Create session
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            my_session_channel_id,
            their_session_channel_id,
            message_full.author().clone(),
        );

        // Update state
        let mut current_state = state.write().await;
        ObservableWriteGuard::update(&mut current_state, |state| {
            if state
                .sessions
                .insert(my_session_channel_id, session)
                .is_some()
            {
                error!("overwriting existing pqxdh session. Shouldn't happen");
            }
        });

        Ok((my_session_channel_id, user_message))
    }

    async fn on_regular_message<U>(
        state: &SharedObservable<PqxdhProtocolState, AsyncLock>,
        message_full: &MessageFull,
        session_id: &PqxdhSessionId,
    ) -> Result<U>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let shared_secret = {
            let current_state = state.get().await;
            let Some(session) = current_state.sessions.get(session_id) else {
                return Err(PqxdhError::SessionNotFound);
            };

            if &session.their_key != message_full.author() {
                return Err(PqxdhError::InvalidSender);
            };
            session.shared_secret.clone()
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

    async fn send_message_inner<U>(
        &self,
        session_id: &PqxdhSessionId,
        message: &U,
        kind: Kind,
    ) -> Result<()>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        let full_msg = {
            let mut current_state = self.state.write().await;
            let Some(mut session) = current_state.sessions.get(session_id).cloned() else {
                return Err(PqxdhError::SessionNotFound);
            };

            let msg = session.gen_next_message(self.client_keypair, message, kind)?;

            ObservableWriteGuard::update(&mut current_state, |state: &mut PqxdhProtocolState| {
                state.sessions.insert(session_id.clone(), session); // re-add the changed session
            });

            msg
        };

        self.messages_manager.publish(full_msg).await?;

        Ok(())
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
    use crate::services::messages_manager::MockMessagesManagerTrait;
    use futures::stream;
    use mockall::predicate::*;

    use zoe_wire_protocol::{
        Content, KeyPair, Kind, Message, MessageFull,
        inbox::pqxdh::{InboxType, PqxdhInbox},
    };
    use zoe_wire_protocol::{PublishResult, StoreKey, Tag};

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
            session_channel_id, // their_session_channel_id
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
        assert_eq!(
            session.my_session_channel_id,
            deserialized.my_session_channel_id
        );
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
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            [5u8; 32],
            [6u8; 32], // their_session_channel_id
            keypair.public_key(),
        );
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
            original_session.my_session_channel_id,
            deserialized_session.my_session_channel_id
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

    // Helper functions for tests
    fn create_test_keypair() -> KeyPair {
        KeyPair::generate(&mut rand::thread_rng())
    }

    fn create_test_inbox() -> PqxdhInbox {
        let keypair = create_test_keypair();
        let (prekey_bundle, _) = create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3).unwrap();
        PqxdhInbox::new(InboxType::Public, prekey_bundle, Some(1024), None)
    }

    fn create_test_message_full(content: Content, author: &KeyPair) -> MessageFull {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let message = Message::new_v0(
            content,
            author.public_key(),
            timestamp,
            Kind::Regular,
            vec![],
        );
        MessageFull::new(message, author).unwrap()
    }

    type TestPqxdhHandler<'a> = PqxdhProtocolHandler<'a, MockMessagesManagerTrait>;

    #[tokio::test]
    async fn test_publish_service_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Mock the publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "123".to_string(),
            })
        });

        let mut handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        let result = handler.publish_service(false).await;
        assert!(result.is_ok());

        // Verify that the state was updated
        let state = handler.state.read().await;
        assert!(state.inbox_tag.is_some());
        assert!(state.private_keys.is_some());
        assert!(state.inbox.is_some());
    }

    /// Test service provider publish_service with already published inbox
    #[tokio::test]
    async fn test_publish_service_already_published() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        let mut handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Manually set inbox_tag to simulate already published state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
            },
        )
        .await;

        let result = handler.publish_service(false).await;
        assert!(matches!(result, Err(PqxdhError::InboxAlreadyPublished)));
    }

    /// Test service provider publish_service with force overwrite
    #[tokio::test]
    async fn test_publish_service_force_overwrite() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Mock the publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "123".to_string(),
            })
        });

        let mut handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Manually set inbox_tag to simulate already published state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
            },
        )
        .await;

        let result = handler.publish_service(true).await;
        assert!(result.is_ok());
    }

    /// Test client connect_to_service functionality
    #[tokio::test]
    async fn test_connect_to_service_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let client_keypair = create_test_keypair();
        let service_keypair = create_test_keypair();
        let service_key = service_keypair.public_key();

        let test_inbox = create_test_inbox();

        // Mock user_data call to return the inbox
        let inbox_message = create_test_message_full(
            Content::Raw(postcard::to_stdvec(&test_inbox).unwrap()),
            &service_keypair,
        );
        mock_manager
            .expect_user_data()
            .with(
                eq(*service_key.id()),
                eq(StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService)),
            )
            .times(1)
            .returning(move |_, _| Ok(Some(inbox_message.clone())));

        // Mock publish call for the initial PQXDH message
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "456".to_string(),
            })
        });

        // Mock catch_up_and_subscribe for listening to responses
        mock_manager
            .expect_catch_up_and_subscribe()
            .times(1)
            .returning(|_, _| Ok(Box::pin(stream::empty())));

        let mut handler = TestPqxdhHandler::new(
            &mock_manager,
            &client_keypair,
            PqxdhInboxProtocol::EchoService,
        );

        let initial_message = "Hello, service!".to_string();
        let result = handler
            .connect_to_service::<String, String>(&service_key, &initial_message)
            .await;

        assert!(result.is_ok());
        let (session_id, _stream) = result.unwrap();

        // Verify session was created
        let state = handler.state.read().await;
        assert!(state.sessions.contains_key(&session_id));
    }

    /// Test client connect_to_service with inbox not found
    #[tokio::test]
    async fn test_connect_to_service_inbox_not_found() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let client_keypair = create_test_keypair();
        let service_keypair = create_test_keypair();
        let service_key = service_keypair.public_key();

        // Mock user_data call to return None (inbox not found)
        mock_manager
            .expect_user_data()
            .with(
                eq(*service_key.id()),
                eq(StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService)),
            )
            .times(1)
            .returning(|_, _| Ok(None));

        let mut handler = TestPqxdhHandler::new(
            &mock_manager,
            &client_keypair,
            PqxdhInboxProtocol::EchoService,
        );

        let initial_message = "Hello, service!".to_string();
        let result = handler
            .connect_to_service::<String, String>(&service_key, &initial_message)
            .await;

        assert!(matches!(result, Err(PqxdhError::InboxNotFound)));
    }

    /// Test send_message functionality
    #[tokio::test]
    async fn test_send_message_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Mock publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "789".to_string(),
            })
        });

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Create a test session
        let session_id: PqxdhSessionId = [42u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [1u8; 32],
            consumed_one_time_key_ids: vec![],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [43u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        // Add session to state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.sessions.insert(session_id, test_session);
            },
        )
        .await;

        let message = "Test message".to_string();
        let result = handler.send_message(&session_id, &message).await;

        assert!(result.is_ok());
    }

    /// Test send_message with session not found
    #[tokio::test]
    async fn test_send_message_session_not_found() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        let session_id: PqxdhSessionId = [42u8; 32];
        let message = "Test message".to_string();
        let result = handler.send_message(&session_id, &message).await;

        assert!(matches!(result, Err(PqxdhError::SessionNotFound)));
    }

    /// Test inbox_stream functionality for service providers
    #[tokio::test]
    async fn test_inbox_stream_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Mock ensure_contains_filter and filtered_messages_stream
        mock_manager
            .expect_ensure_contains_filter()
            .times(1)
            .returning(|_| Ok(()));

        mock_manager
            .expect_filtered_messages_stream()
            .times(1)
            .returning(|_| Box::pin(stream::empty()));

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Set up service provider state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
                let (_, private_keys) =
                    create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3).unwrap();
                state.private_keys = Some(private_keys);
                state.inbox = Some(create_test_inbox());
            },
        )
        .await;

        let result = handler.inbox_stream::<String>().await;
        assert!(result.is_ok());
    }

    /// Test inbox_stream without published service
    #[tokio::test]
    async fn test_inbox_stream_service_not_published() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        let result = handler.inbox_stream::<String>().await;
        assert!(matches!(result, Err(PqxdhError::ServiceNotPublished)));
    }

    /// Test state serialization and restoration
    #[tokio::test]
    async fn test_state_persistence() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Create handler with initial state
        let original_handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Add some state
        let session_id: PqxdhSessionId = [99u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [2u8; 32],
            consumed_one_time_key_ids: vec!["test_key".to_string()],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [100u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        SharedObservable::<_, AsyncLock>::update(
            &original_handler.state,
            |state: &mut PqxdhProtocolState| {
                state.sessions.insert(session_id, test_session);
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![4, 5, 6],
                    relays: vec![],
                });
            },
        )
        .await;

        // Serialize state
        let serialized_state = {
            let state = original_handler.state.read().await;
            postcard::to_stdvec(&*state).unwrap()
        };

        // Deserialize and create new handler
        let restored_state: PqxdhProtocolState = postcard::from_bytes(&serialized_state).unwrap();
        let restored_handler =
            TestPqxdhHandler::from_state(&mock_manager, &keypair, restored_state);

        // Verify state was restored correctly
        let restored_state = restored_handler.state.read().await;
        assert!(restored_state.sessions.contains_key(&session_id));
        assert_eq!(restored_state.protocol, PqxdhInboxProtocol::EchoService);
        assert_eq!(
            restored_state.inbox_tag,
            Some(Tag::Channel {
                id: vec![4, 5, 6],
                relays: vec![]
            })
        );
    }

    /// Test error handling for various scenarios
    #[tokio::test]
    async fn test_error_handling_scenarios() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Test RPC error during publish
        mock_manager
            .expect_publish()
            .times(1)
            .returning(|_| Err(crate::ClientError::Generic("Network error".to_string())));

        let mut handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        let result = handler.publish_service(false).await;
        assert!(matches!(result, Err(PqxdhError::MessagesService(_))));
    }

    /// Test session management with multiple sessions
    #[tokio::test]
    async fn test_multiple_session_management() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Create multiple test sessions
        let session_ids = [[1u8; 32], [2u8; 32], [3u8; 32]];

        for (i, session_id) in session_ids.iter().enumerate() {
            let shared_secret = PqxdhSharedSecret {
                shared_key: [i as u8; 32],
                consumed_one_time_key_ids: vec![format!("key_{}", i)],
            };
            let test_session = PqxdhSession::from_shared_secret(
                shared_secret,
                *session_id,
                [(i + 10) as u8; 32], // their_session_channel_id
                keypair.public_key(),
            );

            SharedObservable::<_, AsyncLock>::update(
                &handler.state,
                |state: &mut PqxdhProtocolState| {
                    state.sessions.insert(*session_id, test_session);
                },
            )
            .await;
        }

        // Verify all sessions are tracked
        let state = handler.state.read().await;
        assert_eq!(state.sessions.len(), 3);
        for session_id in &session_ids {
            assert!(state.sessions.contains_key(session_id));
        }
    }

    /// Test emphemeral message functionality
    #[tokio::test]
    async fn test_send_emphemeral_message() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Mock publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "emp123".to_string(),
            })
        });

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Create a test session
        let session_id: PqxdhSessionId = [55u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [3u8; 32],
            consumed_one_time_key_ids: vec![],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [56u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        // Add session to state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.sessions.insert(session_id, test_session);
            },
        )
        .await;

        let message = "Emphemeral message".to_string();
        let result = handler
            .send_emphemeral_message(&session_id, &message, 60)
            .await;

        assert!(result.is_ok());
    }

    /// Test listen_for_messages functionality
    #[tokio::test]
    async fn test_listen_for_messages() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        // Mock catch_up_and_subscribe
        mock_manager
            .expect_catch_up_and_subscribe()
            .times(1)
            .returning(|_, _| Ok(Box::pin(stream::empty())));

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        // Create a test session
        let session_id: PqxdhSessionId = [77u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [4u8; 32],
            consumed_one_time_key_ids: vec![],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [78u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        // Add session to state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.sessions.insert(session_id, test_session);
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
            },
        )
        .await;

        let result = handler
            .listen_for_messages::<String>(session_id, true)
            .await;
        assert!(result.is_ok());
    }

    /// Test listen_for_messages with session not found
    #[tokio::test]
    async fn test_listen_for_messages_session_not_found() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = create_test_keypair();

        let handler =
            TestPqxdhHandler::new(&mock_manager, &keypair, PqxdhInboxProtocol::EchoService);

        let session_id: PqxdhSessionId = [88u8; 32];
        let result = handler
            .listen_for_messages::<String>(session_id, true)
            .await;

        assert!(matches!(result, Err(PqxdhError::SessionNotFound)));
    }
}
