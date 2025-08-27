use crate::{KeyPair, Signature, VerifyingKey};
use blake3::{Hash, Hasher};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{ChaCha20Poly1305Content, PqxdhEncryptedContent},
    keys::Id as VerifyingKeyId,
    Ed25519SelfEncryptedContent, EphemeralEcdhContent, MlDsaSelfEncryptedContent,
};
use forward_compatible_enum::ForwardCompatibleEnum;

mod store_key;
pub use store_key::{PqxdhInboxProtocol, StoreKey};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum Tag {
    Protected, // may not be forwarded, unless the other end is authenticated as the author, may it be accepted
    Event {
        // referes to another event in some form
        id: Hash,
        #[serde(default)]
        relays: Vec<String>,
    },
    User {
        // Refers to a user in some form
        id: VerifyingKeyId,
        #[serde(default)]
        relays: Vec<String>,
    },
    Channel {
        // Refers to a channel in some form, custom length but often times a hash
        id: Vec<u8>,
        #[serde(default)]
        relays: Vec<String>,
    },
}

impl From<&MessageFull> for Tag {
    fn from(message: &MessageFull) -> Self {
        Tag::Event {
            id: *message.id(),
            relays: vec![],
        }
    }
}

impl std::fmt::Debug for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tag::Protected => write!(f, "Protected"),
            Tag::Event { id, .. } => write!(f, "Event(#{})", hex::encode(id.as_bytes())),
            Tag::User { id, .. } => write!(f, "User(#{})", hex::encode(id)),
            Tag::Channel { id, .. } => write!(f, "Channel(#{})", hex::encode(id)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// This is a regular event, that should be stored and made available to query for afterwards
    Regular,
    /// An ephemeral event is not kept permanently but mainly forwarded to who ever is interested
    /// if a number larger than 0 is provided, this is the maximum seconds the event should be
    /// stored for in case someone asks. If the timestamp + seconds is smaller than the current
    /// server time, the event might be discarded without even forwarding it.
    Emphemeral(u32),
    /// This is an event that should be stored in a specific store
    Store(StoreKey),
    /// This is an event that should clear a specific store
    ClearStore(StoreKey), // clear the given storekey of the user, if the events timestamp is larger than the stored one
}

/// Message content variants supporting both raw bytes and encrypted content.
///
/// # Content Type Design and Versioning Strategy
///
/// The `Content` enum represents the payload of a message and supports different encryption
/// schemes. **Important**: The choice of available content types and their cryptographic
/// implementations is **hard-wired at the message version level** (e.g., `MessageV0`).
/// This means that when a new message version is introduced (like `MessageV1`), it can
/// have different content variants or updated cryptographic schemes.
///
/// ## Serialization with Postcard
///
/// This enum uses [postcard](https://docs.rs/postcard/) for efficient binary serialization.
/// Postcard distinguishes enum variants using a compact binary tag system:
/// - `Raw(Vec<u8>)` → serialized as `[0, ...data bytes...]`
/// - `ChaCha20Poly1305(content)` → serialized as `[1, ...encrypted content...]`  
/// - `Ed25519Encrypted(content)` → serialized as `[2, ...encrypted content...]`
///
/// The first byte indicates which variant is being deserialized, making the format
/// self-describing and forwards-compatible. For more details on postcard's enum
/// handling, see: <https://docs.rs/postcard/latest/postcard/#enums>
///
/// ## Content Type Security Model
///
/// Each content type has different security properties and use cases:
///
/// ### `Raw` - Unencrypted Content
/// - Used for public messages or when encryption is handled at a higher layer
/// - Suitable for metadata, public announcements, or already-encrypted data
/// - No confidentiality protection - readable by all message recipients
///
/// ### `ChaCha20Poly1305` - Context-Based Encryption
/// - Uses ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)
/// - Encryption key derived from message context (channel tags, group keys, etc.)
/// - Provides both confidentiality and authenticity
/// - Minimal overhead, suitable for high-throughput scenarios
///
/// ### `Ed25519Encrypted` - Identity-Based Encryption
/// - Uses Ed25519 keypairs (typically from mnemonic phrases) for key derivation
/// - Encrypts using ChaCha20-Poly1305 with keys derived from Ed25519 operations
/// - Suitable for direct peer-to-peer encrypted messaging
/// - Self-contained encryption that doesn't require additional context
///
/// ## Version Evolution
///
/// When message formats evolve (e.g., `MessageV0` → `MessageV1`), the `Content` enum
/// can be updated with:
/// - New encryption schemes (e.g., post-quantum cryptography)
/// - Additional metadata or structure
/// - Different key derivation methods
/// - Backwards-incompatible changes to existing variants
///
/// The versioning at the `Message` level ensures that older clients can gracefully
/// handle unknown message versions while maintaining compatibility with supported versions.
///
/// ## Example Usage
///
/// ```rust
/// use zoe_wire_protocol::Content;
///
/// // Raw content for public data
/// let public_msg = Content::raw("Hello, world!".as_bytes().to_stdvec());
///
/// // Typed content (serialized with postcard)
/// #[derive(serde::Serialize)]
/// struct MyData { value: u32 }
/// let typed_content = Content::raw_typed(&MyData { value: 42 })?;
/// # Ok::<(), postcard::Error>(())
/// ```
#[derive(Clone, PartialEq, ForwardCompatibleEnum)]
pub enum Content {
    /// Raw byte content without encryption.
    ///
    /// Use this variant for:
    /// - Public messages that don't require encryption
    /// - Content that is already encrypted at a higher layer
    /// - Metadata or routing information
    /// - Binary data that should be transmitted as-is
    #[discriminant(0)]
    Raw(Vec<u8>),

    /// ChaCha20-Poly1305 encrypted content with context-derived keys.
    ///
    /// The encryption key is determined by message context such as:
    /// - Channel tags and group membership
    /// - Shared secrets established through key exchange
    /// - Derived keys from parent encryption contexts
    ///
    /// This variant provides minimal serialization overhead while maintaining
    /// strong AEAD security properties.
    #[discriminant(20)]
    ChaCha20Poly1305(ChaCha20Poly1305Content),

    /// Ed25519-derived ChaCha20-Poly1305 self-encrypted content.
    ///
    /// Uses sender's Ed25519 keypair to derive ChaCha20-Poly1305 encryption keys.
    /// Only the sender can decrypt this content (encrypt-to-self pattern).
    /// Suitable for:
    /// - Personal data storage
    /// - Self-encrypted notes and backups
    /// - Content where only the author should have access
    #[discriminant(40)]
    Ed25519SelfEncrypted(Ed25519SelfEncryptedContent),

    /// ML-DSA-derived ChaCha20-Poly1305 self-encrypted content.
    ///
    /// Uses sender's ML-DSA keypair to derive ChaCha20-Poly1305 encryption keys.
    /// Only the sender can decrypt this content (encrypt-to-self pattern).
    /// Post-quantum secure version of Ed25519SelfEncrypted.
    /// Suitable for:
    /// - Personal data storage (post-quantum secure)
    /// - Self-encrypted notes and backups
    /// - Content where only the author should have access
    #[discriminant(41)]
    MlDsaSelfEncrypted(MlDsaSelfEncryptedContent),

    /// PQXDH encrypted content.
    ///
    /// Uses the PQXDH (Post-Quantum Extended Diffie-Hellman) protocol for
    /// asynchronous secure communication establishment. Combines X25519 ECDH
    /// with ML-KEM for hybrid classical/post-quantum security.
    /// Suitable for:
    /// - Asynchronous RPC initiation (tarpc-over-message)
    /// - Secure inbox messaging
    /// - Initial key agreement for ongoing sessions
    /// - Post-quantum secure communication setup
    #[discriminant(42)]
    PqxdhEncrypted(PqxdhEncryptedContent),

    /// Ephemeral ECDH encrypted content.
    ///
    /// Uses ephemeral X25519 key pairs for each message to encrypt for
    /// the recipient. Only the recipient can decrypt (proper public key encryption).
    /// Provides perfect forward secrecy. Suitable for:
    /// - RPC calls over message infrastructure  
    /// - One-off encrypted messages
    /// - Public key encryption scenarios
    #[discriminant(80)]
    EphemeralEcdh(EphemeralEcdhContent),

    /// Unknown content type.
    ///
    /// This variant is used when the content type is unknown or not supported.
    /// It contains the discriminant and the raw data.
    Unknown { discriminant: u32, data: Vec<u8> },
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Content::Raw(data) => write!(f, "Raw([u8; {}])", data.len()),
            Content::ChaCha20Poly1305(..) => write!(f, "ChaCha20Poly1305(#redacted#)"),
            Content::Ed25519SelfEncrypted(..) => write!(f, "Ed25519SelfEncrypted(#redacted#)"),
            Content::MlDsaSelfEncrypted(..) => write!(f, "MlDsaSelfEncrypted(#redacted#)"),
            Content::PqxdhEncrypted(..) => write!(f, "PqxdhEncrypted(#redacted#)"),
            Content::EphemeralEcdh(..) => write!(f, "EphemeralEcdh(#redacted#)"),
            Content::Unknown { discriminant, data } => write!(f, "Unknown({:?}, {:?})", discriminant, data.len()),
        }
    }
}

impl Content {
    /// Create raw content from bytes
    pub fn raw(data: Vec<u8>) -> Self {
        Content::Raw(data)
    }

    /// Create raw content from serializable object
    pub fn raw_typed<T: Serialize>(data: &T) -> Result<Self, postcard::Error> {
        Ok(Content::Raw(postcard::to_stdvec(data)?))
    }

    /// Create encrypted content
    pub fn encrypted(content: ChaCha20Poly1305Content) -> Self {
        Content::ChaCha20Poly1305(content)
    }

    /// Create ed25519 self-encrypted content
    pub fn ed25519_self_encrypted(content: Ed25519SelfEncryptedContent) -> Self {
        Content::Ed25519SelfEncrypted(content)
    }

    /// Create ML-DSA self-encrypted content
    pub fn ml_dsa_self_encrypted(content: MlDsaSelfEncryptedContent) -> Self {
        Content::MlDsaSelfEncrypted(content)
    }

    /// Create ephemeral ECDH encrypted content
    pub fn ephemeral_ecdh(content: EphemeralEcdhContent) -> Self {
        Content::EphemeralEcdh(content)
    }

    /// Create PQXDH encrypted content
    pub fn pqxdh_encrypted(content: PqxdhEncryptedContent) -> Self {
        Content::PqxdhEncrypted(content)
    }

    /// Create PQXDH initial message content
    pub fn pqxdh_initial(message: crate::inbox::pqxdh::PqxdhInitialMessage) -> Self {
        Content::PqxdhEncrypted(PqxdhEncryptedContent::Initial(message))
    }

    /// Create PQXDH session message content
    pub fn pqxdh_session(message: crate::inbox::pqxdh::PqxdhSessionMessage) -> Self {
        Content::PqxdhEncrypted(PqxdhEncryptedContent::Session(message))
    }

    /// Get the raw bytes if this is raw content
    pub fn as_raw(&self) -> Option<&Vec<u8>> {
        let Content::Raw(ref content) = self else {
            return None;
        };
        Some(content)
    }

    /// Get the encrypted content if this is encrypted
    pub fn as_encrypted(&self) -> Option<&ChaCha20Poly1305Content> {
        let Content::ChaCha20Poly1305(ref content) = self else {
            return None;
        };
        Some(content)
    }

    /// Get the ed25519 self-encrypted content if this is ed25519 self-encrypted
    pub fn as_ed25519_self_encrypted(&self) -> Option<&Ed25519SelfEncryptedContent> {
        let Content::Ed25519SelfEncrypted(ref content) = self else {
            return None;
        };
        Some(content)
    }

    /// Get the ML-DSA self-encrypted content if this is ML-DSA self-encrypted
    pub fn as_ml_dsa_self_encrypted(&self) -> Option<&MlDsaSelfEncryptedContent> {
        let Content::MlDsaSelfEncrypted(ref content) = self else {
            return None;
        };
        Some(content)
    }

    /// Get the ephemeral ECDH encrypted content if this is ephemeral ECDH encrypted
    pub fn as_ephemeral_ecdh(&self) -> Option<&EphemeralEcdhContent> {
        let Content::EphemeralEcdh(ref content) = self else {
            return None;
        };
        Some(content)
    }

    /// Get the PQXDH encrypted content if this is PQXDH encrypted
    pub fn as_pqxdh_encrypted(&self) -> Option<&PqxdhEncryptedContent> {
        let Content::PqxdhEncrypted(ref content) = self else {
            return None;
        };
        Some(content)
    }

    /// Check if this content is encrypted
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            Content::ChaCha20Poly1305(_)
                | Content::Ed25519SelfEncrypted(_)
                | Content::MlDsaSelfEncrypted(_)
                | Content::EphemeralEcdh(_)
                | Content::PqxdhEncrypted(_)
        )
    }

    /// Check if this content is raw
    pub fn is_raw(&self) -> bool {
        matches!(self, Content::Raw(_))
    }
}

/// Top-level message format with versioning support.
///
/// # Message Versioning Strategy
///
/// The `Message` enum provides **the primary versioning mechanism** for the wire protocol.
/// Each variant (e.g., `MessageV0`) represents a specific version of the message format
/// with **hard-wired cryptographic choices and content types**.
///
/// ## Version-Specific Design Philosophy
///
/// Unlike other protocols where features are negotiated dynamically, this protocol
/// **hard-wires** cryptographic algorithms and content types into each message version.
/// This design provides several benefits:
///
/// - **Security**: No downgrade attacks through feature negotiation
/// - **Simplicity**: Clear, unambiguous message format per version
/// - **Performance**: No runtime algorithm selection overhead
/// - **Evolution**: Clean migration path to new cryptographic standards
///
/// ## Content Type Binding
///
/// Each message version has a **fixed set** of supported [`Content`] variants:
/// - `MessageV0` supports: `Raw`, `ChaCha20Poly1305`, `Ed25519Encrypted`
/// - Future versions (e.g., `MessageV1`) may support different encryption schemes
///
/// This binding ensures that cryptographic choices are made explicitly during protocol
/// design rather than being negotiated at runtime.
///
/// ## Serialization and Wire Compatibility
///
/// Messages are serialized using [postcard](https://docs.rs/postcard/), which handles
/// enum versioning through compact binary tags:
/// - `MessageV0(data)` → serialized as `[0, ...message data...]`
/// - `MessageV1(data)` → would serialize as `[1, ...message data...]` (future)
///
/// This allows clients to:
/// 1. Quickly identify the message version from the first byte
/// 2. Skip unknown message versions gracefully
/// 3. Maintain backwards compatibility with supported versions
///
/// ## Evolution Path
///
/// When cryptographic standards change or new features are needed, the protocol
/// evolves by adding new message versions:
///
/// ```rust,ignore
/// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// pub enum Message {
///     MessageV0(MessageV0),        // Legacy: ChaCha20-Poly1305, Ed25519
///     MessageV1(MessageV1),        // Future: Post-quantum crypto, new content types
/// }
/// ```
///
/// This ensures that:
/// - Older clients continue working with `MessageV0`
/// - Newer clients can handle both versions
/// - Migration happens gradually and safely
///
/// ## Example: Version-Specific Handling
///
/// ```rust
/// use zoe_wire_protocol::{Message, MessageV0, Content};
///
/// fn handle_message(msg: Message) {
///     match msg {
///         Message::MessageV0(v0_msg) => {
///             // Handle v0-specific features
///             match v0_msg.content {
///                 Content::Raw(data) => { /* process raw data */ },
///                 Content::ChaCha20Poly1305(_) => { /* decrypt with ChaCha20 */ },
///                 Content::Ed25519SelfEncrypted(_) => { /* decrypt with Ed25519 */ },
///             }
///         }
///         // Future: MessageV1 would be handled here with its own content types
///     }
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Message {
    /// Message format version 0.
    ///
    /// Supports the following cryptographic primitives:
    /// - **Signing**: Ed25519 digital signatures
    /// - **Encryption**: ChaCha20-Poly1305 AEAD
    /// - **Key Derivation**: Ed25519-based and context-based schemes
    /// - **Content Types**: [`Content::Raw`], [`Content::ChaCha20Poly1305`], [`Content::Ed25519SelfEncrypted`], [`Content::EphemeralEcdh`]
    ///
    /// This version is designed for high-performance messaging with modern cryptographic
    /// standards as of 2025.
    MessageV0(MessageV0),
}

impl Message {
    pub fn verify_sender_signature(
        &self,
        message_bytes: &[u8],
        signature: &Signature,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match self {
            Message::MessageV0(ref inner) => inner.header.sender.verify(message_bytes, signature),
        }
    }

    pub fn new_v0(
        content: Content,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Self {
        Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender,
                when,
                kind,
                tags,
            },
            content,
        })
    }

    pub fn new_v0_raw(
        content: Vec<u8>,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Self {
        Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender,
                when,
                kind,
                tags,
            },
            content: Content::Raw(content),
        })
    }

    pub fn new_v0_encrypted(
        content: ChaCha20Poly1305Content,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Self {
        Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender,
                when,
                kind,
                tags,
            },
            content: Content::ChaCha20Poly1305(content),
        })
    }

    #[deprecated(note = "use new_v0 instead")]
    pub fn new_typed<T>(
        content: T,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Result<Self, postcard::Error>
    where
        T: Serialize,
    {
        Ok(Message::MessageV0(MessageV0 {
            header: MessageV0Header {
                sender,
                when,
                kind,
                tags,
            },
            content: Content::Raw(postcard::to_stdvec(&content)?),
        }))
    }
}

/// Header information for MessageV0 containing metadata and routing information.
///
/// # MessageV0Header Structure
///
/// `MessageV0Header` contains all the metadata fields from a MessageV0 message
/// except for the content payload. This allows RPC transport layers to access
/// sender information, timing, message types, and routing tags without having
/// to deserialize the potentially encrypted content.
///
/// ## Field Description
///
/// - **`sender`**: Ed25519 public key of the message author
/// - **`when`**: Unix timestamp in seconds (for ordering and expiration)
/// - **`kind`**: Message type determining storage and forwarding behavior
/// - **`tags`**: Routing and reference tags (channels, users, events)
///
/// ## Usage in RPC Transport
///
/// This header allows RPC systems to examine message metadata before deciding
/// how to handle the content, enabling efficient routing and access control.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageV0Header {
    /// ML-DSA public key of the message sender (serialized as bytes).
    ///
    /// This key is used to verify the digital signature in [`MessageFull`].
    /// The sender must possess the corresponding private key to create valid signatures.
    /// Stored as encoded bytes for serialization compatibility.
    pub sender: VerifyingKey,

    /// Unix timestamp in seconds when the message was created.
    ///
    /// Used for:
    /// - Message ordering in conversations
    /// - Expiration of ephemeral messages  
    /// - Preventing replay attacks (with reasonable clock skew tolerance)
    pub when: u64,

    /// Message type determining storage and forwarding behavior.
    ///
    /// See [`Kind`] for details on different message types:
    /// - `Regular`: Stored permanently
    /// - `Ephemeral`: Temporary storage with optional TTL
    /// - `Store`: Updates a specific key-value store
    /// - `ClearStore`: Clears a key-value store
    pub kind: Kind,

    /// Tags for routing, references, and metadata.
    ///
    /// Common tag types include:
    /// - `Protected`: Message should only be forwarded to authenticated recipients
    /// - `Event`: References another message or event by ID
    /// - `User`: References a user identity
    /// - `Channel`: Routes to a specific channel or group
    ///
    /// Default value is an empty vector when deserializing legacy messages.
    #[serde(default)]
    pub tags: Vec<Tag>,
}

/// Version 0 of the message format with Ed25519 signatures and ChaCha20-Poly1305 encryption.
///
/// # Message Structure
///
/// `MessageV0` represents the core message data that gets signed and transmitted.
/// It contains metadata (header) and the actual content payload.
/// The message is signed using Ed25519 to create a [`MessageFull`] for transmission.
///
/// ## Cryptographic Binding
///
/// This message version **hard-wires** the following cryptographic choices:
/// - **Digital Signatures**: Ed25519 (see [`MessageFull`])
/// - **Content Encryption**: ChaCha20-Poly1305 AEAD (see [`Content`])
/// - **Hash Function**: Blake3 for message IDs (see [`MessageFull::new`])
/// - **Key Derivation**: Ed25519-based and context-based schemes
///
/// These choices cannot be negotiated or downgraded - they are fixed for all
/// `MessageV0` instances to prevent cryptographic downgrade attacks.
///
/// ## Field Description
///
/// - **`header`**: Message metadata including sender, timestamp, type, and tags
/// - **`content`**: The actual message payload (see [`Content`] variants)
///
/// ## Serialization Format
///
/// Messages are serialized using [postcard](https://docs.rs/postcard/) for efficiency:
///
/// ```text
/// [header: variable][content: 1+ bytes]
/// ```
///
/// The compact binary format minimizes wire overhead while maintaining
/// self-describing properties through postcard's type system.
///
/// ## Example Usage
///
/// ```rust
/// use zoe_wire_protocol::{MessageV0, MessageV0Header, Content, Kind, Tag};
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
///
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let message = MessageV0 {
///     header: MessageV0Header {
///         sender: signing_key.verifying_key(),
///         when: 1640995200, // 2022-01-01 00:00:00 UTC
///         kind: Kind::Regular,
///         tags: vec![Tag::Protected],
///     },
///     content: Content::raw("Hello, world!".as_bytes().to_stdvec()),
/// };
///
/// // Convert to signed message for transmission
/// use zoe_wire_protocol::{Message, MessageFull};
/// let full_message = MessageFull::new(Message::MessageV0(message), &signing_key)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MessageV0 {
    /// Message header containing metadata and routing information.
    ///
    /// Contains sender identity, timestamp, message type, and routing tags.
    /// This information is accessible without deserializing the content.
    pub header: MessageV0Header,

    /// The message payload with optional encryption.
    ///
    /// See [`Content`] for available variants:
    /// - `Raw`: Unencrypted data
    /// - `ChaCha20Poly1305`: Context-encrypted data  
    /// - `Ed25519Encrypted`: Identity-encrypted data
    pub content: Content,
}

impl std::ops::Deref for MessageV0 {
    type Target = MessageV0Header;

    fn deref(&self) -> &Self::Target {
        &self.header
    }
}

/// Complete signed message ready for transmission and storage.
///
/// # Message Authentication and Integrity
///
/// `MessageFull` represents a complete, authenticated message that includes:
/// 1. **Content**: The original [`Message`] (e.g., [`MessageV0`])
/// 2. **Signature**: Ed25519 digital signature over the serialized message
/// 3. **Identity**: Blake3 hash-based unique identifier
///
/// This structure ensures **non-repudiation** and **integrity** - recipients can
/// cryptographically verify that the message came from the claimed sender and
/// hasn't been tampered with.
///
/// ## Cryptographic Construction
///
/// The message construction follows a specific protocol:
///
/// 1. **Serialize**: Convert [`Message`] to bytes using [postcard](https://docs.rs/postcard/)
/// 2. **Sign**: Create Ed25519 signature over the serialized bytes
/// 3. **Hash**: Compute Blake3 hash of `serialized_message || signature` for the ID
///
/// This ensures that:
/// - The signature covers the entire message content
/// - The ID uniquely identifies this specific signed message
/// - Replay attacks are prevented through unique IDs
///
/// ## Wire Format and Storage
///
/// `MessageFull` is the **canonical storage format** used throughout the system:
/// - **Network transmission**: Serialized with postcard for efficiency
/// - **Database storage**: Stored as binary blobs in key-value stores
/// - **Message indexing**: ID used as primary key, sender/timestamp extracted for indexes
///
/// The postcard serialization format is:
/// ```text
/// [id: 32 bytes][message: variable][signature: 64 bytes]
/// ```
///
/// ## Identity and Deduplication
///
/// The Blake3-based ID serves multiple purposes:
/// - **Deduplication**: Identical signed messages have identical IDs
/// - **Content addressing**: Messages can be retrieved by their cryptographic hash
/// - **Integrity verification**: ID changes if any part of the message is modified
/// - **Ordering**: IDs provide deterministic message ordering (with timestamp ties)
///
/// ## Security Properties
///
/// `MessageFull` provides the following security guarantees:
/// - **Authentication**: Ed25519 signature proves sender identity
/// - **Integrity**: Any modification invalidates the signature
/// - **Non-repudiation**: Sender cannot deny creating a valid signature
/// - **Uniqueness**: Blake3 ID prevents message duplication
///
/// Note: **Confidentiality** is provided by the [`Content`] encryption, not at this layer.
///
/// ## Example Usage
///
/// ```rust
/// use zoe_wire_protocol::{MessageFull, Message, MessageV0, Content, Kind};
/// use ed25519_dalek::SigningKey;
/// use rand::rngs::OsRng;
///
/// // Create a signed message
/// let signing_key = SigningKey::generate(&mut OsRng);
/// let message = Message::MessageV0(MessageV0 {
///     sender: signing_key.verifying_key(),
///     when: 1640995200,
///     kind: Kind::Regular,
///     tags: vec![],
///     content: Content::raw("Hello!".as_bytes().to_stdvec()),
/// });
///
/// let full_message = MessageFull::new(message, &signing_key)?;
///
/// // Verify the signature and ID
/// assert!(full_message.verify()?);
///
/// // The ID is deterministic for the same signed content
/// let id = full_message.id;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Storage Integration
///
/// This structure is optimized for the key-value storage architecture:
/// - **Primary key**: `id` field for O(1) message retrieval  
/// - **Indexed fields**: `sender` and `when` extracted from embedded message for queries
/// - **Tag tables**: Separate tables for efficient tag-based filtering
/// - **Blob storage**: Entire `MessageFull` serialized as atomic unit
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "MessageFullWire")]
pub struct MessageFull {
    /// Blake3 hash serving as the unique message identifier.
    ///
    /// Computed as: `Blake3(messsage.as_bytes())`
    /// Notice that the ID does not include the signature as
    /// that may contain random ness (ML-DSA does) and thus would
    /// create different hash IDs for the same content message.
    ///
    /// That means that if there are two messages with the same contentn
    /// but valid signatures (verified against the sender) they are considered
    /// the same in terms of storage and retrieval and there is no guarantee you
    /// received the one with the same signature - just with _a_ valid signature.
    ///
    /// This ID is:
    /// - **Unique**: Cryptographically improbable to collide
    /// - **Deterministic**: Same content  always produces same ID
    /// - **Tamper-evident**: Changes to messagd change the ID
    /// - **Content-addressed**: Can be used to retrieve the message
    #[serde(skip_serializing)]
    id: Hash, // FIXNE we could and should compute this on the fly and caceh it

    /// Cryptographic signature over the serialized message.
    ///
    /// Created by signing `postcard::serialize(message)` with the sender's private key.
    /// Recipients verify this signature using the public key in `message.sender`.
    ///
    /// **Security note**: The signature covers the *entire* serialized message,
    /// including all metadata, tags, and content. This prevents partial modification attacks.
    signature: Signature,

    /// The original message content and metadata.
    ///
    /// Boxed to minimize stack usage since messages can be large.
    /// Contains version-specific message data (e.g., [`MessageV0`]).
    message: Box<Message>,
}

/// The Wire protocol variant just signature and message as bytes
/// the signature is redundent and the message is raw bytes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFullWire {
    signature: Signature,
    message: Box<Message>,
}

impl From<MessageFull> for MessageFullWire {
    fn from(val: MessageFull) -> Self {
        MessageFullWire {
            signature: val.signature,
            message: val.message,
        }
    }
}

impl TryFrom<MessageFullWire> for MessageFull {
    type Error = Box<dyn std::error::Error>;
    fn try_from(value: MessageFullWire) -> Result<Self, Self::Error> {
        let message_bytes = postcard::to_stdvec(&value.message)?;
        Self::with_signature(value.signature, value.message, &message_bytes)
    }
}

impl MessageFull {
    /// Create a new MessageFull with proper signature and ID
    pub fn new(message: Message, signer: &KeyPair) -> Result<Self, Box<dyn std::error::Error>> {
        let message_bytes = postcard::to_stdvec(&message)?;
        let signature = signer.sign(&message_bytes);
        Self::with_signature(signature, Box::new(message), &message_bytes)
    }

    fn with_signature(
        signature: Signature,
        message: Box<Message>,
        message_bytes: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if !message.verify_sender_signature(message_bytes, &signature)? {
            return Err("Signature does not match sender message".into());
        }
        let mut hasher = Hasher::new();
        hasher.update(message_bytes);
        Ok(Self {
            id: hasher.finalize(),
            message,
            signature,
        })
    }

    pub fn id(&self) -> &Hash {
        &self.id
    }

    pub fn message(&self) -> &Message {
        &self.message
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn ref_tag(&self) -> Tag {
        Tag::Event {
            id: *self.id(),
            relays: vec![],
        }
    }

    /// The value this message is stored under in the storage
    pub fn storage_value(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(postcard::to_stdvec(&self)?)
    }

    /// The timeout for this message in the storage
    pub fn storage_timeout(&self) -> Option<u64> {
        match &*self.message {
            Message::MessageV0(msg) => match msg.header.kind {
                Kind::Emphemeral(timeout) if timeout > 0 => Some(timeout as u64),
                _ => None,
            },
        }
    }

    pub fn store_key(&self) -> Option<StoreKey> {
        match &*self.message {
            Message::MessageV0(msg) => match &msg.header.kind {
                Kind::Store(key) => Some(key.clone()),
                _ => None,
            },
        }
    }

    /// this is meant to clear a storage key
    pub fn clear_key(&self) -> Option<StoreKey> {
        None
    }

    /// Deserialize a message from its storage value
    pub fn from_storage_value(value: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let message: Self = postcard::from_bytes(value)?;
        Ok(message)
    }

    pub fn author(&self) -> &VerifyingKey {
        match &*self.message {
            Message::MessageV0(message) => &message.header.sender,
        }
    }

    pub fn when(&self) -> &u64 {
        match &*self.message {
            Message::MessageV0(message) => &message.header.when,
        }
    }

    pub fn kind(&self) -> &Kind {
        match &*self.message {
            Message::MessageV0(message) => &message.header.kind,
        }
    }

    pub fn tags(&self) -> &Vec<Tag> {
        match &*self.message {
            Message::MessageV0(message) => &message.header.tags,
        }
    }

    pub fn content(&self) -> &Content {
        match &*self.message {
            Message::MessageV0(message) => &message.content,
        }
    }

    /// Get raw content bytes if this message contains raw content
    pub fn raw_content(&self) -> Option<&Vec<u8>> {
        self.content().as_raw()
    }

    /// Get encrypted content if this message contains encrypted content
    pub fn encrypted_content(&self) -> Option<&ChaCha20Poly1305Content> {
        self.content().as_encrypted()
    }
}

impl MessageFull {
    /// Try to deserialize content if it's raw (unencrypted)
    pub fn try_deserialize_content<C>(&self) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(bytes) => Ok(postcard::from_bytes(bytes)?),
                Content::ChaCha20Poly1305(_) => {
                    Err("Cannot deserialize encrypted content without decryption key".into())
                }
                Content::Ed25519SelfEncrypted(_) => {
                    Err("Cannot deserialize ed25519-encrypted content without signing key".into())
                }
                Content::MlDsaSelfEncrypted(_) => {
                    Err("Cannot deserialize ML-DSA-encrypted content without signing key".into())
                }
                Content::EphemeralEcdh(_) => Err(
                    "Cannot deserialize ephemeral ECDH-encrypted content without signing keys"
                        .into(),
                ),
                Content::PqxdhEncrypted(_) => {
                    Err("Cannot deserialize PQXDH-encrypted content without private keys".into())
                }
                Content::Unknown { discriminant, .. } => {
                    Err(format!("Unknown content type: {discriminant}").into())
                }
            },
        }
    }

    /// Try to deserialize encrypted content by decrypting it first
    pub fn try_deserialize_encrypted_content<C>(
        &self,
        encryption_key: &crate::crypto::EncryptionKey,
    ) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(_) => Err("Content is not encrypted".into()),
                Content::ChaCha20Poly1305(encrypted) => {
                    let plaintext = encryption_key.decrypt_content(encrypted)?;
                    Ok(postcard::from_bytes(&plaintext)?)
                }
                Content::Ed25519SelfEncrypted(_) => {
                    Err("Cannot decrypt ed25519-encrypted content with EncryptionKey - use signing key instead".into())
                }
                Content::MlDsaSelfEncrypted(_) => {
                    Err("Cannot decrypt ML-DSA-encrypted content with EncryptionKey - use ML-DSA signing key instead".into())
                }
                Content::EphemeralEcdh(_) => {
                    Err("Cannot decrypt ephemeral ECDH-encrypted content with EncryptionKey - use signing keys instead".into())
                }
                Content::PqxdhEncrypted(_) => {
                    Err("Cannot decrypt PQXDH-encrypted content with EncryptionKey - use PQXDH private keys instead".into())
                }
                Content::Unknown { discriminant,.. } => Err(format!("Unknown content type: {discriminant}").into()),
            },
        }
    }

    /// Try to deserialize ed25519-encrypted content by decrypting it first
    pub fn try_deserialize_ed25519_encrypted_content<C>(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(_) => Err("Content is not encrypted".into()),
                Content::ChaCha20Poly1305(_) => {
                    Err("Cannot decrypt ChaCha20Poly1305 content with signing key - use EncryptionKey instead".into())
                }
                Content::Ed25519SelfEncrypted(encrypted) => {
                    let plaintext = encrypted.decrypt(signing_key)?;
                    Ok(postcard::from_bytes(&plaintext)?)
                }
                Content::MlDsaSelfEncrypted(_) => {
                    Err("Cannot decrypt ML-DSA content with Ed25519 key - use ML-DSA signing key instead".into())
                }
                Content::EphemeralEcdh(encrypted) => {
                    let plaintext = encrypted.decrypt(signing_key)?;
                    Ok(postcard::from_bytes(&plaintext)?)
                }
                Content::PqxdhEncrypted(_) => {
                    Err("Cannot decrypt PQXDH-encrypted content with Ed25519 key - use PQXDH private keys instead".into())
                }
                Content::Unknown { discriminant,.. } => Err(format!("Unknown content type: {discriminant}").into()),
            },
        }
    }

    /// Try to deserialize ML-DSA-encrypted content by decrypting it first
    pub fn try_deserialize_ml_dsa_encrypted_content<C>(
        &self,
        signing_key: &KeyPair,
    ) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(_) => Err("Content is not encrypted".into()),
                Content::ChaCha20Poly1305(_) => {
                    Err("Cannot decrypt ChaCha20Poly1305 content with signing key - use EncryptionKey instead".into())
                }
                Content::Ed25519SelfEncrypted(_) => {
                    Err("Cannot decrypt Ed25519 content with ML-DSA key - use Ed25519 signing key instead".into())
                }
                Content::MlDsaSelfEncrypted(encrypted) => {
                    match signing_key {
                        KeyPair::MlDsa65(key, _) => {
                            let plaintext = encrypted.decrypt(&key.signing_key)?;
                            Ok(postcard::from_bytes(&plaintext)?)
                        }
                        _ => Err("ML-DSA self-encrypted content requires MlDsa65 signing key".into()),
                    }
                }
                Content::EphemeralEcdh(_) => {
                    Err("Cannot decrypt ephemeral ECDH content with ML-DSA key - use Ed25519 signing key instead".into())
                }
                Content::PqxdhEncrypted(_) => {
                    Err("Cannot decrypt PQXDH-encrypted content with ML-DSA key - use PQXDH private keys instead".into())
                }
                Content::Unknown { discriminant,.. } => Err(format!("Unknown content type: {discriminant}").into()),
            },
        }
    }
}

/// Manual PartialEq implementation for MessageV0Header
impl PartialEq for MessageV0Header {
    fn eq(&self, other: &Self) -> bool {
        // Compare ML-DSA keys by their encoded bytes
        let self_encoded = self.sender.encode();
        let other_encoded = other.sender.encode();

        self_encoded == other_encoded
            && self.when == other.when
            && self.kind == other.kind
            && self.tags == other.tags
    }
}

/// Manual Eq implementation for MessageV0Header
impl Eq for MessageV0Header {}

/// Manual PartialEq implementation for MessageFull
impl PartialEq for MessageFull {
    fn eq(&self, other: &Self) -> bool {
        // Compare signatures by their encoded bytes
        let self_sig_encoded = self.signature.encode();
        let other_sig_encoded = other.signature.encode();

        self.id == other.id
            && self.message == other.message
            && self_sig_encoded == other_sig_encoded
    }
}

/// Manual Eq implementation for MessageFull
impl Eq for MessageFull {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyPair, VerifyingKey};
    use rand::rngs::OsRng;
    // use signature::Signer; // Not needed since we use KeyPair.sign() method

    fn make_hash() -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(b"1234567890abcdef");
        hasher.finalize()
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct DummyContent {
        value: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ComplexContent {
        text: String,
        numbers: Vec<i32>,
        flag: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestContent {
        text: String,
        timestamp: u64,
        value: u32,
    }

    fn make_keys() -> (KeyPair, VerifyingKey) {
        let mut csprng = OsRng;
        let keypair = KeyPair::generate(&mut csprng);
        let public_key = keypair.public_key();
        (keypair, public_key)
    }

    #[test]
    fn test_message_sign_and_verify() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core.clone(), &sk).unwrap();
        let mut tampered: MessageFullWire = msg_full.clone().into();
        // Tamper with the message by modifying the content
        match &mut *tampered.message {
            Message::MessageV0(ref mut msg_v0) => {
                msg_v0.header.when += 1; // Change timestamp to invalidate signature
            }
        }
        assert!(MessageFull::try_from(tampered).is_err());
    }

    #[test]
    fn test_signature_fails_with_wrong_key() {
        let (sk1, pk1) = make_keys();
        let (sk2, _pk2) = make_keys();
        let content = DummyContent { value: 7 };
        let core = Message::new_typed(
            content.clone(),
            pk1,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core, &sk1).unwrap();
        let mut tampered: MessageFullWire = msg_full.clone().into();
        // Replace signature with one from a different key
        let message_bytes = postcard::to_stdvec(&tampered.message).unwrap();
        let fake_sig = sk2.sign(&message_bytes);
        tampered.signature = fake_sig;
        assert!(MessageFull::try_from(tampered).is_err());
    }

    #[test]
    fn test_empty_content() {
        let (sk, pk) = make_keys();
        let core = Message::new_typed(
            DummyContent { value: 0 },
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let _msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
    }

    #[test]
    fn test_multiple_content_items() {
        let (sk, pk) = make_keys();
        let contents = [
            DummyContent { value: 1 },
            DummyContent { value: 2 },
            DummyContent { value: 3 },
        ];
        let core = Message::new_typed(
            contents[0].clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![
                Tag::Protected,
                Tag::Event {
                    id: make_hash(),
                    relays: vec!["relay1".to_string()],
                },
            ],
        )
        .unwrap();

        let _msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
    }

    #[test]
    fn test_complex_content_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::User {
                id: [1u8; 32],
                relays: vec!["relay1".to_string()],
            }],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();

        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
        // Deserialized MessageFull is also verified by construction
    }

    #[test]
    #[ignore = "this won't work, and that's the proof"]
    fn test_complex_content_serialization_is_not_vec_u8() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::User {
                id: [1u8; 32],
                relays: vec!["relay1".to_string()],
            }],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        // Deserialized MessageFull is also verified by construction

        let deserialize_u8 = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialize_u8.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
    }

    #[test]
    fn test_complex_content_no_tags_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();

        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
        // Deserialized MessageFull is also verified by construction
    }

    #[test]
    fn test_all_tag_types_serialization() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 100 };

        let tags = [
            Tag::Protected,
            Tag::Event {
                id: make_hash(),
                relays: vec!["relay1".to_string()],
            },
            Tag::User {
                id: [2u8; 32],
                relays: vec!["relay2".to_string()],
            },
            Tag::Channel {
                id: vec![3],
                relays: vec!["relay3".to_string()],
            },
        ];

        for tag in tags {
            let core = Message::new_typed(
                content.clone(),
                pk.clone(),
                1714857600,
                Kind::Regular,
                vec![tag.clone()],
            )
            .unwrap();

            let msg_full = MessageFull::new(core, &sk).unwrap();
            // MessageFull only exists in verified state, so creation success implies verification
            // Serialize and deserialize
            let serialized = msg_full.storage_value().unwrap();
            let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
            let de_content: DummyContent = deserialized.try_deserialize_content().unwrap();

            assert_eq!(msg_full, deserialized);
            assert_eq!(content, de_content);
            // Deserialized MessageFull is also verified by construction
        }
    }
    #[test]
    fn test_complex_content_empheral_kind_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Emphemeral(10),
            vec![],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);

        assert_eq!(msg_full, deserialized);
        // Deserialized MessageFull is also verified by construction
    }

    #[test]
    fn test_complex_content_clear_store_kind_serialization() {
        // Create a signing key for testing
        let (signing_key, verifying_key) = make_keys();

        for i in 0..10 {
            let content = TestContent {
                text: format!("Test message {}", i + 1),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                value: i as u32,
            };

            let mut tags = Vec::new();
            // Create a fake event ID (32 bytes)
            let mut event_id_bytes = [0u8; 32];
            event_id_bytes[0] = i as u8;
            let event_id = blake3::Hash::from(event_id_bytes);
            tags.push(Tag::Event {
                id: event_id,
                relays: Vec::new(),
            });

            let message = Message::new_typed(
                content.clone(),
                verifying_key.clone(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Kind::Regular,
                tags,
            )
            .unwrap();

            let msg_full = MessageFull::new(message, &signing_key).unwrap();
            // MessageFull only exists in verified state, so creation success implies verification
            // Serialize and deserialize
            let serialized = msg_full.storage_value().unwrap();
            let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
            let de_content: TestContent = deserialized.try_deserialize_content().unwrap();

            assert_eq!(msg_full, deserialized);
            assert_eq!(content, de_content);
            // Deserialized MessageFull is also verified by construction
        }
    }

    #[test]
    fn test_complex_content_store_kind_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Store(StoreKey::CustomKey(10)),
            vec![],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
        // Deserialized MessageFull is also verified by construction
    }

    #[test]
    fn test_wire_format_roundtrip() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core, &sk).unwrap();
        let original_id = *msg_full.id();

        // Convert to wire format and back
        let wire: MessageFullWire = msg_full.clone().into();
        let reconstructed = MessageFull::try_from(wire).unwrap();

        // Should be identical after roundtrip
        assert_eq!(msg_full, reconstructed);
        assert_eq!(original_id, *reconstructed.id());
    }

    #[test]
    fn test_invalid_signature_wire() {
        let (sk, pk) = make_keys();
        let (wrong_sk, _) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core.clone(), &sk).unwrap();
        let mut tampered_wire: MessageFullWire = msg_full.into();

        // Replace signature with one from a different key
        let message_bytes = postcard::to_stdvec(&tampered_wire.message).unwrap();
        let wrong_sig = wrong_sk.sign(&message_bytes);
        tampered_wire.signature = wrong_sig;

        // Attempting to convert back to MessageFull should fail
        assert!(MessageFull::try_from(tampered_wire).is_err());
    }

    #[test]
    fn test_message_tampering_wire() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core.clone(), &sk).unwrap();
        let mut tampered_wire: MessageFullWire = msg_full.into();

        // Tamper with the message content by modifying the sender
        let (_, different_pk) = make_keys();
        match &mut *tampered_wire.message {
            Message::MessageV0(ref mut msg_v0) => {
                msg_v0.header.sender = different_pk;
            }
        }

        // Attempting to convert back to MessageFull should fail due to signature mismatch
        assert!(MessageFull::try_from(tampered_wire).is_err());
    }

    #[test]
    fn test_signature_tampering_wire() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core.clone(), &sk).unwrap();
        let mut tampered_wire: MessageFullWire = msg_full.into();

        // Create a completely different signature using a different key
        let (wrong_sk, _) = make_keys();
        let message_bytes = postcard::to_stdvec(&tampered_wire.message).unwrap();
        let wrong_signature = wrong_sk.sign(&message_bytes);
        tampered_wire.signature = wrong_signature;

        // Attempting to convert back to MessageFull should fail due to invalid signature
        assert!(MessageFull::try_from(tampered_wire).is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (sk, pk) = make_keys();
        let content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![
                Tag::Protected,
                Tag::Event {
                    id: make_hash(),
                    relays: vec!["relay1".to_string()],
                },
            ],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();

        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(content, de_content);
        // Deserialized MessageFull is also verified by construction
    }

    #[test]
    fn test_multiple_tags() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![
                Tag::Protected,
                Tag::Event {
                    id: make_hash(),
                    relays: vec!["relay1".to_string()],
                },
                Tag::User {
                    id: [2u8; 32],
                    relays: vec!["relay2".to_string()],
                },
            ],
        )
        .unwrap();
        let _msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
    }

    #[test]
    fn test_large_content() {
        let (sk, pk) = make_keys();
        let large_content = ComplexContent {
            text: "A".repeat(1000),       // Large string
            numbers: (0..1000).collect(), // Large vector
            flag: false,
        };
        let core = Message::new_typed(
            large_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Channel {
                id: vec![1],
                relays: vec!["relay1".to_string()],
            }],
        )
        .unwrap();
        let _msg_full = MessageFull::new(core, &sk).unwrap();
        // MessageFull only exists in verified state, so creation success implies verification
    }

    #[test]
    fn test_id_uniqueness() {
        let (sk, pk) = make_keys();
        let content1 = DummyContent { value: 1 };
        let content2 = DummyContent { value: 2 };

        let core1 = Message::new_typed(
            content1.clone(),
            pk.clone(),
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let core2 = Message::new_typed(
            content2.clone(),
            pk.clone(),
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();

        let msg_full1 = MessageFull::new(core1, &sk).unwrap();
        let msg_full2 = MessageFull::new(core2, &sk).unwrap();

        // Different content should produce different IDs
        assert_ne!(msg_full1.id, msg_full2.id);
    }

    #[test]
    fn test_same_content_different_signatures_but_same_id() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };

        let core1 = Message::new_typed(
            content.clone(),
            pk.clone(),
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let core2 = Message::new_typed(
            content.clone(),
            pk.clone(),
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();

        let msg_full1 = MessageFull::new(core1, &sk).unwrap();
        let msg_full2 = MessageFull::new(core2, &sk).unwrap();

        // Same content but different signatures (ML-DSA is non-deterministic)
        assert_ne!(msg_full1.signature, msg_full2.signature);

        // but the id and message should be the same
        assert_eq!(msg_full1.id, msg_full2.id);
        assert_eq!(msg_full1.message, msg_full2.message);
    }

    #[test]
    fn test_pqxdh_encrypted_content() {
        use crate::{
            inbox::pqxdh::{PqxdhInitialMessage, PqxdhSessionMessage},
            PqxdhEncryptedContent,
        };

        // Create a mock PQXDH initial message
        let pqxdh_initial = PqxdhInitialMessage {
            initiator_identity: VerifyingKey::Ed25519(Box::new(
                ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
            )),
            ephemeral_key: x25519_dalek::PublicKey::from([1u8; 32]),
            kem_ciphertext: vec![2u8; 100],
            signed_prekey_id: "spk_001".to_string(),
            one_time_prekey_id: Some("otk_001".to_string()),
            pq_signed_prekey_id: "pqspk_001".to_string(),
            pq_one_time_key_id: Some("pqotk_001".to_string()),
            encrypted_payload: vec![3u8; 50],
        };

        // Create a mock PQXDH session message
        let pqxdh_session = PqxdhSessionMessage {
            session_id: [4u8; 16],
            sequence_number: 42,
            encrypted_payload: vec![5u8; 30],
            auth_tag: [6u8; 16],
        };

        // Test initial message content
        let initial_content = Content::pqxdh_initial(pqxdh_initial.clone());

        // Test session message content
        let session_content = Content::pqxdh_session(pqxdh_session.clone());

        // Test getters
        let retrieved_initial = initial_content.as_pqxdh_encrypted().unwrap();
        if let PqxdhEncryptedContent::Initial(msg) = retrieved_initial {
            assert_eq!(*msg, pqxdh_initial);
        } else {
            panic!("Expected Initial variant");
        }

        let retrieved_session = session_content.as_pqxdh_encrypted().unwrap();
        if let PqxdhEncryptedContent::Session(msg) = retrieved_session {
            assert_eq!(*msg, pqxdh_session);
        } else {
            panic!("Expected Session variant");
        }

        // Test is_encrypted
        assert!(initial_content.is_encrypted());
        assert!(session_content.is_encrypted());
        assert!(!initial_content.is_raw());
        assert!(!session_content.is_raw());

        // Test serialization
        let initial_serialized = postcard::to_stdvec(&initial_content).unwrap();
        let initial_deserialized: Content = postcard::from_bytes(&initial_serialized).unwrap();
        assert_eq!(initial_content, initial_deserialized);

        let session_serialized = postcard::to_stdvec(&session_content).unwrap();
        let session_deserialized: Content = postcard::from_bytes(&session_serialized).unwrap();
        assert_eq!(session_content, session_deserialized);
    }

    #[test]
    fn test_content_type_discriminants() {
        // Test that our new PQXDH discriminant doesn't conflict
        let raw_content = Content::raw(vec![1, 2, 3]);
        let pqxdh_content = Content::pqxdh_initial(crate::inbox::pqxdh::PqxdhInitialMessage {
            initiator_identity: VerifyingKey::Ed25519(Box::new(
                ed25519_dalek::VerifyingKey::from_bytes(&[0u8; 32]).unwrap(),
            )),
            ephemeral_key: x25519_dalek::PublicKey::from([0u8; 32]),
            kem_ciphertext: vec![],
            signed_prekey_id: "test".to_string(),
            one_time_prekey_id: None,
            pq_signed_prekey_id: "test".to_string(),
            pq_one_time_key_id: None,
            encrypted_payload: vec![],
        });

        // Serialize both and ensure they have different discriminants
        let raw_serialized = postcard::to_stdvec(&raw_content).unwrap();
        let pqxdh_serialized = postcard::to_stdvec(&pqxdh_content).unwrap();

        // First byte should be the discriminant
        assert_ne!(raw_serialized[0], pqxdh_serialized[0]);
        assert_eq!(raw_serialized[0], 0); // Raw should be discriminant 0
        assert_eq!(pqxdh_serialized[0], 42); // PQXDH should be discriminant 42
    }
}

#[cfg(test)]
mod size_tests {
    use super::*;
    use crate::keys::KeyPair;
    use rand::rngs::OsRng;
    /// Test helper to create keypairs of different types for size testing
    fn create_keypairs_by_type() -> Vec<(String, KeyPair)> {
        let mut rng = OsRng;
        vec![
            ("Ed25519".to_string(), KeyPair::generate_ed25519(&mut rng)),
            ("MlDsa44".to_string(), KeyPair::generate_ml_dsa44(&mut rng)),
            ("MlDsa65".to_string(), KeyPair::generate_ml_dsa65(&mut rng)),
            ("MlDsa87".to_string(), KeyPair::generate_ml_dsa87(&mut rng)),
        ]
    }

    /// Create a minimal message with empty content and no tags
    fn create_minimal_message(keypair: &KeyPair) -> MessageFull {
        let public_key = keypair.public_key();

        // Create message with empty raw content and no tags
        let message = MessageV0 {
            header: MessageV0Header {
                sender: public_key,
                when: 1640995200, // Fixed timestamp for consistency
                kind: Kind::Regular,
                tags: vec![], // Empty tags for minimum size
            },
            content: Content::Raw(vec![]), // Empty raw content for minimum size
        };

        MessageFull::new(Message::MessageV0(message), keypair).unwrap()
    }

    #[test]
    fn test_minimum_message_sizes_by_key_variant() {
        let keypairs = create_keypairs_by_type();

        for (key_type, keypair) in keypairs {
            let msg_full = create_minimal_message(&keypair);
            let serialized = postcard::to_stdvec(&MessageFullWire::from(msg_full)).unwrap();
            let size = serialized.len();

            println!("Minimum serialized size for {}: {} bytes", key_type, size);

            // Assert expected minimum sizes based on our analysis
            match key_type.as_str() {
                "Ed25519" => {
                    // Ed25519: ~120 bytes (allow some variance for postcard overhead)
                    assert!(
                        (100..=150).contains(&size),
                        "Ed25519 message size {size} should be ~120 bytes (100-150 range)"
                    );
                }
                "MlDsa44" => {
                    // ML-DSA-44: ~3,832 bytes (allow reasonable variance)
                    assert!(
                        (3700..=4000).contains(&size),
                        "ML-DSA-44 message size {size} should be ~3,832 bytes (3700-4000 range)"
                    );
                }
                "MlDsa65" => {
                    // ML-DSA-65: ~5,362 bytes (allow reasonable variance)
                    assert!(
                        (5200..=5600).contains(&size),
                        "ML-DSA-65 message size {size} should be ~5,362 bytes (5200-5600 range)"
                    );
                }
                "MlDsa87" => {
                    // ML-DSA-87: ~7,322 bytes (allow reasonable variance)
                    assert!(
                        (7100..=7600).contains(&size),
                        "ML-DSA-87 message size {} should be ~7,322 bytes (7100-7600 range)",
                        size
                    );
                }
                _ => panic!("Unknown key type: {}", key_type),
            }
        }
    }

    #[test]
    fn test_ed25519_minimum_size_precise() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_ed25519(&mut rng);
        let msg_full = create_minimal_message(&keypair);
        let serialized = postcard::to_stdvec(&MessageFullWire::from(msg_full)).unwrap();
        let size = serialized.len();

        // Ed25519 should be the smallest - around 120 bytes
        assert!(
            (100..=150).contains(&size),
            "Ed25519 minimum message size {} should be approximately 120 bytes",
            size
        );

        println!("Ed25519 precise minimum size: {} bytes", size);
    }

    #[test]
    fn test_mldsa44_minimum_size_precise() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_ml_dsa44(&mut rng);
        let msg_full = create_minimal_message(&keypair);
        let serialized = postcard::to_stdvec(&MessageFullWire::from(msg_full)).unwrap();
        let size = serialized.len();

        // ML-DSA-44 should be around 3,832 bytes
        assert!(
            (3700..=4000).contains(&size),
            "ML-DSA-44 minimum message size {} should be approximately 3,832 bytes",
            size
        );

        println!("ML-DSA-44 precise minimum size: {} bytes", size);
    }

    #[test]
    fn test_mldsa65_minimum_size_precise() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_ml_dsa65(&mut rng);
        let msg_full = create_minimal_message(&keypair);
        let serialized = postcard::to_stdvec(&MessageFullWire::from(msg_full)).unwrap();
        let size = serialized.len();

        // ML-DSA-65 should be around 5,362 bytes
        assert!(
            (5200..=5600).contains(&size),
            "ML-DSA-65 minimum message size {} should be approximately 5,362 bytes",
            size
        );

        println!("ML-DSA-65 precise minimum size: {} bytes", size);
    }

    #[test]
    fn test_mldsa87_minimum_size_precise() {
        let mut rng = OsRng;
        let keypair = KeyPair::generate_ml_dsa87(&mut rng);
        let msg_full = create_minimal_message(&keypair);
        let serialized = postcard::to_stdvec(&MessageFullWire::from(msg_full)).unwrap();
        let size = serialized.len();

        // ML-DSA-87 should be around 7,322 bytes
        assert!(
            (7100..=7600).contains(&size),
            "ML-DSA-87 minimum message size {} should be approximately 7,322 bytes",
            size
        );

        println!("ML-DSA-87 precise minimum size: {} bytes", size);
    }

    #[test]
    fn test_size_comparison_ratios() {
        let keypairs = create_keypairs_by_type();
        let mut sizes = std::collections::BTreeMap::new();

        for (key_type, keypair) in keypairs {
            let msg_full = create_minimal_message(&keypair);
            let serialized = postcard::to_stdvec(&MessageFullWire::from(msg_full)).unwrap();
            sizes.insert(key_type, serialized.len());
        }

        let ed25519_size = sizes["Ed25519"] as f64;

        // Test size ratios relative to Ed25519
        let mldsa44_ratio = sizes["MlDsa44"] as f64 / ed25519_size;
        let mldsa65_ratio = sizes["MlDsa65"] as f64 / ed25519_size;
        let mldsa87_ratio = sizes["MlDsa87"] as f64 / ed25519_size;

        println!("Size ratios relative to Ed25519:");
        println!("  Ed25519: {} bytes (1.0x)", sizes["Ed25519"]);
        println!(
            "  ML-DSA-44: {} bytes ({:.1}x)",
            sizes["MlDsa44"], mldsa44_ratio
        );
        println!(
            "  ML-DSA-65: {} bytes ({:.1}x)",
            sizes["MlDsa65"], mldsa65_ratio
        );
        println!(
            "  ML-DSA-87: {} bytes ({:.1}x)",
            sizes["MlDsa87"], mldsa87_ratio
        );

        // Assert expected ratios (ML-DSA should be significantly larger)
        assert!(
            (25.0..=40.0).contains(&mldsa44_ratio),
            "ML-DSA-44 should be 25-40x larger than Ed25519, got {:.1}x",
            mldsa44_ratio
        );
        assert!(
            (35.0..=55.0).contains(&mldsa65_ratio),
            "ML-DSA-65 should be 35-55x larger than Ed25519, got {:.1}x",
            mldsa65_ratio
        );
        assert!(
            (50.0..=75.0).contains(&mldsa87_ratio),
            "ML-DSA-87 should be 50-75x larger than Ed25519, got {:.1}x",
            mldsa87_ratio
        );
    }

    #[test]
    fn test_component_sizes_breakdown() {
        let mut rng = OsRng;

        // Test each key type and break down the component sizes
        let test_cases = vec![
            ("Ed25519", KeyPair::generate_ed25519(&mut rng)),
            ("MlDsa44", KeyPair::generate_ml_dsa44(&mut rng)),
            ("MlDsa65", KeyPair::generate_ml_dsa65(&mut rng)),
            ("MlDsa87", KeyPair::generate_ml_dsa87(&mut rng)),
        ];

        for (key_type, keypair) in test_cases {
            let public_key = keypair.public_key();

            // Serialize individual components
            let verifying_key_size = postcard::to_stdvec(&public_key).unwrap().len();

            // Create a minimal signature
            let test_data = b"test message";
            let signature = keypair.sign(test_data);
            let signature_size = postcard::to_stdvec(&signature).unwrap().len();

            // Create full message and measure
            let msg_full = create_minimal_message(&keypair);
            let total_size = postcard::to_stdvec(&MessageFullWire::from(msg_full))
                .unwrap()
                .len();

            println!("{} component breakdown:", key_type);
            println!("  VerifyingKey: {} bytes", verifying_key_size);
            println!("  Signature: {} bytes", signature_size);
            println!("  Total message: {} bytes", total_size);
            println!(
                "  Overhead: {} bytes",
                total_size - verifying_key_size - signature_size
            );
            println!();

            // Verify that the key and signature are the dominant components
            let key_and_sig_size = verifying_key_size + signature_size;
            let overhead = total_size - key_and_sig_size;

            // Overhead should be reasonable (< 100 bytes for fixed fields + postcard encoding)
            assert!(
                overhead < 100,
                "{} overhead {} bytes should be less than 100 bytes",
                key_type,
                overhead
            );

            // Key and signature should account for most of the message size
            let key_sig_ratio = key_and_sig_size as f64 / total_size as f64;
            assert!(
                key_sig_ratio >= 0.85,
                "{} key+signature should be at least 85% of total size, got {:.1}%",
                key_type,
                key_sig_ratio * 100.0
            );
        }
    }
}
