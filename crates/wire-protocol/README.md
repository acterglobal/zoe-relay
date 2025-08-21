# Zoe Wire Protocol

The wire protocol crate provides the core messaging infrastructure for the Zoe distributed messaging system. It defines message formats, cryptographic primitives, transport security, and RPC service interfaces.

## Features

- **Versioned Message Protocol**: Forward-compatible message types with multiple encryption schemes
- **Hybrid Cryptography**: Support for both Ed25519 (legacy) and ML-DSA (post-quantum) signatures
- **Multiple Content Types**: Raw, ChaCha20-Poly1305, self-encrypted, and ephemeral ECDH encryption
- **Transport Security**: TLS certificate generation with embedded identity keys
- **RPC Services**: MessageService and BlobService for relay communication
- **Streaming Protocol**: Real-time message subscriptions and filtering
- **Challenge-Response Authentication**: Dynamic session management with configurable timeouts

## Quick Start

```rust
use zoe_wire_protocol::{
    MessageFull, Message, MessageV0, MessageV0Header, Content, Kind, Tag,
    KeyPair, VerifyingKey, SigningKey
};

// Create a keypair (supports Ed25519, ML-DSA-44, ML-DSA-65, ML-DSA-87)
let keypair = KeyPair::generate_ml_dsa_65();
let signing_key = keypair.signing_key();
let verifying_key = keypair.verifying_key();

// Create message content (multiple encryption options available)
let content = Content::raw(b"Hello, Zoeyr!".to_vec());

// Create message header
let header = MessageV0Header {
    sender: verifying_key.clone(),
    when: std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs(),
    kind: Kind::Regular,
    tags: vec![], // Optional: Tag::Event, Tag::User, Tag::Channel, Tag::Protected
};

// Create versioned message
let message = Message::V0(MessageV0 { header, content });

// Create full message with signature
let message_full = MessageFull::new(message, &signing_key)?;

// Verify the message
assert!(message_full.verify()?);

// Access message properties
println!("Message ID: {}", message_full.id());
println!("Sender: {:?}", message_full.sender());
println!("Timestamp: {}", message_full.when());
```

## RPC Service Interfaces

The wire protocol defines two main services for relay communication over QUIC+tarpc:

### MessageService

Provides messaging operations with real-time streaming support:

```rust
use zoe_wire_protocol::{MessageService, MessageServiceClient};

// Core message operations
async fn publish(message: MessageFull) -> Result<PublishResult, MessageError>;
async fn message(id: Hash) -> Result<Option<MessageFull>, MessageError>;
async fn user_data(
    author: SerializableVerifyingKey,
    storage_key: StoreKey,
) -> Result<Option<MessageFull>, MessageError>;

// Bulk operations for sync
async fn check_messages(message_ids: Vec<Hash>) -> Result<Vec<Option<String>>, MessageError>;

// Real-time subscriptions
async fn subscribe(config: SubscriptionConfig) -> Result<String, MessageError>;
async fn update_filters(
    subscription_id: String,
    request: FilterUpdateRequest,
) -> Result<(), MessageError>;
async fn catch_up(request: CatchUpRequest) -> Result<String, MessageError>;
async fn unsubscribe(subscription_id: String) -> Result<(), MessageError>;
```

### BlobService

Provides blob storage operations:

```rust
use zoe_wire_protocol::{BlobService, BlobServiceClient};

// Service methods available:
async fn health_check() -> BlobResult<BlobHealth>;
async fn upload(data: Vec<u8>) -> BlobResult<String>;
async fn download(hash: String) -> BlobResult<Option<Vec<u8>>>;
async fn get_info(hash: String) -> BlobResult<Option<BlobInfo>>;
async fn check_blobs(hashes: Vec<String>) -> BlobResult<Vec<bool>>;
```

### Service Usage Example

```rust
use zoe_wire_protocol::{MessageServiceClient, BlobServiceClient, SubscriptionConfig};

// Message operations
let message_client: MessageServiceClient = /* connected via relay crate */;

// Publish a message
let result = message_client.publish(message_full).await?;
match result {
    PublishResult::StoredNew { global_stream_id } => {
        println!("Message stored with ID: {}", global_stream_id);
    }
    PublishResult::AlreadyExists { global_stream_id } => {
        println!("Message already exists: {}", global_stream_id);
    }
    PublishResult::Expired => {
        println!("Message was expired and not stored");
    }
}

// Subscribe to messages
let subscription_config = SubscriptionConfig {
    filters: MessageFilters {
        authors: Some(vec![author_key.encode()]),
        channels: Some(vec![channel_id]),
        ..Default::default()
    },
    include_existing: false,
};
let subscription_id = message_client.subscribe(subscription_config).await?;

// Blob operations
let blob_client: BlobServiceClient = /* connected via relay crate */;
let blob_data = b"Hello, blob world!".to_vec();
let blob_hash = blob_client.upload(blob_data).await?;
let retrieved_data = blob_client.download(blob_hash).await?;
```

## Message Types and Wire Format

### Core Message Structure

Messages in Zoe follow a versioned, forward-compatible structure:

```rust
// Complete signed message ready for transmission
pub struct MessageFull {
    id: Hash,                    // Blake3 hash (computed from signature)
    signature: Signature,        // Digital signature (Ed25519 or ML-DSA)
    message: Box<Message>,       // Versioned message content
}

// Versioned message envelope
pub enum Message {
    V0(MessageV0),              // Current version
    // Future versions: V1(MessageV1), etc.
}

// Version 0 message format
pub struct MessageV0 {
    header: MessageV0Header,    // Metadata and routing
    content: Content,           // Payload with encryption options
}

// Message metadata
pub struct MessageV0Header {
    sender: VerifyingKey,       // Author's public key
    when: u64,                  // Unix timestamp
    kind: Kind,                 // Message type and storage behavior
    tags: Vec<Tag>,            // Routing and reference tags
}
```

### Content Types and Encryption

The `Content` enum provides multiple encryption schemes for different use cases:

```rust
pub enum Content {
    // Unencrypted content
    Raw(Vec<u8>),                                    // [discriminant: 0]
    
    // Context-based encryption
    ChaCha20Poly1305(ChaCha20Poly1305Content),      // [discriminant: 20]
    
    // Self-encryption (encrypt-to-self patterns)
    Ed25519SelfEncrypted(Ed25519SelfEncryptedContent),     // [discriminant: 40]
    MlDsaSelfEncrypted(MlDsaSelfEncryptedContent),         // [discriminant: 41]
    
    // Public key encryption
    EphemeralEcdh(EphemeralEcdhContent),            // [discriminant: 80]
    
    // Forward compatibility
    Unknown { discriminant: u32, data: Vec<u8> },
}
```

#### Content Type Use Cases

- **`Raw`**: Public messages, metadata, pre-encrypted data
- **`ChaCha20Poly1305`**: Group/channel encryption with shared keys
- **`Ed25519SelfEncrypted`**: Personal data storage (legacy)
- **`MlDsaSelfEncrypted`**: Personal data storage (post-quantum)
- **`EphemeralEcdh`**: Direct encrypted messaging with perfect forward secrecy

### Message Kinds and Storage Behavior

```rust
pub enum Kind {
    Regular,                    // Persistent storage
    Emphemeral(Option<u8>),    // Temporary storage (optional TTL in seconds)
    Store(StoreKey),           // User-specific storage
    ClearStore(StoreKey),      // Clear user storage
}
```

### Tags and Routing

```rust
pub enum Tag {
    Protected,                 // Relay must verify sender identity
    Event { id: Hash, relays: Vec<String> },      // Reference to another event
    User { id: Vec<u8>, relays: Vec<String> },    // Reference to a user
    Channel { id: Vec<u8>, relays: Vec<String> }, // Reference to a channel
}
```

### Hybrid Key System

The protocol supports multiple signature algorithms for gradual migration:

```rust
pub enum VerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    MlDsa44(ml_dsa::VerifyingKey<ml_dsa::MlDsa44>),    // TLS certificates
    MlDsa65(ml_dsa::VerifyingKey<ml_dsa::MlDsa65>),    // Message signatures
    MlDsa87(ml_dsa::VerifyingKey<ml_dsa::MlDsa87>),    // High security
}

pub enum SigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa44(ml_dsa::SigningKey<ml_dsa::MlDsa44>),
    MlDsa65(ml_dsa::SigningKey<ml_dsa::MlDsa65>),
    MlDsa87(ml_dsa::SigningKey<ml_dsa::MlDsa87>),
}
```

#### Algorithm Specifications

| Algorithm | Use Case | Security Level | Public Key | Signature Size |
|-----------|----------|----------------|------------|----------------|
| **Ed25519** | Legacy compatibility | ~128-bit | 32 bytes | 64 bytes |
| **ML-DSA-44** | TLS certificates | ~128-bit | 1,312 bytes | ~2,420 bytes |
| **ML-DSA-65** | Message signatures | ~192-bit | 1,952 bytes | ~3,309 bytes |
| **ML-DSA-87** | High security | ~256-bit | 2,592 bytes | ~4,627 bytes |

**Post-Quantum Security**: ML-DSA algorithms are standardized in FIPS 204 and provide security against both classical and quantum computer attacks.

## Transport Security and Connection Management

### TLS Certificate Generation

The protocol supports embedding identity keys directly in TLS certificates:

```rust
use zoe_wire_protocol::{
    generate_ed25519_cert_for_tls, generate_ml_dsa_44_cert_for_tls,
    extract_ed25519_public_key_from_cert, extract_ml_dsa_44_public_key_from_cert
};

// Ed25519 certificates (legacy)
let ed25519_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
let certs = generate_ed25519_cert_for_tls(&ed25519_key, "example.com")?;
let extracted_key = extract_ed25519_public_key_from_cert(&certs[0])?;

// ML-DSA-44 certificates (post-quantum, feature-gated)
#[cfg(feature = "tls-ml-dsa-44")]
{
    let ml_dsa_key = ml_dsa::KeyGen::keygen(&mut OsRng);
    let certs = generate_ml_dsa_44_cert_for_tls(&ml_dsa_key, "example.com")?;
    let extracted_key = extract_ml_dsa_44_public_key_from_cert(&certs[0])?;
}
```

### QUIC Transport Configuration

```rust
use zoe_wire_protocol::{create_ed25519_server_config, AcceptSpecificEd25519ServerCertVerifier};

// Server configuration with Ed25519 identity
let server_config = create_ed25519_server_config(server_keypair, "server.example.com")?;

// Client configuration with certificate verification
let cert_verifier = AcceptSpecificEd25519ServerCertVerifier::new(expected_server_key);
```

## Streaming Protocol and Real-Time Messaging

### Message Subscriptions

The streaming protocol provides real-time message delivery with filtering:

```rust
use zoe_wire_protocol::{
    MessageFilters, SubscriptionConfig, FilterUpdateRequest, CatchUpRequest
};

// Create subscription with filters
let filters = MessageFilters {
    authors: Some(vec![author_key.encode()]),
    channels: Some(vec![channel_id.to_vec()]),
    events: None,
    users: None,
};

let subscription_config = SubscriptionConfig {
    filters,
    include_existing: false,  // Only new messages
};

// Subscribe to filtered message stream
let subscription_id = message_client.subscribe(subscription_config).await?;

// Update filters dynamically
let update_request = FilterUpdateRequest {
    subscription_id: subscription_id.clone(),
    operation: FilterOperation::add_channels(vec![new_channel_id.to_vec()]),
};
message_client.update_filters(subscription_id.clone(), update_request).await?;

// Catch up on missed messages
let catch_up_request = CatchUpRequest {
    subscription_id: subscription_id.clone(),
    since_stream_id: Some(last_known_stream_id),
    limit: Some(100),
};
let catch_up_id = message_client.catch_up(catch_up_request).await?;
```

### Filter Operations

```rust
use zoe_wire_protocol::FilterOperation;

// Add values to filters
FilterOperation::add_channels(vec![channel_id]);
FilterOperation::add_authors(vec![author_key]);

// Remove values from filters  
FilterOperation::remove_channels(vec![old_channel_id]);

// Replace entire filter field
FilterOperation::replace_authors(vec![new_author_key]);

// Clear a filter field
FilterOperation::Clear { field: FilterField::Channel };

// Replace entire filter set (forces restart)
FilterOperation::ReplaceAll(new_filters);
```

## Authentication System

### Challenge-Response Authentication

The protocol implements dynamic challenge-response authentication for secure session management:

```rust
use zoe_wire_protocol::{
    DynamicSession, SessionManager, AuthChallenge, AuthChallengeResponse
};

// Server-side session management
let session_manager = SessionManager::new();

// Create session for client
let client_public_key = /* client's verifying key */;
session_manager.create_session("session_id".to_string(), client_public_key)?;

// Issue challenge to client
let challenge = session_manager.with_session("session_id", |session| {
    Ok(session.issue_challenge(30)) // 30 second timeout
})?;

// Client signs the challenge
let challenge_message = format!("auth:{}:{}", challenge.nonce, challenge.timestamp);
let signature = client_signing_key.sign(challenge_message.as_bytes());

// Server verifies the response
let is_valid = session_manager.with_session("session_id", |session| {
    session.verify_challenge_response(
        &challenge.nonce,
        challenge.timestamp,
        &signature,
        30 // timeout in seconds
    )
})?;

if is_valid {
    println!("Client authenticated successfully");
}
```

### Session Management

```rust
// Session configuration
pub struct DynamicSession {
    pub client_key: VerifyingKey,
    pub created_at: u64,
    pub last_challenge: Option<AuthChallenge>,
}

// Challenge structure
pub struct AuthChallenge {
    pub nonce: String,
    pub timestamp: u64,
}
```

## Serialization and Wire Format

### Postcard Binary Serialization

All data structures use [postcard](https://docs.rs/postcard/) for efficient binary serialization:

```rust
use zoe_wire_protocol::{MessageFull, PostcardFormat};

// Serialize message for transmission
let message_bytes = postcard::to_stdvec(&message_full)?;

// Deserialize received message
let received_message: MessageFull = postcard::from_bytes(&message_bytes)?;

// Use with tarpc transport
let format = PostcardFormat::default();
// PostcardFormat implements both Serializer and Deserializer for tarpc
```

### Service Identification

Services are identified by numeric IDs for efficient routing:

```rust
use zoe_wire_protocol::ZoeServices;

// Service routing
match service_id {
    ZoeServices::Messages => { /* route to message service */ },
    ZoeServices::Blob => { /* route to blob service */ },
}
```

## Implementation Guide for Alternative Clients

### Message Creation Workflow

1. **Create Content**: Choose appropriate encryption scheme
2. **Build Header**: Set sender, timestamp, kind, and tags  
3. **Construct Message**: Wrap in versioned envelope
4. **Sign Message**: Create MessageFull with signature
5. **Serialize**: Use postcard for wire transmission

### Connection Establishment

1. **Generate Identity**: Create Ed25519 or ML-DSA keypair
2. **Create Certificate**: Embed public key in TLS certificate
3. **Establish QUIC**: Connect with certificate-based identity
4. **Send Service ID**: First byte indicates desired service (10=Messages, 11=Blob)
5. **Authenticate**: Complete challenge-response if required

### Message Processing

1. **Deserialize**: Use postcard to decode MessageFull
2. **Verify Signature**: Check against sender's public key
3. **Validate Timestamp**: Ensure message is not too old/future
4. **Process Tags**: Handle routing and references
5. **Decrypt Content**: If encrypted, use appropriate decryption method

## Testing and Development

```bash
# Run all tests
cargo nextest run -p zoe-wire-protocol

# Run with specific features
cargo test -p zoe-wire-protocol --features tls-ml-dsa-44

# Check documentation examples
cargo test -p zoe-wire-protocol --doc
```

## Feature Flags

- `tls-ml-dsa-44` - Enable ML-DSA-44 TLS certificate support (experimental)
- `client` - Client-side functionality (deprecated, always enabled)
- `server` - Server-side functionality (deprecated, always enabled)

## Dependencies and Architecture

### Core Dependencies
- **`ml-dsa`** - Post-quantum digital signatures (FIPS 204)
- **`ed25519-dalek`** - Legacy Ed25519 signatures
- **`blake3`** - Fast cryptographic hashing for message IDs
- **`postcard`** - Compact binary serialization
- **`serde`** - Serialization framework
- **`tarpc`** - RPC framework for service communication

### Transport Layer
- **`quinn`** - QUIC transport implementation
- **`rustls`** - TLS 1.3 with post-quantum cipher suites
- **`rcgen`** - X.509 certificate generation
- **`x509-parser`** - Certificate parsing and validation

### Cryptographic Primitives
- **`chacha20poly1305`** - AEAD encryption for content
- **`x25519-dalek`** - Elliptic curve Diffie-Hellman
- **`argon2`** - Key derivation for mnemonic-based keys
- **`bip39`** - Mnemonic phrase generation and validation

## Security Model

### Threat Model
- **Confidentiality**: Content encryption protects message privacy
- **Authenticity**: Digital signatures ensure message integrity
- **Non-repudiation**: Cryptographic signatures prevent denial
- **Forward Secrecy**: Ephemeral keys protect past communications
- **Post-Quantum Security**: ML-DSA protects against quantum attacks

### Security Properties
- Message IDs are collision-resistant Blake3 hashes
- Signatures use post-quantum secure ML-DSA algorithms
- TLS transport provides confidentiality and server authentication
- Challenge-response prevents replay and impersonation attacks
- Content encryption supports multiple threat models

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option. 