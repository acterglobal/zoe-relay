# Zoe Wire Protocol

The wire protocol crate provides core message definitions, post-quantum cryptographic utilities, tarpc service interfaces, and authentication types for the Zoe messaging system.

## Features

- **Message Protocol**: Serializable message types with support for generic content
- **tarpc Service Interfaces**: RelayService and BlobService definitions for RPC communication
- **Cryptographic Utilities**: ML-DSA key management and deterministic TLS certificate generation
- **Authentication System**: Dynamic challenge-response authentication with session management
- **Protocol Types**: Core protocol definitions for relay communication

## Quick Start

```rust
use zoe_wire_protocol::{
    MessageFull, Message, MessageContent, Kind, Tag,
    generate_keypair, generate_deterministic_cert_from_ml_dsa_44_for_tls
};
use rand::rngs::OsRng;

// Create a signing key (ML-DSA-65 for messages)
let signing_key = generate_keypair(&mut OsRng);

// Create message content
let content = MessageContent::Text { 
    text: "Hello, Zoeyr!".to_string() 
};

// Create a message
let message = Message::new_v0(
    content,
    signing_key.verifying_key(),
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs(),
    Kind::Regular,
    vec![], // tags
);

// Create full message with signature
let message_full = MessageFull::new(message, &signing_key)?;

// Verify the message
assert!(message_full.verify()?);
```

## tarpc Service Interfaces

### RelayService

Provides messaging operations over RPC:

```rust
use zoe_wire_protocol::{RelayService, RelayServiceClient};

// Service methods available:
// - get_message(id: Vec<u8>) -> RelayResult<Option<Vec<u8>>>
// - store_message(data: Vec<u8>) -> RelayResult<String>
// - start_message_stream(filters: MessageFilters) -> RelayResult<String>
```

### BlobService

Provides blob storage operations over RPC:

```rust
use zoe_wire_protocol::{BlobService, BlobServiceClient};

// Service methods available:
// - health_check() -> BlobResult<BlobHealth>
// - upload_blob(data: Vec<u8>) -> BlobResult<String>
// - download_blob(hash: String) -> BlobResult<Vec<u8>>
// - get_blob_info(hash: String) -> BlobResult<BlobInfo>
```

### Service Client Usage

```rust
// RelayService client (connected via QUIC+tarpc)
let relay_client: RelayServiceClient = /* connected via relay crate */;

// Store a message
let message_data = postcard::to_allocvec(&message_full)?;
let message_id = relay_client.store_message(message_data).await??;

// BlobService client
let blob_client: BlobServiceClient = /* connected via relay crate */;

// Upload a blob
let blob_data = b"Hello, blob world!".to_vec();
let blob_hash = blob_client.upload_blob(blob_data).await??;
```

## Message Types

### Core Message Structure

Messages in Zoe follow this structure:

```rust
pub struct MessageFull<T> {
    pub id: Hash,           // Blake3 hash of message + signature
    pub message: Message<T>, // The actual message content
    pub signature: Signature, // ML-DSA-65 signature (~3309 bytes)
}
```

### Cryptographic Specifications

**ML-DSA Algorithm Details:**
- **ML-DSA-65**: Used for message signatures (security level 3, ~192-bit security)
  - Public key size: 1952 bytes
  - Signature size: ~3309 bytes
  - Algorithm OID: `2.16.840.1.101.3.4.3.18`
- **ML-DSA-44**: Used for TLS certificates (security level 2, ~128-bit security)
  - Public key size: 1312 bytes  
  - Signature size: ~2420 bytes
  - Algorithm OID: `2.16.840.1.101.3.4.3.17`

**Post-Quantum Security:**
ML-DSA (Module Lattice-based Digital Signature Algorithm) is standardized in FIPS 204 and provides security against both classical and quantum computer attacks.

**Ed25519 Compatibility:**
Ed25519 is still used in specific contexts for compatibility:
- Legacy relay operations and some internal systems
- Compatibility with existing Ed25519-based identity systems
- The codebase is in transition from Ed25519 to ML-DSA

### Content Types for T

The protocol supports custom content types, as long as they are serializable and deserializable with postcard encoding.

### Message Kinds

- `Kind::Regular` - Standard persistent messages
- `Kind::Emphemeral(Option<u8>)` - Temporary messages with optional timeout
- `Kind::Store(StoreKey)` - Messages for specific storage
- `Kind::ClearStore(StoreKey)` - Storage clearing commands

### Tags

Messages can be tagged for organization and filtering:

- `Tag::Event { id: Hash, relays: Vec<String> }` - Event references
- `Tag::User { id: Vec<u8>, relays: Vec<String> }` - User references  
- `Tag::Channel { id: Vec<u8>, relays: Vec<String> }` - Channel references
- `Tag::Protected` - Messages that are only accepted if the author is the same as the connection holder. Relays must reject the message if that is not the case and will not
store it

## Cryptographic Features

### ML-DSA Key Management

```rust
use zoe_wire_protocol::{
    generate_keypair, generate_ml_dsa_44_keypair_for_tls,
    load_ml_dsa_public_key_from_hex,
    save_ml_dsa_public_key_to_hex,
    load_ml_dsa_44_key_from_hex_for_tls,
    save_ml_dsa_44_key_to_hex_for_tls,
};
use rand::rngs::OsRng;

// Generate new keypair (ML-DSA-65 for messages)
let key = generate_keypair(&mut OsRng);
let public_key = key.verifying_key();

// Generate TLS keypair (ML-DSA-44 for certificates)
let tls_key = generate_ml_dsa_44_keypair_for_tls();

// Serialize keys to hex
let hex_tls_private_key = save_ml_dsa_44_key_to_hex_for_tls(&tls_key.signing_key());
let hex_public_key = save_ml_dsa_public_key_to_hex(&public_key);

// Load keys from hex
let loaded_tls_private_key = load_ml_dsa_44_key_from_hex_for_tls(&hex_tls_private_key)?;
let loaded_public_key = load_ml_dsa_public_key_from_hex(&hex_public_key)?;
```

### Deterministic TLS Certificates

Generate TLS certificates that embed ML-DSA-44 public keys:

```rust
use zoe_wire_protocol::{
    generate_deterministic_cert_from_ml_dsa_44_for_tls,
    extract_public_key_from_cert,
    generate_ml_dsa_44_keypair_for_tls,
};

let ml_dsa_key = generate_ml_dsa_44_keypair_for_tls();

// Generate TLS certificate embedding the ML-DSA-44 key
let certs = generate_deterministic_cert_from_ml_dsa_44_for_tls(
    &ml_dsa_key, 
    "example.com"
)?;

// Extract ML-DSA-44 key from certificate
let extracted_key = extract_public_key_from_cert(&certs[0])?;
assert_eq!(extracted_key.encode(), ml_dsa_key.verifying_key().encode());
```

## Authentication System

### Dynamic Sessions

The protocol supports dynamic challenge-response authentication:

```rust
use zoe_wire_protocol::{DynamicSession, SessionManager, generate_keypair};
use rand::rngs::OsRng;
use signature::Signer;

let client_key = generate_keypair(&mut OsRng);
let session_manager = SessionManager::new();

// Create session
session_manager.create_session("session_id".to_string(), client_key.verifying_key().clone())?;

// Issue challenge
let challenge = session_manager.with_session("session_id", |session| {
    Ok(session.issue_challenge(30)) // 30 second timeout
})?;

// Verify response (in real use, client would sign the challenge)
let signature = client_key.signing_key().sign(format!("auth:{}:{}", challenge.nonce, challenge.timestamp).as_bytes());

let is_valid = session_manager.with_session("session_id", |session| {
    session.verify_challenge_response(
        &challenge.nonce,
        challenge.timestamp,
        &signature.to_bytes(),
        30 // timeout
    )
})?;

assert!(is_valid);
```

## Protocol Messages

The wire protocol defines a comprehensive set of message types for relay communication:

```rust
use zoe_wire_protocol::ProtocolMessage;

// Authentication flow
let auth_challenge = ProtocolMessage::AuthChallenge {
    nonce: "random-nonce".to_string(),
    timestamp: 1234567890,
};

// Message operations
let message = ProtocolMessage::Message {
    content: MessageContent::Text { text: "Hello".to_string() },
    session_token: Some("session-token".to_string()),
};

// Health checks
let health_check = ProtocolMessage::HealthCheck;
```

## Testing

The crate includes comprehensive test coverage:

```bash
# Run all tests
cargo test -p zoe-wire-protocol

# Run crypto tests
cargo test -p zoe-wire-protocol crypto::tests

# Run protocol tests  
cargo test -p zoe-wire-protocol tests::unit_protocol
```

## Features Flags

- `client` - Client-side functionality
- `server` - Server-side functionality  
- `pkcs8` - PKCS8 key format support (enabled by default)

## Dependencies

Key dependencies include:
- `ml-dsa` - ML-DSA post-quantum cryptography
- `ed25519-dalek` - Ed25519 cryptography (compatibility)
- `blake3` - Fast cryptographic hashing
- `serde` - Serialization framework
- `postcard` - Compact binary serialization
- `rustls` & `rcgen` - TLS certificate generation
- `x509-parser` - Certificate parsing

## Security Considerations

- All messages are cryptographically signed with ML-DSA-65 (post-quantum secure)
- Message IDs are Blake3 hashes preventing tampering
- TLS certificates embed ML-DSA-44 keys for identity verification
- Challenge-response authentication prevents replay attacks
- Sessions have configurable timeout and freshness requirements
- Post-quantum cryptography provides protection against quantum computer attacks

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option. 