# Architecture Overview

## 🏗️ System Architecture

Zoeyr is a secure messaging relay system built with a modular, multi-crate architecture. The system provides dual-layer security with QUIC transport and ed25519 cryptography.

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        Zoeyr Architecture                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Client Apps   │  │   Client Apps   │  │   Client Apps   │  │
│  │   (Examples)    │  │   (WhatsApp)    │  │   (Custom)      │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│           │                     │                     │          │
│           └─────────────────────┼─────────────────────┘          │
│                                 │                                │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              QUIC/TLS Transport Layer                       │  │
│  │         (Quinn + Ed25519 Identity Verification)            │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                 │                                │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                Relay Service Layer                          │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │  │
│  │  │ Connection Mgmt │  │ Message Routing │  │ Auth Service│  │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                 │                                │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                   Storage Layer                             │  │
│  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  │  │
│  │  │ Redis Streams   │  │ Message Store   │  │ Blob Store  │  │  │
│  │  └─────────────────┘  └─────────────────┘  └─────────────┘  │  │
│  └─────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 📦 Crate Structure

### Core Protocol Crates

#### `zoeyr-wire-protocol`
**Purpose**: Protocol definitions and cryptographic utilities

**Key Components**:
- `ProtocolMessage<T>` - Generic protocol message envelope
- `MessageFull<T>` - Signed wire protocol messages
- Ed25519 cryptography and certificate generation
- JSON/PostCard serialization support

**Key Types**:
```rust
pub enum ProtocolMessage<T> {
    MessageFull { message: MessageFull<T> },
    HealthCheck,
    HealthResponse { status: String, timestamp: u64 },
    Error { message: String },
    // ... authentication flows
}

pub struct MessageFull<T> {
    pub id: Blake3Hash,
    pub message: Message<T>,
    pub signature: Ed25519Signature,
}
```

#### `zoeyr-relay-service`
**Purpose**: Redis-backed message relay service

**Key Components**:
- QUIC connection utilities with ed25519 identity verification
- Redis storage backend with streaming support
- Message filtering and routing
- Working examples (server, send client, listen client)

**Key Features**:
- Shared connection utilities (`RelayClient`, `create_relay_server_endpoint`)
- Redis Streams for real-time message distribution
- Message filtering by author, user, channel
- JSON serialization over QUIC transport

### Integration Crates

#### `zoeyr-whatsmeow`
**Purpose**: WhatsApp bridge integration

**Key Components**:
- Go-based WhatsApp client integration
- Multi-device WhatsApp protocol support
- QR code authentication
- Message bridging to Zoeyr protocol

#### `zoeyr-blob-store`
**Purpose**: Binary data storage service

**Key Components**:
- Content-addressable storage
- Brotli compression
- Upload/download examples
- Integration with main relay service

## 🔐 Security Architecture

### Dual-Layer Security Model

**Layer 1: Transport Security**
- QUIC/TLS 1.3 transport encryption
- Ed25519-derived TLS certificates
- Server identity verification via certificate inspection
- Connection migration and 0-RTT support

**Layer 2: Message Security**
- Ed25519 message signing by clients
- Blake3 message IDs for integrity
- Optional challenge-response authentication
- Message replay protection

### Key Management

```rust
// Ed25519 key generation
let signing_key = generate_ed25519_keypair();
let verifying_key = signing_key.verifying_key();

// TLS certificate generation from ed25519 key
let (cert_chain, private_key) = generate_deterministic_cert_from_ed25519(
    &signing_key, 
    "localhost"
)?;

// Message signing
let message_full = MessageFull::new(message, &signing_key)?;
```

### Identity Verification

```rust
// Custom TLS verifier
impl ServerCertVerifier for ServerEd25519TlsVerifier {
    fn verify_server_cert(&self, end_entity: &Certificate, ...) -> Result<...> {
        let embedded_key = extract_ed25519_from_cert(end_entity)?;
        if embedded_key == self.expected_key {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate)
        }
    }
}
```

## 💾 Storage Architecture

### Redis Integration

**Redis Streams**: Real-time message distribution
```redis
XADD message_stream * message_id <id> content <json>
XREAD BLOCK 1000 STREAMS message_stream $
```

**Key-Value Storage**: Message persistence
```redis
SET message:<blake3_hash> <postcard_serialized_message>
GET message:<blake3_hash>
```

**Indexing**: Fast message lookup
```redis
SADD author:<pub_key> message:<id>
SADD channel:<id> message:<id>
```

### Message Lifecycle

1. **Client Creates Message**
   ```rust
   let message = Message::new_v0(content, author, timestamp, Kind::Regular, tags);
   let signed_message = MessageFull::new(message, &signing_key)?;
   ```

2. **Transport to Server**
   ```rust
   let protocol_msg = ProtocolMessage::MessageFull { message: signed_message };
   let response = client.send_json(&protocol_msg).await?;
   ```

3. **Server Storage**
   ```rust
   storage.store_message(&message_full).await?;
   ```

4. **Redis Distribution**
   ```rust
   // Add to stream for real-time distribution
   redis.xadd("message_stream", &[("message_id", &id), ("content", &json)]).await?;
   ```

5. **Client Retrieval**
   ```rust
   let stream = storage.listen_for_messages(&filters, since, limit).await?;
   ```

## 🔄 Message Flow

### Send Flow
```
Client → MessageFull Creation → QUIC/TLS → Server → Redis Storage → Redis Stream
```

### Receive Flow  
```
Redis Stream → Listen Client → Message Filtering → Message Display
```

### Architecture Patterns

**Generic Protocol Design**:
- `ProtocolMessage<T>` allows different content types
- Supports text, binary, custom structured data
- Extensible for future message types

**Connection Sharing**:
- `RelayClient` provides shared QUIC connection utilities
- `create_relay_server_endpoint` standardizes server setup
- Eliminates code duplication between examples

**Serialization Strategy**:
- JSON for `ProtocolMessage` (compatible with serde tagging)
- PostCard for `MessageFull` (efficient binary serialization)
- Documented compatibility issues and solutions

## 🚀 Performance Characteristics

### QUIC Benefits
- **Multiplexed streams**: Multiple concurrent message flows
- **Connection migration**: Seamless network switching
- **0-RTT resumption**: Instant reconnection
- **Built-in encryption**: No additional TLS overhead

### Redis Performance
- **Streaming**: Real-time message distribution
- **Pipelining**: Batch operations for efficiency
- **Memory optimization**: LRU eviction policies
- **Persistence**: AOF for durability

### Crypto Performance
- **Ed25519**: Fast signature generation/verification
- **Blake3**: High-performance message hashing
- **Deterministic certificates**: Predictable key derivation

## 🎯 Design Principles

### Modularity
- Clear separation of concerns between crates
- Minimal interdependencies
- Pluggable components (storage, transport, crypto)

### Security-First
- Cryptographic identity verification
- Message integrity guarantees
- Transport encryption by default
- Defense against replay attacks

### Performance-Oriented
- Efficient serialization formats
- Streaming message distribution
- Connection pooling and reuse
- Minimal memory allocations

### Developer Experience
- Working examples for all components
- Comprehensive documentation
- Clear error messages
- Extensive testing framework

## 🔮 Future Architecture

### Federation Support
- Multi-relay server connectivity
- Cross-server message routing
- Distributed identity verification
- Load balancing and failover

### Mobile Optimization
- Battery-efficient protocols
- Bandwidth-conscious designs
- Offline message queuing
- Push notification integration

### Scale Considerations
- Horizontal scaling patterns
- Database sharding strategies
- Caching layer integration
- Monitoring and observability 