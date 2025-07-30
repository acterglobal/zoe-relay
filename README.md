# Zoe - Secure Messaging Relay System

A secure, modular messaging relay system built with QUIC transport, tarpc RPC services, and ed25519 cryptography.

## 🚀 Quick Start

### Prerequisites
- **Rust 1.75+** with Cargo
- **Docker** for Redis backend
- **Linux/macOS** (Windows via WSL)

### 1. Start Redis
```bash
docker-compose up -d redis
```

### 2. Run the Examples
```bash
# Start the relay server
cargo run --example relay_server

# In another terminal, send a message (replace <SERVER_PUBLIC_KEY> with key from server output)
cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --message "Hello, Zoeyr!"

# In a third terminal, listen for messages
cargo run --example relay_listen_client -- \
  --authors <SERVER_PUBLIC_KEY> \
  --follow
```

## 📦 What's Included

### Core Components
- **`zoe-wire-protocol`** - Protocol definitions, cryptographic utilities, and tarpc service interfaces
- **`zoe-message-store`** - Message storage, handling, streaming, and RelayService tarpc implementation
- **`zoe-relay`** - QUIC connector providing unified transport for multiple tarpc services
- **`zoe-blob-store`** - Binary data storage with both HTTP and tarpc interfaces
- **`zoe-whatsmeow`** - WhatsApp bridge integration

### Security Features
- **QUIC+tarpc architecture**: Unified RPC services over QUIC transport
- **Ed25519 cryptography** for identity verification via QUIC mutual TLS
- **Server identity verification** via ed25519-embedded TLS certificates
- **No session management** - QUIC certificates provide all authentication

### Working Examples
- **Relay Server** - Message relay with Redis backend over QUIC+tarpc
- **Send Client** - Create and send signed messages via tarpc
- **Listen Client** - Real-time message streaming with filtering

## 🔗 Architecture

```
Client Apps → QUIC Transport → Relay Connector → Multiple Services
     ↓              ↓               ↓              ↓
   tarpc          ed25519        Service         Message Store
  Clients        Mutual TLS      Routing        (Redis Backend)
                                    ↓
                                Blob Store
                               (Iroh Backend)
```

**Key Features:**
- **Unified QUIC stack**: Both message and blob services over same authenticated connection
- **tarpc RPC services**: Clean service interfaces with automatic serialization
- **Service routing**: Relay crate routes different services over QUIC streams
- **Clean separation**: Business logic isolated from transport concerns

## 🛠️ Development

### Build & Test
```bash
# Build all components
cargo build --workspace

# Run tests
cargo test --workspace

# Run specific examples
cargo run --example relay_server --package zoe-relay
cargo run --example upload_download --package zoe-blob-store
```

### Docker Environment
```bash
# Start full development environment
docker-compose up -d

# Check Redis
docker exec zoe-redis redis-cli ping

# Access Redis Commander (web UI)
open http://localhost:8081
```

## 📋 Project Status

### ✅ Working
- **Message Store** - Complete message storage with Redis backend and tarpc service
- **Relay Connector** - QUIC+tarpc routing for multiple services
- **Wire Protocol** - Service definitions and cryptography
- **Blob Storage** - Binary data handling with HTTP and tarpc interfaces
- **WhatsApp Bridge** - Integration with WhatsApp

### 🚧 In Progress
- Integration of blob service through relay QUIC stack
- Comprehensive integration testing
- Production deployment configurations

## 📚 Documentation

- **[Development Guide](docs/development.md)** - Setup, workflow, troubleshooting
- **[Architecture Overview](docs/architecture.md)** - Technical deep dive
- **[Relay Examples](crates/relay/examples/README.md)** - Complete usage guide
- **[Message Store](crates/message-store/)** - Storage and streaming documentation

## 🔐 Security Model

### Transport Security
- **QUIC/TLS 1.3** with ed25519-derived certificates
- **Mutual TLS authentication** via ed25519 public keys embedded in certificates
- **Server identity verification** via certificate inspection
- **Connection migration** for mobile networks

### Message Security
- **Ed25519 signatures** on all messages
- **Blake3 message IDs** for integrity
- **Client-side message creation** with proper signing

## 📈 Performance

- **QUIC multiplexing** for concurrent RPC operations
- **tarpc RPC efficiency** with postcard serialization
- **Redis Streams** for real-time distribution
- **Connection pooling** and reuse
- **Service routing** over single QUIC connection

## 🎯 Use Cases

### Messaging Applications
- Secure chat applications with tarpc RPC interface
- Real-time notifications over QUIC
- Multi-device synchronization

### Integration Hub
- WhatsApp message bridging
- Cross-platform messaging
- Protocol translation

### Development Platform
- QUIC+tarpc service foundation
- Cryptographic messaging examples
- Multi-service integration patterns

## 🏗️ Crate Structure

- **`message-store`**: Pure message logic (storage, tarpc service, Redis backend)
- **`relay`**: QUIC connector with reusable server/client utilities
- **`blob-store`**: Blob storage with both HTTP and tarpc interfaces
- **`wire-protocol`**: Service definitions for RelayService and BlobService

## 🤝 Contributing

1. **Setup Development Environment**
   ```bash
   git clone <repository>
   cd zoeyr
   cargo build --workspace
   docker-compose up -d redis
   ```

2. **Run Tests**
   ```bash
   cargo test --workspace
   ```

3. **Try Examples**
   ```bash
   # Follow the Quick Start guide above
   ```

## 📄 License

This project is licensed under MIT OR Apache-2.0.

---

**Getting Started**: Follow the [Quick Start](#-quick-start) guide above, then explore the [examples](crates/relay/examples/) and [documentation](docs/).

**Questions?** Check the [development guide](docs/development.md) or review the [architecture overview](docs/architecture.md).