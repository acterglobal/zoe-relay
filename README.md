# Zoeyr - Secure Messaging Relay System

A secure, modular messaging relay system built with QUIC transport and ed25519 cryptography.

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
- **`zoeyr-wire-protocol`** - Protocol definitions and cryptographic utilities
- **`zoeyr-relay-service`** - Redis-backed message relay with working examples
- **`zoeyr-whatsmeow`** - WhatsApp bridge integration
- **`zoeyr-blob-store`** - Binary data storage service

### Security Features
- **Dual-layer security**: TLS transport + message signing
- **Ed25519 cryptography** for identity verification
- **QUIC transport** with connection migration
- **Server identity verification** via TLS certificates

### Working Examples
- **Relay Server** - Message relay with Redis backend
- **Send Client** - Create and send signed messages
- **Listen Client** - Real-time message streaming with filtering

## 🔗 Architecture

```
Client Apps → QUIC/TLS Transport → Relay Service → Redis Storage
     ↓              ↓                    ↓            ↓
Message Creation  Identity Verify   Message Routing  Streaming
```

**Key Features:**
- Messages are created and signed by clients
- Server acts as a relay, forwarding messages to Redis
- Real-time message distribution via Redis Streams
- Comprehensive filtering by author, user, channel

## 🛠️ Development

### Build & Test
```bash
# Build all components
cargo build --workspace

# Run tests
cargo test --workspace

# Run specific examples
cargo run --example relay_server --package zoeyr-relay-service
cargo run --example upload_download --package zoeyr-blob-store
```

### Docker Environment
```bash
# Start full development environment
docker-compose up -d

# Check Redis
docker exec zoeyr-redis redis-cli ping

# Access Redis Commander (web UI)
open http://localhost:8081
```

## 📋 Project Status

### ✅ Working
- **Relay Service** - Complete with examples
- **Wire Protocol** - Message format and cryptography
- **WhatsApp Bridge** - Integration with WhatsApp
- **Blob Storage** - Binary data handling

### 🚧 In Progress
- Comprehensive integration testing
- Production deployment configurations
- Performance optimization

## 📚 Documentation

- **[Development Guide](docs/development.md)** - Setup, workflow, troubleshooting
- **[Architecture Overview](docs/architecture.md)** - Technical deep dive
- **[Relay Service Examples](crates/relay-service/examples/README.md)** - Complete usage guide

## 🔐 Security Model

### Transport Security
- **QUIC/TLS 1.3** with ed25519-derived certificates
- **Server identity verification** via certificate inspection
- **Connection migration** for mobile networks

### Message Security
- **Ed25519 signatures** on all messages
- **Blake3 message IDs** for integrity
- **Client-side message creation** with proper signing

## 📈 Performance

- **QUIC multiplexing** for concurrent operations
- **Redis Streams** for real-time distribution
- **Efficient serialization** (JSON + PostCard)
- **Connection pooling** and reuse

## 🎯 Use Cases

### Messaging Applications
- Secure chat applications
- Real-time notifications
- Multi-device synchronization

### Integration Hub
- WhatsApp message bridging
- Cross-platform messaging
- Protocol translation

### Development Platform
- Cryptographic messaging foundation
- QUIC transport examples
- Redis integration patterns

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

**Getting Started**: Follow the [Quick Start](#-quick-start) guide above, then explore the [examples](crates/relay-service/examples/) and [documentation](docs/).

**Questions?** Check the [development guide](docs/development.md) or review the [architecture overview](docs/architecture.md).