# Zoe - Secure Messaging Relay System

[![CI](https://github.com/acterglobal/zoe-relay/workflows/CI/badge.svg?branch=main)](https://github.com/acterglobal/zoe-relay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/acterglobal/zoe-relay/branch/main/graph/badge.svg)](https://codecov.io/gh/acterglobal/zoe-relay)

A secure, modular messaging relay system built with QUIC transport, tarpc RPC services, and encryption.

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