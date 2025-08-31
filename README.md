# Zoe - Secure Messaging Relay System

[![CI](https://github.com/acterglobal/zoe-relay/workflows/CI/badge.svg?branch=main)](https://github.com/acterglobal/zoe-relay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/acterglobal/zoe-relay/branch/main/graph/badge.svg)](https://codecov.io/gh/acterglobal/zoe-relay)

A secure, modular messaging relay system built with QUIC transport, tarpc RPC services, and encryption.

## 🚀 Quick Start

### Prerequisites
- **Rust 1.75+** with Cargo
- **Redis** (or Docker compose for Redis a local redis)
- **Linux/macOS** (Windows via WSL)

### 1. Start Redis (Development)
```bash
docker-compose -f docker-compose.dev.yml up -d

# Or use the existing development setup
docker-compose up -d redis
```

### 2. Run the Examples
```bash
# Start the relay server
cargo run --example relay_server

# In another terminal, send a message (replace <SERVER_PUBLIC_KEY> with key from server output)
cargo run --example relay_send_client -- \
  --server-public-key <SERVE-relayPUBLIC_KEY> \
  --message "Hello, Zoeyr!"

# In a third terminal, listen for messages
cargo run --example relay_listen_client -- \
  --authors <SERVER_PUBLIC_KEY> \
  --follow
```

## 🚀 Deployment

### Production Deployment with Docker Compose

See the [Deployment Guide](DEPLOYMENT.md) for detailed instructions and configuration options.

## 🛠️ Development

### Build & Test
```bash
# Build all components
cargo build --workspace

# Run tests
cargo test --workspace

```

```

## 🤝 Contributing

1. **Setup Development Environment**
   ```bash
   git clone <repository>
   cd zoe-relay
   cargo build --workspace
   docker-compose -f docker-compose.dev.yml up -d # start a redis
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

**Getting Started**: 
- **Development**: Follow the [Quick Start](#-quick-start) guide above
- **Production**: See the [Deployment Guide](DEPLOYMENT.md) for Docker Compose deployment

**Questions?** Check the [development guide](docs/development.md), [deployment guide](DEPLOYMENT.md), or review the [architecture overview](docs/architecture.md).