# Development Guide

## 🛠️ Development Setup

### Prerequisites

- **Rust 1.75+** with Cargo
- **Docker & Docker Compose** for Redis
- **Linux/macOS** (Windows support via WSL)

### Environment Setup

1. **Clone and Build**
   ```bash
   git clone <repository-url>
   cd zoeyr
   cargo build --workspace
   ```

2. **Start Redis Infrastructure**
   ```bash
   # Start Redis in Docker
   docker-compose up -d redis
   
   # Verify Redis is running
   docker exec zoe-redis redis-cli ping  # Should return PONG
   
   # Optional: Start Redis Commander (Web UI on http://localhost:8081)
   docker-compose up -d redis-commander
   ```

3. **Run Tests**
   ```bash
   # Run all tests
   cargo test --workspace
   
   # Run with nextest (if available)
   cargo nextest run --workspace
   ```

## 📋 Current Development Status

### ✅ Working Components

- **`zoe-wire-protocol`** - Protocol definitions and cryptography
- **`zoe-relay-service`** - Redis-backed message relay with working examples
- **`zoe-whatsmeow`** - WhatsApp bridge integration
- **`zoe-blob-store`** - Binary data storage service

### 🚧 In Development

- **Full integration testing** - Comprehensive test suite setup
- **Production deployment** - Docker and configuration management
- **Performance optimization** - Benchmarking and tuning

### 🔧 Configuration

#### Redis Configuration

The included `redis.conf` optimizes Redis for message relay:

- **Stream Support** - Configured for message streaming
- **Memory Management** - LRU eviction for high throughput
- **Persistence** - AOF for durability
- **Performance** - Tuned for low latency operations

#### Testing Configuration

The project uses nextest for advanced testing:

```bash
# Different test profiles
cargo nextest run --profile unit        # Fast unit tests
cargo nextest run --profile integration # Mocked integration tests  
cargo nextest run --profile redis       # Redis container tests
cargo nextest run --profile e2e --ignored # Manual end-to-end tests
cargo nextest run --profile ci          # CI-optimized tests
```

## 🔧 Development Workflow

### Building

```bash
# Build all crates
cargo build --workspace

# Build specific crate
cargo build --package zoe-relay-service

# Build with optimizations
cargo build --workspace --release
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Test specific component
cargo test --package zoe-wire-protocol

# Run integration tests
cargo test --package zoe-relay-service --test integration

# Check compilation without tests
cargo check --workspace
```

### Examples

```bash
# Run relay service examples
cargo run --example relay_server
cargo run --example relay_send_client --help
cargo run --example relay_listen_client --help

# Run blob store examples
cargo run --example upload_download --package zoe-blob-store
```

## 🐛 Troubleshooting

### Common Issues

1. **Redis Connection Refused**
   - Ensure Redis is running: `docker-compose up -d redis`
   - Check Redis logs: `docker-compose logs redis`

2. **Compilation Errors**
   - Update Rust: `rustup update`
   - Clean build cache: `cargo clean`
   - Check dependency versions

3. **Test Failures**
   - Ensure Redis is running for integration tests
   - Check that ports are available (4433, 6379, 8081)
   - Run tests individually to isolate issues

### Debug Logging

Enable debug logging for development:

```bash
# Enable debug logging
export RUST_LOG=debug

# Enable trace logging for specific crate
export RUST_LOG=zoe_relay_service=trace

# Run with logging
cargo run --example relay_server
```

## 📊 Performance Monitoring

### Benchmarking

```bash
# Run benchmarks
cargo bench --workspace

# Run specific benchmark
cargo bench --package zoe-wire-protocol
```

### Profiling

```bash
# Profile with perf (Linux)
perf record --call-graph dwarf cargo run --example relay_server --release
perf report

# Profile memory usage
valgrind --tool=massif cargo run --example relay_server --release
```

## 🔐 Security Considerations

### Development Security

- **Never commit private keys** - Use `.gitignore` for key files
- **Use test keys only** - Generate fresh keys for production
- **Secure Redis** - Use authentication in production
- **Network security** - Bind to localhost for development

### Crypto Implementation

- **Ed25519** signatures for authentication
- **QUIC/TLS 1.3** for transport security
- **Deterministic certificates** from ed25519 keys
- **Challenge-response** authentication

## 🚀 Deployment Preparation

### Building for Production

```bash
# Build optimized release
cargo build --workspace --release

# Create deployment artifacts
cargo build --release --package zoe-relay-service
```

### Docker Integration

```bash
# Build with Docker
docker-compose build

# Run full stack
docker-compose up
```

## 📈 Monitoring and Observability

### Metrics Collection

The relay service includes built-in metrics:

- Connection counts
- Message throughput
- Authentication success rates
- Redis operation latencies

### Log Aggregation

Structured logging is available:

```bash
# JSON structured logs
export RUST_LOG_FORMAT=json
cargo run --example relay_server
``` 