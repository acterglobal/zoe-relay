# Zoeyr Relay Service

A Nostr-inspired relay service built with Rust, using Redis for storage and Tarp for protocol handling. This service provides a scalable, protocol-agnostic message relay system for the Zoeyr wire protocol.

## Features

- **Protocol Agnostic**: Uses Tarp for flexible client-server communication
- **Redis Storage**: Async Redis integration for high-performance message storage
- **Message Types**: Support for regular, ephemeral, and store messages
- **Rate Limiting**: Built-in rate limiting with sliding window implementation
- **Message Filtering**: Advanced query capabilities with multiple filter types
- **Subscription System**: Real-time message broadcasting to subscribers
- **User Data Storage**: Flexible user data storage and retrieval
- **Ephemeral Messages**: Automatic cleanup of time-limited messages
- **Comprehensive Testing**: Full test suite with Redis mocking

## Architecture

The relay service is built with a modular architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Tarp Client   │    │  Relay Service  │    │   Redis Store   │
│                 │◄──►│                 │◄──►│                 │
│  - Publish      │    │  - Protocol     │    │  - Messages     │
│  - Query        │    │  - Storage      │    │  - Metadata     │
│  - Subscribe    │    │  - Rate Limit   │    │  - User Data    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.70+
- Redis server
- Docker (for testing)

### Installation

1. Clone the repository and navigate to the relay service:
```bash
cd crates/relay-service
```

2. Build the service:
```bash
cargo build --release
```

3. Start Redis (if not already running):
```bash
redis-server
```

4. Run the relay service:
```bash
cargo run --bin relay-service
```

### Configuration

The service can be configured via environment variables or by modifying the default configuration:

```rust
use zoeyr_relay_service::RelayConfig;

let config = RelayConfig {
    redis: RedisConfig {
        url: "redis://127.0.0.1:6379".to_string(),
        pool_size: 10,
        timeout: Duration::from_secs(5),
        database: 0,
    },
    service: ServiceConfig {
        max_message_size: 1024 * 1024, // 1MB
        ephemeral_retention: 300, // 5 minutes
        debug: false,
        bind_address: "127.0.0.1".to_string(),
        port: 8080,
    },
    rate_limit: RateLimitConfig {
        messages_per_second: 10,
        messages_per_minute: 1000,
        window_size: 60,
    },
};
```

## Usage

### Creating a Relay Service

```rust
use zoeyr_relay_service::{RelayService, RelayServiceBuilder};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct MyContent {
    text: String,
    user_id: String,
    timestamp: u64,
}

// Create service with default configuration
let service = RelayServiceBuilder::<MyContent>::new()
    .config(RelayConfig::default())
    .build()
    .await?;

// Start the service
service.start().await?;
```

### Message Types

The relay service supports different message types from the wire protocol:

- **Regular Messages**: Stored permanently and available for querying
- **Ephemeral Messages**: Temporary messages with optional TTL
- **Store Messages**: Messages stored in specific user stores
- **Clear Store Messages**: Clear specific user store data

### Message Filtering

Query messages with advanced filters:

```rust
use zoeyr_relay_service::storage::MessageFilters;

let filters = MessageFilters {
    authors: Some(vec!["author1".to_string(), "author2".to_string()]),
    kinds: Some(vec![Kind::Regular, Kind::Emphemeral(None)]),
    tags: Some(vec![Tag::Protected]),
    since: Some(1234567890),
    until: Some(1234567999),
    limit: Some(100),
};

let messages = storage.query_messages(&filters, Some(10)).await?;
```

## API Reference

### Core Types

- `RelayService<T>`: Main service orchestrator
- `RedisStorage`: Redis-based storage implementation
- `RelayProtocol<T>`: Protocol handling with Tarp
- `MessageFilters`: Message query filters
- `RelayConfig`: Service configuration

### Storage Interface

```rust
#[async_trait::async_trait]
pub trait Storage: Send + Sync {
    async fn store_message<T>(&self, message: &MessageFull<T>) -> Result<()>;
    async fn get_message<T>(&self, id: &str) -> Result<Option<MessageFull<T>>>;
    async fn query_messages<T>(&self, filters: &MessageFilters, limit: Option<usize>) -> Result<Vec<MessageFull<T>>>;
    async fn store_user_data(&self, user_id: &str, key: &str, data: &str) -> Result<()>;
    async fn get_user_data(&self, user_id: &str, key: &str) -> Result<Option<String>>;
    async fn clear_user_store(&self, user_id: &str, store_key: &StoreKey) -> Result<()>;
    async fn check_rate_limit(&self, client_id: &str) -> Result<bool>;
    async fn cleanup_ephemeral(&self) -> Result<usize>;
}
```

## Testing

The service includes comprehensive tests with Redis mocking:

```bash
# Run all tests
cargo test

# Run integration tests (requires Docker)
cargo test integration_tests

# Run unit tests only
cargo test unit_tests
```

### Test Features

- **Redis Container Testing**: Uses testcontainers for real Redis testing
- **Mock Storage**: Mockall-based storage mocking for unit tests
- **Message Validation**: Tests for message signing and verification
- **Rate Limiting**: Tests for rate limiting functionality
- **Ephemeral Messages**: Tests for TTL and cleanup functionality

## Performance Considerations

- **Connection Pooling**: Redis connection manager for efficient connection reuse
- **Async Operations**: Full async/await support for high concurrency
- **Batch Operations**: Redis pipelining for bulk operations
- **Memory Management**: Efficient serialization and deserialization
- **Rate Limiting**: Sliding window implementation for accurate rate limiting

## Security Features

- **Message Signing**: Ed25519 signature verification for all messages
- **Rate Limiting**: Per-client rate limiting to prevent abuse
- **Message Size Limits**: Configurable maximum message sizes
- **Protected Messages**: Support for non-forwardable protected messages

## Monitoring and Logging

The service uses structured logging with tracing:

```bash
# Enable debug logging
RUST_LOG=debug cargo run --bin relay-service

# Enable specific module logging
RUST_LOG=zoeyr_relay_service::storage=debug cargo run --bin relay-service
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is part of the Zoeyr ecosystem and follows the same licensing terms. 