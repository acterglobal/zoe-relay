# Zoeyr Relay Service

The relay service provides server-side implementation for the Zoeyr messaging system, including Redis storage, dynamic authentication, and QUIC transport.

## Features

- **Redis Storage Backend**: Persistent message storage with Redis Streams for real-time delivery
- **Dynamic Authentication**: Per-operation challenge-response authentication system
- **QUIC Transport**: High-performance transport with TLS 1.3 and ed25519 identity verification
- **Message Filtering**: Advanced filtering and streaming capabilities
- **Configuration Management**: Flexible configuration for various deployment scenarios

## Quick Start

### Basic Server Setup

```rust
use zoeyr_relay_service::{RelayConfig, RedisStorage, DynamicAuthServer};
use zoeyr_wire_protocol::generate_ed25519_keypair;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = RelayConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 4433,
        },
        redis: RedisConfig {
            url: "redis://localhost:6379".to_string(),
            max_connections: 10,
        },
        auth: AuthConfig {
            challenge_timeout_seconds: 30,
            session_timeout_seconds: 3600,
        },
    };

    // Create Redis storage
    let storage = RedisStorage::new(config.clone()).await?;

    // Generate server key
    let server_key = generate_ed25519_keypair();

    // Create and run server
    let server = DynamicAuthServer::new(
        "127.0.0.1:4433".parse()?,
        server_key,
        Arc::new(storage),
        30, // challenge timeout
    ).await?;

    println!("🚀 Zoeyr relay server running on 127.0.0.1:4433");
    server.run().await?;
    
    Ok(())
}
```

### Message Storage and Retrieval

```rust
use zoeyr_relay_service::{RedisStorage, MessageFilters};
use zoeyr_wire_protocol::{MessageFull, Message, MessageContent, Kind};

// Store a message
let content = MessageContent::Text { text: "Hello, World!".to_string() };
let message = Message::new_v0(
    content,
    signing_key.verifying_key(),
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
    Kind::Regular,
    vec![], // tags
);
let message_full = MessageFull::new(message, &signing_key)?;

let stored = storage.store_message(&message_full).await?;
println!("Message stored: {}", stored);

// Retrieve the message
let retrieved = storage.get_message::<MessageContent>(message_full.id.as_bytes()).await?;
if let Some(msg) = retrieved {
    println!("Retrieved message: {:?}", msg.content());
}
```

### Message Streaming

```rust
use futures_util::StreamExt;

// Create filters for specific authors
let filters = MessageFilters {
    authors: Some(vec![author_public_key.to_bytes().to_vec()]),
    channels: None,
    events: None,
    users: None,
};

// Stream messages
let message_stream = storage.listen_for_messages::<MessageContent>(
    &filters,
    None, // since
    Some(10), // limit
).await?;

tokio::pin!(message_stream);
while let Some(result) = message_stream.next().await {
    match result {
        Ok((Some(message_data), stream_id)) => {
            println!("Received message from stream {}", stream_id);
            // Process message_data
        }
        Ok((None, stream_id)) => {
            println!("Empty batch, stream_id: {}", stream_id);
        }
        Err(e) => {
            eprintln!("Stream error: {}", e);
            break;
        }
    }
}
```

## Storage System

### Redis Backend

The storage system uses Redis for both persistence and real-time message delivery:

- **Key-Value Storage**: Messages stored by Blake3 hash ID
- **Redis Streams**: Real-time message distribution with `XREAD`
- **Expiration**: Configurable message TTL based on message kind
- **Indexing**: Messages indexed by author, channel, event, and user tags

### Message Filtering

Advanced filtering capabilities for message retrieval:

```rust
let filters = MessageFilters {
    authors: Some(vec![author1.to_vec(), author2.to_vec()]),
    channels: Some(vec![b"general".to_vec(), b"announcements".to_vec()]),
    events: Some(vec![event_id.as_bytes().to_vec()]),
    users: Some(vec![user_id.to_vec()]),
};
```

### Storage Modes

Different storage behaviors based on message kind:

- **Regular**: Persistent storage with default 24-hour TTL
- **Ephemeral**: Short-term storage with custom timeout
- **Store**: Specific storage buckets (e.g., key packages, profiles)
- **ClearStore**: Clear specific storage buckets

## Authentication System

### Dynamic Authentication

Per-operation authentication system with challenge-response:

```rust
use zoeyr_relay_service::DynamicAuthServer;

// Server issues challenge
let challenge = auth_server.issue_challenge(client_session_id).await?;

// Client signs challenge (simplified)
let signature = client_key.sign(
    format!("auth:{}:{}", challenge.nonce, challenge.timestamp).as_bytes()
);

// Server verifies response
let is_valid = auth_server.verify_challenge_response(
    client_session_id,
    &challenge.nonce,
    challenge.timestamp,
    &signature.to_bytes(),
).await?;
```

### Session Management

- **Mutual TLS**: Initial identity establishment via ed25519-embedded certificates
- **Session Tracking**: Per-client session state with success/failure counters
- **Freshness Windows**: Configurable authorization timeout periods
- **Challenge Uniqueness**: Nonce-based replay protection

## Transport Layer

### QUIC with TLS 1.3

High-performance transport with modern security:

- **QUIC Protocol**: Multiplexed, encrypted transport
- **TLS 1.3**: Latest TLS with 0-RTT resumption
- **Ed25519 Identity**: Public keys embedded in TLS certificates
- **Certificate Verification**: Custom verifiers for ed25519 identity checking

### Connection Handling

```rust
// Custom certificate verifier
let verifier = InsecureCertVerifier::new(expected_server_key);

let tls_config = rustls::ClientConfig::builder()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(verifier))
    .with_no_client_auth();
```

## Configuration

### Server Configuration

```toml
[server]
host = "0.0.0.0"
port = 4433
max_connections = 1000

[redis]
url = "redis://localhost:6379"
max_connections = 20
connection_timeout_ms = 5000

[auth]
challenge_timeout_seconds = 30
session_timeout_seconds = 3600
max_failed_challenges = 5
```

### Environment Variables

- `ZOEYR_REDIS_URL` - Redis connection URL
- `ZOEYR_SERVER_PORT` - Server listening port
- `ZOEYR_LOG_LEVEL` - Logging level (debug, info, warn, error)

## Examples

### Client Example

```bash
# Generate key pair
cargo run --example relay_client generate-key

# Create message with tags
cargo run --example relay_client \
    --private-key deadbeef... \
    create-message \
    --text "Hello, Zoeyr!" \
    --with-tags
```

### Deterministic Certificates

```bash
# Test certificate generation
cargo run --example deterministic_cert
```

### Dynamic Authentication Client

```bash
# Connect with authentication
cargo run --example dynamic_auth_client \
    --server 127.0.0.1:4433 \
    --server-public-key abcdef... \
    connect \
    --message "Authenticated message"
```

## Testing

### Test Categories

```bash
# All relay service tests
cargo test -p zoeyr-relay-service

# Storage tests (requires Redis)
cargo test -p zoeyr-relay-service storage::tests

# Authentication tests
cargo test -p zoeyr-relay-service auth

# Integration tests
cargo test -p zoeyr-relay-service --test integration_server
```

### Test Profiles

Using cargo-nextest with intelligent filtering:

```bash
# Unit tests only
cargo nextest run --profile unit

# Integration tests with Redis
cargo nextest run --profile redis

# All tests
cargo nextest run --profile ci
```

## Performance

### Benchmarks

```bash
# Storage benchmarks
cargo bench --bench storage_benchmark

# Authentication benchmarks  
cargo bench --bench auth_benchmark

# End-to-end performance
cargo bench --bench e2e_benchmark
```

### Optimization

- **Connection Pooling**: Redis connection pools for concurrent access
- **Async Streams**: Non-blocking message streaming with backpressure
- **Zero-Copy**: Minimal data copying in hot paths
- **Binary Serialization**: Compact postcard serialization

## Monitoring

### Metrics

The service provides metrics for monitoring:

- Message throughput (messages/second)
- Storage utilization (bytes, key count)  
- Authentication success/failure rates
- Connection counts and duration
- Redis performance metrics

### Logging

Structured logging with tracing:

```rust
use tracing::{info, warn, error};

info!("Message stored successfully", message_id = %hex::encode(id));
warn!("High authentication failure rate", client = %client_id);
error!("Redis connection failed", error = %e);
```

## Security Considerations

- **Message Integrity**: All messages cryptographically signed
- **Identity Verification**: Ed25519 keys in TLS certificates  
- **Replay Protection**: Nonce-based challenge system
- **Forward Secrecy**: TLS 1.3 with ephemeral key exchange
- **Storage Security**: Redis AUTH and TLS encryption recommended

## Deployment

### Docker

```dockerfile
FROM rust:alpine
COPY . /app
WORKDIR /app
RUN cargo build --release --bin relay-service
EXPOSE 4433
CMD ["./target/release/relay-service"]
```

### Docker Compose

```yaml
version: '3.8'
services:
  redis:
    image: redis:alpine
    ports: ["6379:6379"]
  
  relay:
    build: .
    ports: ["4433:4433"]
    environment:
      - ZOEYR_REDIS_URL=redis://redis:6379
    depends_on: [redis]
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option. 