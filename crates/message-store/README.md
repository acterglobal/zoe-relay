# Zoeyr Message Store

The message store provides message storage, handling, streaming, and tarpc service implementation for the Zoeyr messaging system.

## Features

- **Redis Storage Backend**: Persistent message storage with Redis Streams for real-time delivery
- **tarpc Service Interface**: RelayService implementation for QUIC+tarpc integration
- **Message Filtering**: Advanced filtering and streaming capabilities
- **Storage Management**: Different storage modes (Regular, Ephemeral, Store, ClearStore)
- **Real-time Streaming**: Redis Streams integration for live message distribution

## Architecture

This crate contains the core business logic for message handling, separated from transport concerns:

- **`storage.rs`**: Redis-backed storage implementation
- **`service.rs`**: tarpc RelayService implementation
- **`config.rs`**: Configuration management
- **`error.rs`**: Error types and handling

## Usage

### Basic Setup

```rust
use zoeyr_message_store::{RelayConfig, RedisStorage, RelayServiceImpl};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = RelayConfig {
        redis: RedisConfig {
            url: "redis://localhost:6379".to_string(),
            pool_size: 10,
        },
        service: ServiceConfig {
            max_message_size: 1024 * 1024, // 1MB
            default_ttl_seconds: 86400,    // 24 hours
        },
    };

    // Create Redis storage
    let storage = RedisStorage::new(config.clone()).await?;

    // Create service implementation
    let service = RelayServiceImpl::new(Arc::new(storage));

    // Use with tarpc server (typically done by relay crate)
    let server_impl = service.serve();
    
    Ok(())
}
```

### Message Storage

```rust
use zoeyr_message_store::{RedisStorage, MessageFilters};
use zoeyr_wire_protocol::{MessageFull, Message, Kind};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MessageContent {
    Text { text: String }
    File { file: Vec<u8>}
}

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

let stream_id = storage.store_message(&message_full).await?;
match stream_id {
    Some(id) => println!("Message stored with stream ID: {}", id),
    None => println!("Message already existed"),
}

// Retrieve the message
let retrieved = storage.get_message(message_full.id.as_bytes()).await?;
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
let message_stream = storage.listen_for_messages::<String>(
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

## tarpc Service Implementation

The RelayService provides the following RPC methods:

- **`get_message`**: Retrieve a message by ID
- **`store_message`**: Store a new message (returns stream ID if newly stored, None if already exists)
- **`start_message_stream`**: Begin streaming messages with filters

### Authentication

Authentication is handled at the QUIC transport layer via ed25519 mutual TLS. The service implementation trusts that the relay layer has properly authenticated clients.

## Configuration

### Redis Configuration

```rust
use zoeyr_message_store::RedisConfig;

let redis_config = RedisConfig {
    url: "redis://localhost:6379".to_string(),
    pool_size: 10,
};
```

### Service Configuration

```rust
use zoeyr_message_store::ServiceConfig;

let service_config = ServiceConfig {
    max_message_size: 1024 * 1024, // 1MB
    default_ttl_seconds: 86400,    // 24 hours
};
```

## Error Handling

The crate provides comprehensive error types:

```rust
use zoeyr_message_store::RelayError;

match storage.get_message(id).await {
    Ok(Some(message)) => println!("Found message"),
    Ok(None) => println!("Message not found"),
    Err(RelayError::Redis(e)) => eprintln!("Redis error: {}", e),
    Err(RelayError::SerializationError(e)) => eprintln!("Serialization error: {}", e),
    Err(e) => eprintln!("Other error: {}", e),
}
```

## Integration

This crate is designed to be used with:

- **`zoeyr-relay`**: Provides QUIC transport and service routing
- **`zoeyr-wire-protocol`**: Defines message formats and service interfaces
- **Redis**: Backend storage and streaming

## License

This project is licensed under MIT OR Apache-2.0. 