# Zoeyr Relay

The relay provides QUIC transport and service routing for the Zoeyr messaging system, acting as a universal connector for multiple tarpc services.

## Features

- **QUIC Transport**: High-performance transport with TLS 1.3 and ed25519 identity verification
- **Service Routing**: Routes multiple tarpc services over single QUIC connections
- **Generic Server/Client Utilities**: Reusable components for any tarpc service
- **Ed25519 Mutual TLS**: Authentication via public keys embedded in certificates
- **No Session Management**: QUIC certificates provide all needed authentication

## Architecture

The relay crate serves as the transport layer, connecting clients to various services:

```
Client Apps → QuicTarpcClient → QUIC Transport → QuicTarpcServer → Services
     ↓              ↓               ↓              ↓              ↓
   tarpc          ed25519        Stream         Service         Message Store
  Clients        Mutual TLS      Routing        Routing        (Redis Backend)
                                    ↓              ↓
                                 QUIC           Blob Store
                                Streams       (Iroh Backend)
```

## Usage

### Server Setup

```rust
use zoeyr_relay::{RelayServerBuilder, QuicTarpcServer};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    
    // Build relay server with message service
    let (server, _storage) = RelayServerBuilder::new(addr)
        .with_redis_url("redis://localhost:6379".to_string())
        .build()
        .await?;

    println!("🚀 Relay server running on {}", addr);
    server.run().await?;
    
    Ok(())
}
```

### Client Connection

```rust
use zoeyr_relay::{RelayClientBuilder, QuicTarpcClient};
use ed25519_dalek::VerifyingKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "127.0.0.1:4433".parse()?;
    let server_public_key = VerifyingKey::from_bytes(&server_key_bytes)?;
    
    // Build relay client
    let mut client = RelayClientBuilder::new(server_addr, server_public_key)
        .build()
        .await?;

    // Get relay service client
    let relay_client = client.relay_service().await?;
    
    // Use the service
    let message_data = b"Hello, World!".to_vec();
    let message_id = relay_client.store_message(message_data).await?;
    println!("Stored message: {}", message_id);
    
    Ok(())
}
```

### Generic Service Hosting

```rust
use zoeyr_relay::QuicTarpcServer;
use ed25519_dalek::SigningKey;

// Host any tarpc service over QUIC
let server_key = SigningKey::generate(&mut rng);
let addr = "127.0.0.1:4433".parse()?;

// Your service implementation
let my_service = MyServiceImpl::new();

// Create generic QUIC+tarpc server
let server = QuicTarpcServer::new(addr, server_key, my_service.serve());
server.run().await?;
```

## Components

### QuicTarpcServer<S>

Generic server that can host any tarpc service over QUIC:

- **Generic over service type**: Works with any `tarpc::server::Serve` implementation
- **QUIC transport**: Automatic QUIC endpoint creation and management
- **Stream handling**: Routes QUIC streams to tarpc service handlers
- **Ed25519 authentication**: Server identity via signing key

### QuicTarpcClient

Generic client for connecting to tarpc services over QUIC:

- **QUIC connection management**: Handles QUIC connection lifecycle
- **Stream creation**: Creates streams for tarpc RPC calls
- **Server verification**: Verifies server identity via ed25519 public key

### RelayServerBuilder

Builder for setting up relay servers with message services:

```rust
let (server, storage) = RelayServerBuilder::new(addr)
    .with_private_key(key_hex)           // Optional: use existing key
    .with_redis_url(redis_url)           // Redis backend URL
    .with_key_output(key_file)           // Optional: save generated key
    .with_blob_storage(blob_dir)         // Optional: enable blob service
    .build()
    .await?;
```

### RelayClientBuilder

Builder for setting up relay clients:

```rust
let client = RelayClientBuilder::new(server_addr, server_public_key)
    .with_private_key(client_key)        // Optional: use specific client key
    .build()
    .await?;
```

## Transport Details

### QUIC with Ed25519 Mutual TLS

- **QUIC Protocol**: Multiplexed, encrypted transport with 0-RTT resumption
- **TLS 1.3**: Latest TLS with ed25519-derived certificates
- **Mutual Authentication**: Both client and server verify each other's ed25519 keys
- **Certificate Embedding**: Public keys embedded in X.509 certificate extensions

### Service Multiplexing

Multiple services can run over the same QUIC connection:

- **Stream-based routing**: Each RPC call uses a separate QUIC stream
- **Concurrent requests**: Multiple RPCs can run simultaneously
- **Service isolation**: Different services are logically separated
- **Shared authentication**: Single authentication for all services

## Security Model

### Authentication Flow

1. **Certificate Generation**: Ed25519 keys embedded in self-signed certificates
2. **QUIC Handshake**: Mutual TLS authentication during QUIC connection
3. **Key Verification**: Both parties verify the other's ed25519 public key
4. **Stream Security**: All RPC traffic encrypted and authenticated

### No Session Management

- **Certificate-based**: Authentication is cryptographically bound to certificates
- **Stateless**: No server-side session storage required
- **Key-based identity**: Identity is the ed25519 public key itself
- **Connection-scoped**: Authentication valid for entire QUIC connection lifetime

## Integration

### With Message Store

```rust
use zoeyr_relay::RelayServerBuilder;
use zoeyr_message_store::RelayServiceImpl;

// Relay automatically integrates message store service
let (server, storage) = RelayServerBuilder::new(addr)
    .with_redis_url("redis://localhost:6379".to_string())
    .build()
    .await?;
```

### With Blob Store

```rust
use zoeyr_relay::QuicTarpcServer;
use zoeyr_blob_store::BlobServiceImpl;

// Host blob service over QUIC
let blob_service = BlobServiceImpl::new(blob_dir).await?;
let server = QuicTarpcServer::new(addr, server_key, blob_service.serve());
```

### Multiple Services

```rust
// Future: Route multiple services on same server
// This is the planned architecture for full integration
```

## Examples

The `examples/` directory contains:

- **`relay_server`**: Complete relay server with message service
- **`relay_send_client`**: Send messages via relay
- **`relay_listen_client`**: Stream messages via relay

Run examples:

```bash
# Start server
cargo run --example relay_server

# Send messages
cargo run --example relay_send_client -- --server-public-key <KEY> --message "Hello"

# Listen for messages  
cargo run --example relay_listen_client -- --authors <KEY> --follow
```

## Error Handling

The relay provides comprehensive error handling:

```rust
use zoeyr_relay::RelayError;

match client.relay_service().await {
    Ok(service) => {
        // Use service
    }
    Err(RelayError::ConnectionFailed(e)) => {
        eprintln!("Failed to connect: {}", e);
    }
    Err(RelayError::AuthenticationFailed) => {
        eprintln!("Server authentication failed");
    }
    Err(e) => {
        eprintln!("Other error: {}", e);
    }
}
```

## Configuration

### Server Configuration

- **Binding address**: IP and port for QUIC server
- **Private key**: Ed25519 signing key for server identity  
- **Redis URL**: Backend storage connection string
- **Key persistence**: Optional file to save/load server key

### Client Configuration

- **Server address**: Target QUIC server address
- **Server public key**: Expected server ed25519 public key
- **Client key**: Optional specific client signing key
- **Connection options**: Timeouts, retry logic, etc.

## License

This project is licensed under MIT OR Apache-2.0. 