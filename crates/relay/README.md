# Zoe Relay

A clean, minimal QUIC relay server with ed25519 bi-directional authentication for service routing.

## Features

- **QUIC Transport**: High-performance transport with TLS 1.3 and ed25519 identity verification
- **Service Routing**: Routes connections to different services based on a u8 service identifier
- **Bi-directional Streams**: Full duplex communication between client and server
- **Ed25519 Authentication**: Client identity verification via embedded public keys in certificates
- **Trait-based Design**: Clean abstraction for implementing service handlers

## Architecture

The relay accepts QUIC connections, authenticates clients via ed25519 keys, reads the first byte of the stream to determine the service type, and routes the connection to the appropriate service handler:

```
Client → QUIC Connection → ed25519 Auth → Read Service ID (u8) → Route to Service
   ↓           ↓                ↓              ↓                    ↓
Certificate  TLS 1.3        Extract Key    First Byte        ServiceRouter::route_connection
```

## Usage

### Implementing a Service Router

```rust
use zoe_relay::{ServiceRouter, ConnectionInfo, StreamPair};
use async_trait::async_trait;

struct MyServiceRouter;

#[async_trait]
impl ServiceRouter for MyServiceRouter {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    async fn route_connection(
        &self,
        service_id: u8,
        connection_info: ConnectionInfo,
        streams: StreamPair,
    ) -> Result<(), Self::Error> {
        match service_id {
            1 => {
                // Handle message service
                println!("Routing to message service for client: {}", 
                         hex::encode(connection_info.client_public_key.to_bytes()));
                // Your message service logic here
            }
            2 => {
                // Handle blob service
                println!("Routing to blob service");
                // Your blob service logic here
            }
            _ => {
                return Err("Unknown service ID".into());
            }
        }
        Ok(())
    }
}
```

### Running the Relay Server

```rust
use zoe_relay::RelayServer;
use ed25519_dalek::SigningKey;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let server_key = SigningKey::generate(&mut rand::thread_rng());
    let router = MyServiceRouter;
    
    let server = RelayServer::new(addr, server_key, router)?;
    println!("🚀 Relay server running on {}", addr);
    server.run().await?;
    
    Ok(())
}
```

## Components

### RelayServer<R>

The main relay server that accepts QUIC connections and routes them to services:

- **Generic over router type**: Works with any `ServiceRouter` implementation
- **QUIC transport**: Automatic QUIC endpoint creation and management
- **Ed25519 authentication**: Server identity via signing key
- **Stream routing**: Routes connections based on service ID

### ServiceRouter Trait

Trait for implementing service routing logic:

```rust
#[async_trait]
pub trait ServiceRouter: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn route_connection(
        &self,
        service_id: u8,
        connection_info: ConnectionInfo,
        streams: StreamPair,
    ) -> Result<(), Self::Error>;
}
```

### ConnectionInfo

Information about an authenticated connection:

- **client_public_key**: The ed25519 public key of the connected client
- **remote_address**: The remote address of the client
- **connected_at**: Timestamp when the connection was established

### StreamPair

Bi-directional streams for communication:

- **recv**: Stream for receiving data from the client
- **send**: Stream for sending data to the client

## Transport Details

### QUIC with Ed25519 Authentication

- **QUIC Protocol**: Multiplexed, encrypted transport with connection-level authentication
- **TLS 1.3**: Latest TLS with ed25519-derived certificates
- **Client Authentication**: Client identity verification via ed25519 keys embedded in certificates
- **Certificate Embedding**: Public keys embedded in X.509 certificate extensions

### Service Routing Protocol

1. **Connection Establishment**: Client connects via QUIC with ed25519 certificate
2. **Authentication**: Server extracts and verifies client's ed25519 public key
3. **Service Selection**: Client sends first byte indicating desired service
4. **Stream Handoff**: Both streams are passed to the selected service handler

## Security Model

### Authentication Flow

1. **Certificate Generation**: Ed25519 keys embedded in deterministic self-signed certificates
2. **QUIC Handshake**: TLS authentication with client certificate verification
3. **Key Extraction**: Server extracts client's ed25519 public key from certificate
4. **Service Routing**: Authenticated client streams are routed to appropriate services

### Identity and Trust

- **Certificate-based**: Client identity is embedded in the certificate
- **Key-based identity**: Identity is the ed25519 public key itself
- **Connection-scoped**: Authentication valid for entire QUIC connection lifetime
- **Service-agnostic**: Authentication happens once, all services trust the identity

## Integration

### Future Service Integration

The relay is designed as a foundation for routing multiple services. Future integrations will implement the `ServiceRouter` trait to handle different service types:

```rust
struct ZoeyrServiceRouter {
    message_service: MessageServiceImpl,
    blob_service: BlobServiceImpl,
}

#[async_trait]
impl ServiceRouter for ZoeyrServiceRouter {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    async fn route_connection(
        &self,
        service_id: u8,
        connection_info: ConnectionInfo,
        streams: StreamPair,
    ) -> Result<(), Self::Error> {
        match service_id {
            1 => self.message_service.handle(connection_info, streams).await,
            2 => self.blob_service.handle(connection_info, streams).await,
            _ => Err("Unknown service".into()),
        }
    }
}
```

## Examples

Basic server implementation:

```rust
use zoe_relay::{RelayServer, ServiceRouter, ConnectionInfo, StreamPair};
use ed25519_dalek::SigningKey;

struct EchoService;

#[async_trait]
impl ServiceRouter for EchoService {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    async fn route_connection(
        &self,
        service_id: u8,
        _connection_info: ConnectionInfo,
        _streams: StreamPair,
    ) -> Result<(), Self::Error> {
        println!("Service {} requested", service_id);
        // Implement your service logic here
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:4433".parse()?;
    let server_key = SigningKey::generate(&mut rand::thread_rng());
    let router = EchoService;
    
    let server = RelayServer::new(addr, server_key, router)?;
    server.run().await?;
    
    Ok(())
}
```

## Error Handling

Service routers should implement proper error handling:

```rust
#[async_trait]
impl ServiceRouter for MyRouter {
    type Error = MyServiceError;

    async fn route_connection(
        &self,
        service_id: u8,
        connection_info: ConnectionInfo,
        streams: StreamPair,
    ) -> Result<(), Self::Error> {
        match service_id {
            1 => self.handle_service_1(connection_info, streams).await,
            2 => self.handle_service_2(connection_info, streams).await,
            _ => Err(MyServiceError::UnknownService(service_id)),
        }
    }
}
```

## Configuration

### Server Configuration

- **Binding address**: IP and port for QUIC server
- **Private key**: Ed25519 signing key for server identity
- **Service router**: Implementation of the ServiceRouter trait

The relay server is intentionally minimal - all service-specific configuration is handled by your ServiceRouter implementation.

## License

This project is licensed under MIT OR Apache-2.0. 