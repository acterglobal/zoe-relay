---
id: crates-relay
title: Relay
sidebar_label: Relay
---

# Relay Crate

The `relay` crate implements the server-side relay functionality for routing messages between clients.

## Overview

This crate provides:
- Message relay server
- Client connection management
- Message routing and delivery
- Storage backend integration

## Key Components

### Relay Server

Main server implementation that handles client connections and message routing between participants.

### Message Router

Message routing logic that ensures secure and reliable delivery of messages to intended recipients.

### Connection Manager

Client connection handling functionality for managing multiple concurrent client sessions.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
zoe-relay = { path = "../relay" }
```

## Examples

### Starting a Relay Server

```rust
use zoe_relay::RelayServer;

let server = RelayServer::new(config).await?;
server.start().await?;
```

### Configuring Message Storage

```rust
let config = RelayConfig {
    storage_backend: StorageBackend::Redis(redis_config),
    // ... other config
};
```

For complete API documentation, see the [Rust API docs](/zoe-relay/rustdoc/zoe_relay/).