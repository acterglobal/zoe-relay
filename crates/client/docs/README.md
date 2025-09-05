---
title: Client
---

# Client Crate

The `client` crate provides the client-side implementation for connecting to and interacting with Zoe Relay servers.

## Overview

This crate includes:
- Client connection management
- Message sending/receiving
- PQXDH session handling
- Local message storage

## Key Components

### Client Implementation

Main client interface:

<!-- Code example will be added here -->

### PQXDH Handler

Post-quantum key exchange handling:

<!-- Code example will be added here -->

### Message Processing

Message handling and routing functionality.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
zoe-client = { path = "../client" }
```

## Examples

### Creating a Client

```rust
use zoe_client::Client;

let client = Client::new(config).await?;
client.connect().await?;
```

### Sending Messages

```rust
let message = client.create_message(content).await?;
client.send_message(message).await?;
```

For complete API documentation, see the [Rust API docs](/zoe-relay/rustdoc/zoe_client/).