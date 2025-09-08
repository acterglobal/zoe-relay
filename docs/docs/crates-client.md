---
id: crates-client
title: Client
sidebar_label: Client
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

Main client interface for connecting to relay servers and managing communication sessions.

### PQXDH Handler

Post-quantum key exchange handling for secure communication establishment.

### Message Processing

Message handling and routing functionality for reliable message delivery.

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

For complete API documentation, see the [Rust API docs](https://acterglobal.github.io/zoe-relay/rustdoc/zoe_client/).