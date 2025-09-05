---
title: Wire Protocol
---

# Wire Protocol Crate

The `wire-protocol` crate defines the message formats and serialization for network communication in Zoe Relay.

## Overview

This crate provides:
- Message type definitions
- Serialization/deserialization
- Protocol versioning
- Network message routing

## Key Components

### Message Types

Core message definitions:

```rust title="crates/wire-protocol/src/lib.rs"
// Example of core message structure
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub content: Vec<u8>,
    pub timestamp: u64,
}
```

### Invitation Protocol

Group invitation message types:

import CodeBlock from '@theme/CodeBlock';
import InvitationSource from '!!raw-loader!../src/invitation.rs';

<CodeBlock language="rust" title="crates/wire-protocol/src/invitation.rs">
{InvitationSource}
</CodeBlock>

### PQXDH Protocol

Post-quantum key exchange messages:

```rust title="Example PQXDH Message Structure"
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqxdhInitialMessage {
    pub sender_identity_key: Vec<u8>,
    pub sender_ephemeral_key: Vec<u8>,
    pub kyber_ciphertext: Vec<u8>,
    pub encrypted_payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqxdhSessionMessage {
    pub message_id: u64,
    pub encrypted_content: Vec<u8>,
    pub authentication_tag: Vec<u8>,
}
```

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
zoe-wire-protocol = { path = "../wire-protocol" }
```

## Examples

### Creating an Invitation Message

```rust
use zoe_wire_protocol::invitation::{VerificationHandshakeRequest, HandshakePurpose};

let request = VerificationHandshakeRequest {
    protocol_version: ProtocolVersion::V1,
    purpose: HandshakePurpose::GroupInvitation,
    timestamp: SystemTime::now(),
};
```

For complete API documentation, see the [Rust API docs](/zoe-relay/rustdoc/zoe_wire_protocol/).