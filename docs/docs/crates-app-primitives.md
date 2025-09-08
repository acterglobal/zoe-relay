---
id: crates-app-primitives
title: App Primitives
sidebar_label: App Primitives
---

# App Primitives Crate

The `app-primitives` crate provides core functionality and utilities used across the Zoe Relay ecosystem.

## Overview

This crate contains:
- Cryptographic primitives and utilities
- Common data structures
- Invitation flow logic
- Emoji verification system

## Key Components

### Invitation System

The invitation system handles secure group invitations:

import CodeBlock from '@theme/CodeBlock';
import InvitationPrimitivesSource from '!!raw-loader!../../crates/app-primitives/src/invitation.rs';

<details>
<summary>View Full Invitation Implementation</summary>

<CodeBlock language="rust" title="crates/app-primitives/src/invitation.rs">
{InvitationPrimitivesSource}
</CodeBlock>

</details>

Here's a key function from the invitation system:

```rust title="Emoji Verification Function"
use blake3::Hasher;

pub fn derive_emoji_verification(shared_secret: &[u8]) -> [&'static str; 6] {
    let mut hasher = Hasher::new();
    hasher.update(b"zoe-relay-emoji-verification-v1");
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    
    let mut emojis = [""; 6];
    for i in 0..6 {
        let chunk_start = i * 8;
        let chunk = &hash.as_bytes()[chunk_start..chunk_start + 8];
        let value = u64::from_le_bytes(chunk.try_into().unwrap());
        let emoji_index = (value % EMOJI_SET.len() as u64) as usize;
        emojis[i] = EMOJI_SET[emoji_index];
    }
    
    emojis
}
```

### Cryptographic Utilities

Core cryptographic functions and utilities for the application including key derivation and verification functions.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
zoe-app-primitives = { path = "../app-primitives" }
```

## Examples

### Using the Invitation System

```rust
use zoe_app_primitives::invitation::{derive_emoji_verification, EMOJI_SET};

// Derive emoji sequence from shared secret
let emojis = derive_emoji_verification(&shared_secret);
println!("Verification emojis: {:?}", emojis);
```

For complete API documentation, see the [Rust API docs](https://acterglobal.github.io/zoe-relay/rustdoc/zoe_app_primitives/).