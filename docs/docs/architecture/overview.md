# Architecture Overview

Zoe Relay is designed as a secure, decentralized messaging infrastructure that provides end-to-end encrypted communication with post-quantum security guarantees.

## System Components

### Core Components

- **Relay Server**: Routes messages between clients
- **Client Library**: Handles encryption, key exchange, and communication
- **Wire Protocol**: Defines message formats and serialization
- **Storage Backend**: Persists messages and metadata

### Security Components

- **PQXDH Protocol**: Post-quantum key exchange
- **AES Encryption**: Message content encryption
- **Ephemeral Keys**: Forward secrecy guarantees
- **Digital Signatures**: Message authentication

## Architecture Principles

### Decentralization
- No single point of failure
- Multiple relay servers can operate independently
- Clients can connect to any compatible relay

### Security
- End-to-end encryption for all messages
- Post-quantum cryptography for future-proofing
- Forward secrecy through ephemeral keys
- Deniable authentication

### Performance
- Efficient binary serialization
- Minimal memory allocation
- Async/await throughout
- Zero-copy where possible

## Message Flow

1. **Key Exchange**: Clients establish secure channels using PQXDH
2. **Message Creation**: Content is encrypted with session keys
3. **Relay Routing**: Messages are routed through relay servers
4. **Message Delivery**: Recipients decrypt using session keys

## Storage Architecture

Messages are stored temporarily on relay servers and persistently on clients:

- **Relay Storage**: Short-term message queuing
- **Client Storage**: Long-term message history
- **Metadata**: Minimal information for routing

For detailed implementation information, see the [Rust API Documentation](/zoe-relay/rustdoc/).