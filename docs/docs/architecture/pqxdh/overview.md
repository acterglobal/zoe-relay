# PQXDH Protocol Overview

The Post-Quantum Extended Diffie-Hellman (PQXDH) protocol is a key agreement protocol that provides post-quantum security for establishing secure communication channels.

## What is PQXDH?

PQXDH extends the traditional Extended Diffie-Hellman (X3DH) protocol with post-quantum cryptographic primitives to ensure security against quantum computer attacks.

## Key Components

### Classical ECDH
- Uses Curve25519 for backwards compatibility
- Provides security against classical computers

### Post-Quantum KEM
- Uses Kyber for quantum-resistant key encapsulation
- Protects against future quantum attacks

### Hybrid Approach
The protocol combines both classical and post-quantum methods for maximum security.

## Security Properties

- **Forward Secrecy**: Past communications remain secure even if long-term keys are compromised
- **Post-Quantum Security**: Resistant to attacks by quantum computers
- **Deniability**: Participants can deny having participated in conversations
- **Asynchronous**: Participants don't need to be online simultaneously

## Implementation

The PQXDH implementation in Zoe Relay provides:

- Secure key generation and exchange
- Session establishment for encrypted messaging
- Ephemeral key management for forward secrecy

For detailed API documentation, see the [Rust API docs](https://acterglobal.github.io/zoe-relay/rustdoc/).