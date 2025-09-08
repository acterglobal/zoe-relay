# PQXDH Key Exchange

This document describes the key exchange process in the PQXDH protocol.

## Key Exchange Flow

The PQXDH key exchange involves several steps to establish a shared secret between two parties.

### 1. Key Generation

Each participant generates their key pairs for both classical and post-quantum cryptography:

<!-- Code example will be added here -->

### 2. Initial Message

The initiator creates an initial PQXDH message containing their public keys and encrypted data:

<!-- Code example will be added here -->

### 3. Response Processing

The responder processes the initial message and generates a response with their own keys.

### 4. Shared Secret Derivation

Both parties derive the same shared secret using the exchanged keys:

<!-- Code example will be added here -->

## Security Considerations

- Keys should be generated using cryptographically secure random number generators
- Ephemeral keys should be deleted after use to ensure forward secrecy
- The protocol includes protection against replay attacks

## Error Handling

The implementation includes comprehensive error handling for:

- Invalid key formats
- Cryptographic failures
- Protocol violations

For complete implementation details, refer to the [Rust API documentation](https://acterglobal.github.io/zoe-relay/rustdoc/).