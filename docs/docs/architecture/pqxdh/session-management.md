# PQXDH Session Management

This document describes how PQXDH sessions are managed in Zoe Relay.

## Session Lifecycle

### Session Creation

Sessions are created after successful key exchange between two parties:

<!-- Code example will be added here -->

### Session Storage

Sessions are stored securely with appropriate metadata for later retrieval:

<!-- Code example will be added here -->

### Session Usage

Once established, sessions are used for encrypting and decrypting messages between parties.

### Session Cleanup

Sessions have a limited lifetime and are cleaned up automatically to maintain security.

## Session Security

- Sessions use unique keys derived from the PQXDH handshake
- Forward secrecy is maintained through ephemeral key deletion
- Sessions can be revoked if compromise is suspected

## Performance Considerations

- Session establishment has higher computational cost than message encryption
- Sessions should be reused when possible to amortize setup costs
- Automatic cleanup prevents memory leaks in long-running applications

For implementation details, see the [Rust API documentation](/zoe-relay/rustdoc/).