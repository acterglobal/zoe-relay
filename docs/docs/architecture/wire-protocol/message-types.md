# Wire Protocol Message Types

This document describes the various message types used in the Zoe Relay wire protocol.

## Core Message Types

### PQXDH Messages

Messages for post-quantum key exchange:

<!-- Code example will be added here -->

### Invitation Messages

Messages for group invitation flow:

<!-- Code example will be added here -->

### Content Messages

Messages for encrypted content:

<!-- Code example will be added here -->

## Message Routing

Messages are routed based on their type and destination:

<!-- Code example will be added here -->

## Error Handling

The protocol includes comprehensive error types:

<!-- Code example will be added here -->

## Message Validation

All messages undergo validation before processing:

- Signature verification
- Format validation
- Protocol version checks
- Size limits

For complete message specifications, see the [Rust API documentation](/zoe-relay/rustdoc/).