# Wire Protocol Serialization

Zoe Relay uses efficient binary serialization for network communication.

## Serialization Format

The wire protocol uses [Postcard](https://github.com/jamesmunns/postcard) for serialization, which provides:

- Compact binary format
- Zero-copy deserialization where possible
- Strong type safety
- Cross-platform compatibility

## Message Structure

All messages follow a common structure:

<!-- Code example will be added here -->

## Serialization Implementation

The serialization is implemented using Serde:

<!-- Code example will be added here -->

## Versioning

The protocol includes versioning to handle compatibility:

<!-- Code example will be added here -->

## Performance

Postcard serialization provides:
- Fast serialization/deserialization
- Small message sizes
- Minimal memory allocation

For detailed API documentation, see the [Rust API docs](https://acterglobal.github.io/zoe-relay/rustdoc/).