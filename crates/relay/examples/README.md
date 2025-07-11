# Zoeyr Relay Examples

This directory contains working examples that demonstrate the complete end-to-end message relay functionality of the Zoeyr system.

## Overview

The examples demonstrate:
- **Relay Server** - Accepts text messages and stores them in Redis
- **Send Client** - Sends messages to the relay server
- **Listen Client** - Listens for messages from Redis storage

## Prerequisites

Before running the examples, ensure you have:

1. **Redis Server** running
2. **Rust toolchain** installed
3. **Network access** between components

### Starting Redis

```bash
# Using Docker (recommended)
docker run -d --name redis -p 6379:6379 redis:7

# Or using docker-compose from project root
docker-compose up -d redis

# Verify Redis is running
docker exec redis redis-cli ping  # Should return PONG
```

## Examples

### 1. Relay Server (`relay_server.rs`)

A server that accepts text messages via QUIC and stores them in Redis.

**Features:**
- Generates or loads ed25519 server keys
- Accepts QUIC connections with TLS identity verification
- Stores messages in Redis with streaming support
- Prints server public key for clients

**Usage:**
```bash
# Start server (generates new key)
cargo run --example relay_server

# Start server with specific key
cargo run --example relay_server -- --private-key <HEX_KEY>

# Start server on different address/port
cargo run --example relay_server -- --addr 127.0.0.1:8080

# Start server with custom Redis URL
cargo run --example relay_server -- --redis-url redis://localhost:6379
```

**Example Output:**
```
🚀 Starting Zoeyr Relay Server
📋 Server Address: 127.0.0.1:4433
🔑 Server Public Key: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
💾 Redis storage initialized

🚀 Zoeyr Relay Server is now running!
   📡 Server will show detailed logs when messages are stored
   💾 Redis storage backend connected
   🔄 Ready to process client connections

🔑 IMPORTANT: Server Public Key for clients:
   a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
   Copy this key to connect clients!

# When a message is received and stored:
📥 Received message for storage (156 bytes)
📝 Storing message with ID: 789abc123def456789012345678901234567890abcdef123456789012345678
✅ Message stored successfully!
   Message ID: 789abc123def456789012345678901234567890abcdef123456789012345678
   Stream ID: 1640995200000-0
   Author: f1e2d3c4b5a6987012345678901234567890fedcba1234567890fedcba123456
   Content preview: "Hello, Zoeyr!"
```

### 2. Send Client (`relay_send_client.rs`)

A client that sends text messages to the relay server.

**Features:**
- Verifies server identity via TLS certificate
- Sends text messages or health checks
- Handles ed25519 key verification

**Usage:**
```bash
# Send a message (requires server public key)
cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --message "Hello, Zoeyr!"

# Send health check
cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --health-check

# Use specific client key
cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --private-key <CLIENT_HEX_KEY> \
  --message "Authenticated message"

# Connect to different server
cargo run --example relay_send_client -- \
  --server 127.0.0.1:8080 \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --message "Hello from client"
```

**Example Output:**
```
🚀 Zoeyr QUIC+Tarpc Send Client
📋 Server: 127.0.0.1:4433
🔑 Expected server public key: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
🔗 Connecting to relay server at 127.0.0.1:4433
✅ Server TLS certificate contains expected ed25519 key!
✅ Connected! TLS handshake verified server identity.
📤 Sending message via QUIC+tarpc: Hello, Zoeyr!
📤 Sending store_message request via tarpc

🎉 SUCCESS: Message stored on relay server!
   📦 Storage ID: 1640995200000-0
   🆔 Message ID: 789abc123def456789012345678901234567890abcdef123456789012345678
   📝 Content: "Hello, Zoeyr!"
   👤 Author: f1e2d3c4b5a6987012345678901234567890fedcba1234567890fedcba123456

✨ Message relay operation completed!
   Check the server logs to see storage confirmation.
```

### 3. Listen Client (`relay_listen_client.rs`)

A client that listens for messages from Redis storage.

**Features:**
- Connects directly to Redis (no QUIC needed)
- Supports message filtering by authors, users, channels
- Can listen for new messages or retrieve historical ones
- Displays full message details

**Usage:**
```bash
# Listen for messages from specific author (server public key)
cargo run --example relay_listen_client -- \
  --authors <SERVER_PUBLIC_KEY>

# Listen for messages and follow new ones
cargo run --example relay_listen_client -- \
  --authors <SERVER_PUBLIC_KEY> \
  --follow

# Listen with multiple filters
cargo run --example relay_listen_client -- \
  --authors <PUB_KEY1>,<PUB_KEY2> \
  --users <USER_ID1>,<USER_ID2> \
  --limit 20

# Listen starting from specific message
cargo run --example relay_listen_client -- \
  --authors <SERVER_PUBLIC_KEY> \
  --since <MESSAGE_ID>

# Use custom Redis URL
cargo run --example relay_listen_client -- \
  --redis-url redis://localhost:6379 \
  --authors <SERVER_PUBLIC_KEY>
```

**Example Output:**
```
🎧 Starting to listen for messages...
📋 Client public key: f1e2d3c4b5a6987012345678901234567890fedcba1234567890fedcba123456
🔍 Listening with filters applied:
   👥 Authors: 1 keys
📨 Received message: 789abc123def456789012345678901234567890abcdef123456789012345678 at height: 1640995200000-0

┌─────────────────────────────────────────────────────
│ 📨 Message ID: 789abc123def456789012345678901234567890abcdef123456789012345678
│ 👤 Author: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
│ ⏰ Timestamp: 1640995200
│ 📍 Stream Position: 1640995200000-0
│ 🏷️  Kind: Regular
│
│ 💬 Content: Hello, Zoeyr!
└─────────────────────────────────────────────────────

✅ Finished listening - received 1 messages
```

## Complete End-to-End Demo

Here's how to run a complete demonstration:

### Step 1: Start Redis
```bash
docker run -d --name redis -p 6379:6379 redis:7
```

### Step 2: Start the Relay Server
```bash
# Terminal 1
cargo run --example relay_server

# Note the server public key from output, e.g.:
# 🔑 Server Public Key: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
```

### Step 3: Start the Listener Client
```bash
# Terminal 2 - Replace <SERVER_PUBLIC_KEY> with actual key from Step 2
cargo run --example relay_listen_client -- \
  --authors <SERVER_PUBLIC_KEY> \
  --follow
```

### Step 4: Send Messages
```bash
# Terminal 3 - Replace <SERVER_PUBLIC_KEY> with actual key from Step 2
cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --message "Hello, world!"

cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --message "This is a test message"

# Send health check
cargo run --example relay_send_client -- \
  --server-public-key <SERVER_PUBLIC_KEY> \
  --health-check
```

You should see:
- **Terminal 1** (Server): Connection logs and detailed message storage confirmations with storage IDs
- **Terminal 2** (Listener): Real-time message display as they arrive
- **Terminal 3** (Sender): Success confirmations with message IDs and storage confirmation

### Message Storage Confirmation

When a message is successfully sent and stored, you'll see detailed logs on both client and server:

**Client Output:**
```
🎉 SUCCESS: Message stored on relay server!
   📦 Storage ID: 1640995200000-0
   🆔 Message ID: 789abc123def456789012345678901234567890abcdef123456789012345678
   📝 Content: "Hello, world!"
   👤 Author: f1e2d3c4b5a6987012345678901234567890fedcba1234567890fedcba123456
```

**Server Output:**
```
2024-01-12T10:30:45.123456Z  INFO relay_server: 🔗 New QUIC connection from 127.0.0.1:54321
2024-01-12T10:30:45.123789Z  INFO relay_server: 🎯 Handling QUIC connection, waiting for streams...
2024-01-12T10:30:45.124012Z  INFO relay_server: 📡 New bidirectional stream accepted
2024-01-12T10:30:45.124234Z  INFO relay_server: 🔧 Setting up tarpc transport over QUIC stream
2024-01-12T10:30:45.124456Z  INFO zoeyr_message_store::service: 📥 Received message for storage (156 bytes)
2024-01-12T10:30:45.124678Z  INFO zoeyr_message_store::service: 📝 Storing message with ID: 789abc123def456789012345678901234567890abcdef123456789012345678
2024-01-12T10:30:45.124890Z  INFO zoeyr_message_store::service: ✅ Message stored successfully!
2024-01-12T10:30:45.124912Z  INFO zoeyr_message_store::service:    Message ID: 789abc123def456789012345678901234567890abcdef123456789012345678
2024-01-12T10:30:45.124934Z  INFO zoeyr_message_store::service:    Stream ID: 1640995200000-0
2024-01-12T10:30:45.124956Z  INFO zoeyr_message_store::service:    Author: f1e2d3c4b5a6987012345678901234567890fedcba1234567890fedcba123456
2024-01-12T10:30:45.124978Z  INFO zoeyr_message_store::service:    Content preview: "Hello, world!"
```

This makes it easy to confirm that messages are properly stored and to correlate client requests with server-side storage operations.

**Note:** The examples are configured to show INFO level logs, which include detailed connection handling and message processing information. The timestamps and module names help trace the complete flow from QUIC connection establishment through message storage.

## Key Features Demonstrated

### 🔒 Security
- **TLS Identity Verification**: Server identity verified via ed25519 keys in TLS certificates
- **QUIC Transport**: Modern, secure transport with connection migration support
- **Message Integrity**: Messages signed and verified using ed25519 cryptography

### 📨 Messaging
- **Text Messages**: Simple string content with full metadata
- **Message IDs**: Unique Blake3 hashes for each message
- **Timestamps**: Unix timestamps for message ordering
- **Tags**: Support for event, user, and channel tagging (unused in basic example)
- **JSON Serialization**: Uses JSON for message serialization (compatible with serde tagging)

### 🔄 Real-time Streaming
- **Redis Streams**: Efficient message distribution and persistence
- **Message Filtering**: Filter by authors, users, channels, or combinations
- **Historical Retrieval**: Access past messages with pagination
- **Live Following**: Real-time message updates as they arrive

### 🛠️ Operational
- **Health Checks**: Server health monitoring via dedicated endpoint
- **Logging**: Comprehensive logging with emoji indicators
- **Error Handling**: Graceful error handling and reporting
- **Configuration**: Flexible configuration via command-line arguments

## Architecture Notes

### Message Flow
1. **Send Client** creates `MessageFull<String>` with proper signing → **QUIC/TLS** → **Relay Server** forwards to **Redis Storage**
2. **Redis Storage** → **Redis Streams** → **Listen Client**

### Key Architectural Changes
- **Client-Side Message Creation**: Send clients now create proper `MessageFull<String>` wire protocol messages with signing and timestamps
- **Server as Pure Relay**: The server receives `MessageFull` messages and forwards them to Redis storage without modification
- **Shared Connection Utilities**: QUIC connection and TLS verification logic is shared via the relay library
- **JSON Network Protocol**: All QUIC communication uses JSON serialization for compatibility with serde's external tagging

### Security Model
- **Layer 1**: TLS/QUIC provides transport security and server identity verification
- **Layer 2**: Application-level message signing (for message integrity) - done by clients
- **No Dynamic Auth**: These examples use simple message relay without per-operation authentication

### Storage Model
- **Redis Key-Value**: Messages stored by Blake3 hash ID
- **Redis Streams**: Real-time message distribution with `XADD`/`XREAD`
- **Message Indexing**: Authors, users, channels indexed for efficient filtering

### Serialization Format
- **JSON over QUIC**: Examples use JSON serialization for `ProtocolMessage` types
- **PostCard for Wire Messages**: The underlying `MessageFull` types use PostCard for efficiency
- **Serde Tagging**: `ProtocolMessage` uses `#[serde(tag = "type")]` which requires JSON/bincode
- **Cross-Language**: JSON format enables easy client implementation in other languages

## Troubleshooting

### Connection Issues
- **Server Key Mismatch**: Ensure you're using the correct server public key
- **Network**: Check that server is reachable on the specified address/port
- **TLS**: Certificate verification failures usually indicate key mismatches

### Redis Issues
- **Connection Refused**: Ensure Redis is running and accessible
- **Empty Results**: Check that messages exist and filters are correct
- **Performance**: Large message volumes may require Redis tuning

### Message Issues
- **Not Received**: Check that listener filters match message attributes
- **Duplicates**: Messages with identical content+timestamp+key create same ID
- **Missing**: Messages may expire based on their `Kind` (ephemeral messages)

### Serialization Issues
- **PostCard "never implement" Error**: `ProtocolMessage` uses serde tagging incompatible with PostCard
  - **Solution**: Use JSON serialization (`serde_json`) instead of PostCard for `ProtocolMessage`
  - **Background**: PostCard doesn't support `#[serde(tag = "type")]` externally tagged enums
  - **Note**: Wire protocol `MessageFull` types still use PostCard for efficiency

## Next Steps

To extend these examples:

1. **Add Authentication**: Implement dynamic per-operation authentication
2. **Add Encryption**: Implement end-to-end message encryption
3. **Add File Transfer**: Support for binary file content
4. **Add Group Chat**: Implement channel-based messaging
5. **Add Web UI**: Create a web interface for easier interaction
6. **Add Mobile Client**: Create mobile clients using the same protocol

The examples provide a solid foundation for building more complex messaging applications with the Zoeyr protocol. 