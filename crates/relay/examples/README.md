# Relay Examples

This directory contains example clients demonstrating how to interact with the Zoe Relay Server.

## Echo Message Client Example

The `echo_message_client` example demonstrates the full message streaming workflow:

1. **Connect** to relay server with ed25519 authentication
2. **Subscribe** to message stream with filters
3. **Publish** a message to the relay
4. **Receive** the message back via the stream
5. **Verify** the round-trip was successful

### Usage

First, start the relay server (make sure Redis is running):

```bash
# Terminal 1: Start Redis (if not already running)
redis-server

# Terminal 2: Start the relay server
cargo run --bin zoe-relay
# Note the server's public key from the output
```

Then run the message client:

```bash
# Terminal 3: Run the echo message client
cargo run --example echo_message_client -- \
  --address 127.0.0.1:4433 \
  --server-key <SERVER_PUBLIC_KEY_HEX>
```

### Example Output

```
🚀 Starting message client
🔑 Client public key: a1b2c3d4e5f6...
🌐 Connecting to server: 127.0.0.1:4433
🔐 Server public key: f6e5d4c3b2a1...
✅ Connected to relay server
📡 Selected Messages service (ID: 10)
🔄 Transport established, starting message flow
📬 Sent subscription request for our own messages
📝 Created message with ID: 1234567890abcdef...
📤 Published echo message to relay server
👂 Listening for messages...
🎉 Received message via stream!
   Stream height: 1699123456789-0
   Message ID: 1234567890abcdef...
   Author: a1b2c3d4e5f6...
   Content: "Hello from message client! 🚀"
✅ SUCCESS: Received our own echo message!
   Original content: "Hello from message client! 🚀"
   Received content: "Hello from message client! 🚀"
🔌 Disconnected from server
🎊 Message client test completed successfully!
```

### Command Line Options

- `--address` / `-a`: Server address (default: `127.0.0.1:4433`)
- `--server-key` / `-k`: Server's ed25519 public key (hex encoded, required)
- `--client-key` / `-c`: Client's ed25519 private key (hex encoded, optional - generates random if not provided)

### What It Tests

This example verifies the complete message flow:

✅ **QUIC Connection**: Establishes authenticated QUIC connection to relay server  
✅ **Service Selection**: Connects to Messages service (ID: 10)  
✅ **Subscription**: Sets up message filters to receive own messages  
✅ **Message Publishing**: Creates and publishes a signed message  
✅ **Stream Reception**: Receives the published message via the subscription stream  
✅ **Message Verification**: Verifies the received message matches what was sent  

This demonstrates that the relay server correctly:
- Accepts QUIC connections with ed25519 authentication
- Routes to the Messages service
- Handles subscription requests
- Stores messages in Redis
- Streams messages back to subscribers in real-time
- Maintains message integrity throughout the process