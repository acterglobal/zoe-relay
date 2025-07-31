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

## Blob Client Example

The `blob_client` example demonstrates the blob store functionality:

1. **Connect** to relay server with ed25519 authentication
2. **Upload** files to the remote blob store
3. **Download** files by their content hash
4. **Verify** round-trip integrity (upload + download + compare)

### Usage

First, start the relay server:

```bash
# Terminal 1: Start the relay server
cargo run --bin zoe-relay
# Note the server's public key from the output
```

Then run the blob client with different operations:

#### Upload a File

```bash
cargo run --example blob_client -- \
  --address 127.0.0.1:4433 \
  --server-key <SERVER_PUBLIC_KEY_HEX> \
  --upload ./README.md
```

#### Download a Blob

```bash
cargo run --example blob_client -- \
  --address 127.0.0.1:4433 \
  --server-key <SERVER_PUBLIC_KEY_HEX> \
  --download <BLOB_HASH> \
  --output ./downloaded_file.md
```

#### Round-trip Test

```bash
cargo run --example blob_client -- \
  --address 127.0.0.1:4433 \
  --server-key <SERVER_PUBLIC_KEY_HEX> \
  --test ./crates/client/examples/test_upload.txt
```

### Example Output

#### Upload Operation
```
🔗 Connected to relay server at 127.0.0.1:4433
🔑 Client public key: a1b2c3d4e5f6...
🗃️  Connected to blob service
📁 Reading file: ./README.md
📊 File size: 1024 bytes
📤 Uploading file to blob store...
✅ File uploaded successfully!
🔗 Blob hash: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
📏 Uploaded 1024 bytes
🔌 Disconnected from server
🎊 Blob client operation completed successfully!
```

#### Download Operation
```
🔗 Connected to relay server at 127.0.0.1:4433
🔑 Client public key: a1b2c3d4e5f6...
🗃️  Connected to blob service
📥 Downloading blob with hash: b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
📊 Downloaded 1024 bytes
💾 Writing to file: ./downloaded_file.md
✅ File saved successfully!
🔌 Disconnected from server
🎊 Blob client operation completed successfully!
```

#### Round-trip Test
```
🔗 Connected to relay server at 127.0.0.1:4433
🔑 Client public key: a1b2c3d4e5f6...
🗃️  Connected to blob service
🔄 Starting round-trip test with file: ./test_upload.txt
📖 Original file size: 512 bytes
📁 Reading file: ./test_upload.txt
📊 File size: 512 bytes
📤 Uploading file to blob store...
✅ File uploaded successfully!
🔗 Blob hash: c3ab8ff13720e3ad87cb6e6e5b4b1b44d1a3b7fb6e8b3c6e2e0c2b4e4a7f8e3d
📏 Uploaded 512 bytes
🔄 Now downloading the uploaded blob...
📥 Downloaded 512 bytes
🎉 SUCCESS: Round-trip test passed!
✅ Original and downloaded data match perfectly
🔗 Blob hash: c3ab8ff13720e3ad87cb6e6e5b4b1b44d1a3b7fb6e8b3c6e2e0c2b4e4a7f8e3d
🔌 Disconnected from server
🎊 Blob client operation completed successfully!
```

### Command Line Options

- `--address` / `-a`: Server address (default: `127.0.0.1:4433`)
- `--server-key` / `-k`: Server's ed25519 public key (hex encoded, required)
- `--client-key` / `-c`: Client's ed25519 private key (hex encoded, optional - generates random if not provided)
- `--upload` / `-u`: Upload a file to the blob store
- `--download` / `-d`: Download a blob by its hash
- `--output` / `-o`: Output file path for downloaded blob (only used with --download)
- `--test` / `-t`: Run round-trip test: upload file then download it back

### What It Tests

This example verifies the complete blob storage workflow:

✅ **QUIC Connection**: Establishes authenticated QUIC connection to relay server  
✅ **Service Selection**: Connects to Blob service (ID: 20)  
✅ **File Upload**: Uploads arbitrary files to content-addressed storage  
✅ **Hash Generation**: Receives cryptographic hash for uploaded content  
✅ **File Download**: Retrieves files by their content hash  
✅ **Data Integrity**: Verifies downloaded data matches original exactly  
✅ **Binary Support**: Handles both text and binary files correctly  

This demonstrates that the relay server correctly:
- Accepts QUIC connections with ed25519 authentication
- Routes to the Blob service
- Stores files in content-addressed storage
- Generates consistent cryptographic hashes
- Retrieves files by hash
- Maintains file integrity throughout upload/download cycles