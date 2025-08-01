# Zoe Client Examples

This directory contains example applications demonstrating how to use the Zoe client library to interact with a Zoe relay server.

## Examples

### Chat Client (`chat_client.rs`)

A real-time chat application that demonstrates:

- Connecting to a Zoe relay server
- Subscribing to channel-based messages
- Publishing messages with channel tags
- Live message updates in a simple CLI interface
- Abbreviated author ID display

#### Usage

First, start a Zoe relay server:

```bash
# From the relay crate directory
cargo run --bin zoe-relay
```

Then run the chat client:

```bash
# Basic usage with default channel "general"
cargo run --example chat_client -- --server-key <HEX_SERVER_PUBLIC_KEY>

# Connect to specific channel
cargo run --example chat_client -- \
  --address 127.0.0.1:4433 \
  --server-key <HEX_SERVER_PUBLIC_KEY> \
  --channel gaming

# Use a specific client key (otherwise random key is generated)
cargo run --example chat_client -- \
  --server-key <HEX_SERVER_PUBLIC_KEY> \
  --client-key <HEX_CLIENT_PRIVATE_KEY> \
  --channel general
```

#### Features

- **Real-time messaging**: Messages appear instantly as they're received
- **Channel-based**: Each channel is isolated using channel tags
- **User identification**: Shows abbreviated author IDs (first 4 bytes as hex)
- **Message history**: Displays the last 20 messages when joining
- **Simple UI**: Clean CLI interface with message timestamps
- **Graceful exit**: Type `/quit` to exit the chat

#### Example Session

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Zoe Chat - Channel: general                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ [14:23:15] a1b2c3d4: Hello everyone! 👋                                    │
│ [14:23:32] e5f6a7b8: Hey there! How's everyone doing?                      │
│ [14:24:01] a1b2c3d4: Great! Just testing this new chat system              │
├─────────────────────────────────────────────────────────────────────────────┤
│ Type your message and press Enter to send. Type '/quit' to exit.           │
└─────────────────────────────────────────────────────────────────────────────┘
> 
```

### MLS Chat Client (`mls_chat_client.rs`)

**🔐 End-to-End Encrypted Chat using Message Layer Security (MLS) - Proof of Concept**

A proof-of-concept implementation demonstrating MLS integration architecture:

- **End-to-End Encryption**: Messages encrypted using MLS protocol
- **Forward Secrecy**: Past messages remain secure even if keys are compromised
- **Group Messaging**: Secure multi-party encrypted conversations
- **Key Management**: Automated MLS key rotation and group state management
- **Out-of-Band Setup**: Secure key package exchange for group joining

#### Quick Start

**Create an encrypted group:**
```bash
cargo run --example mls_chat_client --features mls -- --server-key <HEX_SERVER_PUBLIC_KEY> --user-name Alice create-group
```

**Generate key package (for someone who wants to join):**
```bash
cargo run --example mls_chat_client --features mls -- --server-key <HEX_SERVER_PUBLIC_KEY> --user-name Bob create-group
# This generates bob_keypackage.bin which Bob shares with Alice
```

**Add member to group:**
```bash
cargo run --example mls_chat_client --features mls -- --server-key <HEX_SERVER_PUBLIC_KEY> --user-name Alice add-member --key-package bob_keypackage.bin
# This generates welcome_bob.bin which Alice shares with Bob
```

**Join group with welcome message:**
```bash
cargo run --example mls_chat_client --features mls -- --server-key <HEX_SERVER_PUBLIC_KEY> --user-name Bob join --welcome welcome_bob.bin
```

#### Available Subcommands

- `create-group` - Create a new MLS group and generate key package
- `add-member --key-package <file>` - Add a member to existing group (generates welcome message)
- `join --welcome <file>` - Join a group using a Welcome message
- `chat` - Resume existing chat session

#### MLS Flow Summary

1. **Alice creates group** → `alice_keypackage.bin` (stays with Alice)
2. **Bob generates key package** → `bob_keypackage.bin` (Bob shares with Alice)
3. **Alice adds Bob** → `welcome_bob.bin` (Alice shares with Bob)
4. **Bob joins** → Uses `welcome_bob.bin` to join Alice's group

**📖 For detailed setup instructions and multi-client coordination, see [MLS_CHAT_README.md](./MLS_CHAT_README.md)**

#### Security Features

- **MLS Protocol**: RFC 9420 compliant implementation
- **Cryptographic Authentication**: All messages cryptographically signed and verified
- **Group Membership**: Secure member addition/removal with cryptographic verification
- **Persistent Security**: Group state maintained across sessions
- **Forward Secrecy**: Key rotation ensures past message security

### Blob Client (`blob_client.rs`)

A client for testing the blob storage service that demonstrates:

- Uploading files to the blob store and receiving unique content hashes
- Downloading files by their hash with optional file output
- Round-trip testing to verify upload/download integrity
- Binary content detection and preview functionality

#### Usage

**Upload a file:**
```bash
cargo run --example blob_client -- --server-key <HEX_SERVER_PUBLIC_KEY> upload ./README.md
```

**Download a file:**
```bash
cargo run --example blob_client -- --server-key <HEX_SERVER_PUBLIC_KEY> download <BLOB_HASH> --output ./downloaded_file.md
```

**Test round-trip (upload + download):**
```bash
cargo run --example blob_client -- --server-key <HEX_SERVER_PUBLIC_KEY> test ./test_file.txt
```

#### Available Subcommands

- `upload <file>` - Upload a file to the blob store
- `download <hash> [--output <file>]` - Download a blob by its hash
- `test <file>` - Run round-trip test: upload file then download it back

#### Features

- **Content-Addressed Storage**: Files identified by their cryptographic hash
- **Binary & Text Support**: Handles any file type with intelligent preview
- **Integrity Verification**: Hash-based verification ensures data integrity
- **Flexible Output**: Download to file or display content preview

### Echo Message Client (`echo_message_client.rs`)

A simple test client that:

- Connects to the relay server
- Subscribes to its own messages
- Publishes an echo message
- Verifies the message is received back through the stream

#### Usage

```bash
cargo run --example echo_message_client -- \
  --address 127.0.0.1:4433 \
  --server-key <HEX_SERVER_PUBLIC_KEY>
```

## Getting Server Public Key

The server public key is displayed when you start the relay server. Look for a line like:

```
🔑 Server public key: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
```

## Development

### Adding New Examples

1. Create a new `.rs` file in this directory
2. Add example metadata at the top with `//!` doc comments
3. Use the existing examples as templates
4. Test with `cargo run --example <name>`

### Dependencies

Examples can use additional dependencies beyond the core client library. Add them to the `[dev-dependencies]` section in the client's `Cargo.toml`.

## Architecture

The examples demonstrate the core patterns for Zoe client applications:

1. **Connection**: Establish QUIC connection with mutual TLS authentication
2. **Service Access**: Connect to specific services (messages, blob storage, etc.)
3. **Streaming**: Handle real-time message streams
4. **Publishing**: Send messages through the relay system
5. **Filtering**: Subscribe to specific message types using filters