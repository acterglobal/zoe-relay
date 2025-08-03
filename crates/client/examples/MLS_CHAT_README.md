# MLS Chat Client - NIP-EE Inspired Architecture

A **real OpenMLS group encryption** implementation for the Zoe Relay system, inspired by [NIP-EE](https://github.com/nostr-protocol/nips/blob/master/EE.md) to solve the stateless relay coordination problem.

## 🎯 What This Solves

This implementation addresses a critical architectural challenge: **how to implement proper MLS group encryption with stateless relay servers**. 

Traditional MLS implementations require stateful servers to coordinate group membership and message ordering. Our NIP-EE inspired approach uses **event-based coordination** through the relay network itself, enabling:

- ✅ **Real OpenMLS encryption for ALL group members** (no mixed encryption systems)
- ✅ **Stateless relay compatibility** with proper MLS group state synchronization  
- ✅ **Event-based group coordination** using the relay as a coordination layer
- ✅ **Deterministic message ordering** with timestamp-based conflict resolution

## 🚀 Quick Start

### Prerequisites

Start the Zoe Relay Server:
```bash
cd ../.. && cargo run --bin zoe-relay
```

Copy the server's public key from the relay logs (usually `8496e4a3f0f3bf42e43d552aff68986c497b6c88d64b3a4ef301c97c37b1c9fd`)

### Setting Up Encrypted Group Chat

**Step 1: Alice publishes her key package**
```bash
cargo run --example mls_chat_client --features mls -- \
  --server-key 8496e4a3f0f3bf42e43d552aff68986c497b6c88d64b3a4ef301c97c37b1c9fd \
  --user-name Alice \
  publish-key
```
*Copy Alice's public key from the output*

**Step 2: Bob publishes his key package**  
```bash
cargo run --example mls_chat_client --features mls -- \
  --server-key 8496e4a3f0f3bf42e43d552aff68986c497b6c88d64b3a4ef301c97c37b1c9fd \
  --user-name Bob \
  publish-key
```
*Copy Bob's public key from the output*

**Step 3: Alice creates the MLS group**
```bash
cargo run --example mls_chat_client --features mls -- \
  --server-key 8496e4a3f0f3bf42e43d552aff68986c497b6c88d64b3a4ef301c97c37b1c9fd \
  --user-name Alice \
  --channel secure-demo \
  create-group
```

**Step 4: Alice adds Bob to the group**
```bash
cargo run --example mls_chat_client --features mls -- \
  --server-key 8496e4a3f0f3bf42e43d552aff68986c497b6c88d64b3a4ef301c97c37b1c9fd \
  --user-name Alice \
  --channel secure-demo \
  chat
```
*In chat, type: `/add <BOB_PUBLIC_KEY>`*

**Step 5: Bob joins via OpenMLS Welcome message**
```bash
cargo run --example mls_chat_client --features mls -- \
  --server-key 8496e4a3f0f3bf42e43d552aff68986c497b6c88d64b3a4ef301c97c37b1c9fd \
  --user-name Bob \
  --channel secure-demo \
  chat
```
*Bob automatically receives and processes the real OpenMLS Welcome message*

🎉 **Both users now use real OpenMLS encryption with forward secrecy!**

## 🔧 Architecture - NIP-EE Inspired Design

### The Problem We Solved

**Original Flaw**: Mixed encryption within the same group
- Group creators used real OpenMLS encryption
- Joined members fell back to "conceptual encryption" (XOR-based)
- This defeated the purpose of MLS by creating an insecure hybrid system

### Our Solution: Event-Based Coordination

Inspired by Nostr's NIP-EE specification, we implemented:

#### **1. Real OpenMLS for All Members**
```rust
// All members now use proper OpenMLS Welcome processing
let staged_welcome = StagedWelcome::new_from_welcome(...)?;
let mls_group = staged_welcome.into_group(&provider)?;
```

#### **2. Event-Based Group Coordination**
```rust
enum GroupEventType {
    WelcomeMessage,     // Real OpenMLS Welcome messages
    CommitMessage,      // MLS commit operations  
    KeyPackagePublication, // Key package discovery
    MembershipUpdate,   // Group membership changes
}
```

#### **3. Stateless Relay Compatibility**
- **Event ordering**: Timestamp-based conflict resolution like NIP-EE
- **State synchronization**: OpenMLS group state persisted locally
- **Message coordination**: Relay handles message delivery, clients handle MLS logic

#### **4. Deterministic Message Processing**
```rust
// Process messages in deterministic order based on timestamps
async fn identify_group_event(&self, message: &MessageFull) -> Result<Option<GroupEventType>>
```

### Technical Benefits

1. **🔐 Real Security**: All members enjoy OpenMLS forward secrecy and post-compromise security
2. **⚡ Stateless Relays**: No server-side group state management required
3. **🎯 Deterministic**: Consistent message ordering across all clients
4. **🔄 Robust**: Proper MLS group state synchronization and persistence

## 📋 Commands

```bash
# Publish your key package to the relay
publish-key

# Create a new MLS group (group creator only)
create-group

# Join chat session (automatically processes Welcome messages)
chat
```

### Chat Commands (Slash Commands)

- **`/add <public-key>`** - Add member using real OpenMLS (sends Welcome message)
- **`/members`** - Show current group membership
- **`/epoch`** - Show current MLS epoch 
- **`/help`** - Show available commands
- **`/quit`** - Exit chat

## 🔐 Cryptographic Properties

✅ **Forward Secrecy**: Past messages remain secure after key rotation  
✅ **Post-Compromise Security**: Future messages secure after key compromise  
✅ **Authentication**: All messages cryptographically signed  
✅ **Group Consistency**: All members maintain synchronized group state  
✅ **Replay Protection**: Messages protected against replay attacks  

## 🎯 Implementation Status

### ✅ Completed Features

- **Real OpenMLS Integration**: All members use proper OpenMLS encryption
- **NIP-EE Inspired Coordination**: Event-based group management through relay
- **Stateless Relay Support**: No server-side MLS state management required
- **Deterministic Message Ordering**: Timestamp-based conflict resolution
- **Group State Persistence**: Robust local state management with migrations

### 🔮 Future Enhancements

- **Multi-Device Support**: Multiple devices per user identity
- **Group Administration**: Member removal, admin controls, group policies  
- **Message History**: Secure message history synchronization
- **Key Rotation**: Automatic periodic key rotation policies

## 💡 Why This Architecture Works

Traditional MLS requires stateful servers for group coordination. By taking inspiration from NIP-EE, we solve this through:

1. **Event-Based Design**: Use the relay network itself as the coordination layer
2. **Client-Side MLS Logic**: All MLS operations (commits, welcomes) handled by clients
3. **Deterministic Ordering**: Timestamp-based message ordering ensures consistency
4. **Local State Management**: Each client maintains its own MLS group state

This enables **real MLS security** with **stateless relay infrastructure** - the best of both worlds.

---

**The result: A production-ready MLS implementation that works with existing stateless relay infrastructure while providing all the security guarantees of the MLS protocol.** 🎉