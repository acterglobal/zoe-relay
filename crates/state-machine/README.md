# Zoe State Machine - Digital Group Assistant (DGA) Protocol

A PDA-like application framework using the `zoe-wire-protocol` to send activity-events as messages between participants to organize state machines of organizational objects.

## Overview

The Digital Group Assistant (DGA) protocol provides an **encrypted group management system** built on top of Zoe's wire protocol. It enables creating and managing private groups where:

- Each group starts with a **CreateGroup event** whose Blake3 message hash becomes the group's unique identifier
- The group ID **is** the root event ID - no separate UUIDs are used
- **All messages are encrypted with AES-256-GCM** using a shared group key
- **No public groups** - everything is encrypted and private
- **Key-based access control** - if you have the encryption key, you can participate
- Subsequent events use the group ID as a **channel tag** for easy subscription and collation
- Group state is maintained as an **event-sourced state machine**
- All events are cryptographically signed and verified

## Key Features

### Encrypted Group Management
- **Create Encrypted Groups**: Establish new groups with AES-256-GCM encryption
- **Key-Based Access**: Anyone with the group key can participate
- **Role-Based Permissions**: Owner, Admin, Moderator, and Member roles within key holders
- **No Traditional Joining**: Access is controlled by key possession, not invitations
- **Inbox System Integration**: Keys distributed via separate secure inbox system (not over wire protocol)

### Encrypted Event-Driven Architecture
- All group interactions are expressed as **encrypted** activity events
- Events are AES-GCM encrypted before being sent over the wire
- Events are immutable and cryptographically signed (after encryption)
- State is derived by decrypting and replaying events in order
- Easy to audit, replicate, and synchronize (for key holders)

### Wire Protocol Integration
- Built on Zoe's secure message protocol
- Uses Event tags with root event IDs as channel identifiers
- Supports subscription filters for real-time updates
- Compatible with Zoe's relay and messaging infrastructure

## Basic Usage

```rust
use zoe_state_machine::{
    GroupManager, CreateGroupConfig, GroupSettings
};

// Create a DGA instance
let mut dga = GroupManager::new();

// Create a group
let config = CreateGroupConfig {
    name: "My Group".to_string(),
    description: Some("A test group".to_string()),
    metadata: HashMap::new(),
    settings: GroupSettings::default(),
};

let result = dga.create_group(config, &creator_key, timestamp)?;

// The encryption key is automatically generated and stored
// In real usage, you'd distribute this key via the inbox system

// The group ID is the Blake3 hash of the CreateGroup message
println!("Group ID/Channel: {:?}", result.group_id);
```

## Event Types

The DGA protocol supports these **encrypted** activity events:

- `CreateGroup` - Establish a new encrypted group (root event, includes key info)
- `LeaveGroup` - Announce departure from group (group identified by channel tag)
- `UpdateGroup` - Modify group settings/metadata (group identified by channel tag)
- `UpdateMemberRole` - Change member permissions (group identified by channel tag) 
- `GroupActivity` - Custom group activities (group identified by channel tag)

**Key Design Changes**:
- **No Join/Invite Events**: Access is controlled by key possession, not invitations
- **All Events Encrypted**: Events are AES-GCM encrypted before transmission
- **Key-Based Participation**: Anyone with the group key can send valid messages
- **Channel Tag Identification**: Group identification happens through wire-protocol channel tags
- **Inbox System**: Encryption keys distributed via separate secure inbox system

## Encrypted Channel-Based Architecture

Each group operates as an **encrypted channel** identified by the Blake3 hash of its CreateGroup message:

1. **Root Event**: The encrypted `CreateGroup` event's message hash becomes the group ID
2. **Channel Tag**: All subsequent encrypted events include `Tag::Event { id: group_id }`
3. **Subscription**: Clients can subscribe to encrypted events for a specific group using this hash
4. **Decryption**: Only participants with the group key can decrypt and process events
5. **Collation**: Encrypted events are easily grouped and ordered by channel
6. **No Embedded IDs**: Events don't contain group IDs - they're identified purely by channel tags
7. **Key Distribution**: Group keys distributed via separate inbox system, never over wire protocol

## Permission System

Encrypted groups support a role-based permission system **within** key holders:

- **Owner**: Full control over group settings and roles
- **Admin**: Update group settings, assign roles (except Owner)
- **Moderator**: Limited administrative functions  
- **Member**: Basic participation rights

**Key Changes**:
- **Primary Access Control**: Possession of the AES encryption key
- **Secondary Permissions**: Role-based permissions enforced after decryption
- **No "Removal"**: Members cannot be truly "removed" (they still have the key)
- **Key Rotation**: Future feature for revoking access by rotating encryption keys

## Examples

See `examples/basic_group_example.rs` for a complete working example that demonstrates:
- Creating an encrypted group (group ID = Blake3 hash of encrypted CreateGroup message)
- AES-256-GCM encryption of all group events
- Key-based access control (anyone with key can participate)
- Processing encrypted events (automatic decryption for key holders)
- Subscribing to encrypted group channels (using the group's Blake3 hash)
- No traditional invitation system (access controlled by key possession)

## Architecture

The DGA protocol consists of:

- **Events** (`events.rs`): Activity event definitions and permissions
- **State** (`state.rs`): Event-sourced group state machine
- **Group** (`group.rs`): High-level DGA management interface
- **Error** (`error.rs`): Error types and handling

This design allows for:
- **Privacy**: All group communications encrypted with AES-256-GCM
- **Scalability**: Event-sourced architecture scales horizontally
- **Consistency**: Deterministic state from encrypted event replay
- **Auditability**: Complete encrypted history of all group activities (for key holders)
- **Key-Based Access**: Simple access control through encryption key possession
- **Interoperability**: Compatible with Zoe's broader ecosystem via encrypted payloads