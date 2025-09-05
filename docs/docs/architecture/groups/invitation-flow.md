# Group Invitation Flow

## Overview

This document describes the architecture and message flow for inviting users into a group. The invitation process uses ephemeral PQXDH inboxes to establish secure connections between users and facilitate group membership.


## Invitation Flow

### Participants
- **Charly**: The inviting user (existing group member)
- **Denis**: The invited user (new group member)

### Step-by-Step Process

#### 1. Ephemeral Inbox Creation (Denis)
- Denis creates a new **ephemeral PQXDH inbox** specifically for receiving this invitation
- Denis generates a QR code containing:
  - User identifier (Denis's identity)
  - Ephemeral inbox identifier
  - Relay information (which relays the inbox can be found on)
- Denis shares the QR code with Charly (out-of-band)

#### 2. QR Code Scanning (Charly)
- Charly scans Denis's QR code using their client
- Charly extracts the invitation information:
  - Denis's user ID (invitee)
  - Denis's ephemeral inbox ID
  - Relay endpoints

#### 3. PQXDH Session Establishment (Charly)
- Charly connects to the specified relays (if not yet connected)
- Charly fetches Denis's ephemeral inbox PQXDH prekey bundle using the provided inbox ID
- Charly initiates PQXDH key agreement by sending a **PqxdhInitialMessage**.

#### 4. Verification Handshake (Denis)
- Denis monitors their ephemeral inbox for incoming PQXDH messages
- Denis receives and decrypts Charly's PqxdhInitialMessage using the ephemeral inbox private keys
- Denis sees this is a verification handshake request (NOT sensitive group data)
- Denis extracts the shared PQXDH session secret

#### 5. Cryptographic Verification Display (Both Parties)
- **Both parties derive identical verification data from the shared PQXDH secret**:
  - Use Blake3 to derive a verification key: `Blake3(shared_key, "PQXDH-VERIFICATION-v1", 16)`
  - Map the 16 bytes to a sequence of 6 emojis from a predefined set (e.g., 🔑🌟🚀🎯🌈🔒)
  - **Both devices display the same 6 emoji sequence derived from the shared secret**
- Users manually verify the emoji sequences match (cryptographic verification)

#### 6. User Confirmation (Both Users)
- Both Charly and Denis see the same 6 emoji sequence derived from the shared PQXDH secret
- Users manually verify the emoji sequences match (cryptographic verification)

#### 7. Handshake Response (Denis)
- **ONLY after user confirms emoji sequences match (or rejects if they don't)**:
  - Denis sends a **HandshakeResponse** message via `PqxdhSessionMessage` (sequence: 1)
  - Contains `accepted: true` if verification successful, `accepted: false` if rejected

#### 8. Group Data Sharing (Charly)
- **ONLY if handshake response has `accepted: true`**:
  - Charly sends the sensitive group information via **GroupInvitationData** message:
    - Group's shared tag (hash of initial creation message)
    - Group's shared AES key 
    - Inviter profile and group details

#### 9. Group Integration (Denis)
- Denis receives the group information from Charly via the secure PQXDH session
- Denis uses the shared AES key to decrypt and catch up on existing group data
- Denis synchronizes with the group's message history
- Denis sends a **profile set event** to the group to announce their membership
- Other group members are notified of Denis's joining through the profile set event

#### 10. Cleanup
- The ephemeral PQXDH inbox is no longer needed and can be discarded
- The PQXDH session is terminated after successful group data transfer
- Normal group communication proceeds using the shared tag and AES key

## Security Considerations

### Ephemeral Inbox Security
- Ephemeral inboxes are temporary and single-use
- They provide a secure channel for the initial handshake
- Once the invitation is complete, the ephemeral inbox is discarded

### PQXDH Security
- **Post-Quantum Resistance**: Uses ML-KEM 768 for quantum-resistant key encapsulation
- **Forward Secrecy**: Ephemeral keys and one-time prekeys provide perfect forward secrecy
- **Hybrid Security**: Combines X25519 (classical) and ML-KEM (post-quantum) for defense in depth
- The shared AES key is transmitted through the secure PQXDH session channel

### Authentication and Verification
- Users authenticate each other through their established identity keys
- **Cryptographic emoji verification** derived from shared PQXDH secret prevents MITM attacks
- Both parties derive identical emoji sequences from the shared secret using HKDF
- A MITM attacker cannot forge the correct emoji sequence without the shared secret
- Users must manually verify the emoji sequences match on both devices before proceeding
- PQXDH signatures ensure message authenticity and integrity
- Profile set events provide transparency about new group members

## Protocol Messages

### 1. Initial Handshake Request (Charly → Denis)
**Message Type**: `PqxdhInitialMessage`
**Purpose**: Establish PQXDH session and request verification handshake

**Payload Structure**:
```rust
<!-- Code example will be added here -->
```

**Enums**:
```rust
<!-- Code example will be added here -->
```
```rust
<!-- Code example will be added here -->
```

**Security**: Contains NO sensitive group information  
**Note**: Initiator identity already provided in outer `PqxdhInitialMessage.initiator_identity`

### Cryptographic Verification (Both Parties)
Both parties derive the same emoji sequence from the shared PQXDH secret using secure key derivation.

**Implementation**:
```rust
<!-- Code example will be added here -->
```

**Emoji Set**:
```rust
<!-- Code example will be added here -->
```

**Security**: 64^6 = 68,719,476,736 possible combinations (~68.7 billion)

#### **Step-by-Step Emoji Derivation Algorithm**

**Input**: 32-byte BLAKE3 fingerprint  
**Output**: 6 emojis from the 64-emoji set

**Algorithm**:
1. **Divide fingerprint into 6 chunks**:
   - Chunk 0: bytes [0..5]   (5 bytes)
   - Chunk 1: bytes [5..10]  (5 bytes) 
   - Chunk 2: bytes [10..15] (5 bytes)
   - Chunk 3: bytes [15..20] (5 bytes)
   - Chunk 4: bytes [20..25] (5 bytes)
   - Chunk 5: bytes [25..32] (7 bytes, last chunk gets remainder)

2. **For each chunk, compute emoji index**:
   ```
   index = 0
   for each byte in chunk:
       index = index + (byte_value << (byte_position * 8))
   emoji_index = index % 64
   ```

3. **Select emoji**: `emoji_set[emoji_index]`

**Example** (with hypothetical fingerprint bytes):
```
Fingerprint: [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, ...]

Chunk 0: [0x1A, 0x2B, 0x3C, 0x4D, 0x5E]
index = 0x1A + (0x2B << 8) + (0x3C << 16) + (0x4D << 24) + (0x5E << 32)
index = 26 + 11008 + 3932160 + 1291845632 + 404620279808
index = 406926259634
emoji_index = 406926259634 % 64 = 18
emoji = emoji_set[18] = "🍎"
```

**Language-Agnostic Pseudocode**:
```
function derive_emoji_sequence(fingerprint_32_bytes, emoji_set_64):
    emojis = []
    
    for i in range(6):
        start = i * 5
        end = min(start + 5, 32)
        chunk = fingerprint_32_bytes[start:end]
        
        index = 0
        for j, byte in enumerate(chunk):
            index += byte << (j * 8)
        
        emoji_index = index % 64
        emojis.append(emoji_set_64[emoji_index])
    
    return emojis
```

### Security Considerations

#### **Collision Resistance**
- **Emoji Set Size**: 64 distinct, visually different emojis
- **Sequence Length**: 6 emojis per verification
- **Total Combinations**: 64^6 = 68,719,476,736 (~68.7 billion possible sequences)
- **Collision Probability**: 1 in 68.7 billion chance of accidental match
- **MITM Attack Success Rate**: 0.000000001456% (practically impossible)

#### **Comparison with Other Approaches**
- **6-digit PIN**: 10^6 = 1 million combinations (68,719x weaker)
- **4-word BIP39**: 2048^4 = 17.6 trillion combinations (256x stronger, but harder to verify)
- **6 emojis from 16**: 16^6 = 16.7 million combinations (4,115x weaker than our approach)

#### **Cryptographic Security**
- **Key Recovery Impossible**: Even if an attacker knows the emoji mapping, they only see 6 bytes of a 32-byte derived fingerprint
- **One-Way Function**: BLAKE3 is cryptographically one-way - cannot derive the original key from the output
- **Domain Separation**: The verification fingerprint uses different BLAKE3 context than encryption keys
- **Insufficient Entropy for Key Recovery**: 48 bits is far too little information to recover a 256-bit key (2^208 times insufficient)

#### **Usability vs Security Trade-off**
- **Human Verification**: 6 emojis is manageable for users to compare accurately
- **Error Detection**: Visual differences between 64 distinct emojis are easily spotted
- **False Positive Rate**: 1 in 68.7 billion is acceptable for interactive verification
- **Single Use**: Each PQXDH session generates unique verification sequence

### 2. Handshake Response (Denis → Charly)
**Message Type**: `PqxdhSessionMessage` (sequence: 1)
**Purpose**: Accept or reject invitation after emoji verification

**Payload Structure**:
```rust
<!-- Code example will be added here -->
```

**Trigger**: Sent ONLY after users confirm emoji sequences match (or reject if they don't)

### 3. Group Information Transfer (Charly → Denis)
**Message Type**: `PqxdhSessionMessage` (sequence: 2)
**Purpose**: Transfer sensitive group data after verification

**Payload Structure**:
```rust
<!-- Code example will be added here -->
```

**Supporting Types**:
```rust
<!-- Code example will be added here -->
```
```rust
<!-- Code example will be added here -->
```

**Security**: Sent ONLY after handshake confirmation received

### 4. Group Join Event (Denis → Group)
**Message Type**: Group message (outside PQXDH session)
**Purpose**: Announce membership to existing group members

**Payload Structure**:
```rust
<!-- Code example will be added here -->
```

## Ephemeral Protocol IDs

For enhanced privacy and unlinkability, group invitations use randomized protocol IDs:

**Protocol Range**:
```rust
<!-- Code example will be added here -->
```

**ID Generation**:
```rust
<!-- Code example will be added here -->
```

Each invitation session uses a random ID from the 1000-value range, making it impossible to link different invitation attempts to the same user or group.

## Flow Diagram

```
Charly (Inviter)                    Denis (Invitee)
       |                                  |
       |                                  |  1. Create ephemeral PQXDH inbox
       |                                  |  2. Generate QR code
       |                                  |
       |          QR Code                 |
       |  3. Scan QR code    <----------  |
       |  4. Fetch PQXDH prekeys          |
       |  5. Send PqxdhInitialMessage     |
       |  ------ PqxdhInitialMessage ---> |  6. Receive handshake request
       |         (handshake only)         |     (NO sensitive data)
       |                                  |  7. Derive shared secret
       |  8. Derive shared secret         |  9. Derive shared secret
       |                                  |
       |  10. Derive emoji verification   |  11. Derive emoji verification
       |      from shared secret          |      from shared secret
       |                                  |
       |  [Both devices show same emojis: 🔑🌟🚀🎯🌈🔒]
       |  12. User verifies emojis match  |  13. User verifies emojis match
       |                                  |  14. Send handshake response
       |                                  |  ------ PqxdhSessionMessage (seq: 1)
       |  15. Receive response            |         (accepted: true/false)
       |  <------ PqxdhSessionMessage     |
       |                                  |
       |  16. Send group data (IF ACCEPTED)|
       |  ------ PqxdhSessionMessage ---> |  17. Receive group data
       |         (seq: 2, sensitive info) |
       |                                  |  18. Catch up on group
       |                                  |  19. Send profile event
       |  <------ profile_set_event       |
       |                                  |
    Group Members                    Group Members
       |  <------ profile_set_event       |
       |         (broadcast)              |
```

## Implementation Notes

### PQXDH Protocol Requirements
- Ephemeral PQXDH inboxes should have a reasonable timeout (e.g., 24 hours)
- Use [`PqxdhInboxProtocol::Ephemeral`](../../../wire-protocol/src/message/store_key.rs#L20) with random IDs
- Generate sufficient one-time prekeys to handle multiple concurrent invitations
- Implement proper key rotation for signed prekeys
- Use [`generate_ephemeral_group_invite_id`](../../../wire-protocol/src/invitation.rs#L90-L95) for unlinkable protocol IDs

### Cryptographic Verification Security
- **Key Derivation Safety**: Use BLAKE3 to derive a separate 256-bit verification fingerprint from the shared secret
- **High Collision Resistance**: 64^6 = 68.7 billion possible emoji combinations
- **Limited Information Exposure**: Only 48 bits (6 bytes) of the fingerprint are used for emojis - insufficient to recover the 256-bit key
- **One-Way Security**: BLAKE3 is cryptographically one-way - emojis cannot be reverse-engineered to the original key
- **Domain Separation**: Verification fingerprint uses different BLAKE3 context than encryption keys
- **Codebase Consistency**: Uses BLAKE3 like the rest of the project for better maintainability and performance

#### **Emoji Set Selection Criteria**
- **Visual Distinction**: 64 emojis chosen for maximum visual differences
- **Category Diversity**: Objects, animals, food, activities to avoid confusion
- **Cross-Platform Consistency**: Common emojis that render similarly across devices
- **Accessibility Friendly**: High contrast, distinct shapes for users with visual impairments
- **Cultural Neutrality**: Avoid emojis with cultural or religious significance

#### **Implementation Security**
- **Display Security**: Show emoji sequence prominently with clear instructions
- **MITM Resistance**: Attackers cannot forge the correct sequence without the shared secret
- **Accessibility**: Consider audio descriptions, high-contrast mode, alternative symbols
- **No Timeout**: Verification data is derived deterministically - no expiration needed

### Network and Error Handling
- The invitation process should handle network interruptions gracefully
- Implement retry logic for PQXDH message delivery
- Handle cases where ephemeral inboxes are not found or expired
- Provide clear error messages for failed verification attempts

### Performance Considerations
- Group catch-up should be efficient for large groups with extensive history
- Consider incremental sync for groups with many messages
- Profile set events should be rate-limited to prevent spam
- Cache PQXDH prekey bundles to reduce relay load

### Security Best Practices
- Zeroize PQXDH private keys and session secrets when no longer needed
- Implement invitation expiration for security
- Log security-relevant events (failed verifications, expired codes)
- Consider implementing invitation quotas to prevent abuse
