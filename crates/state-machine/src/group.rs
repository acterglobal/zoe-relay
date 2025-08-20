// ChaCha20-Poly1305 and AES-GCM functionality moved to crypto module
use blake3::Hash;
use zoe_wire_protocol::{KeyPair, VerifyingKey};
// Random number generation imports removed - no longer needed
// Temporary import for Ed25519 workaround in create_role_update_event

use zoe_app_primitives::{GroupInfo, IdentityRef};
// Random number generation moved to wire-protocol crypto module
use std::collections::HashMap;

use zoe_wire_protocol::{Kind, Message, MessageFull, Tag};

use crate::{
    DgaError, DgaResult, GroupActivityEvent, GroupEncryptionState, GroupKeyInfo, GroupRole,
};

// Import the unified GroupState from app-primitives
use zoe_app_primitives::{GroupState, GroupStateError};
use zoe_wire_protocol::{ChaCha20Poly1305Content, Content, EncryptionKey, MnemonicPhrase};

/// Digital Group Assistant - manages encrypted groups using the wire protocol
#[derive(Debug)]
pub struct DigitalGroupAssistant {
    /// All group states managed by this DGA instance
    /// Key is the Blake3 hash of the CreateGroup message (which serves as both group ID and root event ID)
    pub(crate) groups: HashMap<Hash, GroupState>,
    /// Encryption keys for groups (never sent over wire - obtained via inbox system)
    pub(crate) group_keys: HashMap<Hash, GroupEncryptionState>,
}

/// Result of creating a new group
#[derive(Debug, Clone)]
pub struct CreateGroupResult {
    /// The created group's unique identifier (Blake3 hash of the CreateGroup message)
    /// This is also the root event ID used as channel tag for subsequent events
    pub group_id: Hash,
    /// The full message that was created
    pub message: MessageFull,
}

// Helper function removed - now using KeyPair enum which provides direct access to verifying key

impl DigitalGroupAssistant {
    /// Create a new DGA instance
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            group_keys: HashMap::new(),
        }
    }

    /// Add an encryption key for a group (obtained via inbox system)
    pub fn add_group_key(&mut self, group_id: Hash, key: EncryptionKey) {
        let encryption_state = GroupEncryptionState {
            current_key: key,
            previous_keys: Vec::new(),
        };
        self.group_keys.insert(group_id, encryption_state);
    }

    /// Generate a new encryption key for a group (ChaCha20-Poly1305)
    pub fn generate_group_key(timestamp: u64) -> EncryptionKey {
        EncryptionKey::generate(timestamp)
    }

    /// Create a group key from a mnemonic phrase
    pub fn create_key_from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        group_name: &str,
        timestamp: u64,
    ) -> DgaResult<EncryptionKey> {
        let context = format!("dga-group-{group_name}");

        EncryptionKey::from_mnemonic(mnemonic, passphrase, &context, timestamp)
            .map_err(|e| DgaError::CryptoError(format!("Key derivation failed: {e}")))
    }

    /// Recover a group key from a mnemonic phrase with specific salt
    pub fn recover_key_from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        group_name: &str,
        salt: &[u8; 32],
        timestamp: u64,
    ) -> DgaResult<EncryptionKey> {
        let context = format!("dga-group-{group_name}");

        EncryptionKey::from_mnemonic_with_salt(mnemonic, passphrase, &context, salt, timestamp)
            .map_err(|e| DgaError::CryptoError(format!("Key recovery failed: {e}")))
    }

    /// Create a new encrypted group, returning the root event message to be sent
    pub fn create_group(
        &mut self,
        create_group: zoe_app_primitives::CreateGroup,
        encryption_key: Option<EncryptionKey>,
        creator: &KeyPair,
        timestamp: u64,
    ) -> DgaResult<CreateGroupResult> {
        // Generate or use provided encryption key
        let encryption_key = encryption_key.unwrap_or_else(|| Self::generate_group_key(timestamp));

        // Get the group info from the CreateGroup object and update its key_info
        let mut group_info = create_group.into_group_info();

        // Update the key info with the actual encryption key metadata
        group_info.key_info = GroupKeyInfo::ChaCha20Poly1305 {
            key_id: encryption_key.key_id.clone(),
            derivation_info: encryption_key.derivation_info.clone().unwrap_or_else(|| {
                // Default derivation info if none provided
                zoe_wire_protocol::crypto::KeyDerivationInfo {
                    method: zoe_wire_protocol::crypto::KeyDerivationMethod::ChaCha20Poly1305Keygen,
                    salt: vec![],
                    argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
                    context: "dga-group-key".to_string(),
                }
            }),
        };

        let event = GroupActivityEvent::UpdateGroup(group_info.clone());

        // Encrypt the event before creating the wire protocol message
        let encrypted_payload = self.encrypt_group_event(&event, &encryption_key)?;

        // Create the wire protocol message with encrypted payload
        let message = Message::new_v0_encrypted(
            encrypted_payload,
            creator.public_key(),
            timestamp,
            Kind::Regular, // Group creation events should be permanently stored
            vec![],        // No tags needed for the root event
        );

        // Sign the message and create MessageFull
        let message_full = MessageFull::new(message, creator)?;
        let group_id = message_full.id(); // The group ID is the Blake3 hash of this message

        // Store the encryption key
        let encryption_state = GroupEncryptionState {
            current_key: encryption_key,
            previous_keys: Vec::new(),
        };
        self.group_keys.insert(group_id.clone(), encryption_state);

        // Create the initial group state using the unified constructor
        let group_state = GroupState::new(
            group_id.clone(),
            group_info.name.clone(),
            group_info.settings.clone(),
            group_info.metadata.clone(),
            creator.public_key(),
            timestamp,
        );

        // Store the group state
        self.groups.insert(group_id.clone(), group_state);

        Ok(CreateGroupResult {
            group_id: group_id.clone(),
            message: message_full,
        })
    }

    /// Create an encrypted message for a group activity event
    /// The group_id parameter should be the Blake3 hash of the CreateGroup message
    pub fn create_group_event_message(
        &self,
        group_id: Hash,
        event: GroupActivityEvent<()>,
        sender: &KeyPair,
        timestamp: u64,
    ) -> DgaResult<MessageFull> {
        // Find the group to verify it exists
        let _group_state = self
            .groups
            .get(&group_id)
            .ok_or_else(|| DgaError::GroupNotFound(format!("{group_id:?}")))?;

        // Get the encryption key for this group
        let encryption_state = self.group_keys.get(&group_id).ok_or_else(|| {
            DgaError::InvalidEvent(format!(
                "No encryption key available for group {group_id:?}"
            ))
        })?;

        // Encrypt the event
        let encrypted_payload = self.encrypt_group_event(&event, &encryption_state.current_key)?;

        // Create the message with the group ID (root event ID) as a channel tag
        let message = Message::new_v0_encrypted(
            encrypted_payload,
            sender.public_key(),
            timestamp,
            Kind::Regular,
            vec![Tag::Event {
                id: group_id,   // The group ID is the root event ID
                relays: vec![], // Could be populated with known relays
            }],
        );

        // Sign and return the message
        MessageFull::new(message, sender).map_err(DgaError::WireProtocol)
    }

    /// Process an incoming group event message
    pub fn process_group_event(&mut self, message_full: &MessageFull) -> DgaResult<()> {
        // Extract the encrypted payload from the message
        let Message::MessageV0(message) = message_full.message();

        // Get the encrypted payload from the message content
        let Content::ChaCha20Poly1305(encrypted_payload) = &message.content else {
            return Err(DgaError::InvalidEvent(
                "Message is not a ChaCha20Poly1305 encrypted message".to_string(),
            ));
        };

        let sender = &message.sender;
        let timestamp = message.when;

        // Determine the group ID and decrypt the event
        let (group_id, event) = if message.tags.is_empty() {
            // This is a root event (CreateGroup) - the group ID is the message ID itself
            let group_id = message_full.id();

            // Get the encryption key for this group (must have been added via inbox system)
            let encryption_state = self.group_keys.get(&group_id).ok_or_else(|| {
                DgaError::InvalidEvent(format!(
                    "No encryption key available for group {group_id:?}"
                ))
            })?;

            let event =
                self.decrypt_group_event(encrypted_payload, &encryption_state.current_key)?;
            (group_id.clone(), event)
        } else {
            // This is a subsequent event - find the group by channel tag
            let group_id = self.find_group_by_event_tag(&message.tags)?;

            // Get the encryption key for this group
            let encryption_state = self.group_keys.get(&group_id).ok_or_else(|| {
                DgaError::InvalidEvent(format!(
                    "No encryption key available for group {group_id:?}"
                ))
            })?;

            let event =
                self.decrypt_group_event(encrypted_payload, &encryption_state.current_key)?;
            (group_id, event)
        };

        // Handle the root event (group creation) specially
        if let GroupActivityEvent::UpdateGroup(group_info) = &event {
            // This is a root event - create the group state using the new constructor
            let group_state = GroupState::new(
                group_id,
                group_info.name.clone(),
                group_info.settings.clone(),
                group_info.metadata.clone(),
                sender.clone(),
                timestamp,
            );

            self.groups.insert(group_id, group_state);
            return Ok(());
        }

        // This is a subsequent event - apply to existing group state
        let group_state = self
            .groups
            .get_mut(&group_id)
            .ok_or_else(|| DgaError::GroupNotFound(format!("{group_id:?}")))?;

        // Apply the event to the group state (convert GroupStateError to DgaError)
        group_state
            .apply_event(&event, message_full.id().clone(), sender.clone(), timestamp)
            .map_err(|e| match e {
                GroupStateError::PermissionDenied(msg) => DgaError::PermissionDenied(msg),
                GroupStateError::MemberNotFound { member, group } => {
                    DgaError::MemberNotFound { member, group }
                }
                GroupStateError::StateTransition(msg) => DgaError::StateTransition(msg),
                GroupStateError::InvalidOperation(msg) => DgaError::InvalidOperation(msg),
            })?;

        Ok(())
    }

    /// Find a group by looking for Event tags in the message
    fn find_group_by_event_tag(&self, tags: &[Tag]) -> DgaResult<Hash> {
        for tag in tags {
            if let Tag::Event { id, .. } = tag
                && self.groups.contains_key(id)
            {
                return Ok(*id);
            }
        }
        Err(DgaError::InvalidEvent(
            "No valid group channel tag found".to_string(),
        ))
    }

    /// Get a group's current state
    pub fn get_group_state(&self, group_id: &Hash) -> Option<&GroupState> {
        self.groups.get(group_id)
    }

    /// Get all managed groups
    pub fn get_all_groups(&self) -> &HashMap<Hash, GroupState> {
        &self.groups
    }

    /// Check if a user is a member of a specific group
    pub fn is_member(&self, group_id: &Hash, user: &VerifyingKey) -> bool {
        self.groups
            .get(group_id)
            .map(|group| group.is_member(user))
            .unwrap_or(false)
    }

    /// Get a user's role in a specific group
    pub fn get_member_role(&self, group_id: &Hash, user: &VerifyingKey) -> Option<&GroupRole> {
        self.groups
            .get(group_id)
            .and_then(|group| group.get_member_role(user))
    }

    /// List all groups a user is a member of
    pub fn get_user_groups(&self, user: &VerifyingKey) -> Vec<&GroupState> {
        self.groups
            .values()
            .filter(|group| group.is_member(user))
            .collect()
    }

    /// Create a subscription filter for a specific group
    /// This returns the Event tag that should be used to subscribe to group events
    pub fn create_group_subscription_filter(&self, group_id: &Hash) -> DgaResult<Tag> {
        // Verify the group exists
        if !self.groups.contains_key(group_id) {
            return Err(DgaError::GroupNotFound(format!("{group_id:?}")));
        }

        Ok(Tag::Event {
            id: *group_id,  // The group ID is the root event ID
            relays: vec![], // Could be populated with known relays
        })
    }

    /// Encrypt a group event using ChaCha20-Poly1305
    pub(crate) fn encrypt_group_event(
        &self,
        event: &GroupActivityEvent<()>,
        key: &EncryptionKey,
    ) -> DgaResult<ChaCha20Poly1305Content> {
        // Serialize the event
        let plaintext = postcard::to_stdvec(event)?;

        // Encrypt using ChaCha20-Poly1305
        key.encrypt_content(&plaintext)
            .map_err(|e| DgaError::CryptoError(format!("Group event encryption failed: {e}")))
    }

    /// Decrypt a group event using ChaCha20-Poly1305
    pub(crate) fn decrypt_group_event(
        &self,
        payload: &ChaCha20Poly1305Content,
        key: &EncryptionKey,
    ) -> DgaResult<GroupActivityEvent<()>> {
        // Note: No key ID verification needed since key is determined by channel context

        // Decrypt using ChaCha20-Poly1305
        let plaintext = key
            .decrypt_content(payload)
            .map_err(|e| DgaError::CryptoError(format!("Group event decryption failed: {e}")))?;

        // Deserialize the event
        let event: GroupActivityEvent<()> = postcard::from_bytes(&plaintext)?;
        Ok(event)
    }
}

impl Default for DigitalGroupAssistant {
    fn default() -> Self {
        Self::new()
    }
}

// Helper functions for common encrypted group operations

/// Create a leave group event
pub fn create_leave_group_event(message: Option<String>) -> GroupActivityEvent<()> {
    GroupActivityEvent::LeaveGroup { message }
}

/// Create a role update event
/// TODO: This function is temporarily disabled due to IdentityRef expecting Ed25519 keys
/// while the message system now uses ML-DSA keys. This needs to be updated when
/// IdentityRef is migrated to ML-DSA.
pub fn create_role_update_event(member: VerifyingKey, role: GroupRole) -> GroupActivityEvent<()> {
    // Use the provided ML-DSA member key directly
    GroupActivityEvent::AssignRole {
        target: IdentityRef::Key(member),
        role,
    }
}

/// Create a custom group activity event
pub fn create_group_activity_event<T>(activity_data: T) -> GroupActivityEvent<T> {
    GroupActivityEvent::Activity(activity_data)
}

/// Create a group update event
pub fn create_group_update_event(group_info: GroupInfo) -> GroupActivityEvent<()> {
    GroupActivityEvent::UpdateGroup(group_info)
}
