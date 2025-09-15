// ChaCha20-Poly1305 and AES-GCM functionality moved to crypto module
use serde::Serialize;
use zoe_wire_protocol::{KeyPair, MessageId, VerifyingKey};
// Random number generation imports removed - no longer needed
// Temporary import for Ed25519 workaround in create_role_update_event

use zoe_app_primitives::{GroupInfo, IdentityRef};
// Random number generation moved to wire-protocol crypto module
use std::{collections::HashMap, sync::Arc};

use zoe_wire_protocol::{Kind, Message, MessageFull, Tag};

use crate::{
    GroupActivityEvent, GroupError, GroupKeyInfo, GroupResult, GroupRole, GroupSession,
    state::encrypt_group_event_content,
};

use async_broadcast::{Receiver, Sender};
use tokio::sync::RwLock;

// Import the unified GroupState from app-primitives
use zoe_app_primitives::{GroupState, GroupStateError};
use zoe_wire_protocol::{Content, EncryptionKey, MnemonicPhrase};

#[derive(Debug, Clone)]
pub enum GroupDataUpdate {
    GroupAdded(GroupSession),
    GroupUpdated(GroupSession),
    GroupRemoved(GroupSession),
}

/// Digital Group Assistant - manages encrypted groups using the wire protocol
#[derive(Debug, Clone)]
pub struct GroupManager {
    /// All group states managed by this DGA instance
    /// Key is the Blake3 hash of the CreateGroup message (which serves as both group ID and root event ID)
    pub(crate) groups: Arc<RwLock<HashMap<MessageId, GroupSession>>>,

    broadcast_channel: Arc<Sender<GroupDataUpdate>>,
    /// Keeper receiver to prevent broadcast channel closure (not actively used)
    /// Arc-wrapped to ensure channel stays open even when GroupManager instances are cloned and dropped
    _broadcast_keeper: Arc<async_broadcast::InactiveReceiver<GroupDataUpdate>>,
}

/// Result of creating a new group
#[derive(Debug, Clone)]
pub struct CreateGroupResult {
    /// The created group's unique identifier (Blake3 hash of the CreateGroup message)
    /// This is also the root event ID used as channel tag for subsequent events
    pub group_id: MessageId,
    /// The full message that was created
    pub message: MessageFull,
}

pub struct GroupManagerBuilder {
    sessions: Vec<GroupSession>,
}

impl GroupManagerBuilder {
    pub fn with_sessions(mut self, sessions: Vec<GroupSession>) -> Self {
        self.sessions = sessions;
        self
    }

    pub fn build(self) -> GroupManager {
        let GroupManagerBuilder { sessions } = self;
        let (tx, rx) = async_broadcast::broadcast(1000);
        let broadcast_keeper = rx.deactivate();
        GroupManager {
            groups: Arc::new(RwLock::new(HashMap::from_iter(
                sessions
                    .into_iter()
                    .map(|session| (session.state.group_id, session)),
            ))),
            broadcast_channel: Arc::new(tx),
            _broadcast_keeper: Arc::new(broadcast_keeper),
        }
    }
}

// Helper function removed - now using KeyPair enum which provides direct access to verifying key

impl GroupManager {
    /// Create a new DGA instance builder
    pub fn builder() -> GroupManagerBuilder {
        GroupManagerBuilder { sessions: vec![] }
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
    ) -> GroupResult<EncryptionKey> {
        let context = format!("dga-group-{group_name}");

        EncryptionKey::from_mnemonic(mnemonic, passphrase, &context, timestamp)
            .map_err(|e| GroupError::CryptoError(format!("Key derivation failed: {e}")))
    }

    /// Recover a group key from a mnemonic phrase with specific salt
    pub fn recover_key_from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        group_name: &str,
        salt: &[u8; 32],
        timestamp: u64,
    ) -> GroupResult<EncryptionKey> {
        let context = format!("dga-group-{group_name}");

        EncryptionKey::from_mnemonic_with_salt(mnemonic, passphrase, &context, salt, timestamp)
            .map_err(|e| GroupError::CryptoError(format!("Key recovery failed: {e}")))
    }

    /// Create a new encrypted group, returning the root event message to be sent
    pub async fn create_group(
        &self,
        create_group: zoe_app_primitives::CreateGroup,
        encryption_key: Option<EncryptionKey>,
        creator: &KeyPair,
        timestamp: u64,
    ) -> GroupResult<CreateGroupResult> {
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

        let event: GroupActivityEvent<()> = GroupActivityEvent::UpdateGroup(group_info.clone());

        // Encrypt the event before creating the wire protocol message
        let encrypted_payload = encrypt_group_event_content(&encryption_key, &event)?;

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

        // Create the initial group state using the unified constructor
        let group_state = GroupState::new(
            *group_id,
            group_info.name.clone(),
            group_info.settings.clone(),
            group_info.metadata.clone(),
            creator.public_key(),
            timestamp,
        );

        // Create the unified group session
        let group_session = GroupSession::new(group_state, encryption_key);

        // Store the group session
        self.groups
            .write()
            .await
            .insert(*group_id, group_session.clone());

        // Broadcast the group addition
        if let Err(e) = self
            .broadcast_channel
            .try_broadcast(GroupDataUpdate::GroupAdded(group_session))
        {
            tracing::error!(error=?e, "Failed to broadcast group addition");
        }

        Ok(CreateGroupResult {
            group_id: *group_id,
            message: message_full,
        })
    }

    /// Create an encrypted message for a group activity event
    /// The group_id parameter should be the Blake3 hash of the CreateGroup message
    pub async fn create_group_event_message<T>(
        &self,
        group_id: MessageId,
        event: GroupActivityEvent<T>,
        sender: &KeyPair,
        timestamp: u64,
    ) -> GroupResult<MessageFull>
    where
        T: Serialize,
    {
        // Find the group session to verify it exists and get encryption key
        let groups = self.groups.read().await;
        let group_session = groups
            .get(&group_id)
            .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;

        // Encrypt the event using the session's current key
        let encrypted_payload = group_session.encrypt_group_event_content(&event)?;

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
        Ok(MessageFull::new(message, sender)?)
    }

    /// Process an incoming group event message
    pub async fn process_group_event(&self, message_full: &MessageFull) -> GroupResult<()> {
        // Extract the encrypted payload from the message
        let Message::MessageV0(message) = message_full.message();

        // Get the encrypted payload from the message content
        let Content::ChaCha20Poly1305(encrypted_payload) = &message.content else {
            return Err(GroupError::InvalidEvent(
                "Message is not a ChaCha20Poly1305 encrypted message".to_string(),
            ));
        };

        let sender = &message.sender;
        let timestamp = message.when;

        // Determine the group ID and decrypt the event
        let (group_id, event) = if message.tags.is_empty() {
            // This is a root event (CreateGroup) - the group ID is the message ID itself
            let group_id = message_full.id();

            // Get the group session for this group (must have been added via inbox system)
            let groups = self.groups.read().await;
            let group_session = groups.get(group_id).ok_or_else(|| {
                GroupError::InvalidEvent(format!(
                    "No group session available for group {group_id:?}"
                ))
            })?;

            let event = group_session.decrypt_group_event::<()>(encrypted_payload)?;
            (*group_id, event)
        } else {
            // This is a subsequent event - find the group by channel tag
            let group_id = self.find_group_by_event_tag(&message.tags).await?;

            // Get the group session for this group
            let groups = self.groups.read().await;
            let group_session = groups.get(&group_id).ok_or_else(|| {
                GroupError::InvalidEvent(format!(
                    "No group session available for group {group_id:?}"
                ))
            })?;

            let event = group_session.decrypt_group_event(encrypted_payload)?;
            (group_id, event)
        };

        // Handle the root event (group creation) specially
        if let GroupActivityEvent::UpdateGroup(group_info) = &event {
            // This is a root event - the group session should already exist from create_group
            // Just verify it exists and update if needed
            let mut groups = self.groups.write().await;
            if let Some(group_session) = groups.get_mut(&group_id) {
                // Update the group state within the session
                group_session.state = GroupState::new(
                    group_id,
                    group_info.name.clone(),
                    group_info.settings.clone(),
                    group_info.metadata.clone(),
                    sender.clone(),
                    timestamp,
                );

                // Broadcast the group update
                let _ = self
                    .broadcast_channel
                    .try_broadcast(GroupDataUpdate::GroupUpdated(group_session.clone()));
            }
            return Ok(());
        }

        // This is a subsequent event - apply to existing group state
        let mut groups = self.groups.write().await;
        let group_session = groups
            .get_mut(&group_id)
            .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;

        // Apply the event to the group state (convert GroupStateError to GroupError)
        group_session
            .state
            .apply_event(&event, *message_full.id(), sender.clone(), timestamp)
            .map_err(|e| match e {
                GroupStateError::PermissionDenied(msg) => GroupError::PermissionDenied(msg),
                GroupStateError::MemberNotFound { member, group } => {
                    GroupError::MemberNotFound { member, group }
                }
                GroupStateError::StateTransition(msg) => GroupError::StateTransition(msg),
                GroupStateError::InvalidOperation(msg) => GroupError::InvalidOperation(msg),
            })?;

        // Broadcast the group update
        let _ = self
            .broadcast_channel
            .try_broadcast(GroupDataUpdate::GroupUpdated(group_session.clone()));

        Ok(())
    }

    /// Find a group by looking for Event tags in the message
    async fn find_group_by_event_tag(&self, tags: &[Tag]) -> GroupResult<MessageId> {
        let groups = self.groups.read().await;
        for tag in tags {
            if let Tag::Event { id, .. } = tag
                && groups.contains_key(id)
            {
                return Ok(*id);
            }
        }
        Err(GroupError::InvalidEvent(
            "No valid group channel tag found".to_string(),
        ))
    }

    /// Get a group's current state
    pub async fn get_group_state(&self, group_id: &MessageId) -> Option<GroupState> {
        let groups = self.groups.read().await;
        groups.get(group_id).map(|session| session.state.clone())
    }

    /// Get a group session (state + encryption)
    pub async fn get_group_session(&self, group_id: &MessageId) -> Option<GroupSession> {
        let groups = self.groups.read().await;
        groups.get(group_id).cloned()
    }

    /// Get all managed group sessions
    pub async fn get_all_group_sessions(&self) -> HashMap<MessageId, GroupSession> {
        let groups = self.groups.read().await;
        groups.clone()
    }

    /// Get all managed groups (state only, for backward compatibility)
    pub async fn get_all_groups(&self) -> HashMap<MessageId, GroupState> {
        let groups = self.groups.read().await;
        groups
            .iter()
            .map(|(id, session)| (*id, session.state.clone()))
            .collect()
    }

    /// Check if a user is a member of a specific group
    pub async fn is_member(&self, group_id: &MessageId, user: &VerifyingKey) -> bool {
        let groups = self.groups.read().await;
        groups
            .get(group_id)
            .map(|session| session.state.is_member(user))
            .unwrap_or(false)
    }

    /// Get a user's role in a specific group
    pub async fn get_member_role(
        &self,
        group_id: &MessageId,
        user: &VerifyingKey,
    ) -> Option<GroupRole> {
        let groups = self.groups.read().await;
        groups
            .get(group_id)
            .and_then(|session| session.state.get_member_role(user).cloned())
    }

    /// List all groups a user is a member of
    pub async fn get_user_groups(&self, user: &VerifyingKey) -> Vec<GroupState> {
        let groups = self.groups.read().await;
        groups
            .values()
            .filter(|session| session.state.is_member(user))
            .map(|session| session.state.clone())
            .collect()
    }

    /// Add a complete group session
    pub async fn add_group_session(&self, group_id: MessageId, session: GroupSession) {
        self.groups.write().await.insert(group_id, session.clone());
        let _ = self
            .broadcast_channel
            .try_broadcast(GroupDataUpdate::GroupAdded(session));
    }

    /// Remove a group session
    pub async fn remove_group_session(&self, group_id: &MessageId) -> Option<GroupSession> {
        if let Some(session) = self.groups.write().await.remove(group_id) {
            let _ = self
                .broadcast_channel
                .try_broadcast(GroupDataUpdate::GroupRemoved(session.clone()));
            Some(session)
        } else {
            None
        }
    }

    /// Update a group session's encryption key (for key rotation)
    pub async fn rotate_group_key(
        &self,
        group_id: &MessageId,
        new_key: EncryptionKey,
    ) -> GroupResult<()> {
        let mut groups = self.groups.write().await;
        let session = groups
            .get_mut(group_id)
            .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;

        session.rotate_key(new_key);
        let _ = self
            .broadcast_channel
            .try_broadcast(GroupDataUpdate::GroupUpdated(session.clone()));
        Ok(())
    }

    /// Subscribe to group updates
    pub fn subscribe_to_updates(&self) -> Receiver<GroupDataUpdate> {
        self.broadcast_channel.new_receiver()
    }

    /// Create a subscription filter for a specific group
    /// This returns the Event tag that should be used to subscribe to group events
    pub async fn create_group_subscription_filter(&self, group_id: &MessageId) -> GroupResult<Tag> {
        // Verify the group exists
        let groups = self.groups.read().await;
        if !groups.contains_key(group_id) {
            return Err(GroupError::GroupNotFound(format!("{group_id:?}")));
        }

        Ok(Tag::Event {
            id: *group_id,  // The group ID is the root event ID
            relays: vec![], // Could be populated with known relays
        })
    }
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::builder().build()
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
