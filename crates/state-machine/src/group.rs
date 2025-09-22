// ChaCha20-Poly1305 and AES-GCM functionality moved to crypto module
use zoe_wire_protocol::{ChaCha20Poly1305Content, KeyPair, MessageId, VerifyingKey};

use zoe_app_primitives::{
    digital_groups_organizer::models::core::ActivityMeta,
    group::{
        events::{GroupInfo, settings::GroupSettings},
        states::GroupState,
    },
    identity::IdentityRef,
    metadata::Metadata,
    protocol::{AppProtocolVariant, InstalledApp},
};
// Random number generation moved to wire-protocol crypto module
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use zoe_wire_protocol::{Kind, Message, MessageFull, Tag};

use crate::{
    dgo_executor::{DgoExecutor, create_dgo_executor},
    error::{GroupError, GroupResult},
    state::GroupSession,
    state::encrypt_group_event_content,
};
use zoe_app_primitives::{
    digital_groups_organizer::events::core::DgoActivityEvent,
    group::events::key_info::GroupKeyInfo,
    group::events::{GroupActivityEvent, GroupInfoUpdate, roles::GroupRole},
};

use async_broadcast::{Receiver, Sender};
use tokio::sync::RwLock;
use zoe_wire_protocol::{ChannelId, Content, EncryptionKey, MnemonicPhrase, version::Version};

// Import GroupStateError from app-primitives
use zoe_app_primitives::group::states::GroupStateError;

/// Registry key for app executors: (group_id, channel_id)
type AppExecutorKey = (MessageId, ChannelId);

/// Trait for app executors that can handle encrypted app events
#[async_trait::async_trait]
pub trait AppExecutor: Send + Sync + std::fmt::Debug {
    /// Process a decrypted app event
    async fn process_app_event(
        &self,
        event_data: Vec<u8>,
        activity_id: MessageId,
    ) -> GroupResult<()>;

    /// Get the app protocol variant this executor handles
    fn app_variant(&self) -> AppProtocolVariant;
}

/// DGO executor wrapper that implements AppExecutor
#[derive(Debug)]
pub struct DgoAppExecutor {
    executor: DgoExecutor,
}

impl Default for DgoAppExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl DgoAppExecutor {
    pub fn new() -> Self {
        Self {
            executor: create_dgo_executor(),
        }
    }
}

#[async_trait::async_trait]
impl AppExecutor for DgoAppExecutor {
    async fn process_app_event(
        &self,
        event_data: Vec<u8>,
        activity_id: MessageId,
    ) -> GroupResult<()> {
        // Deserialize the DGO event from the decrypted data
        let event: DgoActivityEvent = postcard::from_bytes(&event_data).map_err(|e| {
            GroupError::InvalidEvent(format!("Failed to deserialize DGO event: {e}"))
        })?;

        // Execute the event through the DGO executor
        let _execute_refs = self
            .executor
            .execute_event(event, activity_id)
            .await
            .map_err(|e| {
                GroupError::InvalidEvent(format!("Failed to execute DGO event: {:?}", e))
            })?;

        // TODO: Handle execute references for notifications/indexing
        Ok(())
    }

    fn app_variant(&self) -> AppProtocolVariant {
        AppProtocolVariant::DigitalGroupsOrganizer
    }
}

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(non_opaque))]
#[derive(Debug, Clone)]
pub enum GroupDataUpdate {
    GroupAdded(GroupSession),
    GroupUpdated(GroupSession),
    GroupRemoved(GroupSession),
}

/// Digital Group Assistant - manages encrypted groups using the wire protocol
#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone)]
pub struct GroupManager {
    /// All group states managed by this DGA instance
    /// Key is the Blake3 hash of the CreateGroup message (which serves as both group ID and root event ID)
    pub(crate) groups: Arc<RwLock<HashMap<MessageId, GroupSession>>>,

    /// Registry of app executors by (group_id, channel_id)
    /// Each installed app gets its own executor instance
    app_executors: Arc<RwLock<HashMap<AppExecutorKey, Box<dyn AppExecutor>>>>,

    broadcast_channel: Arc<Sender<GroupDataUpdate>>,
    /// Keeper receiver to prevent broadcast channel closure (not actively used)
    /// Arc-wrapped to ensure channel stays open even when GroupManager instances are cloned and dropped
    _broadcast_keeper: Arc<async_broadcast::InactiveReceiver<GroupDataUpdate>>,
}

/// Result of creating a new group
#[cfg_attr(feature = "frb-api", frb(ignore))]
#[derive(Debug, Clone)]
pub struct CreateGroupResult {
    /// The created group's unique identifier (Blake3 hash of the CreateGroup message)
    /// This is also the root event ID used as channel tag for subsequent events
    pub group_id: MessageId,
    /// The full message that was created
    pub message: MessageFull,
}
#[cfg_attr(feature = "frb-api", frb(ignore))]
pub struct GroupManagerBuilder {
    sessions: Vec<GroupSession>,
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
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
            app_executors: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: Arc::new(tx),
            _broadcast_keeper: Arc::new(broadcast_keeper),
        }
    }
}

#[cfg_attr(feature = "frb-api", frb)]
impl GroupManager {
    /// Generate a new encryption key for a group (ChaCha20-Poly1305)
    pub fn generate_group_key() -> EncryptionKey {
        EncryptionKey::generate()
    }
    /// Get a group's current state
    pub async fn group_state(&self, group_id: &MessageId) -> Option<GroupState> {
        let groups = self.groups.read().await;
        groups.get(group_id).map(|session| session.state.clone())
    }
    /// Get a group session (state + encryption)
    pub async fn group_session(&self, group_id: &MessageId) -> Option<GroupSession> {
        let groups = self.groups.read().await;
        groups.get(group_id).cloned()
    }

    /// Get all managed group sessions
    pub async fn all_group_sessions(&self) -> HashMap<MessageId, GroupSession> {
        let groups = self.groups.read().await;
        groups.clone()
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
    pub async fn member_role(
        &self,
        group_id: &MessageId,
        user: &VerifyingKey,
    ) -> Option<GroupRole> {
        let groups = self.groups.read().await;
        groups
            .get(group_id)
            .and_then(|session| session.state.member_role(user).clone())
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl GroupManager {
    /// Create a new DGA instance builder
    pub fn builder() -> GroupManagerBuilder {
        GroupManagerBuilder { sessions: vec![] }
    }

    /// Create a group key from a mnemonic phrase
    pub fn create_key_from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        group_name: &str,
    ) -> GroupResult<EncryptionKey> {
        let context = format!("dga-group-{group_name}");

        EncryptionKey::from_mnemonic(mnemonic, passphrase, &context)
            .map_err(|e| GroupError::CryptoError(format!("Key derivation failed: {e}")))
    }

    /// Recover a group key from a mnemonic phrase with specific salt
    pub fn recover_key_from_mnemonic(
        mnemonic: &MnemonicPhrase,
        passphrase: &str,
        group_name: &str,
        salt: &[u8; 32],
    ) -> GroupResult<EncryptionKey> {
        let context = format!("dga-group-{group_name}");

        EncryptionKey::from_mnemonic_with_salt(mnemonic, passphrase, &context, salt)
            .map_err(|e| GroupError::CryptoError(format!("Key recovery failed: {e}")))
    }

    /// Create a new encrypted group, returning the root event message to be sent
    pub async fn create_group(
        &self,
        create_group: CreateGroupBuilder,
        creator: &KeyPair,
    ) -> GroupResult<CreateGroupResult> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GroupError::CryptoError(format!("Failed to get timestamp: {e}")))?
            .as_secs();
        // Generate or use provided encryption key
        let (enc_key, encrypted_payload, group_info) = create_group.build()?;

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

        // Create ActivityMeta for the group creation
        let meta = ActivityMeta {
            activity_id: *group_id,
            group_id: *group_id,
            actor: IdentityRef::Key(creator.public_key().clone()),
            timestamp,
        };

        // Create the unified group session
        let group_session = GroupSession::new(
            GroupState::new(
                *group_id,
                group_info.name,
                group_info.settings,
                group_info.metadata,
                creator.public_key().clone(),
                timestamp,
                meta,
            ),
            enc_key,
        );

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
    pub async fn create_group_event_message(
        &self,
        group_id: MessageId,
        event: GroupActivityEvent,
        sender: &KeyPair,
        timestamp: u64,
    ) -> GroupResult<MessageFull> {
        self.create_event_message_raw(
            group_id,
            event,
            sender,
            timestamp,
            Kind::Regular,
            vec![Tag::Event {
                id: group_id,
                relays: vec![],
            }],
        )
        .await
    }

    /// Create an encrypted message for a DGO activity event
    /// The group_id parameter should be the Blake3 hash of the CreateGroup message
    pub async fn create_app_event_message<T: Serialize>(
        &self,
        group_id: MessageId,
        event: T,
        sender: &KeyPair,
        timestamp: u64,
    ) -> GroupResult<MessageFull> {
        self.create_event_message_raw(
            group_id,
            event,
            sender,
            timestamp,
            Kind::Regular,
            vec![Tag::Event {
                id: group_id,
                relays: vec![],
            }],
        )
        .await
    }

    /// Create an encrypted message for a group activity event
    /// The group_id parameter should be the Blake3 hash of the CreateGroup message
    pub async fn create_event_message_raw<T: Serialize>(
        &self,
        group_id: MessageId,
        event: T,
        sender: &KeyPair,
        timestamp: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> GroupResult<MessageFull> {
        // Encrypt the event using the session's current key
        let encrypted_payload = {
            // Find the group session to verify it exists and get encryption key
            let groups = self.groups.read().await;
            let group_session = groups
                .get(&group_id)
                .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;
            group_session.encrypt_group_event_content(&event)?
        };

        // Create the message with the group ID (root event ID) as a channel tag
        let message = Message::new_v0_encrypted(
            encrypted_payload,
            sender.public_key(),
            timestamp,
            kind,
            tags,
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

            let event = group_session.decrypt_group_event(encrypted_payload)?;
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
        if let GroupActivityEvent::CreateGroup(group_info) = &event {
            // This is a root event - the group session should already exist from create_group
            // Just verify it exists and update if needed
            let updated_session = {
                let mut groups = self.groups.write().await;
                if let Some(group_session) = groups.get_mut(&group_id) {
                    // Create ActivityMeta for the group update
                    let meta = ActivityMeta {
                        activity_id: group_id,
                        group_id,
                        actor: IdentityRef::Key(sender.clone()),
                        timestamp,
                    };

                    // Update the group state within the session (including installed apps)
                    group_session.state = GroupState::from_group_info(
                        group_id,
                        group_info,
                        sender.clone(),
                        timestamp,
                        meta,
                    );

                    Some(group_session.clone())
                } else {
                    None
                }
            };

            if let Some(session) = updated_session {
                // Register app executors for installed apps
                self.handle_app_installation(group_id, &group_info.installed_apps)
                    .await?;

                // Broadcast the group update
                let _ = self
                    .broadcast_channel
                    .try_broadcast(GroupDataUpdate::GroupUpdated(session));
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
                GroupStateError::InvalidAcknowledgment(msg) => GroupError::InvalidOperation(msg),
                GroupStateError::HistoryRewriteAttempt(msg) => GroupError::InvalidOperation(msg),
                GroupStateError::InvalidSender(msg) => GroupError::InvalidOperation(msg),
            })?;

        // Check if this event added any apps that need executor registration
        if let GroupActivityEvent::UpdateGroup { updates, .. } = &event {
            for update in updates {
                if let GroupInfoUpdate::AddApp(app) = update {
                    // Register executor for the newly added app
                    drop(groups); // Release the write lock before async call
                    self.register_app_executor(group_id, app).await?;
                    // Re-acquire the lock for broadcasting
                    let groups = self.groups.read().await;
                    let group_session = groups.get(&group_id).unwrap();

                    // Broadcast the group update
                    let _ = self
                        .broadcast_channel
                        .try_broadcast(GroupDataUpdate::GroupUpdated(group_session.clone()));
                    return Ok(());
                }
            }
        }

        // Broadcast the group update
        let _ = self
            .broadcast_channel
            .try_broadcast(GroupDataUpdate::GroupUpdated(group_session.clone()));

        Ok(())
    }

    /// Register an app executor for a specific group and channel
    pub async fn register_app_executor(
        &self,
        group_id: MessageId,
        app: &InstalledApp,
    ) -> GroupResult<()> {
        let executor: Box<dyn AppExecutor> = match app.app_id {
            AppProtocolVariant::DigitalGroupsOrganizer => Box::new(DgoAppExecutor::new()),
            AppProtocolVariant::Unknown(ref variant) => {
                return Err(GroupError::InvalidEvent(format!(
                    "Unknown app variant: {variant}"
                )));
            }
        };

        let key = (group_id, app.app_tag.clone());
        self.app_executors.write().await.insert(key, executor);

        tracing::info!(
            group_id = ?group_id,
            app_variant = ?app.app_id,
            channel_id = ?app.app_tag,
            "Registered app executor"
        );

        Ok(())
    }

    /// Process app installation (either from CreateGroup or AddApp events)
    pub async fn handle_app_installation(
        &self,
        group_id: MessageId,
        installed_apps: &[InstalledApp],
    ) -> GroupResult<()> {
        for app in installed_apps {
            self.register_app_executor(group_id, app).await?;
        }
        Ok(())
    }

    /// Process an incoming app event message (routed by channel tag)
    pub async fn process_app_event(&self, message_full: &MessageFull) -> GroupResult<()> {
        // Extract the encrypted payload from the message
        let Message::MessageV0(message) = message_full.message();

        // Get the encrypted payload from the message content
        let Content::ChaCha20Poly1305(encrypted_payload) = &message.content else {
            return Err(GroupError::InvalidEvent(
                "Message is not a ChaCha20Poly1305 encrypted message".to_string(),
            ));
        };

        // Find the group by channel tag
        let group_id = self.find_group_by_event_tag(&message.tags).await?;

        // Get the group session for decryption
        let groups = self.groups.read().await;
        let group_session = groups.get(&group_id).ok_or_else(|| {
            GroupError::InvalidEvent(format!("No group session available for group {group_id:?}"))
        })?;

        // Decrypt the payload using the group key
        let decrypted_data = group_session
            .current_key
            .decrypt_content(encrypted_payload)
            .map_err(|e| GroupError::InvalidEvent(format!("Failed to decrypt app event: {e}")))?;

        // Find the app executor for this channel
        let channel_id = self.extract_channel_id_from_tags(&message.tags)?;
        let executor_key = (group_id, channel_id);

        let app_executors = self.app_executors.read().await;
        let executor = app_executors.get(&executor_key).ok_or_else(|| {
            GroupError::InvalidEvent(format!(
                "No app executor registered for group {group_id:?} channel {executor_key:?}"
            ))
        })?;

        // Create activity ID from message ID
        let activity_id = *message_full.id();

        // Process the event through the app executor
        executor
            .process_app_event(decrypted_data, activity_id)
            .await?;

        Ok(())
    }

    /// Extract channel ID from message tags
    fn extract_channel_id_from_tags(&self, tags: &[Tag]) -> GroupResult<ChannelId> {
        for tag in tags {
            if let Tag::Event { id, .. } = tag {
                // For now, we use the event ID as the channel ID
                // In a multi-channel setup, this would be more sophisticated
                return Ok(id.as_bytes().to_vec());
            }
        }
        Err(GroupError::InvalidEvent(
            "No valid channel tag found".to_string(),
        ))
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

    /// List all groups a user is a member of
    pub async fn user_groups(&self, user: &VerifyingKey) -> Vec<GroupState> {
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

#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone, PartialEq, Default, Eq)]
pub struct CreateGroupBuilder {
    title: String,
    description: Option<String>,
    group_settings: GroupSettings,
    metadata: Vec<Metadata>,
    installed_apps: Vec<InstalledApp>,
}

#[cfg_attr(feature = "frb-api", frb)]
impl CreateGroupBuilder {
    pub fn new(title: String) -> Self {
        Self {
            title,
            ..Default::default()
        }
    }

    pub fn name(mut self, name: String) -> Self {
        self.title = name;
        self
    }
    pub fn description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
    pub fn group_settings(mut self, group_settings: GroupSettings) -> Self {
        self.group_settings = group_settings;
        self
    }

    pub fn metadata(mut self, metadata: Metadata) -> Self {
        self.metadata.push(metadata);
        self
    }

    /// Add an installed app to the group
    pub fn add_installed_app(mut self, app: InstalledApp) -> Self {
        self.installed_apps.push(app);
        self
    }

    /// Add an installed app with explicit parameters
    pub fn install_app(
        mut self,
        app_id: AppProtocolVariant,
        version: Version,
        app_tag: ChannelId,
    ) -> Self {
        self.installed_apps
            .push(InstalledApp::new(app_id, version, app_tag));
        self
    }

    /// Install the Digital Groups Organizer app with a random channel tag
    pub fn install_dgo_app(mut self, version: Version) -> Self {
        let app_tag = Self::generate_random_channel_id();
        self.installed_apps.push(InstalledApp::new(
            AppProtocolVariant::DigitalGroupsOrganizer,
            version,
            app_tag,
        ));
        self
    }

    /// Generate a random channel ID for app isolation
    fn generate_random_channel_id() -> ChannelId {
        use std::time::{SystemTime, UNIX_EPOCH};

        // Create a simple random channel ID using timestamp and a counter
        // This is sufficient for channel isolation within a group
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        let mut channel_id = Vec::with_capacity(16);
        channel_id.extend_from_slice(b"dgo_");
        channel_id.extend_from_slice(&timestamp.to_le_bytes());

        // Add some entropy from the process ID if available
        #[cfg(unix)]
        {
            let pid = std::process::id();
            channel_id.extend_from_slice(&pid.to_le_bytes());
        }

        channel_id
    }

    /// Install the Digital Groups Organizer app with default version (1.0.0)
    pub fn install_dgo_app_default(self) -> Self {
        self.install_dgo_app(Version::new(1, 0, 0))
    }
}

impl CreateGroupBuilder {
    fn build(self) -> Result<(EncryptionKey, ChaCha20Poly1305Content, GroupInfo), GroupError> {
        let enc_key = EncryptionKey::generate();
        let key_info = GroupKeyInfo::new_chacha20_poly1305(enc_key.key_id);
        let mut metadata = self.metadata;
        if let Some(description) = self.description {
            metadata.push(Metadata::Description(description));
        }
        let group_info = GroupInfo {
            name: self.title,
            settings: self.group_settings,
            key_info,
            metadata,
            installed_apps: self.installed_apps,
        };
        // Encrypt the event before creating the wire protocol message
        let encrypted_payload = encrypt_group_event_content(
            &enc_key,
            &GroupActivityEvent::CreateGroup(group_info.clone()),
        )?;
        Ok((enc_key, encrypted_payload, group_info))
    }
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::builder().build()
    }
}

// Helper functions for common encrypted group operations

/// Create a leave group event
pub fn create_leave_group_event(message: Option<String>) -> GroupActivityEvent {
    GroupActivityEvent::LeaveGroup { message }
}

/// Create a role update event with placeholder acknowledgments for testing
///
/// # ⚠️ WARNING: FOR TESTING ONLY
///
/// This function creates a role update event with placeholder acknowledgments
/// that bypass the dual-acknowledgment security system. It should ONLY be used
/// in tests where the security validation is not the focus.
///
#[cfg(test)]
pub fn create_role_update_event_for_testing(
    member: VerifyingKey,
    role: GroupRole,
) -> GroupActivityEvent {
    // Use placeholder acknowledgments for testing
    let placeholder_ack = MessageId::from_bytes([0; 32]);

    // Create a role assignment event with acknowledgments
    use zoe_app_primitives::group::events::{Acknowledgment, GroupActivityEvent};
    GroupActivityEvent::AssignRole {
        target: zoe_app_primitives::identity::IdentityRef::Key(member),
        role,
        acknowledgment: Acknowledgment::new(placeholder_ack, placeholder_ack),
    }
}

#[cfg(test)]
mod app_integration_tests {
    use super::*;
    use zoe_app_primitives::protocol::{AppProtocolVariant, default_dgo_app};
    use zoe_wire_protocol::version::Version;

    #[tokio::test]
    async fn test_app_executor_registration() {
        let manager = GroupManager::builder().build();

        // Create a test group ID and DGO app
        let group_id = MessageId::from_bytes([1u8; 32]);
        let dgo_app = default_dgo_app();

        // Register the app executor
        let result = manager.register_app_executor(group_id, &dgo_app).await;
        assert!(result.is_ok());

        // Verify the executor was registered
        let app_executors = manager.app_executors.read().await;
        let key = (group_id, dgo_app.app_tag.clone());
        assert!(app_executors.contains_key(&key));

        let executor = app_executors.get(&key).unwrap();
        assert_eq!(
            executor.app_variant(),
            AppProtocolVariant::DigitalGroupsOrganizer
        );
    }

    #[tokio::test]
    async fn test_app_installation_handling() {
        let manager = GroupManager::builder().build();

        // Create test apps
        let group_id = MessageId::from_bytes([2u8; 32]);
        let apps = vec![
            default_dgo_app(),
            InstalledApp::new_simple(
                AppProtocolVariant::DigitalGroupsOrganizer,
                1,
                1,
                vec![3, 4, 5, 6], // Different channel tag
            ),
        ];

        // Handle app installation
        let result = manager.handle_app_installation(group_id, &apps).await;
        assert!(result.is_ok());

        // Verify both executors were registered
        let app_executors = manager.app_executors.read().await;
        assert_eq!(app_executors.len(), 2);

        for app in &apps {
            let key = (group_id, app.app_tag.clone());
            assert!(app_executors.contains_key(&key));
        }
    }

    #[test]
    fn test_installed_apps_support() {
        let builder = CreateGroupBuilder::new("Test Group".to_string())
            .description("A test group with installed apps".to_string())
            .install_dgo_app_default();

        // Verify that the installed apps are properly configured
        assert_eq!(builder.installed_apps.len(), 1);
        let installed_app = &builder.installed_apps[0];
        assert_eq!(
            installed_app.app_id,
            AppProtocolVariant::DigitalGroupsOrganizer
        );
        assert_eq!(installed_app.version, Version::new(1, 0, 0));
        assert!(!installed_app.app_tag.is_empty());
        assert!(installed_app.app_tag.starts_with(b"dgo_"));
    }

    #[test]
    fn test_multiple_installed_apps() {
        let custom_channel_id = vec![1, 2, 3, 4];
        let builder = CreateGroupBuilder::new("Multi-App Group".to_string())
            .install_dgo_app_default()
            .install_app(
                AppProtocolVariant::DigitalGroupsOrganizer,
                Version::new(2, 1, 0),
                custom_channel_id.clone(),
            );

        assert_eq!(builder.installed_apps.len(), 2);

        // First app (default DGO)
        let first_app = &builder.installed_apps[0];
        assert_eq!(first_app.app_id, AppProtocolVariant::DigitalGroupsOrganizer);
        assert_eq!(first_app.version, Version::new(1, 0, 0));

        // Second app (custom DGO)
        let second_app = &builder.installed_apps[1];
        assert_eq!(
            second_app.app_id,
            AppProtocolVariant::DigitalGroupsOrganizer
        );
        assert_eq!(second_app.version, Version::new(2, 1, 0));
        assert_eq!(second_app.app_tag, custom_channel_id);
    }

    #[test]
    fn test_create_group_with_installed_apps() {
        let builder = CreateGroupBuilder::new("Test Group".to_string()).install_dgo_app_default();

        let result = builder.build();
        assert!(result.is_ok());

        let (_, _, group_info) = result.unwrap();
        assert_eq!(group_info.installed_apps.len(), 1);

        let installed_app = &group_info.installed_apps[0];
        assert_eq!(
            installed_app.app_id,
            AppProtocolVariant::DigitalGroupsOrganizer
        );
        assert_eq!(installed_app.version, Version::new(1, 0, 0));
    }
}
