// ChaCha20-Poly1305 and AES-GCM functionality moved to crypto module
use zoe_wire_protocol::{ChaCha20Poly1305Content, KeyPair, MessageId, VerifyingKey};

use zoe_app_primitives::{
    group::{
        app_updates::GroupAppUpdate,
        events::{
            GroupActivityEvent, GroupId, GroupInfo, GroupInitialization, key_info::GroupKeyInfo,
            roles::GroupRole, settings::GroupSettings,
        },
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
    app_manager::GroupAppService,
    error::{GroupError, GroupResult},
    messages::{MessageEvent, MessagesManagerTrait},
    state::GroupSession,
    state::encrypt_group_initialization_content,
};

use async_broadcast::{Receiver, Sender};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use zoe_wire_protocol::{ChannelId, Content, EncryptionKey, MnemonicPhrase, version::Version};

// Import GroupStateError from app-primitives
use zoe_app_primitives::group::states::GroupStateError;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(non_opaque))]
#[derive(Debug, Clone)]
pub enum GroupDataUpdate {
    GroupAdded(GroupSession),
    GroupUpdated(GroupSession),
    GroupRemoved(GroupSession),
}

/// Result of creating a new group
#[cfg_attr(feature = "frb-api", frb(ignore))]
#[derive(Debug, Clone)]
pub struct CreateGroupResult {
    /// The created group's unique identifier (Blake3 hash of the CreateGroup message)
    /// This is also the root event ID used as channel tag for subsequent events
    pub group_id: GroupId,
    /// The full message that was created
    pub published: bool,
    /// the message id of the full message
    pub message_id: MessageId,
    /// The complete message that can be used for joining
    pub message: MessageFull,
}

/// Digital Group Assistant - manages encrypted groups using the wire protocol
#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone)]
pub struct GroupManager<M: MessagesManagerTrait + Clone + 'static> {
    /// All group states managed by this DGA instance
    /// Key is the Blake3 hash of the CreateGroup message (which serves as both group ID and root event ID)
    pub(crate) groups: Arc<RwLock<HashMap<GroupId, GroupSession>>>,

    /// Message manager for publishing and subscribing to messages
    message_manager: Arc<M>,

    broadcast_channel: Arc<Sender<GroupDataUpdate>>,
    /// Keeper receiver to prevent broadcast channel closure (not actively used)
    /// Arc-wrapped to ensure channel stays open even when GroupManager instances are cloned and dropped
    _broadcast_keeper: Arc<async_broadcast::InactiveReceiver<GroupDataUpdate>>,

    /// Channel for broadcasting app settings updates to the app manager
    app_updates_channel: Arc<Sender<GroupAppUpdate>>,
    /// Keeper receiver to prevent app updates channel closure
    _app_updates_keeper: Arc<async_broadcast::InactiveReceiver<GroupAppUpdate>>,

    spawn_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
pub struct GroupManagerBuilder<M: MessagesManagerTrait + Clone + 'static> {
    sessions: Vec<GroupSession>,
    message_manager: Option<Arc<M>>,
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl<M: MessagesManagerTrait + Clone + 'static> GroupManagerBuilder<M> {
    pub fn new(message_manager: Arc<M>) -> Self {
        Self {
            sessions: vec![],
            message_manager: Some(message_manager),
        }
    }

    pub fn with_sessions(mut self, sessions: Vec<GroupSession>) -> Self {
        self.sessions = sessions;
        self
    }

    pub async fn build(self) -> GroupManager<M> {
        let GroupManagerBuilder {
            sessions,
            message_manager,
        } = self;
        let message_manager = message_manager.expect("Message manager must be provided");
        let (tx, rx) = async_broadcast::broadcast(10);
        let (app_tx, app_rx) = async_broadcast::broadcast(10);

        let group_manager = GroupManager {
            groups: Arc::new(RwLock::new(HashMap::from_iter(
                sessions
                    .into_iter()
                    .map(|session| (session.state.group_info.group_id.clone(), session)),
            ))),
            message_manager,
            broadcast_channel: Arc::new(tx),
            _broadcast_keeper: Arc::new(rx.deactivate()),
            app_updates_channel: Arc::new(app_tx),
            _app_updates_keeper: Arc::new(app_rx.deactivate()),
            spawn_handle: Arc::new(RwLock::new(None)),
        };

        // Subscribe to all existing groups and start message processing asynchronously
        // Note: This is done in a spawn to avoid blocking the build method
        let manager_clone = group_manager.clone();
        let spawn_handle = tokio::spawn(async move {
            manager_clone.start_message_processing().await;
        });

        *group_manager.spawn_handle.write().await = Some(spawn_handle);

        group_manager
    }
}

#[cfg_attr(feature = "frb-api", frb)]
impl<M: MessagesManagerTrait + Clone + 'static> GroupManager<M> {
    /// Generate a new encryption key for a group (ChaCha20-Poly1305)
    pub fn generate_group_key() -> EncryptionKey {
        EncryptionKey::generate()
    }

    /// Get the list of group IDs currently known
    pub async fn groups_and_stream(&self) -> (Vec<GroupInfo>, Receiver<GroupDataUpdate>) {
        let groups = self.groups.read().await;
        (
            groups
                .values()
                .map(|session| session.state.group_info.clone())
                .collect(),
            self.subscribe_to_updates(),
        )
    }

    /// Get a group's current state
    pub async fn group_state(&self, group_id: &GroupId) -> Option<GroupState> {
        let groups = self.groups.read().await;
        groups.get(group_id).map(|session| session.state.clone())
    }
    /// Get a group session (state + encryption)
    pub async fn group_session(&self, group_id: &GroupId) -> Option<GroupSession> {
        let groups = self.groups.read().await;
        groups.get(group_id).cloned()
    }

    /// Check if a user is a member of a specific group
    pub async fn is_member(&self, group_id: &GroupId, user: &VerifyingKey) -> bool {
        let groups = self.groups.read().await;
        groups
            .get(group_id)
            .map(|session| session.state.is_member(&IdentityRef::Key(user.clone())))
            .unwrap_or(false)
    }

    /// Get a user's role in a specific group
    pub async fn member_role(&self, group_id: &GroupId, user: &VerifyingKey) -> Option<GroupRole> {
        let groups = self.groups.read().await;
        groups
            .get(group_id)
            .and_then(|session| session.state.member_role(&IdentityRef::Key(user.clone())))
    }

    /// Subscribe to messages for a specific group
    async fn subscribe_to_group(&self, group_id: &GroupId) -> GroupResult<()> {
        use zoe_wire_protocol::Filter;

        // Subscribe to group events (messages tagged with this group ID)
        let group_filter = Filter::Channel(group_id.into());
        self.message_manager
            .ensure_contains_filter(group_filter)
            .await
            .map_err(|e| {
                GroupError::MessageError(format!("Failed to subscribe to group {group_id:?}: {e}"))
            })?;

        tracing::info!(
            group_id = ?group_id,
            "Successfully subscribed to group messages"
        );

        Ok(())
    }

    /// Publish a group event message through the message manager
    async fn publish(&self, message: MessageFull) -> GroupResult<()> {
        let message_id = *message.id();

        self.message_manager
            .publish(message)
            .await
            .map_err(|e| GroupError::MessageError(format!("Failed to publish group event: {e}")))?;

        tracing::info!(
            message_id = ?message_id,
            "Successfully published group event"
        );

        Ok(())
    }

    /// Create and publish a group event in one operation
    pub async fn publish_group_event(
        &self,
        group_id: &GroupId,
        event: GroupActivityEvent,
        sender: &KeyPair,
    ) -> GroupResult<MessageFull> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GroupError::CryptoError(format!("Failed to get timestamp: {e}")))?
            .as_secs();

        // Create the message
        let message = self
            .create_event_message_raw(
                group_id,
                event,
                sender,
                timestamp,
                Kind::Regular,
                vec![Tag::Channel {
                    id: group_id.into(),
                    relays: vec![],
                }],
            )
            .await?;

        // Publish it
        self.publish(message.clone()).await?;

        Ok(message)
    }

    /// Set identity for the current user in a group
    ///
    /// This is a convenience method that creates and publishes a SetIdentity event
    /// to announce the user's participation in the group.
    ///
    /// # Arguments
    /// * `group_id` - The group to set identity in
    /// * `display_name` - The display name for the user
    /// * `metadata` - Additional metadata for the user
    /// * `sender` - The keypair of the user setting their identity
    ///
    /// # Returns
    /// The published message containing the SetIdentity event
    pub async fn set_identity(
        &self,
        group_id: &GroupId,
        display_name: String,
        metadata: Vec<zoe_app_primitives::metadata::Metadata>,
        sender: &KeyPair,
    ) -> GroupResult<MessageFull> {
        let identity = zoe_app_primitives::identity::IdentityInfo {
            display_name,
            metadata,
        };

        let event = zoe_app_primitives::group::events::GroupActivityEvent::SetIdentity(identity);

        self.publish_group_event(group_id, event, sender).await
    }

    /// Create and publish an app event in one operation
    pub async fn publish_event_with_tag<T: serde::Serialize + Send>(
        &self,
        group_id: &GroupId,
        app_tag: ChannelId,
        event: T,
        sender: &KeyPair,
    ) -> GroupResult<MessageFull> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GroupError::CryptoError(format!("Failed to get timestamp: {e}")))?
            .as_secs();

        let message = self
            .create_event_message_raw(
                group_id,
                event,
                sender,
                timestamp,
                Kind::Regular,
                vec![Tag::Channel {
                    id: app_tag,
                    relays: vec![],
                }],
            )
            .await?;

        // Publish it
        self.publish(message.clone()).await?;

        Ok(message)
    }

    /// Start processing incoming messages from the message manager
    async fn start_message_processing(&self) {
        let mut messages_stream = self.message_manager.message_events_stream();
        let group_ids: Vec<GroupId> = {
            let groups = self.groups.read().await;
            groups.keys().cloned().collect()
        };
        for group_id in group_ids {
            if let Err(e) = self.subscribe_to_group(&group_id).await {
                tracing::error!(
                    error = ?e,
                    group_id = ?group_id,
                    "Failed to subscribe to existing group during build"
                );
            }
        }

        tracing::info!("Starting automatic message processing for GroupManager");

        loop {
            let stream_message = match messages_stream.recv().await {
                Ok(stream_message) => stream_message,
                Err(async_broadcast::RecvError::Closed) => {
                    tracing::debug!("Message stream closed, stopping message processing");
                    break;
                }
                Err(e) => {
                    tracing::error!(error = ?e, "Failed to receive message from stream");
                    continue;
                }
            };
            match stream_message {
                MessageEvent::MessageReceived {
                    message,
                    stream_height: _,
                } => {
                    if let Err(e) = self.handle_incoming_message_internal(message).await {
                        tracing::error!(
                            error = ?e,
                            "Failed to process incoming message"
                        );
                    }
                }
                MessageEvent::MessageSent { message, .. } => {
                    if let Err(e) = self.handle_incoming_message_internal(message).await {
                        tracing::error!(
                            error = ?e,
                            "Failed to process sent message"
                        );
                    }
                }
                MessageEvent::CatchUpMessage { message, .. } => {
                    if let Err(e) = self.handle_incoming_message_internal(message).await {
                        tracing::error!(
                            error = ?e,
                            "Failed to process catch-up message"
                        );
                    }
                }
                MessageEvent::StreamHeightUpdate { height } => {
                    tracing::debug!(height = %height, "Stream height updated");
                }
                MessageEvent::CatchUpCompleted { request_id } => {
                    tracing::debug!(request_id = %request_id, "Catch-up completed");
                }
            }
        }

        tracing::warn!("Message processing stream ended");
    }

    async fn session_for_channel_ids(&self, channel_ids: &[GroupId]) -> Option<GroupSession> {
        let groups = self.groups.read().await;
        for channel_id in channel_ids {
            if let Some(group_session) = groups.get(channel_id) {
                return Some(group_session.clone());
            }
        }
        None
    }
    /// Catch up on missed messages for a specific group
    pub async fn catch_up_group(
        &self,
        group_id: &GroupId,
        since: Option<String>,
    ) -> GroupResult<()> {
        use futures::StreamExt;
        use zoe_wire_protocol::Filter;

        let group_filter = Filter::Channel(group_id.into());

        tracing::info!(
            group_id = ?group_id,
            since = ?since,
            "Starting catch-up for group"
        );

        // Get catch-up stream from message manager
        let mut catch_up_stream = self
            .message_manager
            .catch_up_and_subscribe(group_filter, since)
            .await
            .map_err(|e| {
                GroupError::MessageError(format!(
                    "Failed to start catch-up for group {group_id:?}: {e}"
                ))
            })?;

        let mut processed_count = 0;

        // Process all catch-up messages
        while let Some(message_full) = catch_up_stream.next().await {
            let message_id = *message_full.id();
            if let Err(e) = self.handle_incoming_message_internal(*message_full).await {
                tracing::error!(
                    error = ?e,
                    message_id = ?message_id,
                    group_id = ?group_id,
                    "Failed to process catch-up message"
                );
            } else {
                processed_count += 1;
            }
        }

        tracing::info!(
            group_id = ?group_id,
            processed_count = processed_count,
            "Completed catch-up for group"
        );

        Ok(())
    }
}

/// Implementation of GroupAppService for GroupManager
#[async_trait::async_trait]
impl<M: MessagesManagerTrait + Clone + 'static> GroupAppService for GroupManager<M> {
    fn group_app_updates(&self) -> async_broadcast::Receiver<GroupAppUpdate> {
        self.app_updates_channel.new_receiver()
    }

    async fn current_group_states(&self) -> Vec<GroupState> {
        self.groups
            .read()
            .await
            .values()
            .map(|session| session.state.clone())
            .collect()
    }

    async fn decrypt_app_message<T: serde::de::DeserializeOwned>(
        &self,
        group_id: &GroupId,
        encrypted_content: &zoe_wire_protocol::ChaCha20Poly1305Content,
    ) -> GroupResult<T> {
        let groups = self.groups.read().await;
        // Convert MessageId to GroupId for lookup
        let group_session = groups
            .get(group_id)
            .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;

        let decrypted_bytes = group_session
            .current_key
            .decrypt_content(encrypted_content)
            .map_err(|e| GroupError::InvalidEvent(format!("Failed to decrypt app message: {e}")))?;

        postcard::from_bytes(&decrypted_bytes).map_err(|e| {
            GroupError::InvalidEvent(format!("Failed to deserialize decrypted data: {e}"))
        })
    }
    async fn current_group_state(&self, group_id: &GroupId) -> Option<GroupState> {
        self.groups
            .read()
            .await
            .get(group_id)
            .map(|session| session.state.clone())
    }

    async fn group_state_at_message(
        &self,
        group_id: &GroupId,
        message_id: MessageId,
    ) -> Option<GroupState> {
        let mut groups = self.groups.write().await;
        let group_session = groups.get_mut(group_id)?;

        // Use the group state's reconstruction method to get state at specific message
        group_session
            .state
            .lookup_group_state_at_message(message_id)
    }

    async fn get_permission_context(
        &self,
        group_id: &GroupId,
        actor_identity_ref: &zoe_app_primitives::identity::IdentityRef,
        group_state_reference: zoe_wire_protocol::MessageId,
        app_id: &zoe_app_primitives::protocol::AppProtocolVariant,
    ) -> (
        zoe_app_primitives::group::events::roles::GroupRole,
        zoe_wire_protocol::MessageId,
        zoe_app_primitives::group::events::permissions::GroupPermissions,
    ) {
        let mut groups = self.groups.write().await;

        // Default to Member role and initial group creation message ID
        let mut actor_role = zoe_app_primitives::group::events::roles::GroupRole::Member;
        let mut app_state_message_id = MessageId::from([0u8; 32]); // Default fallback

        if let Some(group_session) = groups.get_mut(group_id) {
            // Get the initial group creation message ID from the event history
            let initial_message_id = group_session
                .state
                .event_history
                .first()
                .copied()
                .unwrap_or(MessageId::from([0u8; 32]));

            // Optimize for the common case: if referencing current state (all zeros), use current state directly
            if group_state_reference == MessageId::from([0u8; 32]) {
                actor_role = group_session
                    .state
                    .members
                    .get(actor_identity_ref)
                    .map(|member| member.role.clone())
                    .unwrap_or(zoe_app_primitives::group::events::roles::GroupRole::Member);

                // For current state, use the initial group creation message ID as baseline
                app_state_message_id = initial_message_id;
            } else {
                // For historical state, use the reconstruction method
                if let Some(group_state) = group_session
                    .state
                    .lookup_group_state_at_message(group_state_reference)
                {
                    actor_role = group_state
                        .get_actor_role_at_message(actor_identity_ref, group_state_reference)
                        .unwrap_or(zoe_app_primitives::group::events::roles::GroupRole::Member);

                    // Get the last app settings message ID before the group state reference
                    // If no app settings found, use the initial group creation message ID
                    app_state_message_id = group_state
                        .get_app_settings_message_before(app_id, group_state_reference)
                        .unwrap_or(initial_message_id);
                }
            }
        }

        // Get group permissions from the group state (always present)
        let group_permissions = if let Some(group_session) = groups.get(group_id) {
            group_session.state.group_info.settings.permissions.clone()
        } else {
            zoe_app_primitives::group::events::permissions::GroupPermissions::default()
        };

        (actor_role, app_state_message_id, group_permissions)
    }

    async fn publish_app_event<T: serde::Serialize + Send>(
        &self,
        group_id: &GroupId,
        app_tag: zoe_wire_protocol::ChannelId,
        event: T,
        sender: &zoe_wire_protocol::KeyPair,
    ) -> GroupResult<zoe_wire_protocol::MessageFull> {
        // Call the actual implementation method (not the trait method)
        GroupManager::publish_event_with_tag(self, group_id, app_tag, event, sender).await
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl<M: MessagesManagerTrait + Clone + 'static> GroupManager<M> {
    /// Create a new DGA instance builder
    pub fn builder(message_manager: Arc<M>) -> GroupManagerBuilder<M> {
        GroupManagerBuilder::new(message_manager)
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
        // The group_id is the channel_id (no conversion needed)
        let group_id = group_info.group_id.clone();
        let installed_apps = group_info.installed_apps.clone();

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

        // Create ActivityMeta for the group creation
        // For ActivityMeta, we need MessageId, so convert the message ID
        let message_id = *message_full.id();

        // Create the unified group session
        let group_session =
            GroupSession::new(GroupState::initial(&message_full, group_info), enc_key);

        // Store the group session
        self.groups
            .write()
            .await
            .insert(group_id.clone(), group_session.clone());

        // Subscribe to messages for this group
        if let Err(e) = self.subscribe_to_group(&group_id).await {
            tracing::error!(
                error = ?e,
                group_id = ?group_id,
                "Failed to subscribe to group messages during creation"
            );
        }
        // Publish the group creation message
        let published = {
            if let Err(e) = self.publish(message_full.clone()).await {
                tracing::error!(
                    error = ?e,
                    group_id = ?group_id,
                    "Failed to publish group creation message"
                );
                false
            } else {
                true
            }
        };

        // Broadcast the group addition
        self.safe_broadcast(GroupDataUpdate::GroupAdded(group_session.clone()));

        // Broadcast app installations for any installed apps
        if !installed_apps.is_empty() {
            self.safe_broadcast_app_update(GroupAppUpdate::InstalledApsUpdate {
                group_id: group_id.clone(),
                installed_apps,
            });
        }

        Ok(CreateGroupResult {
            group_id,
            published,
            message_id,
            message: message_full,
        })
    }

    /// Create an encrypted message for a group activity event
    /// The group_id parameter should be the Blake3 hash of the CreateGroup message
    async fn create_event_message_raw<T: Serialize>(
        &self,
        group_id: &GroupId,
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
                .get(group_id)
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

    /// Process an incoming group event message (internal implementation)
    async fn handle_incoming_message_internal(&self, message_full: MessageFull) -> GroupResult<()> {
        // Extract the encrypted payload from the message
        let message_id = *message_full.id();
        let Message::MessageV0(message) = message_full.message();

        // Get the encrypted payload from the message content
        let Content::ChaCha20Poly1305(encrypted_payload) = &message.content else {
            tracing::trace!(
                message_id = ?message_id,
                "Message is not a ChaCha20Poly1305 encrypted message, skipping"
            );
            return Ok(());
        };

        let channel_tags = message
            .tags
            .clone()
            .into_iter()
            .filter_map(|tag| match tag {
                zoe_wire_protocol::Tag::Channel { id, .. } => id.try_into().ok(),
                _ => None,
            })
            .collect::<Vec<GroupId>>();

        if channel_tags.is_empty() {
            tracing::trace!(
                message_id = ?message_id,
                "No channel tags found for message, skipping"
            );
            return Ok(());
        };

        let Some(group_session) = self.session_for_channel_ids(&channel_tags).await else {
            tracing::trace!(
                message_id = ?message_id,
                channel_tags = ?channel_tags,
                "No group session found for channel tags, skipping"
            );
            return Ok(());
        };

        let event = match group_session.decrypt_group_event::<GroupActivityEvent>(encrypted_payload)
        {
            Ok(event) => event,
            Err(e) => {
                tracing::error!(
                    message_id = ?message_id,
                    "Failed to decrypt group event: {e}"
                );
                return Ok(());
            }
        };

        // CreateGroup events are no longer handled here - they should be processed
        // through the separate group initialization pipeline using GroupInitialization

        // Extract needed information from the message
        let sender = message_full.author().clone();
        let timestamp = *message_full.when();

        // Find the channel_id for this group session
        let group_id = group_session.state.group_info.group_id; // We know there's at least one from the check above

        let (group_session, app_update) = {
            // This is a subsequent event - apply to existing group state
            let mut groups = self.groups.write().await;
            let group_session = groups
                .get_mut(&group_id)
                .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;

            tracing::trace!(
                message_id = ?message_id,
                group_id = ?group_id,
                "Applying event to group state"
            );

            // Apply the event to the group state (convert GroupStateError to GroupError)
            let app_update = group_session
                .state
                .apply_event(
                    event.clone(),
                    *message_full.id(),
                    zoe_app_primitives::identity::IdentityRef::Key(sender.clone()),
                    timestamp,
                )
                .map_err(|e| match e {
                    GroupStateError::PermissionDenied(msg) => GroupError::PermissionDenied(msg),
                    GroupStateError::StateTransition(msg) => GroupError::StateTransition(msg),
                    GroupStateError::InvalidOperation(msg) => GroupError::InvalidOperation(msg),
                    GroupStateError::HistoryRewriteAttempt(msg) => {
                        GroupError::InvalidOperation(msg)
                    }
                    GroupStateError::InvalidSender(msg) => GroupError::InvalidOperation(msg),
                    GroupStateError::InvalidAcknowledgment(msg) => {
                        GroupError::InvalidOperation(msg)
                    }
                })?;
            (group_session.clone(), app_update)
        };

        // Forward app update to app manager if the event was authorized
        if let Some(app_update) = app_update {
            tracing::trace!(
                message_id = ?message_id,
                group_id = ?group_id,
                "Forwarding authorized app update to app manager"
            );
            self.safe_broadcast_app_update(app_update);
        }

        // Broadcast the group update
        self.safe_broadcast(GroupDataUpdate::GroupUpdated(group_session));

        Ok(())
    }

    fn safe_broadcast(&self, message: GroupDataUpdate) {
        match self.broadcast_channel.try_broadcast(message) {
            Ok(_) => {}
            Err(async_broadcast::TrySendError::Closed(_)) => {
                tracing::trace!("Broadcast channel closed, skipping broadcast");
            }
            Err(e) => tracing::error!(error=?e, "Failed to broadcast group update"),
        }
    }

    fn safe_broadcast_app_update(&self, message: GroupAppUpdate) {
        match self.app_updates_channel.try_broadcast(message) {
            Ok(_) => {}
            Err(async_broadcast::TrySendError::Closed(_)) => {
                tracing::trace!("App updates channel closed, skipping broadcast");
            }
            Err(e) => tracing::error!(error=?e, "Failed to broadcast app update"),
        }
    }
    /// Subscribe to group updates
    pub fn subscribe_to_updates(&self) -> Receiver<GroupDataUpdate> {
        self.broadcast_channel.new_receiver()
    }

    /// Join an existing encrypted group by decrypting the group creation event
    ///
    /// This function takes an encrypted group creation message and its decryption key,
    /// decrypts the group initialization event, creates a new GroupSession, adds it to
    /// the session pool, and subscribes to the group channel for future messages.
    ///
    /// # Arguments
    ///
    /// * `encrypted_message` - The encrypted group creation message (MessageFull)
    /// * `decryption_key` - The encryption key needed to decrypt the group creation event
    ///
    /// # Returns
    ///
    /// Returns the group ID (GroupId) of the joined group on success.
    ///
    /// # Errors
    ///
    /// Returns `GroupError` if:
    /// - The message cannot be decrypted with the provided key
    /// - The decrypted content is not a valid GroupInitialization event
    /// - The group session cannot be created
    /// - Subscription to the group channel fails
    pub async fn join_group(
        &self,
        encrypted_message: MessageFull,
        decryption_key: EncryptionKey,
    ) -> GroupResult<GroupId> {
        // Extract the encrypted payload from the message
        let Content::ChaCha20Poly1305(payload) = encrypted_message.content() else {
            return Err(GroupError::CryptoError(
                "Message does not contain ChaCha20Poly1305 encrypted content".to_string(),
            ));
        };

        // Decrypt the group initialization event
        let plaintext = decryption_key.decrypt_content(payload).map_err(|e| {
            GroupError::CryptoError(format!("Failed to decrypt group creation message: {e}"))
        })?;

        // Deserialize the group initialization event
        let group_init: GroupInitialization = postcard::from_bytes(&plaintext).map_err(|e| {
            GroupError::CryptoError(format!(
                "Failed to deserialize group initialization event: {e}"
            ))
        })?;

        let group_info = group_init.group_info;
        let group_name = group_info.name.clone();
        let group_id = group_info.group_id.clone();

        // Create the group state from the decrypted information
        let group_state = GroupState::initial(&encrypted_message, group_info);

        // Create the group session
        let group_session = GroupSession::new(group_state, decryption_key);

        // Store the group session
        self.groups
            .write()
            .await
            .insert(group_id.clone(), group_session.clone());

        // Subscribe to messages for this group
        self.subscribe_to_group(&group_id).await?;

        // Broadcast the group addition
        self.safe_broadcast(GroupDataUpdate::GroupAdded(group_session));

        tracing::info!(
            group_id = ?group_id,
            group_name,
            "Successfully joined encrypted group"
        );

        Ok(group_id)
    }

    /// Create a subscription filter for a specific group
    /// This returns the Event tag that should be used to subscribe to group events
    pub async fn create_group_subscription_filter(&self, group_id: &GroupId) -> GroupResult<Tag> {
        // Verify the group exists
        let groups = self.groups.read().await;
        if !groups.contains_key(group_id) {
            return Err(GroupError::GroupNotFound(format!("{group_id:?}")));
        }

        Ok(Tag::Channel {
            id: group_id.into(), // The group ID is the channel ID
            relays: vec![],      // Could be populated with known relays
        })
    }
}

#[cfg(test)]
impl<M: MessagesManagerTrait + Clone + 'static> GroupManager<M> {
    /// Process an incoming group event message
    pub async fn handle_incoming_message(&self, message_full: MessageFull) -> GroupResult<()> {
        self.handle_incoming_message_internal(message_full).await
    }

    /// Add a complete group session
    pub async fn add_group_session(&self, group_id: GroupId, session: GroupSession) {
        self.groups.write().await.insert(group_id, session.clone());
        self.safe_broadcast(GroupDataUpdate::GroupAdded(session));
    }

    /// Remove a group session
    pub async fn remove_group_session(&self, group_id: &GroupId) -> Option<GroupSession> {
        if let Some(session) = self.groups.write().await.remove(group_id) {
            let _ = self
                .broadcast_channel
                .try_broadcast(GroupDataUpdate::GroupRemoved(session.clone()));
            Some(session)
        } else {
            None
        }
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
        let app_tag = Self::geenrate_random_group_id();
        self.installed_apps.push(InstalledApp::new(
            AppProtocolVariant::DigitalGroupsOrganizer,
            version,
            app_tag.into(),
        ));
        self
    }

    /// Generate a random channel ID for group identification
    ///
    /// Creates a cryptographically random 32-byte identifier that serves as both
    /// the channel ID and group ID. This provides privacy by disconnecting the
    /// group identifier from the original message hash.
    fn geenrate_random_group_id() -> GroupId {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut channel_id = [0u8; 32];
        rng.fill_bytes(&mut channel_id);
        channel_id.into()
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
            group_id: Self::geenrate_random_group_id(),
            settings: self.group_settings,
            key_info,
            metadata,
            installed_apps: self.installed_apps,
        };
        // Create the group initialization structure
        let group_init = zoe_app_primitives::group::events::GroupInitialization {
            group_info: group_info.clone(),
        };

        // Encrypt the initialization event
        let encrypted_payload = encrypt_group_initialization_content(&enc_key, &group_init)?;
        Ok((enc_key, encrypted_payload, group_info))
    }
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
    let _placeholder_ack = MessageId::from_bytes([0; 32]);

    // Create a role assignment event with acknowledgments
    use zoe_app_primitives::group::events::GroupActivityEvent;
    GroupActivityEvent::AssignRole {
        target: IdentityRef::Key(member),
        role,
    }
}

#[cfg(test)]
mod app_integration_tests {
    use super::*;
    use zoe_app_primitives::protocol::AppProtocolVariant;
    use zoe_wire_protocol::version::Version;

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
        assert_eq!(installed_app.app_tag.len(), 32); // Random 32-byte tag
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
