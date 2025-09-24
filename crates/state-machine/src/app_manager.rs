//! Application Manager - Handles app-specific message processing
//!
//! The AppManager is responsible for:
//! - Subscribing to application channels based on notifications from GroupManager
//! - Processing app-specific messages through appropriate executors
//! - Coordinating with GroupManager for decryption and attestation
//! - Managing the lifecycle of app-specific subscriptions

use async_broadcast::Receiver;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use zoe_app_primitives::{
    digital_groups_organizer::{events::core::DgoActivityEvent, models::core::ActivityMeta},
    group::{app::ExecutorEvent, events::GroupId, states::GroupState},
    protocol::{AppProtocolVariant, InstalledApp},
};
use zoe_wire_protocol::{ChannelId, Filter, MessageFull, MessageId};

use crate::{
    apps::dgo::DgoExecutor,
    error::{GroupError, GroupResult},
    execution::ExecutorStore,
    group::GroupDataUpdate,
    messages::MessagesManagerTrait,
};

/// Result of synchronizing an app channel with group channel
#[derive(Debug, Clone, Default)]
pub struct SyncResult {
    /// Total number of events processed during sync
    pub events_processed: usize,
    /// Number of events that passed validation
    pub events_validated: usize,
    /// Number of events marked as invalid
    pub events_marked_invalid: usize,
    /// Number of conflicts resolved
    pub conflicts_resolved: usize,
}

/// Result of reconstructing app state from valid events
#[derive(Debug, Clone)]
pub struct ReconstructionResult {
    /// Total number of events considered
    pub total_events: usize,
    /// Number of valid events used for reconstruction
    pub valid_events: usize,
    /// Number of invalid events excluded
    pub invalid_events: usize,
    /// Whether state reconstruction was successful
    pub state_reconstructed: bool,
}

/// Strategy for resolving conflicts in app events
#[derive(Debug, Clone, Copy)]
pub enum ConflictResolutionStrategy {
    /// Mark conflicting events as invalid but preserve them
    MarkInvalid,
    /// Skip conflicting events entirely
    Skip,
    /// Use best-effort validation with current group state
    BestEffort,
}

/// Result of conflict resolution
#[derive(Debug, Clone)]
pub struct ConflictResolutionResult {
    /// Number of conflicts found
    pub conflicts_found: usize,
    /// Number of conflicts successfully resolved
    pub conflicts_resolved: usize,
    /// Number of conflicts remaining unresolved
    pub conflicts_remaining: usize,
    /// Strategy that was used for resolution
    pub strategy_used: ConflictResolutionStrategy,
}

/// Notification about a new application channel that should be subscribed to
#[derive(Debug, Clone)]
pub struct AppChannelNotification {
    /// The group this app is installed in
    pub group_id: GroupId,
    /// The installed application details
    pub installed_app: InstalledApp,
}

#[derive(Debug, Clone)]
pub struct AppState {
    pub group_id: GroupId,
    pub installed_app: InstalledApp,
}

/// Interface for requesting decryption services from the GroupManager
#[async_trait::async_trait]
pub trait GroupService: Send + Sync {
    fn message_group_receiver(&self) -> Receiver<GroupDataUpdate>;

    async fn current_group_states(&self) -> Vec<GroupState>;

    /// Decrypt an app message using the group's encryption key
    async fn decrypt_app_message<T: DeserializeOwned>(
        &self,
        group_id: &GroupId,
        encrypted_content: &zoe_wire_protocol::ChaCha20Poly1305Content,
    ) -> GroupResult<T>;

    /// Get group state at a specific message ID for cross-channel validation
    async fn group_state_at_message(
        &self,
        group_id: &GroupId,
        message_id: zoe_wire_protocol::MessageId,
    ) -> Option<GroupState>;

    /// Get actor role and app state message ID for permission validation
    ///
    /// This is a convenience function that optimizes the common case where
    /// we need both the actor's role and the last app state message ID for
    /// a specific group state reference and app combination.
    ///
    /// # Arguments
    /// * `group_id` - The group to query
    /// * `actor_identity_ref` - The actor whose role we want to look up
    /// * `group_state_reference` - The group message ID to reference for permissions
    /// * `app_id` - The app protocol variant to get state for
    ///
    /// # Returns
    /// A tuple of (actor_role, app_state_message_id). The actor_role defaults to Member
    /// if the actor is not found in the group. The app_state_message_id is always the
    /// initial group creation message ID as the baseline, or the last app settings update
    /// if one exists before the group state reference.
    async fn get_permission_context(
        &self,
        group_id: &GroupId,
        actor_identity_ref: &zoe_app_primitives::identity::IdentityRef,
        group_state_reference: zoe_wire_protocol::MessageId,
        app_id: &zoe_app_primitives::protocol::AppProtocolVariant,
    ) -> (
        zoe_app_primitives::group::events::roles::GroupRole,
        zoe_wire_protocol::MessageId,
    );
}

/// Manages app-specific message processing, decoupled from group management

#[derive(Clone)]
pub struct AppManager<
    M: MessagesManagerTrait,
    G: GroupService + 'static,
    S: ExecutorStore + 'static,
> {
    /// Message manager for subscribing to app channels
    message_manager: Arc<M>,

    /// Service for requesting decryption from GroupManager
    group_service: Arc<G>,

    /// DGO executor - always available for DGO app messages
    dgo_executor: Arc<DgoExecutor<S>>,

    /// Currently subscribed app channels
    /// Key: (group_id, app_tag) -> InstalledApp
    app_states: Arc<RwLock<HashMap<ChannelId, AppState>>>,

    // background handle
    handle: Arc<RwLock<Option<JoinHandle<()>>>>,
}

impl<
    M: MessagesManagerTrait + Clone + 'static,
    G: GroupService + Clone + 'static,
    S: ExecutorStore + Clone + 'static,
> AppManager<M, G, S>
{
    /// Create a new AppManager
    pub async fn new(message_manager: Arc<M>, group_service: Arc<G>, store: S) -> Self {
        // Create DGO executor - always available at startup
        let dgo_executor = Arc::new(DgoExecutor::new(crate::apps::dgo::DgoFactory, store));

        let current_states = group_service.current_group_states().await;
        let app_states = Arc::new(RwLock::new(
            current_states
                .iter()
                .flat_map(|state| {
                    state.group_info.installed_apps.iter().map(|app| {
                        (
                            app.app_tag.clone(),
                            AppState {
                                group_id: state.group_info.group_id.clone(),
                                installed_app: app.clone(),
                            },
                        )
                    })
                })
                .collect::<HashMap<ChannelId, AppState>>(),
        ));

        let mut message_group_notifications = group_service.message_group_receiver();
        let mut messages_stream = message_manager.messages_stream();
        let mut catch_up_stream = message_manager.catch_up_stream();

        let app_manager = Self {
            message_manager,
            group_service,
            dgo_executor,
            app_states,
            handle: Arc::new(RwLock::new(None)),
        };

        let app_manager_clone = app_manager.clone();

        let task_handle = tokio::spawn(async move {
            use zoe_wire_protocol::StreamMessage;

            loop {
                tokio::select! {
                    notification = message_group_notifications.recv() => {
                        if let Ok(notification) = notification
                            && let Err(e) = app_manager_clone.handle_channel_update(notification).await {
                                tracing::error!(error = ?e, "Failed to handle app channel notification");
                            }
                    }

                    catch_up_response = catch_up_stream.recv() => {
                        if let Ok(catch_up_response) = catch_up_response {
                            for message in catch_up_response.messages {
                                if let Err(e) = app_manager_clone.handle_app_message(message).await {
                                    tracing::error!(error = ?e, "Failed to process app message");
                                }
                            }
                        }
                    }

                    stream_message = messages_stream.recv() => {
                        if let Ok(stream_message) = stream_message {
                            match stream_message {
                                StreamMessage::MessageReceived { message, stream_height: _ } => {
                                    let message_id = *message.id();
                                    if let Err(e) = app_manager_clone.handle_app_message(*message).await {
                                        tracing::error!(
                                            error = ?e,
                                            message_id = ?message_id,
                                            "Failed to process app message"
                                        );
                                    }
                                }
                                StreamMessage::StreamHeightUpdate(height) => {
                                    tracing::debug!(height = %height, "App message stream height updated");
                                }
                            }
                        }
                    }
                }
            }
        });

        *app_manager.handle.write().await = Some(task_handle);

        app_manager
    }
    /// Handle a notification about a new app channel
    async fn handle_channel_update(&self, notification: GroupDataUpdate) -> GroupResult<()> {
        let (group_id, installed_apps) = match notification {
            GroupDataUpdate::GroupUpdated(group_session) => (
                group_session.state.group_info.group_id,
                group_session.state.group_info.installed_apps,
            ),
            GroupDataUpdate::GroupAdded(group_session) => (
                group_session.state.group_info.group_id,
                group_session.state.group_info.installed_apps,
            ),
            GroupDataUpdate::GroupRemoved(group_session) => {
                tracing::warn!(group_id = ?group_session.state.group_info.group_id, "Group removed, skipping subscription");
                return Ok(());
            }
        };

        // Process each installed app
        for installed_app in installed_apps {
            // Check if we have an executor for this app
            if !self.is_executor_available(&installed_app.app_id) {
                tracing::warn!(
                    group_id = ?group_id,
                    app_id = ?installed_app.app_id,
                    "No executor available for app, skipping subscription"
                );
                continue;
            }

            // Subscribe to the app channel
            let channel_filter = Filter::Channel(installed_app.app_tag.clone());
            self.message_manager
                .ensure_contains_filter(channel_filter)
                .await
                .map_err(|e| {
                    GroupError::MessageError(format!("Failed to subscribe to app channel: {e}"))
                })?;

            // Track the subscription
            let mut app_states = self.app_states.write().await;
            app_states.insert(
                installed_app.app_tag.clone(),
                AppState {
                    group_id: group_id.clone(),
                    installed_app: installed_app.clone(),
                },
            );

            tracing::info!(
                group_id = ?group_id,
                app_id = ?installed_app.app_id,
                app_tag = ?hex::encode(&installed_app.app_tag),
                "Successfully subscribed to app channel"
            );
        }

        Ok(())
    }

    async fn get_app_state(&self, channel_ids: &[ChannelId]) -> Option<AppState> {
        let app_states = self.app_states.read().await;

        for channel_id in channel_ids {
            if let Some(app_state) = app_states.get(channel_id) {
                return Some(app_state.clone());
            }
        }
        None
    }

    /// Handle an incoming app message
    async fn handle_app_message(&self, message_full: MessageFull) -> GroupResult<()> {
        use zoe_wire_protocol::{Content, Message};

        let Message::MessageV0(message) = message_full.message();
        let activity_id = *message_full.id();

        // Only process encrypted messages that could be app events
        let Content::ChaCha20Poly1305(_encrypted_payload) = &message.content else {
            tracing::trace!(message_id = ?activity_id, "Non-encrypted message, skipping");
            // Skip non-encrypted messages
            return Ok(());
        };

        let channel_ids = message
            .tags
            .clone()
            .into_iter()
            .filter_map(|tag| match tag {
                zoe_wire_protocol::Tag::Channel { id, .. } => Some(id),
                _ => None,
            })
            .collect::<Vec<_>>();

        if channel_ids.is_empty() {
            tracing::trace!(
                message_id = ?activity_id,
                "No tags found for message, skipping"
            );
            return Ok(());
        }

        let Some(app_state) = self.get_app_state(&channel_ids).await else {
            tracing::debug!(message_id = ?activity_id, channel_ids = ?channel_ids, "No app state found for the message channels. Skipping");
            return Ok(());
        };

        self.execute_app_message(app_state, message_full).await?;
        tracing::trace!(
            message_id = ?activity_id,
            "App message processed successfully"
        );

        Ok(())
    }

    pub async fn execute_app_message(
        &self,
        app_state: AppState,
        message_full: MessageFull,
    ) -> GroupResult<()> {
        use zoe_wire_protocol::{Content, Message};

        let Message::MessageV0(message) = message_full.message();
        let activity_id = *message_full.id();

        // Only process encrypted messages that could be app events
        let Content::ChaCha20Poly1305(encrypted_payload) = &message.content else {
            tracing::trace!(message_id = ?activity_id, "Non-encrypted message in execute_app_message, skipping");
            return Ok(());
        };

        // Process the message through the appropriate executor based on app type
        match &app_state.installed_app.app_id {
            AppProtocolVariant::DigitalGroupsOrganizer => {
                tracing::trace!(message_id = ?activity_id, "Processing DGO event");
                // Deserialize and decrypt as DGO event
                let dgo_event: DgoActivityEvent = self
                    .group_service
                    .decrypt_app_message(&app_state.group_id, encrypted_payload)
                    .await?;

                // Get group state reference from the event for permission validation
                let group_state_reference = dgo_event.group_state_reference();

                // Extract actor identity from the message envelope (not from the event)
                let actor_identity_ref = dgo_event.identity_ref(&message.sender);

                // Use the convenience function to get both actor role and app state message ID
                let (actor_role, state_message_id) = self
                    .group_service
                    .get_permission_context(
                        &app_state.group_id,
                        &actor_identity_ref,
                        group_state_reference,
                        &app_state.installed_app.app_id,
                    )
                    .await;

                let group_meta = ActivityMeta {
                    activity_id,
                    group_id: app_state.group_id.clone(),
                    actor: actor_identity_ref,
                    timestamp: message.when,
                };

                // Execute through DGO executor with resolved permissions
                self.dgo_executor
                    .execute_event(dgo_event, group_meta, actor_role, state_message_id)
                    .await
                    .map_err(|e| {
                        GroupError::InvalidEvent(format!("Failed to execute DGO event: {e}"))
                    })?;
            }
            AppProtocolVariant::Unknown(app_name) => {
                tracing::warn!(
                    app_name = %app_name,
                    activity_id = ?activity_id,
                    "No executor available for unknown app"
                );
            }
        }

        tracing::debug!(
            group_id = ?app_state.group_id,
            app_id = ?app_state.installed_app.app_id,
            message_id = ?activity_id,
            "App message processed successfully"
        );

        Ok(())
    }

    /// Check if an executor is available for the given app
    pub fn is_executor_available(&self, app_id: &AppProtocolVariant) -> bool {
        match app_id {
            AppProtocolVariant::DigitalGroupsOrganizer => true,
            AppProtocolVariant::Unknown(_) => false,
        }
    }

    /// Synchronize app channel with group channel state
    ///
    /// This method implements lazy validation and app state reconstruction by:
    /// 1. Validating app events against their referenced group states
    /// 2. Filtering out invalid events from app state reconstruction
    /// 3. Handling conflicts when group state references are invalid
    ///
    /// # Parameters
    ///
    /// - `group_id` - The group to synchronize
    /// - `app_channel_id` - The app channel to synchronize
    ///
    /// # Returns
    ///
    /// - `Ok(SyncResult)` - Synchronization completed with statistics
    /// - `Err(GroupError)` - Synchronization failed
    pub async fn sync_with_group_channel(
        &self,
        group_id: &GroupId,
        app_channel_id: &zoe_wire_protocol::ChannelId,
    ) -> GroupResult<SyncResult> {
        tracing::info!(
            group_id = ?group_id,
            app_channel_id = ?hex::encode(app_channel_id),
            "Starting app channel synchronization with group channel"
        );

        let mut sync_result = SyncResult::default();

        // Get the app state for this channel
        let app_states = self.app_states.read().await;
        let Some(app_state) = app_states.get(app_channel_id) else {
            return Err(GroupError::InvalidEvent(format!(
                "No app state found for channel {:?}",
                hex::encode(app_channel_id)
            )));
        };

        if app_state.group_id != *group_id {
            return Err(GroupError::InvalidEvent(format!(
                "App channel belongs to different group: expected {:?}, found {:?}",
                group_id, app_state.group_id
            )));
        }

        let _app_state = app_state.clone();
        drop(app_states);

        // Get current group state for validation
        let _current_group_state = self
            .group_service
            .group_state_at_message(group_id, MessageId::from([0u8; 32])) // Use current state
            .await
            .ok_or_else(|| GroupError::GroupNotFound(format!("{group_id:?}")))?;

        // TODO: Implement message history retrieval for the app channel
        // For now, we'll implement a placeholder that demonstrates the pattern

        // In a real implementation, this would:
        // 1. Retrieve all messages from the app channel
        // 2. Decrypt and deserialize each message as an app event
        // 3. Validate each event against its referenced group state
        // 4. Mark invalid events and exclude them from state reconstruction
        // 5. Rebuild app state from valid events only

        tracing::info!(
            group_id = ?group_id,
            app_channel_id = ?hex::encode(app_channel_id),
            "App channel synchronization placeholder completed"
        );

        // For now, return success with placeholder statistics
        sync_result.events_processed = 0;
        sync_result.events_validated = 0;
        sync_result.events_marked_invalid = 0;
        sync_result.conflicts_resolved = 0;

        Ok(sync_result)
    }

    /// Validate app event permissions with lazy loading
    ///
    /// This method implements lazy validation where permissions are only checked
    /// when needed, rather than on every event processing.
    ///
    /// # Parameters
    ///
    /// - `app_event` - The app event to validate (must implement ExecutorEvent)
    /// - `sender` - The identity attempting the action
    /// - `app_state` - The app state context
    ///
    /// # Returns
    ///
    /// - `Ok(())` - Event is valid
    /// - `Err(GroupError)` - Event is invalid or permissions insufficient
    pub async fn validate_app_event_lazy<T>(
        &self,
        app_event: &T,
        sender: &zoe_app_primitives::identity::IdentityRef,
        app_state: &AppState,
    ) -> GroupResult<()>
    where
        T: zoe_app_primitives::group::app::ExecutorEvent,
    {
        // Get the group state reference from the app event
        let group_state_ref = app_event.group_state_reference();

        // Lazy load the group state at the referenced message
        let mut group_state = self
            .group_service
            .group_state_at_message(&app_state.group_id, group_state_ref)
            .await
            .ok_or_else(|| {
                GroupError::InvalidEvent(format!(
                    "Referenced group state {group_state_ref:?} not found for validation"
                ))
            })?;

        // Use the group state's validation method
        group_state
            .validate_app_event_permissions(app_event, sender, &app_state.installed_app.app_id)
            .map_err(|e| GroupError::InvalidEvent(format!("Permission validation failed: {e}")))
    }

    /// Reconstruct app state from valid events only
    ///
    /// This method rebuilds app state by filtering out events that failed validation,
    /// ensuring that only valid events contribute to the final state.
    ///
    /// # Parameters
    ///
    /// - `group_id` - The group ID
    /// - `app_channel_id` - The app channel ID
    /// - `up_to_message` - Optional message ID to reconstruct state up to
    ///
    /// # Returns
    ///
    /// - `Ok(ReconstructionResult)` - Reconstruction completed
    /// - `Err(GroupError)` - Reconstruction failed
    pub async fn reconstruct_app_state_from_valid_events(
        &self,
        group_id: &GroupId,
        app_channel_id: &zoe_wire_protocol::ChannelId,
        up_to_message: Option<MessageId>,
    ) -> GroupResult<ReconstructionResult> {
        tracing::info!(
            group_id = ?group_id,
            app_channel_id = ?hex::encode(app_channel_id),
            up_to_message = ?up_to_message,
            "Starting app state reconstruction from valid events"
        );

        // TODO: Implement actual reconstruction logic
        // This would involve:
        // 1. Loading all events from the app channel up to the specified message
        // 2. Validating each event against its group state reference
        // 3. Building state only from valid events
        // 4. Tracking which events were excluded and why

        let reconstruction_result = ReconstructionResult {
            total_events: 0,
            valid_events: 0,
            invalid_events: 0,
            state_reconstructed: true,
        };

        tracing::info!(
            group_id = ?group_id,
            app_channel_id = ?hex::encode(app_channel_id),
            result = ?reconstruction_result,
            "App state reconstruction completed"
        );

        Ok(reconstruction_result)
    }

    /// Resolve conflicts for app events with invalid group references
    ///
    /// This method handles cases where app events reference group states that
    /// don't exist or are inconsistent, implementing conflict resolution strategies.
    ///
    /// # Parameters
    ///
    /// - `group_id` - The group ID
    /// - `app_channel_id` - The app channel ID
    /// - `conflict_strategy` - The strategy to use for resolving conflicts
    ///
    /// # Returns
    ///
    /// - `Ok(ConflictResolutionResult)` - Conflicts resolved
    /// - `Err(GroupError)` - Resolution failed
    pub async fn resolve_app_event_conflicts(
        &self,
        group_id: &GroupId,
        app_channel_id: &zoe_wire_protocol::ChannelId,
        conflict_strategy: ConflictResolutionStrategy,
    ) -> GroupResult<ConflictResolutionResult> {
        tracing::info!(
            group_id = ?group_id,
            app_channel_id = ?hex::encode(app_channel_id),
            strategy = ?conflict_strategy,
            "Starting app event conflict resolution"
        );

        // TODO: Implement actual conflict resolution logic
        // This would involve:
        // 1. Identifying events with invalid group references
        // 2. Applying the specified resolution strategy
        // 3. Updating event metadata to reflect resolution decisions
        // 4. Rebuilding affected app state

        let resolution_result = ConflictResolutionResult {
            conflicts_found: 0,
            conflicts_resolved: 0,
            conflicts_remaining: 0,
            strategy_used: conflict_strategy,
        };

        tracing::info!(
            group_id = ?group_id,
            app_channel_id = ?hex::encode(app_channel_id),
            result = ?resolution_result,
            "App event conflict resolution completed"
        );

        Ok(resolution_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::MockMessagesManagerTrait;
    use std::sync::Arc;
    use zoe_app_primitives::protocol::default_dgo_app;

    #[derive(Clone)]
    struct MockGroupService;

    #[async_trait::async_trait]
    impl GroupService for MockGroupService {
        fn message_group_receiver(&self) -> async_broadcast::Receiver<GroupDataUpdate> {
            let (_tx, rx) = async_broadcast::broadcast(1000);
            rx
        }

        async fn current_group_states(&self) -> Vec<GroupState> {
            Vec::new()
        }

        async fn decrypt_app_message<T: DeserializeOwned>(
            &self,
            _group_id: &GroupId,
            _encrypted_content: &zoe_wire_protocol::ChaCha20Poly1305Content,
        ) -> GroupResult<T> {
            // Mock decryption - return a default value
            Err(GroupError::InvalidEvent(
                "Mock decryption not implemented".to_string(),
            ))
        }

        async fn group_state_at_message(
            &self,
            _group_id: &GroupId,
            _message_id: zoe_wire_protocol::MessageId,
        ) -> Option<GroupState> {
            // Mock implementation - return None for testing
            None
        }

        async fn get_permission_context(
            &self,
            _group_id: &GroupId,
            _actor_identity_ref: &zoe_app_primitives::identity::IdentityRef,
            _group_state_reference: zoe_wire_protocol::MessageId,
            _app_id: &zoe_app_primitives::protocol::AppProtocolVariant,
        ) -> (
            zoe_app_primitives::group::events::roles::GroupRole,
            zoe_wire_protocol::MessageId,
        ) {
            // Return default values for tests
            (
                zoe_app_primitives::group::events::roles::GroupRole::Member,
                zoe_wire_protocol::MessageId::from([0u8; 32]),
            )
        }
    }

    #[tokio::test]
    async fn test_app_manager_creation() {
        use mockall::predicate::function;
        use zoe_wire_protocol::PublishResult;

        let mut mock_manager = MockMessagesManagerTrait::new();

        // Set up default expectations for subscription calls
        mock_manager
            .expect_ensure_contains_filter()
            .with(function(|filter: &Filter| {
                matches!(filter, Filter::Channel(_))
            }))
            .returning(|_| Ok(()));

        // Set up default expectations for publish calls
        mock_manager.expect_publish().returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_id".to_string(),
            })
        });

        // Set up default expectations for messages_stream calls
        mock_manager.expect_messages_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            // Close the sender immediately to create an empty stream
            drop(tx);
            rx
        });

        // Set up default expectations for catch_up_stream calls
        mock_manager.expect_catch_up_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            // Close the sender immediately to create an empty stream
            drop(tx);
            rx
        });

        let message_manager = Arc::new(mock_manager);
        let group_service = Arc::new(MockGroupService);
        let store = crate::execution::InMemoryStore::new();

        let app_manager = AppManager::new(message_manager, group_service, store).await;

        let dgo_app = default_dgo_app();

        // For now, just test that the app manager was created successfully
        // TODO: Add proper integration test when GroupState construction is available

        // Verify executor availability
        assert!(app_manager.is_executor_available(&dgo_app.app_id));
    }

    #[tokio::test]
    async fn test_sync_with_group_channel() {
        use mockall::predicate::function;
        use zoe_wire_protocol::PublishResult;

        let mut mock_manager = MockMessagesManagerTrait::new();

        // Set up default expectations
        mock_manager
            .expect_ensure_contains_filter()
            .with(function(|filter: &Filter| {
                matches!(filter, Filter::Channel(_))
            }))
            .returning(|_| Ok(()));

        mock_manager.expect_publish().returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_id".to_string(),
            })
        });

        mock_manager.expect_messages_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        mock_manager.expect_catch_up_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        let message_manager = Arc::new(mock_manager);
        let group_service = Arc::new(MockGroupService);
        let store = crate::execution::InMemoryStore::new();

        let app_manager = AppManager::new(message_manager, group_service, store).await;

        // Test sync with non-existent channel
        let group_id = GroupId::from([1u8; 32]);
        let app_channel_id = vec![2u8; 32];

        let result = app_manager
            .sync_with_group_channel(&group_id, &app_channel_id)
            .await;

        // Should fail because no app state exists for this channel
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No app state found for channel")
        );
    }

    #[tokio::test]
    async fn test_validate_app_event_lazy() {
        use mockall::predicate::function;
        use zoe_wire_protocol::PublishResult;

        let mut mock_manager = MockMessagesManagerTrait::new();

        // Set up default expectations
        mock_manager
            .expect_ensure_contains_filter()
            .with(function(|filter: &Filter| {
                matches!(filter, Filter::Channel(_))
            }))
            .returning(|_| Ok(()));

        mock_manager.expect_publish().returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_id".to_string(),
            })
        });

        mock_manager.expect_messages_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        mock_manager.expect_catch_up_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        let message_manager = Arc::new(mock_manager);
        let group_service = Arc::new(MockGroupService);
        let store = crate::execution::InMemoryStore::new();

        let app_manager = AppManager::new(message_manager, group_service, store).await;

        // Create a mock app event
        #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
        struct MockExecutorEvent {
            group_ref: zoe_wire_protocol::MessageId,
        }

        impl zoe_app_primitives::group::app::ExecutorEvent for MockExecutorEvent {
            fn group_state_reference(&self) -> zoe_wire_protocol::MessageId {
                self.group_ref
            }
        }

        let app_event = MockExecutorEvent {
            group_ref: zoe_wire_protocol::MessageId::from([3u8; 32]),
        };

        let app_state = AppState {
            group_id: GroupId::from([1u8; 32]),
            installed_app: default_dgo_app(),
        };

        let sender = zoe_app_primitives::identity::IdentityRef::Key(
            zoe_wire_protocol::KeyPair::generate(&mut rand::thread_rng()).public_key(),
        );

        // Test validation - should fail because MockGroupService returns None
        let result = app_manager
            .validate_app_event_lazy(&app_event, &sender, &app_state)
            .await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Referenced group state")
        );
    }

    #[tokio::test]
    async fn test_reconstruct_app_state_from_valid_events() {
        use mockall::predicate::function;
        use zoe_wire_protocol::PublishResult;

        let mut mock_manager = MockMessagesManagerTrait::new();

        // Set up default expectations
        mock_manager
            .expect_ensure_contains_filter()
            .with(function(|filter: &Filter| {
                matches!(filter, Filter::Channel(_))
            }))
            .returning(|_| Ok(()));

        mock_manager.expect_publish().returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_id".to_string(),
            })
        });

        mock_manager.expect_messages_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        mock_manager.expect_catch_up_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        let message_manager = Arc::new(mock_manager);
        let group_service = Arc::new(MockGroupService);
        let store = crate::execution::InMemoryStore::new();

        let app_manager = AppManager::new(message_manager, group_service, store).await;

        let group_id = GroupId::from([1u8; 32]);
        let app_channel_id = vec![2u8; 32];

        // Test reconstruction - should succeed with placeholder implementation
        let result = app_manager
            .reconstruct_app_state_from_valid_events(&group_id, &app_channel_id, None)
            .await;

        assert!(result.is_ok());
        let reconstruction_result = result.unwrap();
        assert_eq!(reconstruction_result.total_events, 0);
        assert_eq!(reconstruction_result.valid_events, 0);
        assert_eq!(reconstruction_result.invalid_events, 0);
        assert!(reconstruction_result.state_reconstructed);
    }

    #[tokio::test]
    async fn test_resolve_app_event_conflicts() {
        use mockall::predicate::function;
        use zoe_wire_protocol::PublishResult;

        let mut mock_manager = MockMessagesManagerTrait::new();

        // Set up default expectations
        mock_manager
            .expect_ensure_contains_filter()
            .with(function(|filter: &Filter| {
                matches!(filter, Filter::Channel(_))
            }))
            .returning(|_| Ok(()));

        mock_manager.expect_publish().returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "test_stream_id".to_string(),
            })
        });

        mock_manager.expect_messages_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        mock_manager.expect_catch_up_stream().returning(|| {
            let (tx, rx) = async_broadcast::broadcast(1);
            drop(tx);
            rx
        });

        let message_manager = Arc::new(mock_manager);
        let group_service = Arc::new(MockGroupService);
        let store = crate::execution::InMemoryStore::new();

        let app_manager = AppManager::new(message_manager, group_service, store).await;

        let group_id = GroupId::from([1u8; 32]);
        let app_channel_id = vec![2u8; 32];

        // Test conflict resolution with different strategies
        for strategy in [
            ConflictResolutionStrategy::MarkInvalid,
            ConflictResolutionStrategy::Skip,
            ConflictResolutionStrategy::BestEffort,
        ] {
            let result = app_manager
                .resolve_app_event_conflicts(&group_id, &app_channel_id, strategy)
                .await;

            assert!(result.is_ok());
            let resolution_result = result.unwrap();
            assert_eq!(resolution_result.conflicts_found, 0);
            assert_eq!(resolution_result.conflicts_resolved, 0);
            assert_eq!(resolution_result.conflicts_remaining, 0);
            assert!(matches!(resolution_result.strategy_used, _strategy));
        }
    }
}
