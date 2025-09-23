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
    digital_groups_organizer::events::core::DgoActivityEvent,
    group::{
        app::{Acknowledgment, GroupEvent},
        events::GroupId,
        states::GroupState,
    },
    protocol::{AppProtocolVariant, InstalledApp},
};
use zoe_wire_protocol::{ChannelId, Filter, MessageFull};

use crate::{
    apps::dgo::DgoExecutor,
    error::{GroupError, GroupResult},
    execution::ExecutorStore,
    group::GroupDataUpdate,
    messages::MessagesManagerTrait,
};

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

    async fn verify_acknowledgment(
        &self,
        group_id: &GroupId,
        acknowledgment: Acknowledgment,
    ) -> GroupResult<bool>;
}

/// Manages app-specific message processing, decoupled from group management

#[derive(Clone)]
pub struct AppManager<M: MessagesManagerTrait, G: GroupService, S: ExecutorStore + 'static> {
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

                if let Some(ack) = dgo_event.acknowledgment() {
                    tracing::trace!(message_id = ?activity_id, "Processing acknowledgment");
                    self.group_service
                        .verify_acknowledgment(&app_state.group_id, ack)
                        .await?;
                }

                // Execute through DGO executor
                self.dgo_executor
                    .execute_event(dgo_event, activity_id)
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

        async fn verify_acknowledgment(
            &self,
            _group_id: &GroupId,
            _acknowledgment: Acknowledgment,
        ) -> GroupResult<bool> {
            // Mock verification - always allow
            Ok(true)
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
}
