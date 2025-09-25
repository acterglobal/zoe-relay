use tokio::task::JoinHandle;
use zoe_app_primitives::{
    digital_groups_organizer::{events::core::DgoActivityEvent, models::core::ActivityMeta},
    group::app::ExecutorEvent,
    protocol::AppProtocolVariant,
};
use zoe_wire_protocol::{Content, Message, StreamMessage, Tag};
use zoe_wire_protocol::{Filter, MessageFull};

use crate::{
    error::{GroupError, GroupResult},
    execution::ExecutorStore,
    group::GroupDataUpdate,
    messages::MessagesManagerTrait,
};

use super::{AppManager, AppState, GroupService};

impl<
    M: MessagesManagerTrait + Clone + 'static,
    G: GroupService + Clone + 'static,
    S: ExecutorStore + Clone + 'static,
> AppManager<M, G, S>
{
    pub(super) fn start_background_tasks(&self) -> JoinHandle<()> {
        let app_manager_clone = self.clone();

        let mut message_group_notifications = self.group_service.message_group_receiver();
        let mut messages_stream = self.message_manager.messages_stream();
        let mut catch_up_stream = self.message_manager.catch_up_stream();
        tokio::spawn(async move {
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
        })
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
            if let AppProtocolVariant::Unknown(_) = installed_app.app_id {
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

    /// Handle an incoming app message
    async fn handle_app_message(&self, message_full: MessageFull) -> GroupResult<()> {
        use {Content, Message};

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
                Tag::Channel { id, .. } => Some(id),
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

    async fn execute_app_message(
        &self,
        app_state: AppState,
        message_full: MessageFull,
    ) -> GroupResult<()> {
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

                // Use the convenience function to get actor role, app state message ID, and group permissions
                let (actor_role, state_message_id, group_permissions) = self
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
                    .execute_event(
                        dgo_event,
                        group_meta,
                        actor_role,
                        state_message_id,
                        Some(group_permissions),
                    )
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
}
