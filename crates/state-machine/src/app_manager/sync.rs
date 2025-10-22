use tokio::task::JoinHandle;
use zoe_app_primitives::{
    digital_groups_organizer::{
        events::{
            admin::UpdateDgoSettingsContent,
            core::{DgoActivityEvent, DgoSettingsEvent},
        },
        models::core::ActivityMeta,
    },
    group::{app::ExecutorEvent, app_updates::GroupAppUpdate},
    protocol::AppProtocolVariant,
};
use zoe_wire_protocol::{Content, Message, Tag};
use zoe_wire_protocol::{Filter, MessageFull};

use crate::{
    error::{GroupError, GroupResult},
    execution::ExecutorStore,
    messages::{MessageEvent, MessagesManagerTrait},
};

use super::{AppManager, AppState, GroupAppService};

impl<
    M: MessagesManagerTrait + Clone + 'static,
    G: GroupAppService + Clone + 'static,
    S: ExecutorStore + Clone + 'static,
> AppManager<M, G, S>
{
    pub(super) fn start_background_tasks(&self) -> JoinHandle<()> {
        let app_manager_clone = self.clone();

        let mut app_updates_stream = self.group_service.group_app_updates();
        let mut messages_stream = self.message_manager.message_events_stream();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    app_update = app_updates_stream.recv() => {
                        match app_update {
                            Ok(app_update) => {
                                if let Err(e) = app_manager_clone.handle_app_update(app_update).await {
                                    tracing::error!(error = ?e, "Failed to handle app update");
                                }
                            }
                            Err(async_broadcast::RecvError::Closed) => {
                                tracing::warn!("App updates stream closed, stopping message processing");
                                break;
                            }
                            Err(e) => {
                                tracing::error!(error = ?e, "Failed to receive app update from stream in AppManager");
                                continue;
                            }
                        }
                    }

                    message_event = messages_stream.recv() => {
                        let message_event = match message_event {
                            Ok(message_event) => message_event,

                            Err(async_broadcast::RecvError::Closed) => {
                                tracing::debug!("App message stream closed, stopping message processing");
                                break;
                            }
                            Err(e) => {
                                tracing::error!(error = ?e, "Failed to receive message from stream in AppManager");
                                continue;
                            }
                        };

                        let msg = match message_event {
                            MessageEvent::MessageReceived { message, stream_height: _ } => {
                                tracing::trace!(message_id = ?message.id(), "Received app message");
                                message
                            }
                            MessageEvent::MessageSent { message, .. } => {
                                tracing::trace!(message_id = ?message.id(), "Sent app message");
                                message
                            }
                            MessageEvent::CatchUpMessage { message, .. } => {
                                tracing::trace!(message_id = ?message.id(), "Catch-up app message");
                                message
                            }
                            MessageEvent::StreamHeightUpdate { height } => {
                                tracing::debug!(height = %height, "App message stream height updated");
                                continue;
                            }
                            MessageEvent::CatchUpCompleted { request_id } => {
                                tracing::debug!(request_id = %request_id, "Catch-up completed");
                                continue;
                            }
                        };

                        if let Err(e) = app_manager_clone.handle_app_message(msg).await {
                            tracing::error!(error = ?e, "Failed to process app message");
                        }
                    }
                }
            }
        })
    }

    /// Handle an app update notification from the group manager
    async fn handle_app_update(&self, app_update: GroupAppUpdate) -> GroupResult<()> {
        match app_update {
            GroupAppUpdate::InstalledApsUpdate {
                group_id,
                installed_apps,
            } => {
                tracing::info!(
                    group_id = ?group_id,
                    app_count = installed_apps.len(),
                    "Received app installation update"
                );

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
                    let channel_filter = Filter::Channel(installed_app.app_tag.clone().into());
                    self.message_manager
                        .ensure_contains_filter(channel_filter)
                        .await
                        .map_err(|e| {
                            GroupError::MessageError(format!(
                                "Failed to subscribe to app channel: {e}"
                            ))
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
            }
            GroupAppUpdate::AppSettingsUpdate {
                meta,
                group_id,
                app_id,
                settings,
            } => {
                tracing::info!(
                    group_id = ?group_id,
                    app_id = ?app_id,
                    settings_size = settings.len(),
                    "Received app settings update"
                );

                // Find the app state for this group and app
                let app_states = self.app_states.read().await;
                let app_state = app_states.values().find(|state| {
                    state.group_id == group_id && state.installed_app.app_id == app_id
                });

                if let Some(app_state) = app_state {
                    // Process the settings update through the appropriate executor
                    match &app_state.installed_app.app_id {
                        AppProtocolVariant::DigitalGroupsOrganizer => {
                            tracing::trace!(
                                group_id = ?group_id,
                                app_id = ?app_id,
                                "Processing DGO settings update"
                            );

                            // Deserialize the settings data as UpdateDgoSettingsContent
                            let settings_updates: UpdateDgoSettingsContent =
                                match postcard::from_bytes(&settings) {
                                    Ok(updates) => updates,
                                    Err(e) => {
                                        tracing::error!(
                                            group_id = ?group_id,
                                            app_id = ?app_id,
                                            error = ?e,
                                            "Failed to deserialize DGO settings data"
                                        );
                                        return Err(GroupError::MessageError(format!(
                                            "Failed to deserialize DGO settings: {e}"
                                        )));
                                    }
                                };

                            // Create a DgoSettingsEvent
                            let settings_event = DgoSettingsEvent::new(
                                zoe_app_primitives::identity::IdentityType::Main, // TODO: Determine actual identity type from meta.actor
                                meta.activity_id,
                                settings_updates,
                            );

                            // Get the actual actor role and permission context
                            let (actor_role, app_state_message_id, _group_permissions) = self
                                .group_service
                                .get_permission_context(
                                    &group_id,
                                    &meta.actor,
                                    meta.activity_id,
                                    &app_id,
                                )
                                .await;

                            // Execute the settings event using the existing DGO executor
                            if let Err(e) = self
                                .dgo_executor
                                .execute_settings_event(
                                    settings_event,
                                    meta,
                                    actor_role,
                                    app_state_message_id,
                                )
                                .await
                            {
                                tracing::error!(
                                    group_id = ?group_id,
                                    app_id = ?app_id,
                                    error = ?e,
                                    "Failed to execute DGO settings event"
                                );
                                return Err(GroupError::MessageError(format!(
                                    "Failed to execute DGO settings event: {e}"
                                )));
                            }

                            tracing::info!(
                                group_id = ?group_id,
                                app_id = ?app_id,
                                "Successfully processed DGO settings update"
                            );
                        }
                        AppProtocolVariant::Unknown(app_name) => {
                            tracing::warn!(
                                app_name = %app_name,
                                group_id = ?group_id,
                                "No executor available for unknown app settings update"
                            );
                        }
                    }
                } else {
                    tracing::warn!(
                        group_id = ?group_id,
                        app_id = ?app_id,
                        "No app state found for settings update"
                    );
                }
            }
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
