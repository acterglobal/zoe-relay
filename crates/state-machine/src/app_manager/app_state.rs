use std::collections::HashMap;
use std::sync::Arc;
use zoe_app_primitives::{group::events::GroupId, protocol::InstalledApp};
use zoe_wire_protocol::ChannelId;

use crate::{execution::ExecutorStore, messages::MessagesManagerTrait};

#[derive(Debug, Clone)]
pub struct AppState {
    pub group_id: GroupId,
    pub installed_app: InstalledApp,
}

use super::{AppManager, GroupService};

impl<
    M: MessagesManagerTrait + Clone + 'static,
    G: GroupService + Clone + 'static,
    S: ExecutorStore + Clone + 'static,
> AppManager<M, G, S>
{
    pub(super) async fn load_app_states(group_service: Arc<G>) -> HashMap<ChannelId, AppState> {
        group_service
            .current_group_states()
            .await
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
            .collect::<HashMap<ChannelId, AppState>>()
    }
    pub(super) async fn get_app_state(&self, channel_ids: &[ChannelId]) -> Option<AppState> {
        let app_states = self.app_states.read().await;

        for channel_id in channel_ids {
            if let Some(app_state) = app_states.get(channel_id) {
                return Some(app_state.clone());
            }
        }
        None
    }
}
