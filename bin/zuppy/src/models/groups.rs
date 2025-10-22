use gpui::{Context, Entity, Subscription, Task, WeakEntity};
use zoe_app_primitives::group::events::GroupInfo;
use zoe_state_machine::group::GroupDataUpdate;

use crate::models::client_state::ClientState;

pub struct Groups {
    _client_subscription: Subscription,
    current_task: Option<Task<()>>,
    pub groups: Vec<GroupInfo>,
}

impl Groups {
    pub fn new(cx: &mut Context<Self>, client_state: Entity<ClientState>) -> Self {
        let mut s = Self {
            _client_subscription: cx.observe(&client_state, Self::on_client_state_update),
            current_task: None,
            groups: Vec::new(),
        };
        s.on_client_state_update(client_state, cx);
        s
    }

    fn on_client_state_update(
        &mut self,
        client_state: Entity<ClientState>,
        cx: &mut Context<Self>,
    ) {
        let ClientState::Zoe(zoe) = client_state.read(cx) else {
            // new client sessions, we must clear any previous groups
            let mut should_notify = false;
            if let Some(t) = self.current_task.take() {
                should_notify = true;
                drop(t); // end the task
            }
            if !self.groups.is_empty() {
                self.groups.clear();
                should_notify = true
            }
            if should_notify {
                cx.notify();
            }
            return;
        };

        let zoe = zoe.clone();
        let watch_task = cx.spawn(async move |w: WeakEntity<Self>, cx| {
            let (groups, mut updates_stream) = zoe.group_manager().groups_and_stream().await;
            {
                // set current
                let Some(g) = w.upgrade() else {
                    tracing::trace!("groups state has been discarded already");
                    return;
                };
                if let Err(err) = g.update(cx, |i, cx| {
                    i.groups = groups;
                    cx.notify();
                }) {
                    tracing::error!(?err, "Error setting initial groups");
                }
            }

            loop {
                let update = match updates_stream.recv().await {
                    Err(e) => {
                        tracing::error!("Error receiving group update: {}", e);
                        return;
                    }
                    Ok(update) => update,
                };
                let Some(e) = w.upgrade() else {
                    tracing::trace!("Weak reference to widget has been dropped");
                    return;
                };
                if let Err(err) = match update {
                    GroupDataUpdate::GroupAdded(group) => e.update(cx, |i, cx| {
                        i.groups.push(group.state.group_info);
                        cx.notify();
                    }),
                    GroupDataUpdate::GroupUpdated(group) => {
                        let info = group.state.group_info;
                        e.update(cx, |i, cx| {
                            if let Some(index) =
                                i.groups.iter().position(|g| g.group_id == info.group_id)
                            {
                                i.groups[index] = info;
                                cx.notify();
                            } else {
                                tracing::warn!("Group with id {:?} not found", info.group_id);
                            }
                        })
                    }
                    GroupDataUpdate::GroupRemoved(session) => {
                        let info = session.state.group_info;
                        e.update(cx, |i, cx| {
                            if let Some(index) =
                                i.groups.iter().position(|g| g.group_id == info.group_id)
                            {
                                i.groups.remove(index);
                                cx.notify();
                            } else {
                                tracing::warn!("Group with id {:?} not found", info.group_id);
                            }
                        })
                    }
                } {
                    tracing::error!(?err, "Updating entity failed");
                }
            }
        });
        self.current_task = Some(watch_task); // keep around for execution
        cx.notify();
    }
}
