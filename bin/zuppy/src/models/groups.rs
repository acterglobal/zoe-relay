use std::sync::Arc;

use futures::{StreamExt, pin_mut, select};
use gpui::{Context, Entity, Subscription, Task, WeakEntity};
use zoe_app_primitives::group::events::GroupId;
use zoe_client::client::api::groups::SimpleGroupView;

use crate::models::client_state::ClientState;
use crate::util::vector_diff::VectorDiffApplicator;

pub struct Groups {
    _client_subscription: Subscription,
    current_task: Option<Task<()>>,
    pub groups: Vec<Arc<SimpleGroupView>>,
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

    pub fn get(&self, group_id: GroupId) -> Option<Arc<SimpleGroupView>> {
        self.groups.iter().find(|g| g.group_id == group_id).cloned()
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
            let Ok((groups, diff_stream, updates_stream)) =
                zoe.groups_view().await.inspect_err(|err| {
                    tracing::error!(?err, "Error getting groups view");
                })
            else {
                return;
            };

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

            pin_mut!(updates_stream);
            pin_mut!(diff_stream);
            let mut fu = updates_stream.fuse();
            let mut ds = diff_stream.fuse();

            loop {
                select! {
                    _ = fu.next() => {
                        // nothing for us to do than just ensure we poll the stream
                        }
                    o_vec_diff = ds.next() => {
                        let Some(vec_diffs) = o_vec_diff else {
                            tracing::trace!("no vec diff?");
                            continue;
                        };
                        let Some(g) = w.upgrade() else {
                            tracing::trace!("Weak reference to widget has been dropped");
                            return;
                        };
                        if let Err(err) = g.update(cx, |i, cx| {
                            for v in vec_diffs {
                                v.apply_to_vec(&mut i.groups);
                            }
                            cx.notify();
                        }) {
                            tracing::error!(?err, "Error updating groups");
                        }
                    }
                }
            }
        });
        self.current_task = Some(watch_task); // keep around for execution
        cx.notify();
    }
}
