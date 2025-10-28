use futures::{StreamExt, pin_mut};
use gpui::{AsyncApp, Context, Entity, Subscription, Task, WeakEntity};

use zoe_client::OverallConnectionStatus;

use crate::models::client_state::ClientState;

pub struct ConnectionInfo {
    _client_subscription: Subscription,
    current_task: Option<Task<()>>,
    pub current_state: Option<OverallConnectionStatus>,
}

impl ConnectionInfo {
    pub fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        let mut s = Self {
            _client_subscription: cx.observe(&client_state, Self::update_of_client_state),
            current_state: None,
            current_task: None,
        };
        s.update_of_client_state(client_state, cx);
        s
    }

    fn update_of_client_state(
        &mut self,
        client_state: Entity<ClientState>,
        cx: &mut Context<Self>,
    ) {
        let ClientState::Zoe(z) = client_state.read(cx) else {
            tracing::trace!("no client");
            let mut should_notify = self.current_state.take().is_some();
            if let Some(t) = self.current_task.take() {
                should_notify = true;
                drop(t);
            }
            if should_notify {
                cx.notify();
            }
            return;
        };

        let zoe = z.clone();

        self.current_task = Some(cx.spawn(async move |w, ctx| {
            if !Self::update_state_info(&w, zoe.overall_status().await, ctx) {
                return;
            }
            let stream = zoe.overall_status_stream();
            pin_mut!(stream);
            while let Some(n) = stream.next().await {
                if !Self::update_state_info(&w, n, ctx) {
                    return;
                }
            }
        }));
    }

    fn update_state_info(
        w: &WeakEntity<ConnectionInfo>,
        new_status: OverallConnectionStatus,
        ctx: &mut AsyncApp,
    ) -> bool {
        tracing::trace!(?new_status, "gotten status");
        let Some(current_status) = w.upgrade() else {
            tracing::trace!("entity is already gone");
            return false;
        };

        if let Err(e) = current_status.update(ctx, |m, c| {
            m.current_state = Some(new_status);
            c.notify();
        }) {
            tracing::warn!("Updating connection info status failed: {e}");
            return false;
        }
        tracing::trace!("updated status");
        true
    }
}
