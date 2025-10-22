use gpui::{Context, Entity, Subscription};

use crate::models::client_state::ClientState;

pub struct UserInfoModel {
    _client_subscription: Subscription,
    pub user_id: Option<String>,
}

impl UserInfoModel {
    pub fn new(cx: &mut Context<Self>, client_state: Entity<ClientState>) -> Self {
        let mut s = Self {
            _client_subscription: cx.observe(&client_state, Self::on_client_state_update),
            user_id: None,
        };
        s.on_client_state_update(client_state, cx);
        s
    }

    fn on_client_state_update(
        &mut self,
        client_state: Entity<ClientState>,
        cx: &mut Context<Self>,
    ) {
        let ClientState::Zoe(z) = client_state.read(cx) else {
            tracing::trace!("no client");
            let should_notify = self.user_id.take().is_some();
            if should_notify {
                cx.notify();
            }
            return;
        };

        self.user_id = Some(z.id_hex())
    }
}
