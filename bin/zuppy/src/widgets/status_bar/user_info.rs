use gpui::{
    AppContext, Context, Entity, IntoElement, ParentElement, Render, Subscription, Task, Window,
    div,
};
use gpui_component::{Sizable, avatar::Avatar};

use crate::ClientState;

struct UserInfoInner {
    _client_subscription: Subscription,
    user_id: Option<String>,
}

impl UserInfoInner {
    fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
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
            tracing::info!("no client");
            let should_notify = self.user_id.take().is_some();
            if should_notify {
                cx.notify();
            }
            return;
        };

        self.user_id = Some(z.id_hex())
    }
}

pub struct UserInfo {
    info: Entity<UserInfoInner>,
}

impl UserInfo {
    pub fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            info: cx.new(|cx| UserInfoInner::new(client_state, cx)),
        }
    }
}

impl Render for UserInfo {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(ref user_id) = self.info.read(cx).user_id else {
            return div();
        };
        div().child(Avatar::new().name(user_id).xsmall())
    }
}
