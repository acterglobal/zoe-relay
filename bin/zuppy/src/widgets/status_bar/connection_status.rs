use futures::{StreamExt, pin_mut};
use gpui::{
    AppContext, AsyncApp, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    StatefulInteractiveElement, Styled, Subscription, Task, WeakEntity, Window, div,
};
use gpui_component::ActiveTheme;
use gpui_component::Colorize;
use gpui_component::Icon;
use zoe_client::OverallConnectionStatus;

use crate::{
    components::icon::IconName, models::client_state::ClientState,
    widgets::simple_popover::SimplePopover,
};

struct ConnectionInfoInner {
    _client_subscription: Subscription,
    current_task: Option<Task<()>>,
    current_state: Option<OverallConnectionStatus>,
}

impl ConnectionInfoInner {
    fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
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
            tracing::info!("no client");
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
        w: &WeakEntity<ConnectionInfoInner>,
        new_status: OverallConnectionStatus,
        ctx: &mut AsyncApp,
    ) -> bool {
        tracing::info!("gotten status: {new_status:?}");
        let Some(current_status) = w.upgrade() else {
            tracing::info!("entity is already gone");
            return false;
        };

        if let Err(e) = current_status.update(ctx, |m, c| {
            m.current_state = Some(new_status);
            c.notify();
        }) {
            tracing::warn!("Updating connection info status failed: {e}");
            return false;
        }
        tracing::info!("updated status");
        return true;
    }
}

pub struct ConnectionStatus {
    client_state: Entity<ClientState>,
    current_status: Entity<ConnectionInfoInner>,
}

impl ConnectionStatus {
    pub fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            client_state: client_state.clone(),
            current_status: cx.new(|cx| ConnectionInfoInner::new(client_state, cx)),
        }
    }
}

impl ConnectionStatus {
    fn render_error(&self, error_message: String, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("client_error")
            .child(Icon::new(IconName::NetworkWorking).text_color(cx.theme().red))
            .cursor_pointer()
            .hoverable_tooltip(move |_w, ctx| {
                ctx.new(|_| SimplePopover::new(error_message.clone().into()))
                    .into()
            })
    }

    fn render_connection_info(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let e = div()
            .id("connected_info")
            .child(Icon::new(IconName::NetworkSynced).text_color(cx.theme().green.darken(0.2)));
        if let Some(ref info) = self.current_status.read(cx).current_state {
            let msg = format!(
                "Connected to {} / {}",
                info.connected_count, info.total_count
            );
            return e.cursor_pointer().hoverable_tooltip(move |_w, ctx| {
                ctx.new(|_| SimplePopover::new(msg.clone().into())).into()
            });
        }
        e
    }
}

impl Render for ConnectionStatus {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        match self.client_state.read(cx) {
            ClientState::Init => div().child(Icon::new(IconName::NetworkWorking)),
            ClientState::Loading => div().child(Icon::new(IconName::NetworkWorking)),
            ClientState::Zoe(_) => div().child(self.render_connection_info(cx)),
            ClientState::Error(e) => div().child(self.render_error(e.clone(), cx)),
        }
    }
}
