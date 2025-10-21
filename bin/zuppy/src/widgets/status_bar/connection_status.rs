use futures::{StreamExt, pin_mut};
use gpui::{
    AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    SharedString, StatefulInteractiveElement, Styled, Subscription, Window, div,
};
use zoe_client::OverallConnectionStatus;

use crate::{ClientState, widgets::simple_popover::SimplePopover};

pub struct ConnectionStatus {
    client_state: Entity<ClientState>,
    current_status: Entity<Option<OverallConnectionStatus>>,
    _client_subscription: Subscription,
}

fn update_of_client_state(
    cx: &mut Context<ConnectionStatus>,
    client_state: Entity<ClientState>,
    current_status: Entity<Option<OverallConnectionStatus>>,
) {
    let zoe = if let ClientState::Zoe(z) = client_state.read(cx) {
        tracing::info!("found a client");
        z.clone()
    } else {
        tracing::info!("no client");
        current_status.update(cx, |_, _| Option::<OverallConnectionStatus>::None);
        return;
    };

    cx.spawn(async move |_, ctx| {
        let new_status = zoe.overall_status().await;
        tracing::info!("gotten status: {new_status:?}");
        if let Err(e) = current_status.update(ctx, |m, c| {
            *m = Some(new_status);
            c.notify();
        }) {
            tracing::warn!("Updating current status failed: {e}");
        }
        tracing::info!("updated status");
        // gpui_tokio::Tokio::spawn(ctx, async move {
        let stream = zoe.overall_status_stream();
        pin_mut!(stream);
        while let Some(n) = stream.next().await {
            if let Err(e) = current_status.update(ctx, |m, c| {
                *m = Some(n);
                c.notify();
            }) {
                tracing::warn!("Updating current status failed: {e}");
                return;
            }
        }
    })
    .detach(); // forever run in background
}

impl ConnectionStatus {
    pub fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        let current_status = cx.new(|_| None);
        let current_status_ref = current_status.clone();
        let client_sub = cx.observe(&client_state, move |_s, n, cx| {
            update_of_client_state(cx, n, current_status_ref.clone())
        });
        update_of_client_state(cx, client_state.clone(), current_status.clone()); // call once to initialize
        Self {
            client_state,
            current_status,
            _client_subscription: client_sub,
        }
    }
}

impl ConnectionStatus {
    fn render_error(&mut self, error_message: String) -> impl IntoElement {
        div()
            .id("client_error")
            .child(SharedString::new_static("Error"))
            .cursor_pointer()
            .hoverable_tooltip(move |_w, ctx| {
                ctx.new(|_| SimplePopover::new(error_message.clone().into()))
                    .into()
            })
    }

    fn render_connection_info(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let e = div()
            .id("connected_info")
            .child(SharedString::new_static("Connected"));
        if let Some(info) = self.current_status.read(cx) {
            let msg = format!("{} / {}", info.connected_count, info.total_count);
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
            ClientState::Init => div().child(SharedString::new_static("Initializing...")),
            ClientState::Loading => div().child(SharedString::new_static("Loading...")),
            ClientState::Zoe(_) => div().child(self.render_connection_info(cx)),
            ClientState::Error(e) => div().child(self.render_error(e.clone())),
        }
    }
}
