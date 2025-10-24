use gpui::{
    AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    StatefulInteractiveElement, Styled, Window, div,
};
use gpui_component::ActiveTheme;
use gpui_component::Colorize;
use gpui_component::Icon;

use crate::{
    components::icon::IconName,
    models::{client_state::ClientState, connection_info::ConnectionInfo},
    widgets::simple_popover::SimplePopover,
};

pub struct ConnectionStatus {
    client_state: Entity<ClientState>,
    current_status: Entity<ConnectionInfo>,
}

impl ConnectionStatus {
    pub fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            client_state: client_state.clone(),
            current_status: cx.new(|cx| ConnectionInfo::new(client_state, cx)),
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
