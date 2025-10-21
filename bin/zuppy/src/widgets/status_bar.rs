use gpui::{AppContext, Context, Entity, IntoElement, ParentElement, Render, Styled, Window, div};
use gpui_component::ActiveTheme;

use crate::models::client_state::ClientState;

mod connection_status;
mod theme_toggle_button;
mod user_info;
use connection_status::ConnectionStatus;
use theme_toggle_button::ThemeToggleButton;
use user_info::UserInfo;

pub struct StatusBar {
    user_info: Entity<UserInfo>,
    connection_state: Entity<ConnectionStatus>,
    theme_button: Entity<ThemeToggleButton>,
}

impl StatusBar {
    pub fn new(client: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            user_info: cx.new(|cx| UserInfo::new(client.clone(), cx)),
            connection_state: cx.new(|cx| ConnectionStatus::new(client.clone(), cx)),
            theme_button: cx.new(ThemeToggleButton::new),
        }
    }
}

impl Render for StatusBar {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .border_t_1()
            .border_color(cx.theme().border)
            .p_2()
            .flex()
            .flex_row()
            .w_full()
            .gap_1()
            .justify_between()
            .child(self.render_left_tools())
            .child(self.render_right_tools())
    }
}

impl StatusBar {
    fn render_left_tools(&self) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .flex_grow()
            .gap_2()
            .flex_1()
            .items_center()
            .child(self.user_info.clone())
            .child(self.connection_state.clone())
    }
    fn render_right_tools(&self) -> impl IntoElement {
        div().flex_row().gap_5().child(self.theme_button.clone())
    }
}
