use crate::router::Router;
use crate::widgets::sidebar::ZuppySidebar;
use gpui::{AppContext, Context, Entity, IntoElement, ParentElement, Render, Styled, Window, div};
use gpui_component::{ActiveTheme, Root};

use crate::widgets::status_bar::StatusBar;

use crate::models::client_state::ClientState;

pub struct ZuppyLayout {
    sidebar: Entity<ZuppySidebar>,
    status_bar: Entity<StatusBar>,
    router: Entity<Router>,
}

impl ZuppyLayout {
    pub fn new(cx: &mut Context<Self>, client_state: Entity<ClientState>) -> Self {
        Self {
            sidebar: cx.new(|_| ZuppySidebar::new()),
            router: cx.new(|cx| Router::new(cx, client_state.clone())),
            status_bar: cx.new(|cx| StatusBar::new(client_state, cx)),
        }
    }
}

impl Render for ZuppyLayout {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let notification_layer = Root::render_notification_layer(window, cx);
        let theme = cx.theme();
        div()
            .size_full()
            .child(
                div()
                    .relative()
                    .size_full()
                    .flex()
                    .flex_col()
                    .gap_0()
                    .justify_start()
                    .items_start()
                    .overflow_hidden()
                    .bg(theme.background)
                    .text_color(theme.foreground)
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_grow()
                            .w_full()
                            .child(self.sidebar.clone())
                            .child(div().flex_grow().child(self.router.clone())),
                    )
                    .child(self.status_bar.clone()),
            )
            .children(notification_layer)
    }
}
