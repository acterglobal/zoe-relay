use crate::models::groups::Groups;
use crate::router::Router;
use crate::widgets::sidebar::ZuppySidebar;
use gpui::{AppContext, Context, Entity, IntoElement, ParentElement, Render, Styled, Window, div};
use gpui_component::{ActiveTheme, Root, v_flex};

use crate::widgets::status_bar::StatusBar;

use crate::models::client_state::ClientState;

pub struct ZuppyApp {
    sidebar: Entity<ZuppySidebar>,
    status_bar: Entity<StatusBar>,
    router: Entity<Router>,
    groups: Entity<Groups>,
}

impl ZuppyApp {
    pub fn new(
        win: &mut Window,
        cx: &mut Context<Self>,
        client_state: Entity<ClientState>,
    ) -> Self {
        let groups = cx.new(|cx| Groups::new(cx, client_state.clone()));
        Self {
            sidebar: cx.new(|_| ZuppySidebar::new(groups.clone())),
            status_bar: cx.new(|cx| StatusBar::new(client_state.clone(), cx)),
            router: cx.new(|cx| Router::new(win, cx, client_state.clone(), groups.clone())),
            groups,
        }
    }
}

impl Render for ZuppyApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();

        v_flex()
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
            .children(Root::render_modal_layer(window, cx))
            .children(Root::render_drawer_layer(window, cx))
            .children(Root::render_notification_layer(window, cx))
    }
}
