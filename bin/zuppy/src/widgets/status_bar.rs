use gpui::{
    AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    SharedString, StatefulInteractiveElement, Styled, Window, div,
};

use crate::ClientState;
use crate::widgets::simple_popover::SimplePopover;

mod theme_toggle_button;
use theme_toggle_button::ThemeToggleButton;

pub struct StatusBar {
    client: Entity<ClientState>,
    theme_button: Entity<ThemeToggleButton>,
}

impl StatusBar {
    pub fn new(client: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            client,
            theme_button: cx.new(ThemeToggleButton::new),
        }
    }
}

impl Render for StatusBar {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .w_full()
            .justify_between()
            .child(self.render_left_tools(cx))
            .child(self.render_right_tools(cx))
    }
}

impl StatusBar {
    fn render_left_tools(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let dv = div().flex_1();
        match self.client.read(cx) {
            ClientState::Init => dv.child(SharedString::new_static("Initializing...")),
            ClientState::Loading => dv.child(SharedString::new_static("Loading...")),
            ClientState::Zoe(_) => dv.child(SharedString::new_static("Connected")),
            ClientState::Error(e) => {
                let error_message = e.clone();
                dv.child(
                    div()
                        .id("client_error")
                        .child(SharedString::new_static("Error"))
                        .cursor_pointer()
                        .hoverable_tooltip(move |_w, ctx| {
                            ctx.new(|_| SimplePopover::new(error_message.clone().into()))
                                .into()
                        }),
                )
            }
        }
    }
    fn render_right_tools(&self, _cx: &mut Context<Self>) -> impl IntoElement {
        div().flex_row().gap_5().child(self.theme_button.clone())
    }
}
