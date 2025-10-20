use gpui::{
    AppContext, ClickEvent, Context, Entity, InteractiveElement, IntoElement, ParentElement,
    Render, SharedString, StatefulInteractiveElement, Styled, Window, div,
};

use crate::{ClientState, theme::Theme};

pub struct StatusBar {
    client: Entity<ClientState>,
    theme_button: Entity<ThemeButton>,
}

impl StatusBar {
    pub fn new(client: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            client,
            theme_button: cx.new(|_| ThemeButton::new()),
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

struct ThemeButton {
    count: u32,
}

impl ThemeButton {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    fn toggle_theme(&mut self, _event: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        tracing::info!("toggle dark mode");
        let new_theme = cx.default_global::<Theme>().toggle_darkness();
        cx.set_global(new_theme);
        self.count += 1;
        cx.notify();
    }
}
impl Render for ThemeButton {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let clicker = cx.listener(Self::toggle_theme);
        let theme = cx.default_global::<Theme>();

        div()
            .id("toggle_theme")
            .cursor_pointer()
            .flex()
            .items_center()
            .justify_center()
            .rounded_md()
            .child(if !theme.is_dark() {
                SharedString::new_static("Dark Mode")
            } else {
                SharedString::new_static("Light Mode")
            })
            .hover(|style| {
                style
                    .bg(theme.background_inverse())
                    .text_color(theme.text_inverse())
            })
            .hoverable_tooltip(|_w, cx| cx.new(|_| Popover("Click to toggle theme".into())).into())
            .on_click(clicker)
    }
}

struct Popover(SharedString);

impl Render for Popover {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div().child(self.0.clone())
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
                            ctx.new(|_| Popover(error_message.clone().into())).into()
                        }),
                )
            }
        }
    }
    fn render_right_tools(&self, _cx: &mut Context<Self>) -> impl IntoElement {
        div().flex_row().gap_5().child(self.theme_button.clone())
    }
}
