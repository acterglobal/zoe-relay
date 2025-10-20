use gpui::{
    AppContext, ClickEvent, Context, Entity, InteractiveElement, IntoElement, ParentElement,
    Render, SharedString, StatefulInteractiveElement, Styled, Window, div,
};

use crate::{theme::Theme, widgets::simple_popover::SimplePopover};

pub struct ThemeToggleButton {
    popover: Entity<SimplePopover>,
}

impl ThemeToggleButton {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            popover: cx.new(|_| SimplePopover::new("Click to toggle theme".into())),
        }
    }

    fn toggle_theme(&mut self, _event: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        tracing::info!("toggle dark mode");
        let new_theme = cx.default_global::<Theme>().toggle_darkness();
        cx.set_global(new_theme);
    }
}
impl Render for ThemeToggleButton {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let clicker = cx.listener(Self::toggle_theme);
        let theme = cx.default_global::<Theme>();

        let popover = self.popover.clone();
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
            .hoverable_tooltip(move |_w, _cx| popover.clone().into())
            .on_click(clicker)
    }
}
