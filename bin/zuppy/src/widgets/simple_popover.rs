use gpui::{Context, IntoElement, ParentElement, Render, SharedString, Styled, Window, div};

use crate::theme::Theme;

pub struct SimplePopover(SharedString);

impl SimplePopover {
    pub fn new(content: SharedString) -> Self {
        SimplePopover(content)
    }
}

impl Render for SimplePopover {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.default_global::<Theme>();
        div()
            .bg(theme.background())
            .text_color(theme.text())
            .child(self.0.clone())
    }
}
