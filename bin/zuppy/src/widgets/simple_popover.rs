use gpui::{Context, IntoElement, ParentElement, Render, SharedString, Styled, Window, div};
use gpui_component::{ActiveTheme, Theme};

pub struct SimplePopover(SharedString);

impl SimplePopover {
    pub fn new(content: SharedString) -> Self {
        SimplePopover(content)
    }
}

impl Render for SimplePopover {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        div()
            .bg(theme.background)
            .text_color(theme.foreground)
            .child(self.0.clone())
    }
}
