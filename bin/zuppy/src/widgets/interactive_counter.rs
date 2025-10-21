use gpui::{
    ClickEvent, Context, InteractiveElement, IntoElement, ParentElement, Render,
    StatefulInteractiveElement, Styled, Window, div, green, red,
};
use gpui_component::ActiveTheme;

pub struct InteractiveCounter {
    count: isize,
}

impl InteractiveCounter {
    pub fn new(count: isize) -> Self {
        Self { count }
    }
}

impl Render for InteractiveCounter {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dec_listener = cx.listener(Self::decrement);
        let inc_listener = cx.listener(Self::increment);
        let theme = cx.theme();
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .gap_5()
            .bg(theme.background)
            .child(
                div()
                    .id("decrement_button")
                    .cursor_pointer()
                    .flex()
                    .items_center()
                    .justify_center()
                    .size_8()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .child("-")
                    .hover(|style| style.bg(red()))
                    .on_click(dec_listener),
            )
            .child(
                div()
                    .min_w_16()
                    .text_3xl()
                    .text_center()
                    .child(self.count.to_string()),
            )
            .child(
                div()
                    .id("increment_button")
                    .cursor_pointer()
                    .flex()
                    .items_center()
                    .justify_center()
                    .size_8()
                    .rounded_md()
                    .border_1()
                    .border_color(theme.border)
                    .child("+")
                    .hover(|style| style.bg(green()))
                    .on_click(inc_listener),
            )
    }
}

impl InteractiveCounter {
    fn increment(&mut self, _event: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        self.count += 1;
        cx.notify();
    }

    fn decrement(&mut self, _event: &ClickEvent, _window: &mut Window, cx: &mut Context<Self>) {
        self.count -= 1;
        cx.notify();
    }
}
