use gpui::{
    ClickEvent, Context, InteractiveElement, IntoElement, ParentElement, Render,
    StatefulInteractiveElement, Styled, Window, black, div, green, red, white,
};

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
        div()
            .size_full()
            .flex()
            .items_center()
            .justify_center()
            .gap_5()
            .bg(white())
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
                    .border_color(black())
                    .child("-")
                    .hover(|style| style.bg(red()))
                    .on_click(cx.listener(Self::decrement)),
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
                    .border_color(black())
                    .child("+")
                    .hover(|style| style.bg(green()))
                    .on_click(cx.listener(Self::increment)),
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
