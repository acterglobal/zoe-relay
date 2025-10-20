use gpui::*;
use widgets::headline::Headline;
use widgets::interactive_counter::InteractiveCounter;
use widgets::status_bar::StatusBar;

mod widgets;

pub struct ZuppyRoot {
    counter: Entity<InteractiveCounter>,
}

impl ZuppyRoot {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self {
            counter: cx.new(|_cx| InteractiveCounter::new(0)),
        }
    }
}

impl Render for ZuppyRoot {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .gap_0()
            .justify_start()
            .items_start()
            .overflow_hidden()
            .bg(white())
            .child(cx.new(|_cx| Headline::new(SharedString::new_static("Zuppy"))))
            .child(
                div()
                    .flex()
                    .flex_row()
                    .flex_grow()
                    .w_full()
                    .child(
                        div()
                            .flex()
                            .bg(gpui::red())
                            .child(cx.new(|_cx| Headline::new(SharedString::new_static("Left")))),
                    )
                    .child(div().flex_grow().child(self.counter.clone()))
                    .child(
                        div()
                            .flex()
                            .bg(gpui::blue())
                            .child(cx.new(|_cx| Headline::new(SharedString::new_static("Right")))),
                    ),
            )
            .child(cx.new(|_cx| StatusBar::new()))
    }
}
