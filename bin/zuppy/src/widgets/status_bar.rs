use gpui::{Context, IntoElement, ParentElement, Render, SharedString, Styled, Window, div};

pub struct StatusBar {}

impl StatusBar {
    pub fn new() -> Self {
        Self {}
    }
}

impl Render for StatusBar {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_row()
            .w_full()
            .justify_between()
            .child(div().child(SharedString::new_static("Left")).flex_1())
            .child(div().child(SharedString::new_static("Center")).flex_grow())
            .child(div().child(SharedString::new_static("Right")).flex_1())
    }
}

// impl StatusBar {
//     fn render_left_tools(&self) -> impl IntoElement {
//         h_flex()
//             .gap_1()
//             .overflow_x_hidden()
//             .children([text("Left Tools")])
//     }

//     fn render_right_tools(&self) -> impl IntoElement {
//         h_flex()
//             .gap_1()
//             .overflow_x_hidden()
//             .children(self.right_items.iter().rev().map(|item| item.to_any()))
//     }
// }
