use gpui::{
    Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Window, div,
};

use crate::ClientState;

pub struct StatusBar {
    client: Entity<ClientState>,
}

impl StatusBar {
    pub fn new(client: Entity<ClientState>) -> Self {
        Self { client }
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
    }
}

impl StatusBar {
    fn render_left_tools(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let dv = div().flex_1();
        match self.client.read(cx) {
            ClientState::Init => dv.child(SharedString::new_static("Initializing...")),
            ClientState::Loading => dv.child(SharedString::new_static("Loading...")),
            ClientState::Zoe(_) => dv.child(SharedString::new_static("Connected")),
            ClientState::Error(e) => dv.child(SharedString::new(format!("Error: {e}"))),
        }
    }
}

//     fn render_right_tools(&self) -> impl IntoElement {
//         h_flex()
//             .gap_1()
//             .overflow_x_hidden()
//             .children(self.right_items.iter().rev().map(|item| item.to_any()))
//     }
// }
