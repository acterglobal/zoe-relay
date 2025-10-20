use gpui::{Context, IntoElement, ParentElement, Render, SharedString, Styled, Window, div};

pub struct Headline {
    text: SharedString,
}

impl Headline {
    pub fn new(text: SharedString) -> Self {
        Self { text }
    }
}

impl Render for Headline {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div().gap_5().child(self.text.clone())
    }
}
