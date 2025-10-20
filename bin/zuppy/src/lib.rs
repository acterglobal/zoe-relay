use gpui::*;
use widgets::interactive_counter::InteractiveCounter;

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
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div().size_full().child(self.counter.clone())
    }
}
