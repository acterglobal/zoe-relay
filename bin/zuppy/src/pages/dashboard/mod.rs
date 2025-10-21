use gpui::{AppContext, Context, Entity, IntoElement, Render, Window};

use crate::models::client_state::ClientState;
use crate::widgets::interactive_counter::InteractiveCounter;

pub struct DashboardPage {
    counter: Entity<InteractiveCounter>,
}

impl DashboardPage {
    pub fn new(cx: &mut Context<Self>, _client_state: Entity<ClientState>) -> Self {
        Self {
            counter: cx.new(|_cx| InteractiveCounter::new(0)),
        }
    }
}

impl Render for DashboardPage {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        self.counter.clone()
    }
}
