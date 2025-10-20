use gpui::*;
use widgets::headline::Headline;
use widgets::interactive_counter::InteractiveCounter;
use widgets::status_bar::StatusBar;

mod widgets;

use tracing::{error, warn};
use zoe_client::ClientBuilder;

pub enum ClientState {
    Init,
    Loading,
    Zoe(zoe_client::Client),
    Error(String),
}

pub struct ZuppyRoot {
    client: Entity<ClientState>,
    counter: Entity<InteractiveCounter>,
}

impl ZuppyRoot {
    pub fn new(cx: &mut Context<Self>) -> Self {
        cx.spawn(async |me: WeakEntity<Self>, cx: &mut AsyncApp| {
            let new_state = match ClientBuilder::default().build().await {
                Ok(client) => ClientState::Zoe(client),
                Err(err) => ClientState::Error(err.to_string()),
            };
            if let Err(err) = me.update(cx, |me: &mut Self, cx: &mut Context<Self>| {
                me.client.write(cx, new_state);
            }) {
                warn!("Failed to update client state: {}", err);
            };
        })
        .detach();

        Self {
            client: cx.new(|_cx| ClientState::Init),
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
            .child(cx.new(|_cx| StatusBar::new(self.client.clone())))
    }
}
