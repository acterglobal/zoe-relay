use gpui::*;
use theme::Theme;
use widgets::headline::Headline;
use widgets::interactive_counter::InteractiveCounter;
use widgets::status_bar::StatusBar;

pub mod theme;
pub mod widgets;

use tracing::warn;
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
    status_bar: Entity<StatusBar>,
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

        let client_state = cx.new(|_cx| ClientState::Init);
        Self {
            client: client_state.clone(),
            counter: cx.new(|_cx| InteractiveCounter::new(0)),
            status_bar: cx.new(|cx| StatusBar::new(client_state, cx)),
        }
    }
}

impl Render for ZuppyRoot {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.default_global::<Theme>();
        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .gap_0()
            .justify_start()
            .items_start()
            .overflow_hidden()
            .bg(theme.background())
            .text_color(theme.text())
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
                            .child(cx.new(|_cx| Headline::new(SharedString::new_static("Left")))),
                    )
                    .child(div().flex_grow().child(self.counter.clone()))
                    .child(
                        div()
                            .flex()
                            .child(cx.new(|_cx| Headline::new(SharedString::new_static("Right")))),
                    ),
            )
            .child(self.status_bar.clone())
    }
}
