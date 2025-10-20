use std::path::PathBuf;

use gpui::{
    AppContext, AsyncApp, Context, Entity, IntoElement, ParentElement, Render, SharedString,
    Styled, Task, WeakEntity, Window, div,
};
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

    _client_task: Task<()>,
}

impl ZuppyRoot {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self::with_storage_dir(cx, &PathBuf::from(".local/zuppy"))
    }

    pub fn with_storage_dir(cx: &mut Context<Self>, main_dir: &PathBuf) -> Self {
        let mut builder = ClientBuilder::default();

        builder
            .db_storage_dir_pathbuf(main_dir.clone().join("db.sqlite"))
            .media_storage_dir_pathbuf(main_dir.join("media"));
        Self::with_builder(cx, builder)
    }

    async fn init_client_state(cx: &mut AsyncApp, builder: ClientBuilder) -> ClientState {
        let client_state = gpui_tokio::Tokio::spawn(cx, async {
            match builder.build().await {
                Ok(client) => ClientState::Zoe(client),
                Err(err) => ClientState::Error(err.to_string()),
            }
        });
        match client_state {
            Ok(inner_task) => match inner_task.await {
                Ok(new_state) => new_state,
                Err(err) => ClientState::Error(err.to_string()),
            },
            Err(err) => ClientState::Error(err.to_string()),
        }
    }

    pub fn with_builder(cx: &mut Context<Self>, builder: ClientBuilder) -> Self {
        let client_task = cx.spawn(async |me: WeakEntity<Self>, cx: &mut AsyncApp| {
            let new_state = Self::init_client_state(cx, builder).await;
            if let Err(err) = me.update(cx, |me: &mut Self, cx: &mut Context<Self>| {
                me.client.write(cx, new_state);
            }) {
                warn!("Failed to update client state: {}", err);
            };
        });

        let client_state = cx.new(|_cx| ClientState::Init);
        Self {
            client: client_state.clone(),
            _client_task: client_task,
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
