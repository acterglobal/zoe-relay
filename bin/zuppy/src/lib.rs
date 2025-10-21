use std::path::PathBuf;

use gpui::{
    AppContext, AsyncApp, Context, Entity, IntoElement, ParentElement, Render, Styled, Task,
    WeakEntity, Window, div,
};
use gpui_component::{ActiveTheme, Root};
use widgets::sidebar::ZuppySidebar;

use widgets::interactive_counter::InteractiveCounter;
use widgets::status_bar::StatusBar;

pub mod components;
pub mod util;
pub mod widgets;

use tracing::warn;
use zoe_app_primitives::connection::RelayAddress;
use zoe_client::ClientBuilder;
use zoe_wire_protocol::VerifyingKey;

pub enum ClientState {
    Init,
    Loading,
    Zoe(zoe_client::Client),
    Error(String),
}

pub struct ZuppyRoot {
    sidebar: Entity<ZuppySidebar>,
    client: Entity<ClientState>,
    counter: Entity<InteractiveCounter>,
    status_bar: Entity<StatusBar>,

    _client_task: Task<()>,
}

const DEFAULT_SERVER_ADDRESS: &'static str = "a.dev.hellozoe.app:13918";
const DEFAULT_SERVER_KEY: &'static str =
    "00202ee21d8cc6e519ba164ca4d10c2bae101f83bfd46249f2b7bb86f9083d50ed76";

impl ZuppyRoot {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self::with_storage_dir(cx, &PathBuf::from(".local/zuppy"))
    }

    pub fn with_storage_dir(cx: &mut Context<Self>, main_dir: &PathBuf) -> Self {
        let mut builder = ClientBuilder::default();

        // Parse server key
        let server_key =
            VerifyingKey::from_hex(DEFAULT_SERVER_KEY).expect("Static key doesn't fail");
        // Create RelayAddress
        let default_relay = RelayAddress::new(server_key)
            .with_address_str(DEFAULT_SERVER_ADDRESS.to_owned())
            .with_name("Default Server".to_string());

        builder
            .db_storage_dir_pathbuf(main_dir.clone().join("db.sqlite"))
            .media_storage_dir_pathbuf(main_dir.join("media"))
            .servers(vec![default_relay]);
        builder.autoconnect(true);

        Self::with_builder(cx, builder)
    }

    async fn init_client_state(cx: &mut AsyncApp, builder: ClientBuilder) -> ClientState {
        let client_state = crate::util::gpui_tokio::Tokio::spawn(cx, async {
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
            sidebar: cx.new(|_| ZuppySidebar::new()),
            client: client_state.clone(),
            _client_task: client_task,
            counter: cx.new(|_cx| InteractiveCounter::new(0)),
            status_bar: cx.new(|cx| StatusBar::new(client_state, cx)),
        }
    }
}

impl Render for ZuppyRoot {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let notification_layer = Root::render_notification_layer(window, cx);
        let theme = cx.theme();
        div()
            .size_full()
            .child(
                div()
                    .relative()
                    .size_full()
                    .flex()
                    .flex_col()
                    .gap_0()
                    .justify_start()
                    .items_start()
                    .overflow_hidden()
                    .bg(theme.background)
                    .text_color(theme.foreground)
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .flex_grow()
                            .w_full()
                            .child(self.sidebar.clone())
                            .child(div().flex_grow().child(self.counter.clone())),
                    )
                    .child(self.status_bar.clone()),
            )
            .children(notification_layer)
    }
}
