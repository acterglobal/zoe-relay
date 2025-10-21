use std::path::PathBuf;

use gpui::{AppContext, AsyncApp, Context, Entity, IntoElement, Render, Task, WeakEntity, Window};

use crate::layout::ZuppyLayout;
use crate::models::client_state::ClientState;
use tracing::warn;
use zoe_app_primitives::connection::RelayAddress;
use zoe_client::ClientBuilder;
use zoe_wire_protocol::VerifyingKey;

const DEFAULT_SERVER_ADDRESS: &'static str = "a.dev.hellozoe.app:13918";
const DEFAULT_SERVER_KEY: &'static str =
    "00202ee21d8cc6e519ba164ca4d10c2bae101f83bfd46249f2b7bb86f9083d50ed76";

pub struct ZuppyRoot {
    client: Entity<ClientState>,
    layout: Entity<ZuppyLayout>,
    _client_task: Task<()>,
}

impl ZuppyRoot {
    pub fn new(cx: &mut Context<Self>) -> Self {
        Self::with_storage_dir(cx, &PathBuf::from(".local/zuppy"))
    }

    fn with_storage_dir(cx: &mut Context<Self>, main_dir: &PathBuf) -> Self {
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

    fn with_builder(cx: &mut Context<Self>, builder: ClientBuilder) -> Self {
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
            layout: cx.new(|cx| ZuppyLayout::new(cx, client_state)),
            _client_task: client_task,
        }
    }
}

impl Render for ZuppyRoot {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        self.layout.clone()
    }
}
