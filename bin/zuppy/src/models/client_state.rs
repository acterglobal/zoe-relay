use std::path::PathBuf;

use gpui::{App, AppContext, AsyncApp, Context, Entity, Global, Task};
use zoe_app_primitives::connection::RelayAddress;
use zoe_client::ClientBuilder;
use zoe_wire_protocol::VerifyingKey;

pub enum ClientState {
    Init,
    Loading,
    Zoe(zoe_client::Client),
    Error(String),
}

struct ClientStateSyncHolder {
    _client_state: Entity<ClientState>,
    _client_task: Task<()>,
}

impl Global for ClientStateSyncHolder {}

pub struct ClientStateSetup;

const DEFAULT_SERVER_ADDRESS: &'static str = "a.dev.hellozoe.app:13918";
const DEFAULT_SERVER_KEY: &'static str =
    "00202ee21d8cc6e519ba164ca4d10c2bae101f83bfd46249f2b7bb86f9083d50ed76";

impl ClientStateSetup {
    pub fn new(cx: &mut App) -> Entity<ClientState> {
        Self::with_storage_dir(cx, &PathBuf::from(".local/zuppy"))
    }

    pub fn with_storage_dir(cx: &mut App, main_dir: &PathBuf) -> Entity<ClientState> {
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

    fn with_builder(cx: &mut App, builder: ClientBuilder) -> Entity<ClientState> {
        let client_state = cx.new(|_cx| ClientState::Init);
        let cl_clone = client_state.clone();
        let client_task = cx.spawn(async move |cx: &mut AsyncApp| {
            let new_state = Self::init_client_state(cx, builder).await;
            if let Err(err) = cx.update_entity(
                &cl_clone,
                |me: &mut ClientState, cx: &mut Context<ClientState>| {
                    *me = new_state;
                    cx.notify();
                },
            ) {
                tracing::warn!("Failed to update client state: {err}");
            };
        });

        cx.set_global(ClientStateSyncHolder {
            _client_task: client_task,
            _client_state: client_state.clone(),
        });

        client_state
    }
}
