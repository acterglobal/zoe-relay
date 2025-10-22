use std::{fmt::Debug, path::PathBuf};

use gpui::{App, AppContext, AsyncApp, Context, Entity, Global, Task};
use zoe_app_primitives::connection::RelayAddress;
use zoe_client::{ClientBuilder, ClientSecret};
use zoe_wire_protocol::VerifyingKey;

pub enum ClientState {
    Init,
    Loading,
    Zoe(zoe_client::Client),
    Error(String),
}

impl Debug for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ClientState::Init => "ClientState::Init",
            ClientState::Loading => "ClientState::Loading",
            ClientState::Zoe(_client) => "ClientState::Zoe",
            ClientState::Error(_) => "ClientState::Error",
        })
    }
}

struct ClientStateSyncHolder {
    _client_state: Entity<ClientState>,
    _client_task: Task<gpui::Result<()>>,
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
        let client_state_main = cx.new(|_cx| ClientState::Init);
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
            .media_storage_dir_pathbuf(main_dir.join("media"));
        builder.autoconnect(true);

        let credential_url = format!(
            "zuppy:{}",
            std::path::absolute(main_dir)
                .expect("Failed to read dir path")
                .display()
        );
        let client_state = client_state_main.clone();
        let cred_read = cx.read_credentials(&credential_url);

        let client_task = cx.spawn(async move |app: &mut AsyncApp| {
            tracing::trace!("reading creds");
            if !match cred_read.await {
                Ok(None) => {
                    tracing::trace!("none found. contuing");
                    false
                }
                Err(err) => {
                    tracing::error!(?err, "reading credentials failed");
                    false
                }
                Ok(Some((_key, data))) => match ClientSecret::try_from(data) {
                    Ok(secret) => {
                        builder.client_secret(secret);
                        true
                    }
                    Err(err) => {
                        tracing::error!(?err, "parsing secret failed");
                        false
                    }
                },
            } {
                // no credentials found, use default relay
                builder.servers(vec![default_relay]);
            }

            tracing::trace!("building client");
            let new_state = Self::init_client_state(app, builder).await;

            if let ClientState::Zoe(ref zoe) = new_state {
                tracing::trace!("has a zoe");
                match zoe.client_secret().as_bytes() {
                    Err(err) => {
                        tracing::error!(?err, "Can't store the client secret");
                    }
                    Ok(s) => {
                        if let Err(err) = app.update(move |cx: &mut App| {
                            cx.write_credentials(&credential_url, "", &s)
                                .detach_and_log_err(cx)
                        }) {
                            tracing::error!(?err, "Failed to store credentials");
                        }
                    }
                }
            }; // we store the new credentials
            if let Err(err) = app.update_entity(
                &client_state,
                |me: &mut ClientState, cx: &mut Context<ClientState>| {
                    tracing::trace!(?new_state, "Setting to new client");
                    *me = new_state;
                    cx.notify();
                },
            ) {
                tracing::warn!("Failed to update client state: {err}");
            };
            Ok(())
        });

        cx.set_global(ClientStateSyncHolder {
            _client_task: client_task,
            _client_state: client_state_main.clone(),
        });

        client_state_main
    }

    async fn init_client_state(cx: &mut AsyncApp, builder: ClientBuilder) -> ClientState {
        let client_state = crate::config::gpui_tokio::Tokio::spawn(cx, async {
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
}
