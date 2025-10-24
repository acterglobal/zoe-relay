use std::fmt::Debug;

use gpui::{App, AppContext, AsyncApp, Context, Entity, Global, Task};
use zoe_client::{ClientBuilder, ClientSecret};

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

impl ClientStateSetup {
    pub fn with_builder(
        cx: &mut App,
        mut builder: ClientBuilder,
        credential_url: String,
        fresh_instance_fn: impl FnOnce(&mut ClientBuilder) + 'static,
    ) -> Entity<ClientState> {
        let client_state_main = cx.new(|_cx| ClientState::Init);
        let client_state = client_state_main.clone();
        let cred_read = cx.read_credentials(&credential_url);

        let client_task = cx.spawn(async move |app: &mut AsyncApp| {
            tracing::trace!("reading creds");
            if !match cred_read.await {
                Ok(None) => {
                    tracing::trace!("none found. continuing");
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
                fresh_instance_fn(&mut builder);
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
