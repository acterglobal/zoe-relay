use std::path::PathBuf;

use clap::{Parser, command};
use gpui::{App, Entity};
use zoe_app_primitives::connection::RelayAddress;
use zoe_client::ClientBuilder;
use zoe_wire_protocol::VerifyingKey;

use crate::models::client_state::{ClientState, ClientStateSetup};

#[cfg(debug_assertions)]
const IS_DEBUG: bool = true;
#[cfg(not(debug_assertions))]
const IS_DEBUG: bool = false;

// FIXME: allow to load from cli, env and file
const DEFAULT_SERVER_ADDRESS: &str = "a.dev.hellozoe.app:13918";
const DEFAULT_SERVER_KEY: &str =
    "00202ee21d8cc6e519ba164ca4d10c2bae101f83bfd46249f2b7bb86f9083d50ed76";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct ZuppyArgs {
    #[arg(short, long, default_value = "info", env = "ZOE_LOG")]
    pub(crate) log: String,
    pub(crate) base_dir: Option<PathBuf>,
}

impl ZuppyArgs {
    pub fn home_folder(&self) -> PathBuf {
        self.base_dir.clone().unwrap_or_else(|| {
            if IS_DEBUG {
                PathBuf::from(".local")
            } else {
                // FIXME: load from home dir
                PathBuf::from(".local")
            }
        })
    }

    pub fn decorate_builder_fallback(&self, builder: &mut ClientBuilder) {
        // no credentials found, use default relay
        let server_key =
            VerifyingKey::from_hex(DEFAULT_SERVER_KEY).expect("Static key doesn't fail");
        builder.servers(vec![
            RelayAddress::new(server_key)
                .with_address_str(DEFAULT_SERVER_ADDRESS.to_owned())
                .with_name("Default Server".to_string()),
        ]);
    }

    pub fn init_client_state(self, app: &mut App) -> Entity<ClientState> {
        let mut builder = ClientBuilder::default();
        let abs_folder =
            std::path::absolute(self.home_folder()).expect("Failed to read absolute path for home");

        builder
            .db_storage_dir_pathbuf(abs_folder.join("db"))
            .media_storage_dir_pathbuf(abs_folder.join("media"));
        builder.autoconnect(true);

        let credentials_url = format!("zuppy:{}", abs_folder.display());

        ClientStateSetup::with_builder(app, builder, credentials_url, move |builder| {
            self.decorate_builder_fallback(builder)
        })
    }
}
