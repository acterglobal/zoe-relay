use std::process::exit;

use gpui::{App, AppContext, Application, TitlebarOptions, WindowOptions};
use gpui_component::Root;

pub mod app;
pub mod components;
pub mod config;
pub mod models;
pub mod pages;
pub mod router;
pub mod util;
pub mod widgets;

pub fn make_application() -> Application {
    Application::new().with_assets(crate::config::assets::Assets)
}

pub fn run_app() {
    let app = make_application();
    app.run(|app: &mut App| {
        config::init(app);
        let client_state = models::client_state::ClientStateSetup::new(app);
        if let Err(err) = app.open_window(
            WindowOptions {
                titlebar: Some(TitlebarOptions {
                    title: Some("zuppy".into()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            |window, cx| -> gpui::Entity<_> {
                let view = cx.new(|cx| app::ZuppyApp::new(window, cx, client_state));
                cx.new(|cx| Root::new(view.into(), window, cx))
            },
        ) {
            tracing::error!("Running zuppy failed: {err}");
            exit(1);
        }
    });
}
