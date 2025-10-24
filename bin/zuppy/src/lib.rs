use std::process::exit;

use clap::Parser;
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

pub fn run() {
    let opts = app::args::ZuppyArgs::parse();
    run_app(opts)
}

pub fn run_app(opts: app::args::ZuppyArgs) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&opts.log))
        .init();

    let app = make_application();
    app.run(move |app: &mut App| {
        config::init(app);
        let client_state = opts.init_client_state(app);
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
            tracing::error!(%err, "Running zuppy failed");
            exit(1);
        }
    });
}
