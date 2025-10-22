use std::process::exit;

use gpui::{App, AppContext, Application, WindowOptions};
use gpui_component::Root;
use zuppy::app::ZuppyApp;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let app = Application::new().with_assets(zuppy::util::assets::Assets);
    app.run(|app: &mut App| {
        zuppy::init(app);
        let client_state = zuppy::models::client_state::ClientStateSetup::new(app);
        if let Err(err) = app.open_window(WindowOptions::default(), |window, cx| {
            let view = cx.new(|cx| ZuppyApp::new(cx, client_state));
            cx.new(|cx| Root::new(view.into(), window, cx))
        }) {
            tracing::error!("Running zuppy failed: {err}");
            exit(1);
        }
    });
}
