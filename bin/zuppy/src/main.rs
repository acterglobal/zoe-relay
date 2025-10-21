use gpui::{App, AppContext, Application, WindowOptions};
use tracing::error;
use zuppy::ZuppyRoot;

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let app = Application::new().with_assets(zuppy::util::assets::Assets);
    app.run(|app: &mut App| {
        gpui_component::init(app);
        zuppy::util::gpui_tokio::init(app);
        if let Err(err) = app.open_window(WindowOptions::default(), |_, cx| cx.new(ZuppyRoot::new))
        {
            error!("Failed to open window: {err}");
        }
    });
}
