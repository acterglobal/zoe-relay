use gpui::*;
use tracing::error;
use zuppy::{ZuppyRoot, theme};

fn main() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let app = Application::new();
    app.run(|app: &mut App| {
        theme::init(app);
        if let Err(err) = app.open_window(WindowOptions::default(), |_, cx| {
            cx.new(|cx| ZuppyRoot::new(cx))
        }) {
            error!("Failed to open window: {err}");
        }
    });
}
