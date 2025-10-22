pub mod assets;
pub mod gpui_tokio;

use std::rc::Rc;

use gpui::App;
use gpui_component::{Theme, ThemeMode, ThemeSet};

const DEFAULT_THEME: &str = "tokyonight";

fn init_theme(app: &mut App) {
    let assets = app.asset_source();

    let Ok(themes) = assets
        .list("themes")
        .inspect_err(|err| tracing::error!(?err, "Failed to read themes assets"))
    else {
        tracing::error!("Failed to get asset source");
        return;
    };
    tracing::info!("Available themes: {themes:?}");

    let Ok(Some(theme_data)) = assets
        .load(&format!("themes/{DEFAULT_THEME}.json"))
        .inspect_err(|err| tracing::error!(?err, "Failed to read default theme"))
    else {
        return;
    };

    let Ok(theme_set) = serde_json::from_slice::<ThemeSet>(theme_data.as_ref())
        .inspect_err(|err| tracing::error!(?err, "Failed to parse default theme"))
    else {
        return;
    };

    let current_theme = Theme::global_mut(app);

    for theme in theme_set.themes {
        if theme.mode.is_dark() {
            current_theme.dark_theme = Rc::new(theme);
        } else {
            current_theme.light_theme = Rc::new(theme);
        }
    }
    Theme::change(ThemeMode::Dark, None, app);
    tracing::info!("Theme set");
}

pub fn init(app: &mut App) {
    gpui_component::init(app);
    gpui_router::init(app);
    crate::config::gpui_tokio::init(app);
    init_theme(app);
    app.activate(true);
}
