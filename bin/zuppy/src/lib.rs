use gpui::App;

pub mod components;
pub mod layout;
pub mod models;
pub mod pages;
pub mod root;
pub mod router;
pub mod util;
pub mod widgets;

pub fn init(app: &mut App) {
    gpui_component::init(app);
    gpui_router::init(app);
    crate::util::gpui_tokio::init(app);
    app.activate(true);
}
