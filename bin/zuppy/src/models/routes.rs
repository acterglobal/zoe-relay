use gpui::{App, Window};
use gpui_router::use_navigate;

#[derive(Debug)]
pub enum Routes {
    Dashboard,
    MyUserInfo,
}

impl Routes {
    pub fn path(&self) -> &'static str {
        match self {
            Routes::Dashboard => "dashboard",
            Routes::MyUserInfo => "user_info",
        }
    }

    pub fn route(&self, window: &mut Window, cx: &mut App) {
        tracing::info!(route=?self, "Routing");
        let mut nav = use_navigate(cx);
        nav(format!("/{}", self.path()).into());
        window.refresh();
        tracing::info!("issued")
    }
}
