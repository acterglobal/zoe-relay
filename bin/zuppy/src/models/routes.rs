use gpui::{App, Window};
use gpui_router::{Route, use_navigate};

#[derive(Debug)]
pub enum Routes {
    Dashboard,
    MyUserInfo,
    CreateSheet,
    Sheet,
}

impl Routes {
    pub fn base_path(&self) -> &'static str {
        match self {
            Routes::Dashboard => "dashboard",
            Routes::MyUserInfo => "user_info",
            Routes::CreateSheet => "create_sheet",
            Routes::Sheet => "sheet",
        }
    }

    pub fn path(&self) -> &'static str {
        match self {
            Routes::Sheet => "sheet/{id}",
            _ => self.base_path(),
        }
    }

    pub fn route_sub(&self, window: &mut Window, cx: &mut App, sub: Option<String>) {
        tracing::trace!(route=?self, "Routing");
        let mut nav = use_navigate(cx);
        if let Some(sub) = sub {
            nav(format!("/{}/{}", self.base_path(), sub).into());
        } else {
            nav(self.base_path().into());
        }
        window.refresh();
    }

    pub fn route(&self, window: &mut Window, cx: &mut App) {
        self.route_sub(window, cx, None)
    }
}
