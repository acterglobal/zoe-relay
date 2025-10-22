use crate::models::routes::Routes;
use gpui::{AppContext, ParentElement, div};
use gpui::{Context, Entity, IntoElement, Render, Window};
use gpui_router::{NavLink, Route, Routes as GpuiRoutes, use_location, use_params};

use crate::pages::{dashboard::DashboardPage, user_info::UserInfoPage};

use crate::models::client_state::ClientState;

pub struct Router {
    user_info_page: Entity<UserInfoPage>,
    dashboard: Entity<DashboardPage>,
    no_match: Entity<NoMatch>,
}

impl Router {
    pub fn new(cx: &mut Context<Self>, client_state: Entity<ClientState>) -> Self {
        Self {
            user_info_page: cx.new(|cx| UserInfoPage::new(cx, client_state.clone())),
            dashboard: cx.new(|cx| DashboardPage::new(cx, client_state.clone())),
            no_match: cx.new(|_cx| NoMatch {}),
        }
    }
}

impl Render for Router {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        GpuiRoutes::new().basename("/").children(vec![
            Route::new()
                .path(Routes::MyUserInfo.path())
                .element(self.user_info_page.clone()),
            Route::new()
                .path(Routes::Dashboard.path())
                .element(self.dashboard.clone()),
            Route::new().index().element(self.dashboard.clone()),
            Route::new()
                .path("{*not_match}")
                .element(self.no_match.clone()),
        ])
    }
}

struct NoMatch;

impl Render for NoMatch {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let params = use_params(cx);
        let location = use_location(cx);
        tracing::warn!(?params, ?location, "not found");
        div().child(div().child("Nothing to see here!")).child(
            NavLink::new()
                .to("/")
                .child(div().child("Go to the home page")),
        )
    }
}
