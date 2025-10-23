use crate::models::groups::Groups;
use crate::models::routes::Routes;
use crate::pages::sheets::create_sheet::CreateSheetPage;
use crate::pages::sheets::sheet::SheetPage;
use gpui::{AppContext, ParentElement, div};
use gpui::{Context, Entity, IntoElement, Render, Window};
use gpui_router::{NavLink, Route, Routes as GpuiRoutes, use_location, use_params};

use crate::pages::{dashboard::DashboardPage, user_info::UserInfoPage};

use crate::models::client_state::ClientState;

pub struct Router {
    user_info_page: Entity<UserInfoPage>,
    dashboard: Entity<DashboardPage>,
    no_match: Entity<NoMatch>,
    create_sheet: Entity<CreateSheetPage>,
    sheet: Entity<SheetPage>,
}

impl Router {
    pub fn new(
        win: &mut Window,
        cx: &mut Context<Self>,
        client_state: Entity<ClientState>,
        group_state: Entity<Groups>,
    ) -> Self {
        Self {
            user_info_page: cx.new(|cx| UserInfoPage::new(cx, client_state.clone())),
            dashboard: cx.new(|cx| DashboardPage::new(cx, client_state.clone())),
            create_sheet: cx.new(|cx| CreateSheetPage::new(win, cx, client_state.clone())),
            sheet: cx.new(|cx| SheetPage::new(win, cx, client_state.clone(), group_state.clone())),
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
            Route::new()
                .path(Routes::CreateSheet.path())
                .element(self.create_sheet.clone()),
            Route::new()
                .path(Routes::Sheet.path())
                .element(self.sheet.clone()),
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
