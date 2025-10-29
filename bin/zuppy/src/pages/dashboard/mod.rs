use gpui::{AppContext, Context, Entity, IntoElement, Render, Styled, Window};
use gpui_component::group_box::GroupBox;

use crate::models::client_state::ClientState;
use crate::models::user_info::UserInfoModel;

pub struct DashboardPage {
    user_info: Entity<UserInfoModel>,
}

impl DashboardPage {
    pub fn new(cx: &mut Context<Self>, client_state: Entity<ClientState>) -> Self {
        Self {
            user_info: cx.new(|cx| UserInfoModel::new(cx, client_state)),
        }
    }
}

impl Render for DashboardPage {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        GroupBox::new().fill().title("Good day").m_10().p_10()
    }
}
