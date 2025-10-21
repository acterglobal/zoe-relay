use crate::models::{client_state::ClientState, routes::Routes, user_info::UserInfoModel};
use gpui::{
    AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    StatefulInteractiveElement, Styled, Window, div,
};
use gpui_component::{Sizable, avatar::Avatar};

pub struct UserInfo {
    info: Entity<UserInfoModel>,
}

impl UserInfo {
    pub fn new(client_state: Entity<ClientState>, cx: &mut Context<Self>) -> Self {
        Self {
            info: cx.new(|cx| UserInfoModel::new(cx, client_state)),
        }
    }
}

impl Render for UserInfo {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let Some(ref user_id) = self.info.read(cx).user_id else {
            return div();
        };
        div().child(
            div()
                .id("user-info-avatar-small")
                .child(Avatar::new().name(user_id).xsmall())
                .cursor_pointer()
                .on_click(move |_, window, cx| Routes::MyUserInfo.route(window, cx)),
        )
    }
}
