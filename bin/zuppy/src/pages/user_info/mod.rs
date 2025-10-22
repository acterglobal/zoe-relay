use gpui::{
    AppContext, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Window,
    div,
};
use gpui_component::{Sizable, avatar::Avatar, skeleton::Skeleton};

use crate::models::{client_state::ClientState, user_info::UserInfoModel};

pub struct UserInfoPage {
    info: Entity<UserInfoModel>,
}

impl UserInfoPage {
    pub fn new(cx: &mut Context<Self>, client_state: Entity<ClientState>) -> Self {
        Self {
            info: cx.new(|cx| UserInfoModel::new(cx, client_state)),
        }
    }
}

impl Render for UserInfoPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let d = div()
            .size_full()
            .m_5()
            .flex()
            .justify_center()
            .items_center()
            .flex_col()
            .gap_10();
        let Some(ref user_id) = self.info.read(cx).user_id else {
            // no user info yet, show skeletons
            return d
                .child(Skeleton::new().size_12().rounded_full())
                .child(Skeleton::new().h_4());
        };
        d.child(Avatar::new().name(user_id).large())
            .child(SharedString::new(user_id.to_owned()))
    }
}
