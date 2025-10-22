use gpui::{
    AppContext, Context, Div, Entity, IntoElement, ParentElement, Render, Styled, Window, div,
};
use gpui_router::use_params;
use zoe_app_primitives::group::events::GroupId;

use crate::models::groups::Groups;

pub struct SheetPage {
    groups: Entity<Groups>,
}

impl SheetPage {
    pub fn new(entity: Entity<Groups>) -> Self {
        Self { groups: entity }
    }

    pub fn render_error(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
        error: String,
    ) -> Div {
        div().size_full().child(error)
    }
}

impl Render for SheetPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let params = use_params(cx);
        let id = match GroupId::from_hex(&params["id"]) {
            Ok(id) => id,
            Err(error) => return self.render_error(_window, cx, error.to_string()),
        };
        let Some(group) = cx.read_entity(&self.groups, |groups, _app| groups.get(id)) else {
            return self.render_error(_window, cx, "Group not found".to_string());
        };

        div().child(div().child(group.name))
    }
}
