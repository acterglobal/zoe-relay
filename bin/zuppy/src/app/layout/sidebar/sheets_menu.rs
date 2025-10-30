use core::slice::Iter;
use std::sync::Arc;

use gpui::{
    App, InteractiveElement, IntoElement, ParentElement, RenderOnce, SharedString,
    StatefulInteractiveElement, Styled as _, Window, div, prelude::FluentBuilder as _,
};
use gpui_component::{ActiveTheme, Collapsible, button::Button, v_flex};
use zoe_app_primitives::icon::Icon;
use zoe_client::client::api::groups::SimpleGroupView;

use crate::{components::icon::IconName, models::routes::Routes, widgets::sheet_icon::SheetIcon};

#[derive(IntoElement)]
struct GroupMenuEntry {
    hex_id: String,
    name: SharedString,
    collapsed: bool,
    id: SharedString,
    icon_id: SharedString,
    icon: Option<Icon>,
}

impl GroupMenuEntry {
    pub fn new(group: &Arc<SimpleGroupView>) -> Self {
        let hex_id = group.group_id.to_hex();
        let icon = group.icon.clone();
        Self {
            name: SharedString::new(group.name.clone()),
            id: format!("sheet-menu-{hex_id}").into(),
            icon_id: format!("menu-{hex_id}-icon").into(),
            icon,
            hex_id,
            collapsed: false,
        }
    }
}

impl Collapsible for GroupMenuEntry {
    fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    fn collapsed(mut self, collapsed: bool) -> Self {
        self.collapsed = collapsed;
        self
    }
}

impl RenderOnce for GroupMenuEntry {
    fn render(self, _: &mut Window, _cx: &mut App) -> impl IntoElement {
        let hex_id = self.hex_id;
        div()
            .when_else(!self.collapsed, |d| d.ml_5(), |d| d.m_3())
            .flex()
            .flex_row()
            .gap_2()
            .child(SheetIcon::new(self.icon_id, self.icon))
            .when(!self.collapsed, |d| d.child(self.name))
            .id(self.id.clone())
            .cursor_pointer()
            .on_click(move |_, w, cx| Routes::Sheet.route_sub(w, cx, Some(hex_id.clone())))
    }
}

/// A sidebar group
#[derive(IntoElement)]
pub struct SheetsMenu {
    label: SharedString,
    collapsed: bool,
    groups: Vec<GroupMenuEntry>,
}

impl SheetsMenu {
    pub fn new(label: impl Into<SharedString>) -> Self {
        Self {
            label: label.into(),
            collapsed: false,
            groups: Vec::new(),
        }
    }
    pub fn groups(mut self, groups: Iter<Arc<SimpleGroupView>>) -> Self {
        self.groups = groups.map(GroupMenuEntry::new).collect();
        self
    }
}
impl Collapsible for SheetsMenu {
    fn is_collapsed(&self) -> bool {
        self.collapsed
    }

    fn collapsed(mut self, collapsed: bool) -> Self {
        self.collapsed = collapsed;
        self
    }
}
impl RenderOnce for SheetsMenu {
    fn render(self, _: &mut Window, cx: &mut App) -> impl IntoElement {
        let theme = cx.theme();
        let has_groups = !self.groups.is_empty();
        v_flex()
            .relative()
            .p_2()
            .when_else(
                self.collapsed,
                |this| this.child(div().border_b_1().m_1().border_color(theme.drag_border)),
                |this| {
                    // title
                    this.child(
                        div()
                            .flex()
                            .flex_row()
                            .justify_between()
                            .px_2()
                            .rounded(cx.theme().radius)
                            .text_xs()
                            .text_color(cx.theme().sidebar_foreground.opacity(0.7))
                            .h_8()
                            .child(self.label)
                            .when(has_groups, |m| {
                                // we have some other logic to show if there aren't any yet
                                m.child(
                                    Button::new("sidebar-add-sheet")
                                        .text_xs()
                                        .icon(IconName::Plus)
                                        .on_click(|_ev, window, cx| {
                                            Routes::CreateSheet.route(window, cx);
                                        }),
                                )
                            }),
                    )
                },
            )
            .when_else(
                has_groups,
                |m| {
                    m.child(
                        div().gap_2().flex_col().children(
                            self.groups
                                .into_iter()
                                .map(|child| child.collapsed(self.collapsed)),
                        ),
                    )
                },
                |m| {
                    m.child(
                        div()
                            .flex_shrink_0()
                            .px_2()
                            .rounded(cx.theme().radius)
                            .text_xs()
                            .text_color(cx.theme().sidebar_foreground.opacity(0.7))
                            .h_8()
                            .child("No sheets"),
                    )
                },
            )
    }
}
