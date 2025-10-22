use crate::{
    components::icon::IconName,
    models::{groups::Groups, routes::Routes},
};
use gpui::{
    App, AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    RenderOnce, StatefulInteractiveElement, Styled, Window, div, prelude::FluentBuilder,
};
use gpui_component::{
    Collapsible, Icon, Side, h_flex,
    sidebar::{Sidebar, SidebarGroup, SidebarHeader, SidebarMenu, SidebarMenuItem},
};
use gpui_router::use_navigate;

pub struct ZuppySidebar {
    collapsed: bool,
    groups: Entity<Groups>,
}

#[derive(IntoElement)]
pub struct GroupsSidebar {
    collapsed: bool,
    groups: Entity<Groups>,
}

impl GroupsSidebar {
    pub fn new(groups: Entity<Groups>) -> Self {
        Self {
            collapsed: false,
            groups,
        }
    }
}

impl Collapsible for GroupsSidebar {
    fn collapsed(self, collapsed: bool) -> Self {
        Self {
            collapsed,
            groups: self.groups,
        }
    }

    fn is_collapsed(&self) -> bool {
        self.collapsed
    }
}

#[derive(IntoElement)]
struct NoSheetSidebar {
    collapsed: bool,
}

impl NoSheetSidebar {
    pub fn new() -> Self {
        Self { collapsed: false }
    }
}

impl Collapsible for NoSheetSidebar {
    fn collapsed(self, collapsed: bool) -> Self {
        Self { collapsed }
    }

    fn is_collapsed(&self) -> bool {
        self.collapsed
    }
}

impl RenderOnce for NoSheetSidebar {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        div()
    }
}

impl RenderOnce for GroupsSidebar {
    fn render(self, window: &mut Window, cx: &mut App) -> impl IntoElement {
        cx.read_entity(&self.groups, |state, cx| {
            if state.groups.is_empty() {
                SidebarGroup::new("Sheets").child(
                    SidebarMenu::new().child(
                        SidebarMenuItem::new("Create new sheet")
                            .on_click(|_, window, app| Routes::CreateSheet.route(window, app)),
                    ),
                )
            } else {
                return SidebarGroup::new("Sheets").children(
                    state
                        .groups
                        .iter()
                        .map(|g| SidebarMenu::new().child(SidebarMenuItem::new(g.name.clone()))),
                );
            }
        })
    }
}

impl ZuppySidebar {
    pub fn new(groups: Entity<Groups>) -> Self {
        Self {
            collapsed: false,
            groups,
        }
    }
}

impl Render for ZuppySidebar {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        Sidebar::new(Side::Left)
            .collapsed(self.collapsed)
            .collapsible(true)
            .header(
                SidebarHeader::new().child(
                    h_flex()
                        .id("sidebar-menu-home")
                        .child(Icon::new(IconName::Menu))
                        .cursor_pointer()
                        .when(!self.collapsed, |this| this.child("Home"))
                        .on_click(move |_, window, cx| Routes::Dashboard.route(window, cx)),
                ),
            )
            .child(GroupsSidebar::new(self.groups.clone()))
    }

    // // Toggle button
    // SidebarToggleButton::left()
    //     .collapsed(collapsed)
    //     .on_click(|_, _, _| {
    //         collapsed = !collapsed;
    //     })
    // }
}
