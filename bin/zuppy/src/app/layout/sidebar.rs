use crate::{
    components::icon::IconName,
    models::{groups::Groups, routes::Routes},
};
use gpui::{
    App, AppContext, Context, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    RenderOnce, StatefulInteractiveElement, Styled, Window, prelude::FluentBuilder,
};
use gpui_component::{
    Collapsible, Icon, Side, h_flex,
    sidebar::{
        Sidebar, SidebarGroup, SidebarHeader, SidebarMenu, SidebarMenuItem, SidebarToggleButton,
    },
};
use sheets_menu::SheetsMenu;

mod sheets_menu;

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

impl RenderOnce for GroupsSidebar {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        cx.read_entity(&self.groups, |state, _cx| {
            SheetsMenu::new("Sheets")
                .groups(state.groups.iter())
                .collapsed(self.collapsed)
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
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let me = cx.entity().downgrade();
        Sidebar::new(Side::Left)
            .collapsed(self.collapsed)
            .collapsible(true)
            .header(
                SidebarHeader::new().child(
                    h_flex()
                        .gap_2()
                        .id("sidebar-menu-home")
                        .child(Icon::new(IconName::Menu))
                        .cursor_pointer()
                        .when(!self.collapsed, |this| this.child("Home"))
                        .on_click(move |_, window, cx| Routes::Dashboard.route(window, cx)),
                ),
            )
            .child(GroupsSidebar::new(self.groups.clone()).collapsed(self.collapsed))
            // Not really convinced by this
            .footer(
                SidebarToggleButton::left()
                    .collapsed(self.collapsed)
                    .on_click(move |_, _, cx| {
                        if let Err(err) = me.update(cx, |me, cx| {
                            me.collapsed = !me.collapsed;
                            cx.notify();
                        }) {
                            tracing::error!(?err, "Failed to update sidebar state");
                        }
                    }),
            )
    }
}
