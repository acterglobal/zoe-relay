use crate::{components::icon::IconName, models::routes::Routes};
use gpui::{
    Context, InteractiveElement, IntoElement, ParentElement, Render, StatefulInteractiveElement,
    Styled, Window, prelude::FluentBuilder,
};
use gpui_component::{
    Icon, Side, h_flex,
    sidebar::{Sidebar, SidebarGroup, SidebarHeader, SidebarMenu, SidebarMenuItem},
};

pub struct ZuppySidebar {
    collapsed: bool,
}

impl ZuppySidebar {
    pub fn new() -> Self {
        Self { collapsed: false }
    }
}

impl Render for ZuppySidebar {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
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
            .child(
                SidebarGroup::new("Menu")
                    .child(SidebarMenu::new().child(SidebarMenuItem::new("Files"))),
            )
    }

    // // Toggle button
    // SidebarToggleButton::left()
    //     .collapsed(collapsed)
    //     .on_click(|_, _, _| {
    //         collapsed = !collapsed;
    //     })
    // }
}
