use crate::components::icon::IconName;
use gpui::{Context, IntoElement, ParentElement, Render, Window, prelude::FluentBuilder};
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
                        .child(Icon::new(IconName::Menu))
                        .when(!self.collapsed, |this| this.child("Home")),
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
