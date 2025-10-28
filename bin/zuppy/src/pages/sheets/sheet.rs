use std::sync::Arc;

use gpui::{
    App, AppContext, Context, Div, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    SharedString, Stateful, StatefulInteractiveElement, Styled, WeakEntity, Window, div,
};
use gpui_component::{
    ContextModal, StyledExt, group_box::GroupBox, notification::NotificationType,
};
use gpui_router::use_params;
use zoe_app_primitives::{
    group::events::{GroupId, GroupInfoUpdate, permissions::GroupAction},
    icon::Icon,
    metadata::Metadata,
};
use zoe_client::client::api::groups::SimpleGroupView;

use crate::{
    components::edit_modal::EditModal,
    models::{client_state::ClientState, groups::Groups},
    widgets::simple_popover::SimplePopover,
};

pub struct SheetPage {
    client_state: Entity<ClientState>,
    groups: Entity<Groups>,
}

impl SheetPage {
    pub fn new(
        _window: &mut Window,
        _cx: &mut Context<Self>,
        client_state: Entity<ClientState>,
        groups: Entity<Groups>,
    ) -> Self {
        Self {
            client_state,
            groups,
        }
    }

    fn get_group(
        cx: &mut Context<Self>,
        groups: Entity<Groups>,
    ) -> Result<Arc<SimpleGroupView>, String> {
        let params = use_params(cx);
        let hex_id = params.get("id").ok_or("Missing group ID")?;
        let id = GroupId::from_hex(hex_id).map_err(|error| error.to_string())?;
        cx.read_entity(&groups, |groups, _app| groups.get(id))
            .ok_or_else(|| "Group not found".to_string())
    }

    fn render_error(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
        error: String,
    ) -> Div {
        div().size_full().child(error)
    }

    fn submit_group_update(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        group: Arc<SimpleGroupView>,
        update: GroupInfoUpdate,
    ) {
        let ClientState::Zoe(client) = self.client_state.read(cx) else {
            window.push_notification((NotificationType::Error, "Zoe client not found"), cx);
            return;
        };

        let group_id = group.group_id.clone();

        let zoe = client.clone();
        window
            .spawn(cx, async move |w| {
                if let Err(err) = match zoe.update_group(&group_id, vec![update]).await {
                    Err(e) => w.update(|window, cx| {
                        window.push_notification(
                            (
                                NotificationType::Error,
                                SharedString::new(format!("Failed to sent sheet update: {}", e)),
                            ),
                            cx,
                        );
                    }),
                    Ok(_) => w.update(|window, cx| {
                        window.push_notification(
                            (NotificationType::Success, "Sheet updated successfully"),
                            cx,
                        );
                    }),
                } {
                    tracing::error!(?err, "failed to show push");
                };
            })
            .detach();
    }
    fn render_titlebar(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
        group: Arc<SimpleGroupView>,
    ) -> Stateful<Div> {
        let can_edit = group.can_i(GroupAction::UpdateGroup);
        let title = self.render_title(window, cx, group.clone());
        if group.icon.is_none() && !can_edit {
            return title;
        };

        let icon = if let Some(Icon::Emoji(emoji)) = &group.icon {
            div().child(SharedString::from(emoji)).text_xl()
        } else {
            div().child(SharedString::from("❓"))
        };

        let icon_outer = if !can_edit {
            icon.id("sheet-icon")
        } else {
            let this = cx.entity().downgrade();
            icon.cursor_pointer()
                .id("sheet-icon-edit")
                .hoverable_tooltip(move |_w, ctx| {
                    ctx.new(|_| SimplePopover::new("Click to edit".into()))
                        .into()
                })
                .on_click(move |_, win, cx| {
                    let current = if let Some(Icon::Emoji(emoji)) = &group.icon {
                        emoji.clone()
                    } else {
                        String::new()
                    };
                    EditModal::default()
                        .title("Edit Emoji Icon".to_owned())
                        .current_value(current)
                        .placeholder("Enter new emoji")
                        .show(win, cx, {
                            let this = this.clone();
                            let group = group.clone();
                            move |new_value, win, cx| {
                                if let Err(err) = this.update(
                                    cx,
                                    |me: &mut SheetPage, cx: &mut Context<SheetPage>| {
                                        me.submit_group_update(
                                            win,
                                            cx,
                                            group.clone(),
                                            GroupInfoUpdate::AddMetadata(Metadata::Icon(
                                                Icon::Emoji(new_value.to_string()),
                                            )),
                                        );
                                    },
                                ) {
                                    tracing::error!("Failed to update group emoji: {}", err);
                                }
                            }
                        });
                })
        };

        div()
            .id("sheet-title-container")
            .h_flex()
            .justify_start()
            .child(icon_outer.mr_2())
            .child(title)
    }

    fn render_title(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
        group: Arc<SimpleGroupView>,
    ) -> Stateful<Div> {
        let name = group.name.clone();

        let this = cx.entity().downgrade();
        let d = div()
            .id("edit-sheet-name")
            .text_2xl()
            .child(SharedString::new(name.clone()));
        if !group.can_i(GroupAction::UpdateGroup) {
            return d;
        }

        // can edit

        d.cursor_pointer()
            .hoverable_tooltip(move |_w, ctx| {
                ctx.new(|_| SimplePopover::new("Click to edit".into()))
                    .into()
            })
            .on_click(move |_, win, cx| {
                EditModal::default()
                    .title("Edit Group Name".to_owned())
                    .current_value(name.clone())
                    .placeholder("Enter new group name")
                    .show(win, cx, {
                        let this = this.clone();
                        let group = group.clone();
                        move |new_value, win, cx| {
                            if let Err(err) = this.update(
                                cx,
                                |me: &mut SheetPage, cx: &mut Context<SheetPage>| {
                                    me.submit_group_update(
                                        win,
                                        cx,
                                        group.clone(),
                                        GroupInfoUpdate::Name(new_value.to_string()),
                                    );
                                },
                            ) {
                                tracing::error!("Failed to update group name: {}", err);
                            }
                        }
                    });
                print!("done");
            })
    }

    fn _on_submit_descr(
        this: WeakEntity<Self>,
        window: &mut Window,
        cx: &mut App,
        group: Arc<SimpleGroupView>,
        new_value: SharedString,
    ) {
        if let Err(err) = this.update(cx, |me: &mut SheetPage, cx: &mut Context<SheetPage>| {
            me.submit_group_update(
                window,
                cx,
                group.clone(),
                GroupInfoUpdate::AddMetadata(Metadata::Description(new_value.to_string())),
            );
        }) {
            tracing::error!("Failed to update group name: {}", err);
        }
    }
    fn render_description(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
        group: Arc<SimpleGroupView>,
    ) -> Stateful<Div> {
        let can_edit = group.can_i(GroupAction::UpdateGroup);

        let this = cx.entity().downgrade();
        let g = group.clone();

        let description = match &group.description {
            None => None,
            Some(e) if e.is_empty() => None,
            Some(e) => Some(e.clone()),
        };
        // a bit clunky but also confirms we are not empty
        let Some(description) = description else {
            if !can_edit {
                return div().id("description");
            }
            return div()
                .id("description")
                .cursor_pointer()
                .flex()
                .flex_row()
                .gap_2()
                .child(SharedString::new("No description"))
                .child(
                    div()
                        .child(SharedString::new("Click here to add one"))
                        .underline(),
                )
                .on_click(move |_, win, cx| {
                    EditModal::default()
                        .title("Add Group Description".to_owned())
                        .placeholder("What is this about?")
                        .show_with_textinput_decorator(
                            win,
                            cx,
                            |s| s.multi_line().auto_grow(2, 10),
                            {
                                let g = g.clone();
                                let this = this.clone();
                                move |new_value: SharedString, win, cx| {
                                    let this = this.clone();
                                    let group = g.clone();
                                    Self::_on_submit_descr(this, win, cx, group, new_value);
                                }
                            },
                        );
                });
            // nothing for us to show
        };

        let d = div()
            .id("sheet-description")
            .child(SharedString::new(description.clone()));
        if !can_edit {
            return d;
        }

        // can edit

        d.cursor_pointer()
            .hoverable_tooltip(move |_w, ctx| {
                ctx.new(|_| SimplePopover::new("Click to edit".into()))
                    .into()
            })
            .on_click(move |_, win, cx| {
                EditModal::default()
                    .title("Edit Description".to_owned())
                    .current_value(description.clone())
                    .placeholder("Leave empty to clear")
                    .allow_empty(true)
                    .show_with_textinput_decorator(win, cx, |s| s.multi_line().auto_grow(2, 10), {
                        let g = g.clone();
                        let this = this.clone();
                        move |new_value: SharedString, win, cx| {
                            let this = this.clone();
                            let group = g.clone();
                            Self::_on_submit_descr(this, win, cx, group, new_value);
                        }
                    });
            })
    }
}

impl Render for SheetPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        match Self::get_group(cx, self.groups.clone()) {
            // FIXME: for efficient would be nicer
            Err(error) => self.render_error(window, cx, error),
            Ok(group) => div().size_full().flex().flex_row().justify_center().child(
                GroupBox::new()
                    .outline()
                    .rounded_xl()
                    .p_10()
                    .v_flex()
                    .child(self.render_titlebar(window, cx, group.clone()))
                    .child(self.render_description(window, cx, group.clone())),
            ),
        }
    }
}
