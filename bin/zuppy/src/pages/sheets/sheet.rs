use std::sync::Arc;

use gpui::{
    AppContext, Context, Div, Entity, InteractiveElement, IntoElement, ParentElement, Render,
    SharedString, Stateful, StatefulInteractiveElement, Styled, Subscription, Window, div,
};
use gpui_component::{
    ContextModal,
    button::{Button, ButtonVariants},
    group_box::GroupBox,
    input::{InputEvent, InputState, TextInput},
    notification::NotificationType,
    v_flex,
};
use gpui_router::use_params;
use zoe_app_primitives::group::events::{GroupId, GroupInfoUpdate, permissions::GroupAction};
use zoe_client::client::api::groups::SimpleGroupView;

use crate::{
    models::{client_state::ClientState, groups::Groups},
    widgets::simple_popover::SimplePopover,
};

pub struct EditName {
    group: GroupId,
    cur_name: String,
    client_state: Entity<ClientState>,
    input: Entity<InputState>,
    _submit_sub: Subscription,
}

impl EditName {
    pub fn show(
        window: &mut Window,
        cx: &mut Context<Self>,
        group: GroupId,
        cur_name: String,
        client_state: Entity<ClientState>,
    ) -> Self {
        let input = cx.new(|cx| InputState::new(window, cx).default_value(cur_name.clone()));

        let submit_sub = cx.subscribe_in(&input, window, |view, _state, event, window, cx| {
            if let InputEvent::PressEnter { secondary } = event {
                // FIXME: never comes up
                tracing::info!("Enter {secondary}");
                view.submit(window, cx);
            }
        });
        let s = Self {
            group,
            cur_name,
            client_state,
            input,
            _submit_sub: submit_sub,
        };
        s._show(window, cx);
        s
    }

    fn submit(&self, window: &mut Window, cx: &mut Context<Self>) {
        let value = cx.read_entity(&self.input, |e: &InputState, _cx| e.value());
        if value.is_empty() {
            window.push_notification(
                (
                    NotificationType::Warning,
                    SharedString::new(format!("Name cannot be empty")),
                ),
                cx,
            );
            return;
        }
        println!("submitting {}", value);
        window.close_modal(cx);
        if value == self.cur_name {
            // nothing to be done
            return;
        }
        // Handle the event here

        let ClientState::Zoe(client) = self.client_state.read(cx) else {
            window.push_notification((NotificationType::Error, "Zoe client not found"), cx);
            return;
        };
        let group_id = self.group.clone();

        let zoe = client.clone();
        window
            .spawn(cx, async move |w| {
                if let Err(err) = match zoe
                    .update_group(&group_id, vec![GroupInfoUpdate::Name(value.into())])
                    .await
                {
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

    fn _show(&self, window: &mut Window, cx: &mut Context<Self>) {
        let entity = cx.entity();
        let this = entity.downgrade();
        let input = self.input.clone();

        window.open_modal(cx, move |modal, _, _| {
            modal
                .title("Edit Sheet Name")
                .child(entity.clone()) // we keep it around for as long as the modal is open
                .child(
                    v_flex()
                        .gap_3()
                        .child("What should the name be?")
                        .child(TextInput::new(&input).cleanable()),
                )
                .footer({
                    let this = this.clone();
                    move |_, _, _, _| {
                        let this = this.clone();
                        vec![
                            Button::new("ok").primary().label("Submit").on_click(
                                move |_, window, cx| {
                                    if let Err(err) = this
                                        .update(cx, |me: &mut EditName, cx| me.submit(window, cx))
                                    {
                                        tracing::error!(?err, "already gone");
                                    };
                                },
                            ),
                            Button::new("cancel")
                                .label("Cancel")
                                .on_click(|_, window, cx| {
                                    window.close_modal(cx);
                                }),
                        ]
                    }
                })
        });
    }
}

impl Render for EditName {
    fn render(&mut self, _win: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div() // we render as nothing, but need to render to stay around within the modal
    }
}

pub struct SheetPage {
    client_state: Entity<ClientState>,
    groups: Entity<Groups>,
}

impl SheetPage {
    pub fn new(
        window: &mut Window,
        cx: &mut Context<Self>,
        client_state: Entity<ClientState>,
        entity: Entity<Groups>,
    ) -> Self {
        Self {
            client_state,
            groups: entity,
        }
    }

    fn render_error(
        &mut self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
        error: String,
    ) -> Div {
        div().size_full().child(error)
    }

    fn render_title(
        &mut self,
        _window: &mut Window,
        cx: &mut Context<Self>,
        group: Arc<SimpleGroupView>,
    ) -> Stateful<Div> {
        let name = group.name.clone();
        let group_id = group.group_id.clone();

        let d = div()
            .id("edit-sheet-name")
            .child(SharedString::new(name.clone()));
        if group.can_i(GroupAction::UpdateGroup) {
            d.cursor_pointer()
                .hoverable_tooltip(move |_w, ctx| {
                    ctx.new(|_| SimplePopover::new("Click to edit".into()))
                        .into()
                })
                .on_click(cx.listener(move |this, _, win, cx| {
                    cx.new(|cx| {
                        EditName::show(
                            win,
                            cx,
                            group_id.clone(),
                            name.clone(),
                            this.client_state.clone(),
                        )
                    });
                }))
        } else {
            d
        }
    }
}

impl Render for SheetPage {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let params = use_params(cx);
        let id = match GroupId::from_hex(&params["id"]) {
            Ok(id) => id,
            Err(error) => return self.render_error(window, cx, error.to_string()),
        };
        let Some(group) = cx.read_entity(&self.groups, |groups, _app| groups.get(id)) else {
            return self.render_error(window, cx, "Group not found".to_string());
        };

        div().size_full().flex().flex_row().justify_center().child(
            GroupBox::new()
                .outline()
                .rounded_xl()
                .p_10()
                .child(v_flex().child(self.render_title(window, cx, group))),
        )
    }
}
