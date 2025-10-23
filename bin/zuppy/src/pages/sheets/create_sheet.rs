use gpui::{
    AppContext, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled, Window,
    div,
};
use gpui_component::{
    ContextModal, Sizable,
    button::{Button, ButtonVariants},
    form::{form_field, v_form},
    group_box::GroupBox,
    input::{InputState, TextInput},
    notification::NotificationType,
};
use zoe_state_machine::group::CreateGroupBuilder;

use crate::models::{client_state::ClientState, routes::Routes};

pub struct CreateSheetPage {
    client_state: Entity<ClientState>,
    name: Entity<InputState>,
}

impl CreateSheetPage {
    pub fn new(
        win: &mut Window,
        cx: &mut Context<Self>,
        client_state: Entity<ClientState>,
    ) -> Self {
        Self {
            client_state,
            name: cx
                .new(|cx| InputState::new(win, cx).placeholder("e.g. Party Planning, Family Info")),
        }
    }

    fn submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = self.name.read(cx).value();

        // Validate inputs
        if name.is_empty() {
            window.push_notification(
                (NotificationType::Warning, "Sheet name cannot be empty"),
                cx,
            );
            // Show validation error
            return;
        }

        let ClientState::Zoe(client) = self.client_state.read(cx) else {
            window.push_notification((NotificationType::Error, "Zoe client not found"), cx);
            return;
        };

        let zoe = client.clone();
        let create_group_b = CreateGroupBuilder::default().name(name.into());
        window
            .spawn(cx, async move |w| {
                if let Err(err) = match zoe.create_group(create_group_b).await {
                    Err(e) => w.update(|window, cx| {
                        window.push_notification(
                            (
                                NotificationType::Error,
                                SharedString::new(format!("Failed to create group: {}", e)),
                            ),
                            cx,
                        );
                    }),
                    Ok(res) => w.update(|window, cx| {
                        window.push_notification(
                            (NotificationType::Success, "Sheet created successfully"),
                            cx,
                        );
                        Routes::Sheet.route_sub(window, cx, Some(res.group_id.to_hex()));
                    }),
                } {
                    tracing::error!(?err, "failed to show push");
                };
            })
            .detach();
    }
}

impl Render for CreateSheetPage {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div().size_full().p_10().child(
            GroupBox::new().outline().title("Create Sheet").child(
                v_form()
                    .large()
                    .child(
                        form_field()
                            .label("Name")
                            .required(true)
                            .child(TextInput::new(&self.name)),
                    )
                    .child(
                        form_field().no_label_indent().child(
                            Button::new("submit")
                                .primary()
                                .child("Submit")
                                .on_click(cx.listener(|this, _, win, cx| this.submit(win, cx))),
                        ),
                    ),
            ),
        )
    }
}
