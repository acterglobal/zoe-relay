use std::rc::Rc;

use gpui::{
    App, AppContext, Context, Entity, IntoElement, ParentElement, Render, SharedString, Styled,
    Window, div,
};
use gpui_component::{
    ContextModal,
    button::{Button, ButtonVariants},
    input::{InputState, TextInput},
    notification::NotificationType,
    v_flex,
};

pub struct EditModal {
    title: SharedString,
    label: Option<SharedString>,
    placeholder: Option<SharedString>,
    current_value: Option<SharedString>,
    allow_empty: bool,
}

impl EditModal {
    pub fn default() -> Self {
        Self {
            title: "Edit".into(),
            label: None,
            placeholder: None,
            current_value: None,
            allow_empty: false,
        }
    }
    pub fn title<T: Into<SharedString>>(mut self, title: T) -> Self {
        self.title = title.into();
        self
    }
    pub fn label<T: Into<SharedString>>(mut self, label: T) -> Self {
        self.label = Some(label.into());
        self
    }
    pub fn placeholder<T: Into<SharedString>>(mut self, placeholder: T) -> Self {
        self.placeholder = Some(placeholder.into());
        self
    }
    pub fn current_value<T: Into<SharedString>>(mut self, current_value: T) -> Self {
        self.current_value = Some(current_value.into());
        self
    }
    pub fn allow_empty(mut self, allow_empty: bool) -> Self {
        self.allow_empty = allow_empty;
        self
    }

    pub fn show(
        self,
        window: &mut Window,
        cx: &mut App,
        on_submit: impl Fn(SharedString, &mut Window, &mut App) + 'static,
    ) {
        let _ = cx.new(|cx| EditModalImpl::show(self, window, cx, Rc::new(on_submit)));
    }
}

struct EditModalImpl {
    options: EditModal,
    input: Entity<InputState>,
    on_submit: Rc<dyn Fn(SharedString, &mut Window, &mut App) + 'static>,
}

impl EditModalImpl {
    fn show(
        options: EditModal,
        window: &mut Window,
        cx: &mut Context<Self>,
        on_submit: Rc<dyn Fn(SharedString, &mut Window, &mut App) + 'static>,
    ) -> Self {
        let input = cx.new(|cx| {
            let mut s = InputState::new(window, cx);
            s = match &options.current_value {
                Some(current_value) => s.default_value(current_value),
                None => s,
            };
            s = match &options.placeholder {
                Some(placeholder) => s.placeholder(placeholder),
                None => s,
            };
            s
        });

        let s = Self {
            options,
            input,
            on_submit,
        };
        s._show(window, cx);
        s
    }

    fn submit(&self, window: &mut Window, cx: &mut Context<Self>) {
        let value = cx.read_entity(&self.input, |e: &InputState, _cx| e.value());
        if !self.options.allow_empty && value.is_empty() {
            window.push_notification(
                (
                    NotificationType::Warning,
                    SharedString::new("Cannot be empty"),
                ),
                cx,
            );
            return;
        }
        window.close_modal(cx);
        if let Some(current_value) = &self.options.current_value {
            if &value == current_value {
                // nothing to be done
                return;
            }
        }
        (&self.on_submit)(value, window, cx);
    }

    fn _show(&self, window: &mut Window, cx: &mut Context<Self>) {
        let entity = cx.entity();
        let this = entity.downgrade();
        let input = self.input.clone();
        let title = self.options.title.clone();

        window.open_modal(cx, move |modal, _, _| {
            modal
                .title(title.clone())
                .child(entity.clone()) // we keep it around for as long as the modal is open
                .child(
                    v_flex()
                        .gap_3()
                        .child("What should the name be?")
                        .child(TextInput::new(&input).cleanable()),
                )
                .footer({
                    let this = this.clone();
                    move |_, _, _, _| -> Vec<Button> {
                        let this = this.clone();
                        vec![
                            Button::new("ok").primary().label("Submit").on_click(
                                move |_, window, cx| {
                                    if let Err(err) = this
                                        .update(cx, |me: &mut EditModalImpl, cx| {
                                            me.submit(window, cx)
                                        })
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

impl Render for EditModalImpl {
    fn render(&mut self, _win: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        div() // we render as nothing, but need to render to stay around within the modal
    }
}
