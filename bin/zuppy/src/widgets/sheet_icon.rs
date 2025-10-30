use gpui::{
    App, AppContext, Context, Div, ElementId, InteractiveElement, Interactivity, IntoElement,
    ParentElement, RenderOnce, SharedString, StatefulInteractiveElement, StyleRefinement, Styled,
    Window, div, prelude::FluentBuilder,
};
use zoe_app_primitives::icon::Icon;

use crate::components::edit_modal::EditModal;

use super::simple_popover::SimplePopover;

#[derive(IntoElement)]
pub struct SheetIcon {
    id: ElementId,
    icon: Option<Icon>,
    style: StyleRefinement,
    interactivity: Interactivity,
    editable: bool,
    hide_empty: bool,
}

impl SheetIcon {
    pub fn new(id: impl Into<ElementId>, icon: Option<Icon>) -> Self {
        SheetIcon {
            icon,
            id: id.into(),
            style: StyleRefinement::default(),
            interactivity: Interactivity::default(),
            editable: false,
            hide_empty: false,
        }
    }

    pub fn editable(mut self, editable: bool) -> Self {
        self.editable = editable;
        self
    }

    pub fn hide_empty(mut self, hide_empty: bool) -> Self {
        self.hide_empty = hide_empty;
        self
    }
}

impl Styled for SheetIcon {
    fn style(&mut self) -> &mut StyleRefinement {
        &mut self.style
    }
}

impl InteractiveElement for SheetIcon {
    fn interactivity(&mut self) -> &mut Interactivity {
        &mut self.interactivity
    }
}

impl SheetIcon {
    fn render_inner(&self) -> Div {
        if let Some(Icon::Emoji(emoji)) = &self.icon {
            div().child(SharedString::from(emoji))
        } else if self.hide_empty {
            div()
        } else {
            div().child(SharedString::from("❓"))
        }
    }
}

impl RenderOnce for SheetIcon {
    fn render(self, _: &mut Window, cx: &mut App) -> impl IntoElement {
        self.render_inner()
            .id(self.id)
            .when(self.editable, |inner| {
                inner
                    .cursor_pointer()
                    .hoverable_tooltip(move |_w, ctx| {
                        ctx.new(|_| SimplePopover::new("Click to edit".into()))
                            .into()
                    })
                    .on_click(|_ev, window, cx| {
                        EditModal::default()
                            .title("Edit Emoji Icon".to_owned())
                            .placeholder("Enter new emoji")
                            .show(window, cx, |new_value, win, cx| {
                                println!("Submitted: {new_value}");
                            });
                    })
            })
    }
}
