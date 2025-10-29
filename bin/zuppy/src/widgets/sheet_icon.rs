use gpui::{
    App, Div, ElementId, InteractiveElement, Interactivity, IntoElement, ParentElement, RenderOnce,
    SharedString, StyleRefinement, Styled, Window, div,
};
use zoe_app_primitives::icon::Icon;

#[derive(IntoElement)]
pub struct SheetIcon {
    id: ElementId,
    icon: Option<Icon>,
    style: StyleRefinement,
    interactivity: Interactivity,
}

impl SheetIcon {
    pub fn new(id: impl Into<ElementId>, icon: Option<Icon>) -> Self {
        SheetIcon {
            icon,
            id: id.into(),
            style: StyleRefinement::default(),
            interactivity: Interactivity::default(),
        }
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
        let Some(icon) = &self.icon else { return div() };
        if let Icon::Emoji(emoji) = icon {
            div().child(SharedString::from(emoji))
        } else {
            div().child(SharedString::from("❓"))
        }
    }
}

impl RenderOnce for SheetIcon {
    fn render(self, _: &mut Window, _cx: &mut App) -> impl IntoElement {
        let icon = self.render_inner().id(self.id);
        icon
    }
}
