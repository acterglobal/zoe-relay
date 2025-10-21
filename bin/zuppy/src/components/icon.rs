use gpui::{AnyElement, App, Entity, IntoElement, RenderOnce, SharedString, Window};
use gpui_component::Icon;

#[derive(IntoElement, Clone)]
pub enum IconName {
    Menu,
    NetworkAlert,
    NetworkWorking,
    NetworkBroken,
    NetworkSynced,
}

impl IconName {
    pub fn path(self) -> SharedString {
        match self {
            Self::Menu => "icons/menu.svg",
            Self::NetworkBroken => "icons/network-broken.svg",
            Self::NetworkAlert => "icons/network-alert.svg",
            Self::NetworkWorking => "icons/network-cog.svg",
            Self::NetworkSynced => "icons/network-synced.svg",
        }
        .into()
    }

    /// Return the icon as a Entity<Icon>
    pub fn view(self, cx: &mut App) -> Entity<Icon> {
        Self::build(self).view(cx)
    }

    fn build(self) -> Icon {
        Icon::default().path(self.path())
    }
}

impl From<IconName> for Icon {
    fn from(val: IconName) -> Self {
        IconName::build(val)
    }
}

impl From<IconName> for AnyElement {
    fn from(val: IconName) -> Self {
        IconName::build(val).into_any_element()
    }
}

impl RenderOnce for IconName {
    fn render(self, _: &mut Window, _cx: &mut App) -> impl IntoElement {
        Self::build(self)
    }
}
