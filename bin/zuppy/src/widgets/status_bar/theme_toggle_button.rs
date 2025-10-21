use gpui::{Context, IntoElement, Render, Window};

use gpui_component::{ActiveTheme, Side, Theme, ThemeMode, switch::Switch};

pub struct ThemeToggleButton {}

impl ThemeToggleButton {
    pub fn new(_cx: &mut Context<Self>) -> Self {
        Self {}
    }
}
impl Render for ThemeToggleButton {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();

        Switch::new("dark-mode-toggle")
            .label(if !theme.is_dark() { "Dark" } else { "Light " })
            .label_side(Side::Left)
            .checked(theme.is_dark())
            .on_click(|checked, w, cx| {
                tracing::info!("toggle dark mode");
                Theme::change(
                    if *checked {
                        ThemeMode::Dark
                    } else {
                        ThemeMode::Light
                    },
                    Some(w),
                    cx,
                )
            })
    }
}
