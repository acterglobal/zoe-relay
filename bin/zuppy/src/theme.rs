use gpui::{App, Global, Hsla};

pub struct Theme {
    background_color: Hsla,
    text_color: Hsla,
    is_dark: bool,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    pub fn background(&self) -> Hsla {
        self.background_color
    }

    pub fn text(&self) -> Hsla {
        self.text_color
    }

    pub fn text_inverse(&self) -> Hsla {
        self.background_color
    }

    pub fn background_inverse(&self) -> Hsla {
        self.text_color
    }

    pub fn border(&self) -> Hsla {
        self.text_color.alpha(0.1)
    }

    pub fn is_dark(&self) -> bool {
        self.is_dark
    }

    pub fn toggle_darkness(&self) -> Self {
        if self.is_dark {
            Self::light()
        } else {
            Self::dark()
        }
    }
}

impl Theme {
    pub fn dark() -> Self {
        Self {
            background_color: Hsla {
                h: 0.1,
                s: 0.1,
                l: 0.1,
                a: 1.0,
            },
            text_color: Hsla {
                h: 1.0,
                s: 0.0,
                l: 1.0,
                a: 1.0,
            },
            is_dark: true,
        }
    }

    pub fn light() -> Self {
        Self {
            background_color: Hsla {
                h: 1.0,
                s: 0.0,
                l: 1.0,
                a: 1.0,
            },
            text_color: Hsla {
                h: 0.0,
                s: 0.0,
                l: 0.0,
                a: 1.0,
            },
            is_dark: false,
        }
    }
}

impl Global for Theme {}

pub fn init(cx: &mut App) {
    let theme = Theme::dark();
    cx.set_global(theme);
}
