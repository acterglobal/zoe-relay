use gpui::*;
use zuppy::ZuppyRoot;

fn main() {
    let app = Application::new();

    app.run(|cx: &mut App| {
        cx.open_window(WindowOptions::default(), |_, cx| {
            cx.new(|cx| ZuppyRoot::new(cx))
        })
        .unwrap();
    });
}
