use gpui::*;
use zuppy::HelloWorld;

fn main() {
    Application::new().run(|cx: &mut App| {
        cx.open_window(WindowOptions::default(), |_, cx| {
            cx.new(|_cx| HelloWorld::new("Zoe".into()))
        })
        .unwrap();
    });
}
