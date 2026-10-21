//! Отладочная утилита: печатает нажатые клавиши и их аппаратные коды.
//!
//! Нужна, чтобы проверить соответствие кодов GDK и X11-сканкодов, которые
//! отправляются в RDP-сессию (см. `src/ui/rdp_viewer.rs`).
//!
//! Запуск:
//! ```bash
//! cargo run --example keyprobe
//! ```

use gtk4::prelude::*;

fn main() {
    let app = gtk4::Application::builder()
        .application_id("ru.redos.RemotixKeyProbe")
        .build();

    app.connect_activate(|app| {
        let window = gtk4::ApplicationWindow::builder()
            .application(app)
            .title("Remotix keyprobe — нажмите клавиши")
            .default_width(520)
            .default_height(280)
            .build();

        let output = gtk4::Label::new(Some("Нажимайте клавиши — коды появятся здесь"));
        output.set_xalign(0.0);
        output.set_wrap(true);
        output.set_margin_top(12);
        output.set_margin_start(12);
        output.set_margin_end(12);

        let controller = gtk4::EventControllerKey::new();
        controller.connect_key_pressed({
            let output = output.clone();
            move |_, key, keycode, state| {
                let line = format!(
                    "key={} keycode={} (сканкод {}) state={:?}",
                    key.name().unwrap_or_default(),
                    keycode,
                    keycode.saturating_sub(8),
                    state
                );
                eprintln!("PROBE {line}");
                let text = format!("{line}\n{}", output.text());
                output.set_text(&text);
                gtk4::glib::Propagation::Proceed
            }
        });
        window.add_controller(controller);

        window.set_child(Some(&output));
        window.present();
    });

    let _ = app.run();
}
