use gtk4::prelude::*;
use gtk4::{Label, Window};

/// Диалог мастера: выбор адреса/порта и запуск подключения.
pub struct ConnectionDialog {
    pub window: Window,
    pub host_entry: gtk4::Entry,
    pub port_entry: gtk4::Entry,
    pub status: Label,
}

impl ConnectionDialog {
    pub fn new() -> Self {
        let window = Window::builder()
            .title("Подключение")
            .default_width(420)
            .default_height(220)
            .modal(true)
            .hide_on_close(true)
            .build();

        let host_entry = gtk4::Entry::new();
        host_entry.set_placeholder_text(Some("Хост (IP или домен)"));
        let port_entry = gtk4::Entry::new();
        port_entry.set_text("22");
        let status = Label::new(None);

        Self { window, host_entry, port_entry, status }
    }

    pub fn present_transient_for(&self, parent: Option<&Window>) {
        self.window.set_transient_for(parent);
        self.window.present();
    }
}
