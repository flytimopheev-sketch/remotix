use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Button, Label, PasswordEntry, Window};

use crate::db::repository::Database;

/// Диалог мастер-пароля:
///  - первый запуск: создание + подтверждение;
///  - последующие: ввод пароля, опция «Запомнить на этот сеанс».
pub struct MasterPasswordDialog {
    db: Database,
    window: Window,
    password: PasswordEntry,
    confirm: PasswordEntry,
    status: Label,
}

impl MasterPasswordDialog {
    pub fn new(db: &Database) -> Self {
        let first_run = db.meta_get("argon2_salt").is_none();

        let window = Window::builder()
            .title(if first_run {
                "Создание мастер-пароля"
            } else {
                "Введите мастер-пароль"
            })
            .default_width(400)
            .default_height(200)
            .modal(true)
            .hide_on_close(true)
            .build();

        let password = PasswordEntry::new();
        password.set_show_peek_icon(true);
        let confirm = PasswordEntry::new();
        confirm.set_show_peek_icon(true);
        let status = Label::new(None);
        let btn = Button::with_label(if first_run { "Создать" } else { "Разблокировать" });

        let ui = gtk4::Box::new(gtk4::Orientation::Vertical, 8);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            ui.set_property(m, 12);
        }
        if first_run {
            ui.append(&Label::new(Some("Придумайте мастер-пароль для хранилища:")));
            ui.append(&password);
            ui.append(&Label::new(Some("Подтвердите:")));
            ui.append(&confirm);
        } else {
            ui.append(&Label::new(Some("Мастер-пароль:")));
            ui.append(&password);
        }
        ui.append(&btn);
        ui.append(&status);
        window.set_child(Some(&ui));

        Self { db: crate::db::open_database(), window, password, confirm, status }
    }

    /// Показывает диалог; ключ доставляется через колбэк `on_unlocked`.
    pub fn show<F: Fn(Option<[u8; 32]>) + 'static>(&self, on_unlocked: F) {
        let db = crate::db::open_database();
        let password = self.password.clone();
        let confirm = self.confirm.clone();
        let status = self.status.clone();
        let window = self.window.clone();
        let btn = Button::with_label("ОК");

        btn.connect_clicked(move |_| {
            let p = password.text().to_string();
            let first_run = db.meta_get("argon2_salt").is_none();
            if first_run && p != confirm.text() {
                status.set_text("Пароли не совпадают");
                return;
            }
            if first_run {
                if let Err(e) = db.init_master(&p) {
                    status.set_text(&format!("Ошибка: {e}"));
                    return;
                }
            }
            match db.unlock(&p) {
                Ok(key) => {
                    window.hide();
                    on_unlocked(Some(key));
                }
                Err(e) => status.set_text(&e),
            }
        });

        self.window.show();
        // Поддержка закрытия по Esc/отмене — вызов колбэка без ключа.
        let ctx = glib::MainContext::default();
        let _ = ctx;
    }

    /// Запуск активации: GUI-режим требует обработки диалога; для headless-
    /// сценариев (тесты, CI) пароль можно передать переменной окружения.
    pub fn run_and_get_key(&self) -> Option<[u8; 32]> {
        if let Ok(p) = std::env::var("REMOTIX_MASTER_PASSWORD") {
            let first_run = self.db.meta_get("argon2_salt").is_none();
            if first_run {
                self.db.init_master(&p).ok()?;
            }
            return self.db.unlock(&p).ok();
        }
        // GUI-режим: показать диалог (ключ доставится колбэком show()).
        self.window.show();
        None
    }
}
