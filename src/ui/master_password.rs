//! Диалог мастер-пароля.
//!
//! Диалог привязан к `Application` (`ApplicationWindow`), поэтому приложение
//! не завершается, пока пользователь не введёт мастер-пароль. Раньше диалог
//! был обычным `Window` без привязки к приложению и без обработчика кнопки:
//! графический интерфейс не появлялся вовсе, а процесс завершался сразу
//! после запуска.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Button, Label, PasswordEntry};
use zeroize::Zeroize;

use crate::db::repository::Database;

/// Диалог мастер-пароля:
///  - первый запуск: создание + подтверждение;
///  - последующие: ввод пароля (в т.ч. для разблокировки окна по Ctrl+L).
pub struct MasterPasswordDialog {
    window: ApplicationWindow,
}

impl MasterPasswordDialog {
    /// Создаёт диалог и показывает его.
    ///
    /// `on_unlocked` вызывается с базой данных и ключом шифрования после
    /// успешной разблокировки хранилища.
    ///
    /// Если задана переменная окружения `REMOTIX_MASTER_PASSWORD`, диалог не
    /// показывается: мастер-пароль берётся из окружения (сценарии CI и
    /// автоматических проверок).
    pub fn new<F>(app: &Application, db: Rc<Database>, on_unlocked: F) -> Self
    where
        F: FnOnce(Rc<Database>, [u8; 32]) + 'static,
    {
        let callback: Rc<RefCell<Option<F>>> = Rc::new(RefCell::new(Some(on_unlocked)));
        let first_run = db.meta_get("argon2_salt").is_none();

        let window = ApplicationWindow::builder()
            .application(app)
            .title(if first_run {
                "Remotix — создание мастер-пароля"
            } else {
                "Remotix — введите мастер-пароль"
            })
            .default_width(420)
            .default_height(240)
            .modal(true)
            .resizable(false)
            .build();

        let password = PasswordEntry::new();
        password.set_show_peek_icon(true);
        let confirm = PasswordEntry::new();
        confirm.set_show_peek_icon(true);
        let status = Label::new(None);
        status.set_wrap(true);
        status.set_xalign(0.0);

        let ui = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            ui.set_property(m, 16);
        }

        // Шапка: значок + заголовок.
        let icon = gtk4::Image::from_icon_name("dialog-password-symbolic");
        let heading = gtk4::Label::new(Some(if first_run {
            "Создание мастер-пароля"
        } else {
            "Разблокировка хранилища"
        }));
        heading.add_css_class("remotix-dialog-header");

        let header = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
        header.append(&icon);
        header.append(&heading);
        ui.append(&header);
        ui.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));

        if first_run {
            ui.append(&gtk4::Label::new(Some(
                "Придумайте мастер-пароль: он шифрует учётные данные подключений.",
            )));
            ui.append(&password);
            ui.append(&gtk4::Label::new(Some("Подтвердите:")));
            ui.append(&confirm);
        } else {
            ui.append(&gtk4::Label::new(Some("Введите мастер-пароль:")));
            ui.append(&password);
        }

        let note = gtk4::Label::new(Some(
            "Мастер-пароль не сохраняется — его нельзя восстановить. Храните его \
             в менеджере паролей.",
        ));
        note.set_wrap(true);
        note.set_xalign(0.0);
        note.add_css_class("remotix-field-caption");
        ui.append(&note);

        let btn = Button::with_label(if first_run {
            "Создать"
        } else {
            "Разблокировать"
        });
        btn.add_css_class("suggested-action");
        btn.set_halign(gtk4::Align::End);
        ui.append(&btn);
        ui.append(&status);
        window.set_child(Some(&ui));

        let dialog = Self {
            window: window.clone(),
        };

        // Общая логика разблокировки: используется и кнопкой, и Enter.
        let do_unlock: Rc<dyn Fn()> = {
            let callback = callback.clone();
            let db = db.clone();
            let window = window.clone();
            let password = password.clone();
            let confirm = confirm.clone();
            let status = status.clone();

            Rc::new(move || {
                let mut entered = password.text().to_string();

                if db.meta_get("argon2_salt").is_none()
                    && entered.as_str() != confirm.text().as_str()
                {
                    entered.zeroize();
                    status.set_text("Пароли не совпадают");
                    return;
                }

                match unlock_with_password(&db, &entered) {
                    Ok(key) => {
                        entered.zeroize();
                        password.set_text("");
                        confirm.set_text("");
                        let cb = callback.borrow_mut().take();
                        if let Some(cb) = cb {
                            cb(db.clone(), key);
                        }
                        window.destroy();
                    }
                    Err(e) => {
                        entered.zeroize();
                        status.set_text(&e);
                    }
                }
            })
        };

        // Автоматический сценарий без графического интерфейса.
        if let Ok(mut master) = std::env::var("REMOTIX_MASTER_PASSWORD") {
            let unlocked = unlock_with_password(&db, &master);
            master.zeroize();
            // Переменная окружения — тоже секрет; после первого чтения она
            // больше не нужна (например, при перезапуске по Ctrl+L).
            std::env::remove_var("REMOTIX_MASTER_PASSWORD");
            if let Ok(key) = unlocked {
                let cb = callback.borrow_mut().take();
                if let Some(cb) = cb {
                    cb(db.clone(), key);
                }
                // Окно не показываем, но уничтожаем: иначе приложение будет
                // считать, что у него есть окно, и не завершится.
                window.destroy();
                return dialog;
            }
        }

        btn.connect_clicked({
            let do_unlock = do_unlock.clone();
            move |_| do_unlock()
        });

        // Enter в поле пароля — то же, что нажатие кнопки.
        password.connect_activate({
            let do_unlock = do_unlock.clone();
            move |_| do_unlock()
        });

        window.present();
        dialog
    }

    /// Окно диалога (для привязки transient-for и тестирования).
    pub fn window(&self) -> &ApplicationWindow {
        &self.window
    }
}

/// Создаёт мастер-пароль (при первом запуске) либо проверяет уже созданный.
/// Возвращает ключ шифрования хранилища.
fn unlock_with_password(db: &Database, password: &str) -> Result<[u8; 32], String> {
    if db.meta_get("argon2_salt").is_none() {
        db.init_master(password)?;
    }
    db.unlock(password)
}
