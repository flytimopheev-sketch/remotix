//! Диалог создания и редактирования профиля подключения.
//!
//! Окно редактора должно жить дольше, чем вызов `present()`: GTK уничтожает
//! объект, когда исчезает последняя ссылка на него из Rust, поэтому открытые
//! редакторы хранятся в списке (GUI работает в одном потоке).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    Adjustment, Button, DropDown, Entry, Grid, Label, PasswordEntry, SpinButton, StringList, Window,
};

use crate::app::AppState;
use crate::models::{NewProfile, Protocol};

thread_local! {
    /// Открытые редакторы профилей.
    static OPEN_EDITORS: RefCell<Vec<ProfileEditor>> = const { RefCell::new(Vec::new()) };
}

/// Диалог свойств/редактирования профиля подключения.
#[derive(Clone)]
pub struct ProfileEditor {
    window: Window,
    alive: Rc<Cell<bool>>,
}

impl ProfileEditor {
    /// Создаёт диалог редактора профиля.
    ///
    /// `on_saved` вызывается после успешного сохранения профиля.
    pub fn new<F>(state: &AppState, profile_id: Option<i64>, on_saved: F) -> Self
    where
        F: Fn() + 'static,
    {
        let key = state.unlocked_key();
        let existing = state
            .db
            .list_profiles(&key)
            .ok()
            .and_then(|all| all.into_iter().find(|p| Some(p.id) == profile_id));

        let window = Window::builder()
            .title(match profile_id {
                Some(_) => "Свойства подключения",
                None => "Новое подключение",
            })
            .default_width(560)
            .default_height(460)
            .modal(true)
            .build();

        // --- поля формы ---
        let name = Entry::new();
        name.set_placeholder_text(Some("Например: Сервер бухгалтерии"));

        let protocol = DropDown::builder()
            .model(&StringList::new(&["SSH", "RDP", "VNC"]))
            .selected(0)
            .build();

        let host = Entry::new();
        host.set_placeholder_text(Some("IP-адрес или имя узла"));

        let port = SpinButton::new(
            Some(&Adjustment::new(22.0, 1.0, 65535.0, 1.0, 10.0, 0.0)),
            1.0,
            0,
        );

        let user = Entry::new();
        user.set_placeholder_text(Some("Логин"));

        let password = PasswordEntry::new();
        password.set_show_peek_icon(true);

        if let Some(p) = existing.as_ref() {
            name.set_text(&p.name);
            protocol.set_selected(match p.protocol {
                Protocol::Ssh => 0,
                Protocol::Rdp => 1,
                Protocol::Vnc => 2,
            });
            host.set_text(&p.host);
            port.set_value(f64::from(p.port));
            if let Some(u) = p.username.as_ref() {
                user.set_text(u);
            }
            if let Some(pw) = p.password.as_ref() {
                password.set_text(pw);
            }
        } else {
            port.set_value(f64::from(Protocol::Ssh.default_port()));
        }

        let grid = Grid::new();
        grid.set_row_spacing(6);
        grid.set_column_spacing(10);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            grid.set_property(m, 12);
        }

        add_field(&grid, 0, "Название:", &name);
        add_field(&grid, 1, "Протокол:", &protocol);
        add_field(&grid, 2, "Адрес:", &host);
        add_field(&grid, 3, "Порт:", &port);
        add_field(&grid, 4, "Пользователь:", &user);
        add_field(&grid, 5, "Пароль:", &password);

        let status = Label::new(None);
        status.set_wrap(true);
        status.set_xalign(0.0);

        let save = Button::with_label("Сохранить");
        let cancel = Button::with_label("Отмена");

        let buttons = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        buttons.set_halign(gtk4::Align::End);
        buttons.append(&cancel);
        buttons.append(&save);

        let ui = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            ui.set_property(m, 12);
        }
        ui.append(&grid);
        ui.append(&status);
        ui.append(&buttons);
        window.set_child(Some(&ui));

        // Порт по умолчанию меняется вместе с протоколом.
        {
            let port = port.clone();
            protocol.connect_selected_notify(move |protocol| {
                let p = match protocol.selected() {
                    0 => Protocol::Ssh,
                    1 => Protocol::Rdp,
                    _ => Protocol::Vnc,
                };
                port.set_value(f64::from(p.default_port()));
            });
        }

        // Сохранение профиля.
        {
            let window = window.clone();
            let status = status.clone();
            let name = name.clone();
            let protocol = protocol.clone();
            let host = host.clone();
            let port = port.clone();
            let user = user.clone();
            let password = password.clone();
            let db = state.db.clone();
            let on_saved = Rc::new(on_saved);

            save.connect_clicked(move |_| {
                let host = host.text().trim().to_string();
                if host.is_empty() {
                    status.set_text("Укажите адрес узла");
                    return;
                }

                let protocol = match protocol.selected() {
                    0 => Protocol::Ssh,
                    1 => Protocol::Rdp,
                    _ => Protocol::Vnc,
                };

                let mut profile = NewProfile {
                    name: name.text().trim().to_string(),
                    protocol: Some(protocol),
                    host: host.clone(),
                    port: port.value() as u16,
                    username: Some(user.text().trim().to_string()).filter(|s| !s.is_empty()),
                    password: Some(password.text().to_string()).filter(|s| !s.is_empty()),
                    ..Default::default()
                };
                if profile.name.is_empty() {
                    profile.name = profile.host.clone();
                }

                let result = match profile_id {
                    Some(id) => db.update_profile(&key, id, &profile),
                    None => db.add_profile(&key, &profile).map(|_| ()),
                };

                match result {
                    Ok(()) => {
                        on_saved();
                        window.close();
                    }
                    Err(e) => status.set_text(&e),
                }
            });
        }

        {
            let window = window.clone();
            cancel.connect_clicked(move |_| window.close());
        }

        // Отслеживаем уничтожение окна, чтобы убирать закрытые редакторы.
        let alive = Rc::new(Cell::new(true));
        {
            let alive = alive.clone();
            window.connect_destroy(move |_| alive.set(false));
        }

        let editor = Self { window, alive };
        OPEN_EDITORS.with(|editors| {
            let mut editors = editors.borrow_mut();
            editors.retain(|e| e.alive.get());
            editors.push(editor.clone());
        });

        editor
    }

    /// Показывает диалог поверх родительского окна.
    pub fn present_transient_for(&self, parent: Option<&Window>) {
        self.window.set_transient_for(parent);
        self.window.present();
    }
}

/// Добавляет на сетку подпись и поле ввода.
fn add_field(grid: &Grid, row: i32, caption: &str, widget: &impl IsA<gtk4::Widget>) {
    let label = Label::new(Some(caption));
    label.set_xalign(0.0);
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(widget, 1, row, 1, 1);
}
