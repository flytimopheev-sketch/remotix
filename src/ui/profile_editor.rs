//! Диалог создания и редактирования профиля подключения.
//!
//! Окно редактора должно жить дольше, чем вызов `present()`: GTK уничтожает
//! объект, когда исчезает последняя ссылка на него из Rust, поэтому открытые
//! редакторы хранятся в списке (GUI работает в одном потоке).

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    Adjustment, Button, DropDown, Entry, Grid, Image, Label, PasswordEntry, SpinButton, StringList,
    Switch, Window,
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
    /// `on_saved` вызывается после успешного сохранения профиля,
    /// `on_deleted` — после удаления.
    pub fn new<F, D>(state: &AppState, profile_id: Option<i64>, on_saved: F, on_deleted: D) -> Self
    where
        F: Fn() + 'static,
        D: Fn() + 'static,
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
            .default_width(620)
            .default_height(560)
            .modal(true)
            .build();

        // Диалог оформляется так же, как основное окно.
        let settings = crate::settings::Settings::new(state.db.clone());
        crate::ui::theme::apply(&settings.theme(), &window);

        // ---------------- Поля ----------------
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

        // SSH
        let key_path = Entry::new();
        key_path.set_placeholder_text(Some("~/.ssh/id_ed25519"));
        let su_to_root = Switch::new();
        su_to_root.set_active(false);
        let root_password = PasswordEntry::new();
        root_password.set_show_peek_icon(true);

        // RDP
        let domain = Entry::new();
        domain.set_placeholder_text(Some("Домен (необязательно)"));
        let resolution = DropDown::builder()
            .model(&StringList::new(&[
                "1024×768",
                "1280×800",
                "1280×1024",
                "1440×900",
                "1600×900",
                "1920×1080",
            ]))
            .selected(0)
            .build();

        // Значения по умолчанию берём из настроек приложения.
        let settings = crate::settings::Settings::new(state.db.clone());
        let default_resolution = settings.rdp_resolution();
        let nla_default = settings.rdp_nla();

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
            if let Some(k) = p.ssh_key_path.as_ref() {
                key_path.set_text(k);
            }
            su_to_root.set_active(p.ssh_options.su_to_root);
            if let Some(rp) = p.root_password.as_ref() {
                root_password.set_text(rp);
            }
            if !p.rdp_options.domain.is_empty() {
                domain.set_text(&p.rdp_options.domain);
            }
            let idx = match (p.rdp_options.width, p.rdp_options.height) {
                (1280, 800) => 1,
                (1280, 1024) => 2,
                (1440, 900) => 3,
                (1600, 900) => 4,
                (1920, 1080) => 5,
                _ => 0,
            };
            resolution.set_selected(idx);
        } else {
            port.set_value(f64::from(Protocol::Ssh.default_port()));
            // Разрешение экрана по умолчанию — из настроек приложения.
            let idx = match default_resolution.as_str() {
                "1280x800" => 1,
                "1280x1024" => 2,
                "1440x900" => 3,
                "1600x900" => 4,
                "1920x1080" => 5,
                _ => 0,
            };
            resolution.set_selected(idx);
        }

        // ---------------- Сетка полей ----------------
        let grid = Grid::new();
        grid.set_row_spacing(8);
        grid.set_column_spacing(12);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            grid.set_property(m, 16);
        }

        add_field(&grid, 0, "Название:", &name);
        add_field(&grid, 1, "Протокол:", &protocol);
        add_field(&grid, 2, "Адрес:", &host);
        add_field(&grid, 3, "Порт:", &port);
        add_field(&grid, 4, "Пользователь:", &user);
        add_field(&grid, 5, "Пароль:", &password);
        add_field(&grid, 6, "SSH-ключ:", &key_path);
        add_field(&grid, 7, "Вход в root (su -):", &su_to_root);
        add_field(&grid, 8, "Пароль root:", &root_password);
        add_field(&grid, 9, "Домен (RDP):", &domain);
        add_field(&grid, 10, "Разрешение (RDP):", &resolution);

        // ---------------- Шапка и подвал ----------------
        let icon = Image::from_icon_name("preferences-system-remote-symbolic");
        let heading = Label::new(Some(match profile_id {
            Some(_) => "Свойства подключения",
            None => "Новое подключение",
        }));
        heading.add_css_class("remotix-dialog-header");

        let header = gtk4::Box::new(gtk4::Orientation::Horizontal, 10);
        header.append(&icon);
        header.append(&heading);

        let status = Label::new(None);
        status.set_wrap(true);
        status.set_xalign(0.0);
        status.set_hexpand(true);

        let save = Button::with_label("Сохранить");
        save.add_css_class("suggested-action");
        let cancel = Button::with_label("Отмена");
        let remove = Button::with_label("Удалить профиль");
        remove.add_css_class("destructive-action");
        remove.set_visible(profile_id.is_some());

        let footer = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        footer.append(&remove);
        footer.append(&status);
        footer.append(&cancel);
        footer.append(&save);

        let ui = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        ui.append(&header);
        ui.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        ui.append(&grid);
        ui.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));
        ui.append(&footer);
        window.set_child(Some(&ui));

        // Показываем только поля выбранного протокола.
        let update_visibility: Rc<dyn Fn(u32)> = {
            let key_path = key_path.clone();
            let su_to_root = su_to_root.clone();
            let root_password = root_password.clone();
            let domain = domain.clone();
            let resolution = resolution.clone();
            let port = port.clone();
            Rc::new(move |protocol_index: u32| {
                let is_ssh = protocol_index == 0;
                let is_rdp = protocol_index == 1;
                key_path.set_visible(is_ssh);
                su_to_root.set_visible(is_ssh);
                root_password.set_visible(is_ssh && su_to_root.is_active());
                domain.set_visible(is_rdp);
                resolution.set_visible(is_rdp);
                port.set_value(f64::from(match protocol_index {
                    1 => Protocol::Rdp.default_port(),
                    2 => Protocol::Vnc.default_port(),
                    _ => Protocol::Ssh.default_port(),
                }));
            })
        };

        {
            // Начальное состояние видимости.
            update_visibility(protocol.selected());

            let on_protocol = update_visibility.clone();
            protocol.connect_selected_notify(move |protocol| {
                on_protocol(protocol.selected());
            });

            let su_to_root = su_to_root.clone();
            let root_password = root_password.clone();
            su_to_root.connect_active_notify(move |switch| {
                root_password.set_visible(switch.is_active());
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
            let key_path = key_path.clone();
            let su_to_root = su_to_root.clone();
            let root_password = root_password.clone();
            let domain = domain.clone();
            let resolution = resolution.clone();
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
                let (width, height) = match resolution.selected() {
                    1 => (1280, 800),
                    2 => (1280, 1024),
                    3 => (1440, 900),
                    4 => (1600, 900),
                    5 => (1920, 1080),
                    _ => (1024, 768),
                };

                let mut profile = NewProfile {
                    name: name.text().trim().to_string(),
                    protocol: Some(protocol),
                    host: host.clone(),
                    port: port.value() as u16,
                    username: Some(user.text().trim().to_string()).filter(|s| !s.is_empty()),
                    password: Some(password.text().to_string()).filter(|s| !s.is_empty()),
                    ssh_key_path: Some(key_path.text().trim().to_string())
                        .filter(|s| !s.is_empty()),
                    root_password: Some(root_password.text().to_string())
                        .filter(|s| !s.is_empty()),
                    ..Default::default()
                };
                if profile.name.is_empty() {
                    profile.name = profile.host.clone();
                }

                let mut options = crate::models::profile::SshOptions::default();
                options.su_to_root = su_to_root.is_active();
                profile.ssh_options = options;

                let mut rdp = crate::models::profile::RdpOptions::default();
                rdp.width = width;
                rdp.height = height;
                rdp.domain = domain.text().trim().to_string();
                rdp.nla = nla_default;
                profile.rdp_options = rdp;

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

        // Удаление профиля — с подтверждением.
        {
            let remove = remove.clone();
            let window = window.clone();
            let db = state.db.clone();
            let on_deleted = Rc::new(on_deleted);
            remove.connect_clicked(move |_| {
                let Some(id) = profile_id else { return };
                let db = db.clone();

                let confirm = gtk4::MessageDialog::builder()
                    .transient_for(&window)
                    .modal(true)
                    .message_type(gtk4::MessageType::Warning)
                    .buttons(gtk4::ButtonsType::None)
                    .text("Удалить профиль?")
                    .secondary_text("Профиль и его настройки будут удалены безвозвратно.")
                    .build();
                confirm.add_button("Удалить", gtk4::ResponseType::Accept);
                confirm.add_button("Отмена", gtk4::ResponseType::Cancel);

                let on_deleted = on_deleted.clone();
                let window = window.clone();
                confirm.connect_response(move |dialog, response| {
                    if response == gtk4::ResponseType::Accept {
                        let db = db.clone();
                        match db.delete_profile(id) {
                            Ok(n) if n > 0 => {
                                on_deleted();
                                window.close();
                            }
                            _ => {}
                        }
                    }
                    dialog.destroy();
                });

                confirm.present();
            });
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
    label.add_css_class("remotix-field-caption");
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(widget, 1, row, 1, 1);
}
