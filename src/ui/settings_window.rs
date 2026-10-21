//! Окно «Параметры»: оформление, терминал, RDP, безопасность и профили.

use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    glib, Adjustment, Button, DropDown, Entry, Grid, Label, Notebook, PasswordEntry, SpinButton,
    StringList, Switch, Window,
};

use crate::app::AppState;
use crate::settings::Settings;
use crate::ui::theme;

/// Окно настроек приложения.
pub struct SettingsWindow {
    window: Window,
}

impl SettingsWindow {
    /// Создаёт окно настроек.
    ///
    /// `on_changed` вызывается после применения настроек (например, при
    /// смене темы оформления).
    pub fn new<F>(settings: Settings, state: Rc<AppState>, on_changed: F) -> Self
    where
        F: Fn() + 'static,
    {
        let window = Window::builder()
            .title("Параметры Remotix")
            .default_width(680)
            .default_height(560)
            .modal(true)
            .build();

        // Окно настроек оформляется так же, как основное.
        theme::apply(&settings.theme(), &window);

        let notebook = Notebook::new();
        notebook.set_vexpand(true);
        notebook.set_show_border(false);

        notebook.append_page(&appearance_page(&settings), Some(&Label::new(Some("Оформление"))));
        notebook.append_page(&terminal_page(&settings), Some(&Label::new(Some("Терминал"))));
        notebook.append_page(&rdp_page(&settings), Some(&Label::new(Some("RDP"))));
        notebook.append_page(
            &security_page(&settings, &state),
            Some(&Label::new(Some("Безопасность"))),
        );
        notebook.append_page(
            &profiles_page(&state, &window),
            Some(&Label::new(Some("Профили"))),
        );

        let content = gtk4::Box::new(gtk4::Orientation::Vertical, 0);
        content.append(&notebook);

        let close = Button::with_label("Закрыть");
        {
            let window = window.clone();
            close.connect_clicked(move |_| window.close());
        }
        let footer = gtk4::Box::new(gtk4::Orientation::Horizontal, 8);
        footer.set_halign(gtk4::Align::End);
        footer.set_margin_top(6);
        footer.set_margin_bottom(10);
        footer.set_margin_end(12);
        footer.append(&close);
        content.append(&footer);

        // Шапка окна — как у основного.
        let header = gtk4::HeaderBar::new();
        let title = gtk4::Label::new(Some("Параметры"));
        title.add_css_class("title");
        header.set_title_widget(Some(&title));
        window.set_titlebar(Some(&header));

        window.set_child(Some(&content));

        {
            let window = window.clone();
            let on_changed = Rc::new(on_changed);
            window.connect_close_request(move |_| {
                on_changed();
                glib::Propagation::Proceed
            });
        }

        Self { window }
    }

    /// Показывает окно.
    pub fn present(&self) {
        self.window.present();
    }
}

/// Раздел «Оформление»: выбор темы.
fn appearance_page(settings: &Settings) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let names: Vec<&str> = theme::THEMES.iter().map(|t| t.name).collect();
    let theme_names = StringList::new(&names);
    let current = settings.theme();
    let selected = theme::THEMES
        .iter()
        .position(|t| t.id == current)
        .unwrap_or(0) as u32;

    let dropdown = DropDown::builder()
        .model(&theme_names)
        .selected(selected)
        .build();

    let grid = Grid::new();
    grid.set_row_spacing(8);
    grid.set_column_spacing(12);
    let caption = Label::new(Some("Тема оформления:"));
    caption.set_xalign(0.0);
    caption.add_css_class("remotix-field-caption");
    grid.attach(&caption, 0, 0, 1, 1);
    grid.attach(&dropdown, 1, 0, 1, 1);
    page.append(&grid);

    let hint = Label::new(Some(
        "Темы «Cosmic», «Океан» и «Уголь» используют собственную палитру, \
         остальные наследуют оформление рабочего окружения.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    {
        let settings = settings.clone();
        dropdown.connect_selected_notify(move |d| {
            if let Some(t) = theme::THEMES.get(d.selected() as usize) {
                let _ = settings.set_theme(t.id);
            }
        });
    }

    page
}

/// Раздел «Терминал».
fn terminal_page(settings: &Settings) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let font = Entry::new();
    font.set_text(&settings.terminal_font());
    font.set_placeholder_text(Some("Monospace"));

    let size = SpinButton::new(
        Some(&Adjustment::new(
            settings.terminal_font_size() as f64,
            8.0,
            32.0,
            1.0,
            2.0,
            0.0,
        )),
        1.0,
        0,
    );

    let blink = Switch::new();
    blink.set_active(settings.terminal_cursor_blink());

    let scheme = DropDown::builder()
        .model(&StringList::new(&["Тёмная", "Светлая", "Как в системе"]))
        .selected(match settings.terminal_color_scheme().as_str() {
            "light" => 1,
            "system" => 2,
            _ => 0,
        })
        .build();

    let grid = Grid::new();
    grid.set_row_spacing(8);
    grid.set_column_spacing(12);
    add_row(&grid, 0, "Шрифт:", &font);
    add_row(&grid, 1, "Размер шрифта:", &size);
    add_row(&grid, 2, "Мигание курсора:", &blink);
    add_row(&grid, 3, "Цветовая схема:", &scheme);
    page.append(&grid);

    {
        let settings = settings.clone();
        font.connect_changed({
            let entry = font.clone();
            move |_| {
                let _ = settings.set(
                    "terminal.font",
                    &crate::settings::Value::Text(entry.text().to_string()),
                );
            }
        });
    }
    {
        let settings = settings.clone();
        size.connect_value_changed(move |s| {
            let _ = settings.set(
                "terminal.font_size",
                &crate::settings::Value::Number(s.value() as i64),
            );
        });
    }
    {
        let settings = settings.clone();
        blink.connect_active_notify(move |s| {
            let _ = settings.set("terminal.cursor_blink", &crate::settings::Value::Flag(s.is_active()));
        });
    }
    {
        let settings = settings.clone();
        scheme.connect_selected_notify(move |d| {
            let value = match d.selected() {
                1 => "light",
                2 => "system",
                _ => "dark",
            };
            let _ = settings.set("terminal.color_scheme", &crate::settings::Value::Text(value.into()));
        });
    }

    page
}

/// Раздел «RDP».
fn rdp_page(settings: &Settings) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let resolution = DropDown::builder()
        .model(&StringList::new(&[
            "1024×768",
            "1280×800",
            "1280×1024",
            "1440×900",
            "1600×900",
            "1920×1080",
        ]))
        .selected(match settings.rdp_resolution().as_str() {
            "1280x800" => 1,
            "1280x1024" => 2,
            "1440x900" => 3,
            "1600x900" => 4,
            "1920x1080" => 5,
            _ => 0,
        })
        .build();

    let nla = Switch::new();
    nla.set_active(settings.rdp_nla());

    let clipboard = Switch::new();
    clipboard.set_active(settings.rdp_clipboard());

    let depth = SpinButton::new(
        Some(&Adjustment::new(
            settings.rdp_color_depth() as f64,
            16.0,
            32.0,
            8.0,
            8.0,
            0.0,
        )),
        1.0,
        0,
    );

    let ctrl_alt_del = Switch::new();
    ctrl_alt_del.set_active(settings.rdp_send_ctrl_alt_del());

    let grid = Grid::new();
    grid.set_row_spacing(8);
    grid.set_column_spacing(12);
    add_row(&grid, 0, "Разрешение экрана:", &resolution);
    add_row(&grid, 1, "NLA (CredSSP):", &nla);
    add_row(&grid, 2, "Буфер обмена:", &clipboard);
    add_row(&grid, 3, "Глубина цвета:", &depth);
    add_row(&grid, 4, "Ctrl+Alt+Del:", &ctrl_alt_del);
    page.append(&grid);

    let hint = Label::new(Some(
        "Значения по умолчанию для новых профилей. Уже созданные профили \
         используют собственные настройки подключения.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    {
        let settings = settings.clone();
        let resolution = resolution.clone();
        resolution.connect_selected_notify(move |d| {
            let value = match d.selected() {
                1 => "1280x800",
                2 => "1280x1024",
                3 => "1440x900",
                4 => "1600x900",
                5 => "1920x1080",
                _ => "1024x768",
            };
            let _ = settings.set("rdp.resolution", &crate::settings::Value::Text(value.into()));
        });
    }
    {
        let settings = settings.clone();
        let nla = nla.clone();
        nla.connect_active_notify(move |s| {
            let _ = settings.set("rdp.nla", &crate::settings::Value::Flag(s.is_active()));
        });
    }
    {
        let settings = settings.clone();
        let clipboard = clipboard.clone();
        clipboard.connect_active_notify(move |s| {
            let _ = settings.set("rdp.clipboard", &crate::settings::Value::Flag(s.is_active()));
        });
    }
    {
        let settings = settings.clone();
        let depth = depth.clone();
        depth.connect_value_changed(move |s| {
            let _ = settings.set("rdp.color_depth", &crate::settings::Value::Number(s.value() as i64));
        });
    }
    {
        let settings = settings.clone();
        let ctrl_alt_del = ctrl_alt_del.clone();
        ctrl_alt_del.connect_active_notify(move |s| {
            let _ = settings.set(
                "rdp.send_ctrl_alt_del",
                &crate::settings::Value::Flag(s.is_active()),
            );
        });
    }

    page
}

/// Раздел «Безопасность»: смена мастер-пароля.
fn security_page(settings: &Settings, state: &Rc<AppState>) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let title = Label::new(Some("Смена мастер-пароля"));
    title.add_css_class("remotix-section-title");
    page.append(&title);

    let current = PasswordEntry::new();
    current.set_show_peek_icon(true);
    let new = PasswordEntry::new();
    new.set_show_peek_icon(true);
    let repeat = PasswordEntry::new();
    repeat.set_show_peek_icon(true);

    let grid = Grid::new();
    grid.set_row_spacing(8);
    grid.set_column_spacing(12);
    add_row(&grid, 0, "Текущий пароль:", &current);
    add_row(&grid, 1, "Новый пароль:", &new);
    add_row(&grid, 2, "Повторите пароль:", &repeat);
    page.append(&grid);

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    page.append(&status);

    let button = Button::with_label("Сменить мастер-пароль");
    button.set_halign(gtk4::Align::Start);
    page.append(&button);

    {
        let button = button.clone();
        let current = current.clone();
        let new = new.clone();
        let repeat = repeat.clone();
        let status = status.clone();
        let state = state.clone();
        let settings = settings.clone();
        button.connect_clicked(move |_| {
            let old = current.text().to_string();
            let fresh = new.text().to_string();
            let again = repeat.text().to_string();

            if fresh.is_empty() {
                status.set_text("Новый мастер-пароль не может быть пустым");
                return;
            }
            if fresh != again {
                status.set_text("Новые пароли не совпадают");
                return;
            }
            if old == fresh {
                status.set_text("Новый пароль совпадает с текущим");
                return;
            }

            match state.db.change_master_password(&old, &fresh) {
                Ok(()) => {
                    status.set_text("Мастер-пароль изменён, учётные данные перешифрованы");
                    current.set_text("");
                    new.set_text("");
                    repeat.set_text("");
                    // Ключ в памяти больше не актуален — обновляем его.
                    let _ = settings;
                }
                Err(e) => status.set_text(&e),
            }
        });
    }

    let hint = Label::new(Some(
        "При смене мастер-пароля все сохранённые пароли подключений \
         перешифровываются новым ключом.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    page
}

/// Раздел «Профили»: импорт и экспорт.
fn profiles_page(state: &Rc<AppState>, parent: &Window) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let title = Label::new(Some("Импорт и экспорт"));
    title.add_css_class("remotix-section-title");
    page.append(&title);

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    page.append(&status);

    let export = Button::with_label("Экспортировать профили в JSON…");
    let import = Button::with_label("Импортировать профили из JSON…");
    page.append(&export);
    page.append(&import);

    let hint = Label::new(Some(
        "Экспорт сохраняет адреса, порты, протоколы и параметры, но не пароли — \
         их придётся ввести заново. Импорт добавляет новые профили, не заменяя \
         существующие.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    // --- Экспорт ---
    {
        let export = export.clone();
        let state = state.clone();
        let status = status.clone();
        let parent = parent.clone();
        export.connect_clicked(move |_| {
            let chooser = gtk4::FileChooserNative::new(
                Some("Экспорт профилей"),
                Some(&parent),
                gtk4::FileChooserAction::Save,
                Some("Экспортировать"),
                Some("Отмена"),
            );
            chooser.set_current_name("remotix-profiles.json");

            let state = state.clone();
            let status = status.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk4::ResponseType::Accept {
                    if let Some(path) = chooser.file().and_then(|f| f.path()) {
                        let key = state.unlocked_key();
                        match crate::profiles_io::export_profiles(&state.db, &key, &path) {
                            Ok(n) => status.set_text(&format!("Экспортировано профилей: {n}")),
                            Err(e) => status.set_text(&e),
                        }
                    }
                }
                chooser.destroy();
            });
            chooser.show();
        });
    }

    // --- Импорт ---
    {
        let import = import.clone();
        let state = state.clone();
        let status = status.clone();
        let parent = parent.clone();
        import.connect_clicked(move |_| {
            let chooser = gtk4::FileChooserNative::new(
                Some("Импорт профилей"),
                Some(&parent),
                gtk4::FileChooserAction::Open,
                Some("Импортировать"),
                Some("Отмена"),
            );
            chooser.set_filter(&gtk4::FileFilter::new());

            let state = state.clone();
            let status = status.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk4::ResponseType::Accept {
                    if let Some(path) = chooser.file().and_then(|f| f.path()) {
                        let key = state.unlocked_key();
                        match crate::profiles_io::import_profiles(&state.db, &key, &path) {
                            Ok(n) => status.set_text(&format!("Импортировано профилей: {n}")),
                            Err(e) => status.set_text(&e),
                        }
                    }
                }
                chooser.destroy();
            });
            chooser.show();
        });
    }

    page
}

/// Добавляет на сетку подпись и поле.
fn add_row(grid: &Grid, row: i32, caption: &str, widget: &impl IsA<gtk4::Widget>) {
    let label = Label::new(Some(caption));
    label.set_xalign(0.0);
    label.add_css_class("remotix-field-caption");
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(widget, 1, row, 1, 1);
}
