//! Окно «Параметры»: оформление, терминал, RDP, безопасность и профили.

use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    glib, Adjustment, Button, DropDown, Entry, Grid, Label, ListBox, ListBoxRow, Notebook,
    PasswordEntry, ScrolledWindow, SpinButton, StringList, Switch, Window,
};

use crate::app::AppState;
use crate::settings::Settings;
use crate::ui::theme;

/// Окно настроек приложения.
pub struct SettingsWindow {
    window: Window,
    notebook: Notebook,
}

impl SettingsWindow {
    /// Индекс страницы «Профили» (на неё открывается импорт).
    pub const PAGE_PROFILES: u32 = 5;

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

        notebook.append_page(
            &appearance_page(&settings),
            Some(&Label::new(Some("Оформление"))),
        );
        notebook.append_page(
            &terminal_page(&settings),
            Some(&Label::new(Some("Терминал"))),
        );
        notebook.append_page(&rdp_page(&settings), Some(&Label::new(Some("RDP"))));
        notebook.append_page(&expect_page(&state), Some(&Label::new(Some("Автоответы"))));
        notebook.append_page(
            &security_page(&settings, &state),
            Some(&Label::new(Some("Безопасность"))),
        );
        notebook.append_page(
            &profiles_page(&state, &window),
            Some(&Label::new(Some("Профили"))),
        );
        notebook.append_page(&snippets_page(&state), Some(&Label::new(Some("Сниппеты"))));

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

        Self {
            window,
            notebook: notebook.clone(),
        }
    }

    /// Показывает окно.
    pub fn present(&self) {
        self.window.present();
    }

    /// Показывает конкретную страницу (0 — оформление, 5 — профили).
    pub fn present_page(&self, page: u32) {
        self.notebook.set_current_page(Some(page));
        self.window.present();
    }

    /// Открыто ли окно в данный момент.
    pub fn is_visible(&self) -> bool {
        self.window.is_visible()
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

    let metrics = Switch::new();
    metrics.set_active(settings.terminal_metrics());

    let recording = Switch::new();
    recording.set_active(settings.terminal_recording());

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
    add_row(&grid, 4, "Метрики хоста:", &metrics);
    add_row(&grid, 5, "Запись сессий:", &recording);
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
            let _ = settings.set(
                "terminal.cursor_blink",
                &crate::settings::Value::Flag(s.is_active()),
            );
        });
    }
    {
        let settings = settings.clone();
        metrics.connect_active_notify(move |s| {
            let _ = settings.set(
                "terminal.metrics",
                &crate::settings::Value::Flag(s.is_active()),
            );
        });
    }
    {
        let settings = settings.clone();
        recording.connect_active_notify(move |s| {
            let _ = settings.set(
                "terminal.recording",
                &crate::settings::Value::Flag(s.is_active()),
            );
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
            let _ = settings.set(
                "terminal.color_scheme",
                &crate::settings::Value::Text(value.into()),
            );
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
            let _ = settings.set(
                "rdp.resolution",
                &crate::settings::Value::Text(value.into()),
            );
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
            let _ = settings.set(
                "rdp.clipboard",
                &crate::settings::Value::Flag(s.is_active()),
            );
        });
    }
    {
        let settings = settings.clone();
        let depth = depth.clone();
        depth.connect_value_changed(move |s| {
            let _ = settings.set(
                "rdp.color_depth",
                &crate::settings::Value::Number(s.value() as i64),
            );
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

    let hint = Label::new(Some(
        "Экспорт сохраняет адреса, порты, протоколы и параметры, но не пароли — \
         их придётся ввести заново. Импорт сначала показывает предпросмотр: \
         сколько профилей будет добавлено и почему остальные пропущены. \
         Пароли не импортируются никогда.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    let export = Button::with_label("Экспортировать профили в JSON…");
    page.append(&export);

    // --- Экспорт ---
    {
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

    page.append(&gtk4::Separator::new(gtk4::Orientation::Horizontal));

    let import_title = Label::new(Some("Импорт из стандартных источников"));
    import_title.add_css_class("remotix-section-title");
    page.append(&import_title);

    page.append(&crate::import::ui::build(
        state,
        parent,
        &status,
        Rc::new(crate::app::refresh_main_profiles),
    ));

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

/// Виджеты формы expect-правила (клонируются во все обработчики строк).
struct ExpectForm {
    pattern: Entry,
    send: PasswordEntry,
    once: Switch,
    enabled: Switch,
    submit: Button,
    status: Label,
}

/// Состояние страницы «Автоответы»: загруженные правила и id редактируемого.
struct ExpectPageState {
    editing: Option<i64>,
    rules: Vec<crate::db::repository::ExpectRuleRow>,
}

/// Страница «Автоответы»: expect-правила — шаблон вывода → строка отправки.
///
/// Правила глобальные (для всех SSH-сессий) и применяются в порядке списка.
/// Ответы хранятся зашифрованными в таблице expect_rules; в списке и в поле
/// ввода они показываются скрытыми (открыть — значок глаза в поле).
fn expect_page(state: &Rc<AppState>) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let title = Label::new(Some("Автоответы на вывод терминала"));
    title.add_css_class("remotix-section-title");
    page.append(&title);

    let hint = Label::new(Some(
        "Когда в выводе SSH-сессии встречается шаблон, в канал отправляется \
         строка ответа — Enter добавляется автоматически. В шаблоне `*` — \
         любая последовательность символов, `?` — ровно один символ, \
         остальное — литералы. Ответы хранятся зашифрованными, как пароли. \
         Правила применяются ко всем SSH-сессиям, поэтому не пишите в ответ \
         пароль, который не должен уйти на другой хост.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    let list = ListBox::new();
    let scrolled = ScrolledWindow::builder()
        .child(&list)
        .height_request(150)
        .vexpand(true)
        .build();
    page.append(&scrolled);

    let pattern = Entry::new();
    pattern.set_placeholder_text(Some("например: *assword*:"));
    let send = PasswordEntry::new();
    send.set_show_peek_icon(true);
    send.set_placeholder_text(Some("ответ, который отправится в канал"));
    let once = Switch::new();
    let enabled = Switch::new();
    enabled.set_active(true);

    let grid = Grid::new();
    grid.set_row_spacing(8);
    grid.set_column_spacing(12);
    add_row(&grid, 0, "Шаблон вывода:", &pattern);
    add_row(&grid, 1, "Отправить:", &send);
    add_row(&grid, 2, "Один раз за сессию:", &once);
    add_row(&grid, 3, "Включено:", &enabled);
    page.append(&grid);

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    page.append(&status);

    let submit = Button::with_label("Добавить правило");
    page.append(&submit);

    let form = Rc::new(ExpectForm {
        pattern,
        send,
        once,
        enabled,
        submit,
        status,
    });
    let page_state = Rc::new(std::cell::RefCell::new(ExpectPageState {
        editing: None,
        rules: Vec::new(),
    }));

    // Перечитывает правила из БД и перестраивает список строк.
    fn reload(
        state: &Rc<AppState>,
        list: &ListBox,
        page_state: &Rc<std::cell::RefCell<ExpectPageState>>,
        form: &Rc<ExpectForm>,
    ) {
        crate::ui::clear_list(list);

        let key = state.unlocked_key();
        let rules = match state.db.list_expect_rules(&key) {
            Ok(rules) => rules,
            Err(e) => {
                form.status.set_text(&e);
                return;
            }
        };

        for rule in &rules {
            let id = rule.id;
            let row = ListBoxRow::new();
            let hbox = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
            let flags = match (rule.once, rule.enabled) {
                (_, false) => "выключено",
                (true, true) => "один раз",
                (false, true) => "всегда",
            };
            // Ответ в списке не показывается: это может быть пароль.
            let text = Label::new(Some(&format!("{} → •••••• [{}]", rule.pattern, flags)));
            text.set_hexpand(true);
            text.set_xalign(0.0);
            hbox.append(&text);

            let edit = Button::with_label("Изменить");
            hbox.append(&edit);
            let remove = Button::with_label("Удалить");
            hbox.append(&remove);
            row.set_child(Some(&hbox));
            list.append(&row);

            {
                let page_state = page_state.clone();
                let form = form.clone();
                edit.connect_clicked(move |_| {
                    let mut st = page_state.borrow_mut();
                    if let Some(found) = st.rules.iter().find(|r| r.id == id) {
                        use secrecy::ExposeSecret;
                        form.pattern.set_text(&found.pattern);
                        form.send.set_text(found.send.expose_secret());
                        form.once.set_active(found.once);
                        form.enabled.set_active(found.enabled);
                        form.submit.set_label("Сохранить изменения");
                        st.editing = Some(id);
                    }
                });
            }
            {
                let state = state.clone();
                let page_state = page_state.clone();
                let form = form.clone();
                let list_ref = list.clone();
                remove.connect_clicked(move |_| {
                    if let Err(e) = state.db.delete_expect_rule(id) {
                        form.status.set_text(&e);
                    }
                    reload(&state, &list_ref, &page_state, &form);
                });
            }
        }

        page_state.borrow_mut().rules = rules;
        if page_state.borrow().rules.is_empty() {
            let empty = ListBoxRow::new();
            let label = Label::new(Some("Правил пока нет — добавьте первое ниже."));
            label.set_xalign(0.0);
            empty.set_child(Some(&label));
            empty.set_sensitive(false);
            list.append(&empty);
        }
    }

    {
        let list_ref = list.clone();
        reload(state, &list_ref, &page_state, &form);
    }

    {
        let state = state.clone();
        let page_state = page_state.clone();
        let form = form.clone();
        let list_ref = list.clone();
        // Приёмник — отдельный клон кнопки: замыкание двигает form целиком,
        // а `form.submit.connect_clicked` держал бы заимствование form.
        let button = form.submit.clone();
        button.connect_clicked(move |_| {
            let pattern = form.pattern.text().to_string();
            let send = form.send.text().to_string();
            if pattern.trim().is_empty() || send.is_empty() {
                form.status
                    .set_text("Укажите и шаблон, и строку для отправки.");
                return;
            }
            let key = state.unlocked_key();
            let send = secrecy::SecretString::from(send);
            let once = form.once.is_active();
            let enabled = form.enabled.is_active();

            let editing = page_state.borrow().editing;
            let result = match editing {
                Some(id) => state
                    .db
                    .update_expect_rule(&key, id, &pattern, &send, once, enabled),
                None => state
                    .db
                    .add_expect_rule(&key, &pattern, &send, once, enabled)
                    .map(|_| ()),
            };
            match result {
                Ok(()) => {
                    form.pattern.set_text("");
                    form.send.set_text("");
                    form.once.set_active(false);
                    form.enabled.set_active(true);
                    form.submit.set_label("Добавить правило");
                    page_state.borrow_mut().editing = None;
                    form.status.set_text("Сохранено.");
                }
                Err(e) => form.status.set_text(&e),
            }
            reload(&state, &list_ref, &page_state, &form);
        });
    }

    page
}

/// Виджеты формы сниппета (клонируются во все обработчики строк).
struct SnippetForm {
    name: Entry,
    command: Entry,
    submit: Button,
    status: Label,
}

/// Состояние страницы «Сниппеты»: загруженные команды и id редактируемой.
struct SnippetPageState {
    editing: Option<i64>,
    snippets: Vec<crate::db::repository::SnippetRow>,
}

/// Страница «Сниппеты»: сохранённые команды терминала.
///
/// Команды хранятся зашифрованными (BLOB, как ответы expect) и отправляются
/// из меню над SSH-терминалом. Это не менеджер секретов: текст команды
/// виден в списке и в поле редактирования.
fn snippets_page(state: &Rc<AppState>) -> gtk4::Box {
    let page = gtk4::Box::new(gtk4::Orientation::Vertical, 10);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        page.set_property(m, 16);
    }

    let title = Label::new(Some("Сниппеты команд"));
    title.add_css_class("remotix-section-title");
    page.append(&title);

    let hint = Label::new(Some(
        "Сохранённые команды для SSH-терминала. В открытой сессии меню \
         «Сниппеты» над терминалом отправляет выбранную команду в канал и \
         добавляет Enter. Текст команд хранится зашифрованным; не используйте \
         сниппеты как хранилище паролей.",
    ));
    hint.set_wrap(true);
    hint.set_xalign(0.0);
    hint.add_css_class("remotix-field-caption");
    page.append(&hint);

    let list = ListBox::new();
    let scrolled = ScrolledWindow::builder()
        .child(&list)
        .height_request(160)
        .vexpand(true)
        .build();
    page.append(&scrolled);

    let name = Entry::new();
    name.set_placeholder_text(Some("название, например: Свободное место"));
    let command = Entry::new();
    command.set_placeholder_text(Some("команда, например: df -h"));
    let grid = Grid::new();
    grid.set_row_spacing(8);
    grid.set_column_spacing(12);
    add_row(&grid, 0, "Название:", &name);
    add_row(&grid, 1, "Команда:", &command);
    page.append(&grid);

    let status = Label::new(None);
    status.set_wrap(true);
    status.set_xalign(0.0);
    page.append(&status);

    let submit = Button::with_label("Добавить сниппет");
    page.append(&submit);

    let form = Rc::new(SnippetForm {
        name,
        command,
        submit,
        status,
    });
    let page_state = Rc::new(std::cell::RefCell::new(SnippetPageState {
        editing: None,
        snippets: Vec::new(),
    }));

    // Перечитывает сниппеты из БД и перестраивает список строк.
    fn reload(
        state: &Rc<AppState>,
        list: &ListBox,
        page_state: &Rc<std::cell::RefCell<SnippetPageState>>,
        form: &Rc<SnippetForm>,
    ) {
        crate::ui::clear_list(list);

        let key = state.unlocked_key();
        let snippets = match state.db.list_snippets(&key) {
            Ok(snippets) => snippets,
            Err(e) => {
                form.status.set_text(&e);
                return;
            }
        };

        for snippet in &snippets {
            let id = snippet.id;
            let row = ListBoxRow::new();
            let hbox = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
            let text = Label::new(Some(&format!("{} — {}", snippet.name, snippet.command)));
            text.set_hexpand(true);
            text.set_xalign(0.0);
            text.set_ellipsize(gtk4::pango::EllipsizeMode::End);
            hbox.append(&text);

            let edit = Button::with_label("Изменить");
            hbox.append(&edit);
            let remove = Button::with_label("Удалить");
            hbox.append(&remove);
            row.set_child(Some(&hbox));
            list.append(&row);

            {
                let page_state = page_state.clone();
                let form = form.clone();
                edit.connect_clicked(move |_| {
                    let mut st = page_state.borrow_mut();
                    if let Some(found) = st.snippets.iter().find(|s| s.id == id) {
                        form.name.set_text(&found.name);
                        form.command.set_text(&found.command);
                        form.submit.set_label("Сохранить изменения");
                        st.editing = Some(id);
                    }
                });
            }
            {
                let state = state.clone();
                let page_state = page_state.clone();
                let form = form.clone();
                let list_ref = list.clone();
                remove.connect_clicked(move |_| {
                    if let Err(e) = state.db.delete_snippet(id) {
                        form.status.set_text(&e);
                    }
                    reload(&state, &list_ref, &page_state, &form);
                });
            }
        }

        page_state.borrow_mut().snippets = snippets;
        if page_state.borrow().snippets.is_empty() {
            let empty = ListBoxRow::new();
            let label = Label::new(Some("Сниппетов пока нет — добавьте первый ниже."));
            label.set_xalign(0.0);
            empty.set_child(Some(&label));
            empty.set_sensitive(false);
            list.append(&empty);
        }
    }

    {
        let list_ref = list.clone();
        reload(state, &list_ref, &page_state, &form);
    }

    {
        let state = state.clone();
        let page_state = page_state.clone();
        let form = form.clone();
        let list_ref = list.clone();
        // Отдельный клон кнопки: замыкание двигает form целиком.
        let button = form.submit.clone();
        button.connect_clicked(move |_| {
            let name = form.name.text().trim().to_string();
            let command = form.command.text().trim().to_string();
            if name.is_empty() || command.is_empty() {
                form.status
                    .set_text("Укажите и название, и команду для отправки.");
                return;
            }
            let key = state.unlocked_key();

            let editing = page_state.borrow().editing;
            let result = match editing {
                Some(id) => state.db.update_snippet(&key, id, &name, &command),
                None => state.db.add_snippet(&key, &name, &command).map(|_| ()),
            };
            match result {
                Ok(()) => {
                    form.name.set_text("");
                    form.command.set_text("");
                    form.submit.set_label("Добавить сниппет");
                    page_state.borrow_mut().editing = None;
                    form.status.set_text("Сохранено.");
                }
                Err(e) => form.status.set_text(&e),
            }
            reload(&state, &list_ref, &page_state, &form);
        });
    }

    page
}
