//! Логика приложения: запуск, главное окно, диалог «О программе».

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{gio, glib, Application, ApplicationWindow, Button, Label};
use zeroize::{Zeroize, Zeroizing};

use crate::db::repository::Database;
use crate::ui::main_window::MainWindow;
use crate::ui::master_password::MasterPasswordDialog;
use crate::ui::settings_window::SettingsWindow;

/// Состояние приложения: база данных и ключ шифрования после разблокировки.
///
/// База данных обёрнута в `Rc`: соединение SQLite нельзя клонировать, но
/// его можно разделять между диалогами профиля, терминалом и SFTP-клиентом.
#[derive(Clone)]
pub struct AppState {
    pub db: Rc<Database>,
    /// Ключ шифрования в общей ячейке: все копии `AppState` видят одно и
    /// то же значение, поэтому блокировка стирает ключ сразу везде.
    key: Rc<RefCell<Option<[u8; 32]>>>,
}

impl AppState {
    pub fn new(db: Rc<Database>, key: [u8; 32]) -> Self {
        Self {
            db,
            key: Rc::new(RefCell::new(Some(key))),
        }
    }

    /// Копия ключа в `Zeroizing`: временная копия на стеке/в куче также
    /// будет затёрта при выходе из области видимости.
    pub fn unlocked_key(&self) -> Zeroizing<[u8; 32]> {
        let key = self.key.borrow();
        Zeroizing::new(key.expect("приложение разблокировано"))
    }

    /// Устанавливает ключ после повторной разблокировки.
    pub fn set_key(&self, mut key: [u8; 32]) {
        if let Some(old) = self.key.borrow_mut().replace(key) {
            let mut old = old;
            old.zeroize();
        }
        // В ячейке осталась копия, локальную больше не держим.
        key.zeroize();
    }

    /// Стирает ключ из памяти при блокировке.
    pub fn lock(&self) {
        let old = self.key.borrow_mut().take();
        if let Some(mut key) = old {
            key.zeroize();
        }
    }

    /// Заблокировано ли хранилище (ключ стёрт).
    pub fn is_locked(&self) -> bool {
        self.key.borrow().is_none()
    }
}

thread_local! {
    /// Главное окно приложения (создаётся один раз за сеанс).
    static MAIN_WINDOW: RefCell<Option<ApplicationWindow>> = const { RefCell::new(None) };
    /// Состояние приложения (база данных и ключ шифрования).
    static APP_STATE: RefCell<Option<Rc<AppState>>> = const { RefCell::new(None) };
    /// Главный виджет интерфейса — нужен для действий из меню.
    static MAIN_UI: RefCell<Option<Rc<MainWindow>>> = const { RefCell::new(None) };
    /// Диалог мастер-пароля (первичная разблокировка или блокировка по Ctrl+L).
    static UNLOCK_DIALOG: RefCell<Option<MasterPasswordDialog>> = const { RefCell::new(None) };
    /// Открытая база данных — используется повторно при блокировке.
    static APP_DB: RefCell<Option<Rc<Database>>> = const { RefCell::new(None) };
    /// Окно настроек.
    static SETTINGS_WINDOW: RefCell<Option<crate::ui::settings_window::SettingsWindow>> =
        const { RefCell::new(None) };
    /// Окно с сообщением об ошибке (нужно удерживать, иначе оно закроется).
    static ERROR_WINDOW: RefCell<Option<ApplicationWindow>> = const { RefCell::new(None) };
}

/// Обработчик сигнала «activate» — обычный запуск приложения.
pub fn activate(app: &Application) {
    ensure_window(app);
}

/// Обработчик сигнала «open» — запуск с файлами или URI.
///
/// Без этого обработчика GApplication (при флаге HANDLES_OPEN) не знает, что
/// делать с переданными файлами, и завершает работу с сообщением
/// «This application can not open files.».
pub fn open(app: &Application, files: &[gio::File], _hint: &str) {
    // Запуск с аргументами должен приводить к тому же результату, что и
    // обычный запуск: показываем окно приложения.
    ensure_window(app);

    for file in files {
        let target = file
            .path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| file.uri().to_string());
        eprintln!("Remotix: получено имя файла для открытия: {target}");
    }
}

/// Создаёт окно приложения либо поднимает уже созданное.
fn ensure_window(app: &Application) {
    // Стили интерфейса — GTK к этому моменту уже инициализирован.
    crate::ui::theme::install();

    // Повторная активация (клик по значку в меню при уже открытом окне) —
    // просто поднимаем существующее окно.
    if let Some(window) = MAIN_WINDOW.with(|w| w.borrow().clone()) {
        window.present();
        return;
    }

    // Диалог разблокировки уже показан — второй раз открывать не нужно.
    if UNLOCK_DIALOG.with(|d| d.borrow().is_some()) {
        return;
    }

    let db = match crate::db::open_database() {
        Ok(db) => Rc::new(db),
        Err(e) => {
            show_error(app, "Не удалось открыть хранилище", &e);
            return;
        }
    };
    APP_DB.with(|d| *d.borrow_mut() = Some(db.clone()));

    let app_for_callback = app.clone();
    let dialog = MasterPasswordDialog::new(app, db, move |db, key| {
        build_main_window(&app_for_callback, db, key);
    });
    UNLOCK_DIALOG.with(|d| *d.borrow_mut() = Some(dialog));
}

/// Создаёт и показывает главное окно приложения.
fn build_main_window(app: &Application, db: Rc<Database>, mut key: [u8; 32]) {
    let state = AppState::new(db, key);
    key.zeroize();

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Remotix — Клиент удалённого доступа")
        .default_width(1180)
        .default_height(720)
        .build();

    let main = MainWindow::new(state.clone());
    window.set_titlebar(Some(&main.header));
    window.set_child(Some(&main.root));

    // Тема оформления из настроек.
    let settings = crate::settings::Settings::new(state.db.clone());
    crate::ui::theme::apply(&settings.theme(), &window);

    // Действия окна: «win.*»
    let actions = gio::SimpleActionGroup::new();
    window.insert_action_group("win", Some(&actions));

    let new_action = gio::SimpleAction::new("new-profile", None);
    {
        let main = main.clone();
        new_action.connect_activate(move |_, _| main.open_profile_editor(None));
    }
    actions.add_action(&new_action);

    let duplicate_action = gio::SimpleAction::new("duplicate-profile", None);
    {
        let main = main.clone();
        duplicate_action.connect_activate(move |_, _| {
            if let Some(profile) = main.selected_profile() {
                main.duplicate_profile(&profile);
            } else {
                main.set_status("Сначала выберите подключение в списке слева");
            }
        });
    }
    actions.add_action(&duplicate_action);

    let delete_action = gio::SimpleAction::new("delete-profile", None);
    {
        let main = main.clone();
        delete_action.connect_activate(move |_, _| {
            if let Some(profile) = main.selected_profile() {
                main.delete_profile(&profile);
            } else {
                main.set_status("Сначала выберите подключение в списке слева");
            }
        });
    }
    actions.add_action(&delete_action);

    let search_action = gio::SimpleAction::new("focus-search", None);
    {
        let main = main.clone();
        search_action.connect_activate(move |_, _| main.focus_search());
    }
    actions.add_action(&search_action);

    let history_action = gio::SimpleAction::new("history", None);
    {
        let main = main.clone();
        history_action.connect_activate(move |_, _| main.open_history_tab());
    }
    actions.add_action(&history_action);

    let sftp_action = gio::SimpleAction::new("sftp", None);
    {
        let main = main.clone();
        sftp_action.connect_activate(move |_, _| main.open_sftp_tab());
    }
    actions.add_action(&sftp_action);

    let lock_action = gio::SimpleAction::new("lock", None);
    {
        let app = app.clone();
        let window = window.clone();
        lock_action.connect_activate(move |_, _| lock_window(&app, &window));
    }
    actions.add_action(&lock_action);

    let settings_action = gio::SimpleAction::new("settings", None);
    {
        settings_action.connect_activate(move |_, _| open_settings());
    }
    actions.add_action(&settings_action);

    let import_action = gio::SimpleAction::new("import", None);
    {
        import_action.connect_activate(move |_, _| open_import());
    }
    actions.add_action(&import_action);

    let about_action = gio::SimpleAction::new("about", None);
    {
        let window = window.clone();
        about_action.connect_activate(move |_, _| show_about(&window));
    }
    actions.add_action(&about_action);

    let quit_action = gio::SimpleAction::new("quit", None);
    {
        let app = app.clone();
        quit_action.connect_activate(move |_, _| app.quit());
    }
    actions.add_action(&quit_action);

    // Горячие клавиши.
    app.set_accels_for_action("win.new-profile", &["<Primary>n"]);
    app.set_accels_for_action("win.focus-search", &["<Primary>f"]);
    app.set_accels_for_action("win.lock", &["<Primary>l"]);
    app.set_accels_for_action("win.about", &["<Primary>i"]);
    app.set_accels_for_action("win.settings", &["<Primary>comma"]);
    app.set_accels_for_action("win.quit", &["<Primary>q"]);

    APP_STATE.with(|s| *s.borrow_mut() = Some(Rc::new(state)));
    MAIN_UI.with(|u| *u.borrow_mut() = Some(Rc::new(main)));
    MAIN_WINDOW.with(|w| *w.borrow_mut() = Some(window.clone()));
    window.present();
}

/// Открывает окно «Параметры».
fn open_settings() {
    open_settings_page(None);
}

/// Открывает окно «Параметры» сразу на странице импорта профилей.
fn open_import() {
    open_settings_page(Some(4));
}

/// Открывает настройки на указанной странице (или переиспользует открытое
/// окно). `None` — страница по умолчанию.
fn open_settings_page(page: Option<u32>) {
    if SETTINGS_WINDOW.with(|w| w.borrow().as_ref().map(|w| w.is_visible()).unwrap_or(false)) {
        SETTINGS_WINDOW.with(|w| {
            if let Some(window) = w.borrow().as_ref() {
                if let Some(page) = page {
                    window.present_page(page);
                } else {
                    window.present();
                }
            }
        });
        return;
    }

    let state = match APP_STATE.with(|s| s.borrow().clone()) {
        Some(s) => s,
        None => return,
    };

    let settings = crate::settings::Settings::new(state.db.clone());
    let state_for_close = state.clone();
    let window = SettingsWindow::new(settings, state.clone(), move || {
        // После закрытия настроек применяем тему и обновляем список профилей
        // (импорт мог добавить новые записи).
        let settings = crate::settings::Settings::new(state_for_close.db.clone());
        if let Some(w) = MAIN_WINDOW.with(|w| w.borrow().clone()) {
            crate::ui::theme::apply(&settings.theme(), &w);
        }
        refresh_main_profiles();
    });
    if let Some(page) = page {
        window.present_page(page);
    } else {
        window.present();
    }
    SETTINGS_WINDOW.with(|w| *w.borrow_mut() = Some(window));
}

/// Обновляет боковую панель главного окна после импорта.
pub(crate) fn refresh_main_profiles() {
    let unlocked = APP_STATE.with(|s| {
        s.borrow()
            .as_ref()
            .map(|state| !state.is_locked())
            .unwrap_or(false)
    });
    if !unlocked {
        return;
    }
    if let Some(main) = MAIN_UI.with(|m| m.borrow().clone()) {
        main.refresh_profiles();
    }
}

/// Блокирует интерфейс: окно прячется, пользователь вводит мастер-пароль.
fn lock_window(app: &Application, window: &ApplicationWindow) {
    let db = match APP_DB.with(|d| d.borrow().clone()) {
        Some(db) => db,
        None => return,
    };
    let state = match APP_STATE.with(|s| s.borrow().clone()) {
        Some(state) => state,
        None => return,
    };
    let main = MAIN_UI.with(|m| m.borrow().clone());

    window.set_visible(false);

    // Стираем ключ и расшифрованные профили из памяти. Активные вкладки
    // сессий продолжают работать, но новые подключения без разблокировки
    // невозможны.
    if let Some(main) = &main {
        main.lock_secrets();
    }
    state.lock();

    let locked_window = window.clone();
    let state_for_unlock = state.clone();
    let main_for_unlock = main.clone();
    let dialog = MasterPasswordDialog::new(app, db, move |_db, key| {
        state_for_unlock.set_key(key);
        if let Some(main) = &main_for_unlock {
            main.refresh_profiles();
        }
        locked_window.set_visible(true);
        locked_window.present();
    });

    // Если пользователь закрыл диалог, не показываем окно с уже стёртым
    // ключом: это привело бы к панике при первом же обращении к профилям.
    {
        let locked_window = window.clone();
        let state = state.clone();
        let app = app.clone();
        dialog.window().connect_destroy(move |_| {
            if state.is_locked() {
                app.quit();
            } else {
                locked_window.set_visible(true);
                locked_window.present();
            }
        });
    }

    UNLOCK_DIALOG.with(|d| *d.borrow_mut() = Some(dialog));
}

/// Показывает окно с сообщением об ошибке.
fn show_error(app: &Application, title: &str, message: &str) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title(title)
        .default_width(480)
        .resizable(false)
        .build();

    let box_ = gtk4::Box::new(gtk4::Orientation::Vertical, 12);
    for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        box_.set_property(m, 12);
    }

    let label = Label::new(Some(message));
    label.set_wrap(true);
    label.set_xalign(0.0);
    box_.append(&label);

    let close = Button::with_label("Закрыть");
    close.set_halign(gtk4::Align::End);
    box_.append(&close);

    window.set_child(Some(&box_));

    {
        let window = window.clone();
        close.connect_clicked(move |_| window.destroy());
    }

    // Окно ошибки — единственное окно приложения: его закрытие завершает
    // приложение (иначе оно «висит» без единого окна).
    window.connect_close_request(|_| glib::Propagation::Proceed);

    ERROR_WINDOW.with(|w| *w.borrow_mut() = Some(window.clone()));
    window.present();
}

/// Диалог «О программе».
fn show_about(parent: &ApplicationWindow) {
    let about = gtk4::AboutDialog::builder()
        .program_name("Remotix")
        .version(env!("CARGO_PKG_VERSION"))
        .title("О программе Remotix")
        .comments(
            "Единый клиент удалённого доступа для РЕД ОС.\n\
             RDP · VNC · SSH · SFTP — всё в одном окне.\n\
             Работает полностью офлайн: без облака, без телеметрии.",
        )
        .website("https://github.com/flytimopheev-sketch/remotix")
        .website_label("Репозиторий проекта")
        .license_type(gtk4::License::MitX11)
        .copyright("Copyright © 2026 flytimopheev")
        .authors(vec!["flytimopheev <flytimopheev@gmail.com>".to_string()])
        .logo_icon_name("remotix")
        .transient_for(parent)
        .modal(true)
        .build();

    about.set_authors(&["flytimopheev <flytimopheev@gmail.com>"]);
    about.set_license(Some(concat!(
        "MIT License\n\n",
        "Copyright (c) 2026 flytimopheev <flytimopheev@gmail.com>\n\n",
        "Permission is hereby granted, free of charge, to any person obtaining a copy\n",
        "of this software and associated documentation files (the \"Software\"), to deal\n",
        "in the Software without restriction, including without limitation the rights\n",
        "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n",
        "copies of the Software, and to permit persons to whom the Software is\n",
        "furnished to do so, subject to the following conditions:\n\n",
        "The above copyright notice and this permission notice shall be included in all\n",
        "copies or substantial portions of the Software.\n\n",
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n",
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n",
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n",
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n",
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n",
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n",
        "SOFTWARE.\n\n",
        "Обратная связь и предложения: flytimopheev@gmail.com"
    )));

    about.present();
}
