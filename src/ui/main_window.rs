//! Главное окно Remotix.
//!
//! Оформление повторяет макет `mockup.html`: шапка окна с поиском, боковая
//! панель со списком подключений, вкладки активных сессий и строка состояния.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    gio, Box as GtkBox, Button, Entry, HeaderBar, Image, Label, ListBox, ListBoxRow, MenuButton,
    Notebook, Orientation, Overlay, Paned, Popover, ScrolledWindow, SearchEntry,
};

use crate::app::AppState;
use crate::models::{Profile, Protocol};
use crate::protocols::ssh::SshConnection;
use crate::ui::history_tab::HistoryTab;
use crate::ui::profile_editor::ProfileEditor;
use crate::ui::rdp_viewer::RdpViewer;
use crate::ui::sftp_tab::SftpTab;
use crate::ui::terminal::TerminalTab;
use crate::ui::SessionState;

/// Главное окно: список подключений, вкладки сессий, строка состояния.
#[derive(Clone)]
pub struct MainWindow {
    /// Корневой контейнер окна (панель сессий + строка состояния).
    pub root: GtkBox,
    /// Шапка окна (заголовок, кнопки, поиск, меню).
    pub header: HeaderBar,
    state: Rc<AppState>,
    notebook: Notebook,
    search: SearchEntry,
    quick_entry: Entry,
    status: Label,
    sidebar: ListBox,
    welcome: Label,
    profiles: Rc<RefCell<Vec<Profile>>>,
    /// Состояния активных сессий: (название, состояние).
    sessions: Rc<RefCell<Vec<(String, SessionState)>>>,
    /// Открытые вкладки сессий: (название, страница).
    session_pages: Rc<RefCell<Vec<(String, gtk4::Widget)>>>,
}

impl MainWindow {
    pub fn new(state: AppState) -> Self {
        let state = Rc::new(state);

        // ---------------- Шапка окна ----------------
        let header = HeaderBar::new();
        let title = Label::new(Some("Remotix"));
        title.add_css_class("title");
        header.set_title_widget(Some(&title));

        let new_btn = Button::with_label("Новый профиль");
        new_btn.add_css_class("suggested-action");
        new_btn.set_tooltip_text(Some("Создать профиль подключения (Ctrl+N)"));
        header.pack_start(&new_btn);

        let search = SearchEntry::new();
        search.set_placeholder_text(Some("Поиск по названию, адресу или логину"));
        search.set_hexpand(true);
        header.pack_end(&search);

        let menu_button = MenuButton::new();
        menu_button.set_icon_name("open-menu-symbolic");
        menu_button.set_tooltip_text(Some("Главное меню"));
        header.pack_end(&menu_button);

        // ---------------- Боковая панель ----------------
        let sidebar = ListBox::new();
        sidebar.set_selection_mode(gtk4::SelectionMode::Single);
        sidebar.add_css_class("remotix-sidebar");

        let quick_entry = Entry::new();
        quick_entry.set_placeholder_text(Some("Быстрое подключение: user@host"));
        quick_entry.set_tooltip_text(Some("SSH-сессия без создания профиля"));
        let quick_btn = Button::with_label("Подключиться");
        quick_btn.add_css_class("suggested-action");

        let quick_box = GtkBox::new(Orientation::Vertical, 6);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            quick_box.set_property(m, 8);
        }
        quick_box.append(&quick_entry);
        quick_box.append(&quick_btn);

        let scroll = ScrolledWindow::new();
        scroll.set_child(Some(&sidebar));
        scroll.set_vexpand(true);
        scroll.set_hscrollbar_policy(gtk4::PolicyType::Never);

        let sidebar_box = GtkBox::new(Orientation::Vertical, 0);
        sidebar_box.append(&quick_box);
        sidebar_box.append(&gtk4::Separator::new(Orientation::Horizontal));
        sidebar_box.append(&scroll);

        // ---------------- Вкладки сессий ----------------
        let notebook = Notebook::new();
        notebook.set_vexpand(true);
        notebook.set_scrollable(true);
        notebook.set_show_border(false);
        notebook.set_tab_pos(gtk4::PositionType::Top);

        let welcome = Label::new(Some(
            "Нет активных сессий\n\nВыберите подключение в списке слева\nили создайте новое — «Новый профиль»",
        ));
        welcome.set_justify(gtk4::Justification::Center);
        welcome.add_css_class("remotix-empty");

        let overlay = Overlay::new();
        overlay.set_child(Some(&notebook));
        overlay.add_overlay(&welcome);

        let paned = Paned::new(Orientation::Horizontal);
        paned.set_start_child(Some(&sidebar_box));
        paned.set_end_child(Some(&overlay));
        paned.set_position(300);
        paned.set_resize_start_child(false);
        paned.set_vexpand(true);
        // Боковую панель нельзя свернуть совсем: иначе рабочая область
        // «уезжает» влево и окно выглядит бесконечно широким.
        paned.connect_notify_local(Some("position"), move |paned, _| {
            if paned.position() < 200 {
                paned.set_position(200);
            }
        });

        // ---------------- Строка состояния ----------------
        let status = Label::new(Some("Готово"));
        status.set_xalign(0.0);
        status.set_hexpand(true);

        let history_btn = Button::from_icon_name("view-history-symbolic");
        history_btn.set_tooltip_text(Some("Журнал подключений"));
        let sftp_btn = Button::from_icon_name("folder-remote-symbolic");
        sftp_btn.set_tooltip_text(Some("SFTP-клиент"));

        let hints = Label::new(Some(
            "Ctrl+N — профиль · Ctrl+F — поиск · Ctrl+L — блокировка · Ctrl+Q — выход",
        ));
        hints.add_css_class("remotix-hint");

        let statusbar = GtkBox::new(Orientation::Horizontal, 12);
        statusbar.add_css_class("remotix-statusbar");
        statusbar.append(&status);
        statusbar.append(&history_btn);
        statusbar.append(&sftp_btn);
        statusbar.append(&hints);

        let root = GtkBox::new(Orientation::Vertical, 0);
        root.append(&paned);
        root.append(&statusbar);

        let win = Self {
            root,
            header,
            state,
            notebook,
            search: search.clone(),
            quick_entry: quick_entry.clone(),
            status,
            sidebar: sidebar.clone(),
            welcome,
            profiles: Rc::new(RefCell::new(Vec::new())),
            sessions: Rc::new(RefCell::new(Vec::new())),
            session_pages: Rc::new(RefCell::new(Vec::new())),
        };

        // ---------------- Обработчики ----------------
        {
            let win = win.clone();
            new_btn.connect_clicked(move |_| win.open_profile_editor(None));
        }
        {
            let win = win.clone();
            quick_btn.connect_clicked(move |_| win.quick_connect());
        }
        {
            let win = win.clone();
            quick_entry.connect_activate(move |_| win.quick_connect());
        }
        {
            let win = win.clone();
            search.connect_search_changed(move |_| win.refresh_profiles());
        }
        {
            let win = win.clone();
            sidebar.connect_row_activated(move |_, row| {
                let index = row.index();
                if index < 0 {
                    return;
                }
                let profile = win.profiles.borrow().get(index as usize).cloned();
                if let Some(profile) = profile {
                    win.connect_profile(profile);
                }
            });
        }
        {
            let win = win.clone();
            history_btn.connect_clicked(move |_| win.open_history_tab());
        }
        {
            let win = win.clone();
            sftp_btn.connect_clicked(move |_| win.open_sftp_tab());
        }
        {
            let win = win.clone();
            let menu = build_main_menu();
            menu_button.set_menu_model(Some(&menu));
            // Пункты меню вызывают те же действия, что и кнопки.
            let _ = &win;
        }

        win.refresh_profiles();
        win
    }

    /// Переводит фокус в поле поиска (Ctrl+F).
    pub fn focus_search(&self) {
        self.search.grab_focus();
    }

    /// Открывает редактор профиля (None — создание нового).
    pub fn open_profile_editor(&self, profile_id: Option<i64>) {
        let after_save = self.clone();
        let after_delete = self.clone();
        let editor = ProfileEditor::new(
            self.state.as_ref(),
            profile_id,
            move || {
                after_save.refresh_profiles();
            },
            move || {
                after_delete.refresh_profiles();
            },
        );
        editor.present_transient_for(
            self.root
                .root()
                .and_then(|w| w.downcast::<gtk4::Window>().ok())
                .as_ref(),
        );
    }

    /// Дублирует профиль: копия создаётся сразу, без диалогов.
    pub fn duplicate_profile(&self, profile: &Profile) {
        let key = self.state.unlocked_key();
        let copy = crate::models::NewProfile {
            name: format!("{} (копия)", profile.name),
            protocol: Some(profile.protocol),
            host: profile.host.clone(),
            port: profile.port,
            username: profile.username.clone(),
            password: profile.password.clone(),
            ssh_key_path: profile.ssh_key_path.clone(),
            ssh_key_passphrase: profile.ssh_key_passphrase.clone(),
            root_password: profile.root_password.clone(),
            group_id: profile.group_id,
            tags: profile.tags.clone(),
            icon: profile.icon.clone(),
            notes: profile.notes.clone(),
            rdp_options: profile.rdp_options.clone(),
            vnc_options: profile.vnc_options.clone(),
            ssh_options: profile.ssh_options.clone(),
        };

        match self.state.db.add_profile(&key, &copy) {
            Ok(_) => {
                self.set_status(&format!("Создана копия профиля «{}»", copy.name));
                self.refresh_profiles();
            }
            Err(e) => self.set_status(&format!("Не удалось создать копию: {e}")),
        }
    }

    /// Удаляет профиль.
    pub fn delete_profile(&self, profile: &Profile) {
        match self.state.db.delete_profile(profile.id) {
            Ok(n) if n > 0 => {
                self.set_status(&format!("Профиль «{}» удалён", profile.name));
                self.refresh_profiles();
            }
            Ok(_) => self.set_status("Профиль не найден"),
            Err(e) => self.set_status(&format!("Не удалось удалить профиль: {e}")),
        }
    }

    /// Быстрое подключение: `user@host` — SSH-сессия без профиля.
    pub fn quick_connect(&self) {
        let text = self.quick_entry.text().trim().to_string();
        match quick_profile(&text) {
            Some(profile) => {
                self.quick_entry.set_text("");
                self.connect_profile(profile);
            }
            None => self.set_status("Формат быстрого подключения: user@host"),
        }
    }

    /// Перечитывает профили из базы и обновляет боковую панель.
    pub fn refresh_profiles(&self) {
        let key = self.state.unlocked_key();
        let all = match self.state.db.list_profiles(&key) {
            Ok(profiles) => profiles,
            Err(e) => {
                self.set_status(&format!("Ошибка чтения профилей: {e}"));
                return;
            }
        };

        // Запоминаем выбранный профиль: после пересборки списка выделение
        // пропадает, и кнопка «SFTP-клиент» не находит, к чему подключаться.
        let selected_id = self.selected_profile().map(|p| p.id);

        let filter = self.search.text().trim().to_lowercase();
        let visible: Vec<Profile> = all
            .into_iter()
            .filter(|p| {
                filter.is_empty()
                    || p.name.to_lowercase().contains(&filter)
                    || p.host.to_lowercase().contains(&filter)
                    || p.username
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&filter))
                        .unwrap_or(false)
            })
            .collect();

        self.clear_sidebar();

        if visible.is_empty() {
            let empty = Label::new(Some(if filter.is_empty() {
                "Подключений пока нет.\nНажмите «Новый профиль»."
            } else {
                "Ничего не найдено."
            }));
            empty.set_justify(gtk4::Justification::Center);
            empty.set_margin_top(18);
            empty.set_margin_bottom(12);
            empty.set_margin_start(12);
            empty.set_margin_end(12);
            empty.add_css_class("remotix-empty");
            self.sidebar.append(&empty);
        } else {
            for profile in &visible {
                let row = self.build_profile_row(profile);
                self.sidebar.append(&row);
            }
        }

        // Восстанавливаем выделение прежнего профиля.
        if let Some(id) = selected_id {
            if let Some(index) = visible.iter().position(|p| p.id == id) {
                if let Some(row) = self.sidebar.row_at_index(index as i32) {
                    self.sidebar.select_row(Some(&row));
                }
            }
        }

        *self.profiles.borrow_mut() = visible;
    }

    /// Строка профиля в боковой панели: название, протокол, адрес.
    fn build_profile_row(&self, profile: &Profile) -> ListBoxRow {
        let row = ListBoxRow::new();

        let name = Label::new(Some(&profile.name));
        name.set_xalign(0.0);
        name.set_hexpand(true);
        name.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        name.add_css_class("remotix-profile-name");

        let tag = Label::new(Some(profile.protocol.as_str()));
        tag.add_css_class("remotix-tag");
        // Цвет метки — в зависимости от протокола.
        tag.add_css_class(match profile.protocol {
            Protocol::Ssh => "success",
            Protocol::Rdp => "accent",
            Protocol::Vnc => "warning",
        });

        let title_row = GtkBox::new(Orientation::Horizontal, 8);
        title_row.append(&name);
        title_row.append(&tag);

        let details = Label::new(Some(&format!(
            "{}:{} · {}",
            profile.host,
            profile.port,
            profile.username.clone().unwrap_or_else(|| "—".to_string())
        )));
        details.set_xalign(0.0);
        details.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        details.add_css_class("remotix-profile-details");

        let box_ = GtkBox::new(Orientation::Vertical, 2);
        box_.append(&title_row);
        box_.append(&details);

        row.set_child(Some(&box_));

        // Контекстное меню профиля (правая кнопка мыши).
        {
            let popover = self.profile_popover(profile.clone());

            let controller = gtk4::GestureClick::new();
            controller.set_button(3);
            let popup = popover.clone();
            let row_ref = row.clone();
            controller.connect_pressed(move |_, _, x, y| {
                // Поповеру нужен родитель — без него GTK ругается в консоль,
                // а при показе приложение падает. Родителем делаем окно
                // приложения: строка профиля может быть пересоздана, и
                // поповер не должен быть её дочерним виджетом.
                let Some(toplevel) = row_ref.root() else {
                    return;
                };
                if popup.parent().is_none() {
                    popup.set_parent(&toplevel);
                }

                // Координаты клика переводим в систему координат окна.
                let (px, py) = row_ref
                    .translate_coordinates(&toplevel, x as f64, y as f64)
                    .unwrap_or((x as f64, y as f64));
                popup.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(
                    px as i32, py as i32, 1, 1,
                )));
                popup.popup();
            });
            row.add_controller(controller);
        }

        row
    }

    /// Контекстное меню профиля: подключиться, изменить, дублировать, удалить.
    fn profile_popover(&self, profile: Profile) -> Popover {
        let popover = Popover::new();
        popover.set_autohide(true);

        let box_ = GtkBox::new(Orientation::Vertical, 0);
        box_.set_margin_top(4);
        box_.set_margin_bottom(4);
        box_.set_margin_start(4);
        box_.set_margin_end(4);

        let add_item = |container: &GtkBox, label: &str, action: Box<dyn Fn(&Profile)>| {
            let button = Button::new();
            button.add_css_class("flat");
            button.add_css_class("remotix-menu-item");
            button.set_hexpand(true);
            let text = Label::new(Some(label));
            text.set_xalign(0.0);
            button.set_child(Some(&text));
            {
                let profile = profile.clone();
                button.connect_clicked(move |_| action(&profile));
            }
            container.append(&button);
        };

        let win = self.clone();
        add_item(&box_, "Подключиться", Box::new(move |p: &Profile| {
            win.connect_profile(p.clone());
        }));

        let win = self.clone();
        add_item(&box_, "Изменить…", Box::new(move |p: &Profile| {
            win.open_profile_editor(Some(p.id));
        }));

        let win = self.clone();
        add_item(&box_, "Дублировать", Box::new(move |p: &Profile| {
            win.duplicate_profile(p);
        }));

        let win = self.clone();
        add_item(&box_, "Удалить", Box::new(move |p: &Profile| {
            win.delete_profile(p);
        }));

        popover.set_child(Some(&box_));
        popover
    }

    /// Удаляет все строки боковой панели.
    fn clear_sidebar(&self) {
        crate::ui::clear_list(&self.sidebar);
    }

    /// Открывает подключение к выбранному профилю.
    pub fn connect_profile(&self, profile: Profile) {
        match profile.protocol {
            Protocol::Ssh => self.open_ssh_terminal(profile),
            Protocol::Rdp => self.open_rdp_session(profile),
            Protocol::Vnc => self.set_status("VNC: поддержка протокола в разработке"),
        }
    }

    /// Открывает SSH-сессию во встроенном терминале.
    pub fn open_ssh_terminal(&self, profile: Profile) {
        let title = format!(
            "ssh {}@{}",
            profile.username.as_deref().unwrap_or("?"),
            profile.host
        );

        // Если такая сессия уже открыта — просто переключаемся на её вкладку.
        if let Some(page) = self.existing_session(&title) {
            self.focus_session(&page);
            self.set_status(&format!("{title}: сессия уже открыта"));
            return;
        }

        let on_state = {
            let win = self.clone();
            let title = title.clone();
            let profile_id = profile.id;
            let started = crate::db::repository::now();
            Rc::new(move |state: SessionState| {
                win.log_connection(profile_id, started, &state);
                win.on_session_state(&title, state);
            })
        };

        let settings = crate::settings::Settings::new(self.state.db.clone());
        let font_size = settings.terminal_font_size();

        match TerminalTab::new_ssh(&title, SshConnection::new(profile), on_state, font_size) {
            Ok(tab) => {
                self.append_session(&title, "utilities-terminal-symbolic", &tab.root);
                self.set_status(&format!("{title}: подключение…"));
            }
            Err(e) => self.set_status(&format!("{title}: {e}")),
        }
    }

    /// Открывает RDP-сессию (просмотрщик удалённого рабочего стола).
    pub fn open_rdp_session(&self, profile: Profile) {
        let title = format!(
            "RDP {}@{}",
            profile.username.as_deref().unwrap_or("?"),
            profile.host
        );

        if let Some(page) = self.existing_session(&title) {
            self.focus_session(&page);
            self.set_status(&format!("{title}: сессия уже открыта"));
            return;
        }

        let on_state = {
            let win = self.clone();
            let title = title.clone();
            let profile_id = profile.id;
            let started = crate::db::repository::now();
            Rc::new(move |state: SessionState| {
                win.log_connection(profile_id, started, &state);
                win.on_session_state(&title, state);
            })
        };

        let viewer = RdpViewer::new(profile, on_state);
        self.append_session(&title, "computer-symbolic", viewer.root());
        self.set_status(&format!("{title}: подключение…"));
    }

    /// Страница уже открытой сессии с таким заголовком.
    fn existing_session(&self, title: &str) -> Option<gtk4::Widget> {
        self.session_pages
            .borrow()
            .iter()
            .find(|(name, _)| name == title)
            .map(|(_, page)| page.clone())
    }

    /// Переключает рабочую область на указанную вкладку.
    fn focus_session(&self, page: &gtk4::Widget) {
        if let Some(index) = self.notebook.page_num(page) {
            self.notebook.set_current_page(Some(index));
        }
    }

    /// Открывает вкладку журнала подключений.
    pub fn open_history_tab(&self) {
        let tab = HistoryTab::new(self.state.clone());
        self.append_session("История", "view-history-symbolic", &tab.root);
    }

    /// Открывает SFTP-клиент для выбранного профиля.
    pub fn open_sftp_tab(&self) {
        let profile = match self.selected_profile() {
            Some(p) => p,
            None => {
                self.set_status("Сначала выберите подключение в списке слева");
                return;
            }
        };

        let title = format!("SFTP {}", profile.host);
        let on_state = {
            let win = self.clone();
            let title = title.clone();
            Rc::new(move |state: SessionState| win.on_session_state(&title, state))
        };

        // Закрытие вкладки (F10) — нам нужна ссылка на страницу ноутбука,
        // которая появляется только после создания вкладки.
        let page_cell: Rc<RefCell<Option<gtk4::Widget>>> = Rc::new(RefCell::new(None));
        let on_close = {
            let notebook = self.notebook.clone();
            let page_cell = page_cell.clone();
            Rc::new(move || {
                if let Some(page) = page_cell.borrow().clone() {
                    if let Some(index) = notebook.page_num(&page) {
                        notebook.remove_page(Some(index));
                    }
                }
            })
        };

        let tab = SftpTab::new(profile, on_state, on_close);
        let page = tab.root.clone().upcast::<gtk4::Widget>();
        *page_cell.borrow_mut() = Some(page.clone());

        self.append_session(&title, "folder-remote-symbolic", &page);
        self.set_status(&format!("{title}: подключение…"));
    }

    /// Профиль, выбранный в боковой панели.
    pub fn selected_profile(&self) -> Option<Profile> {
        let row = self.sidebar.selected_row()?;
        let index = row.index();
        if index < 0 {
            return None;
        }
        self.profiles.borrow().get(index as usize).cloned()
    }

    /// Добавляет вкладку сессии в рабочую область.
    fn append_session(&self, title: &str, icon_name: &str, widget: &impl IsA<gtk4::Widget>) {
        let icon = Image::from_icon_name(icon_name);
        let label = Label::new(Some(title));

        let tab_box = GtkBox::new(Orientation::Horizontal, 6);
        tab_box.append(&icon);
        tab_box.append(&label);

        // Кнопка закрытия вкладки.
        let close = Button::from_icon_name("window-close-symbolic");
        close.add_css_class("remotix-tab-close");
        close.set_tooltip_text(Some("Закрыть вкладку"));
        tab_box.append(&close);

        let page = widget.clone().upcast::<gtk4::Widget>();
        self.notebook.append_page(&page, Some(&tab_box));
        self.notebook.set_tab_reorderable(&page, true);
        self.notebook.next_page();

        self.session_pages
            .borrow_mut()
            .push((title.to_string(), page.clone()));

        {
            let notebook = self.notebook.clone();
            let page = page.clone();
            let session_pages = self.session_pages.clone();
            close.connect_clicked(move |_| {
                if let Some(index) = notebook.page_num(&page) {
                    notebook.remove_page(Some(index));
                }
                session_pages.borrow_mut().retain(|(_, p)| *p != page);
            });
        }

        self.welcome.set_visible(false);
        self.on_session_state(title, SessionState::Connecting);
    }

    /// Записывает результат подключения в журнал.
    fn log_connection(&self, profile_id: i64, started: i64, state: &SessionState) {
        if profile_id <= 0 {
            return;
        }
        let ended = crate::db::repository::now();
        let (status, error) = match state {
            SessionState::Connected => ("success", None),
            SessionState::Failed(e) => ("error", Some(("E_CONNECT".to_string(), e.clone()))),
            _ => return,
        };
        let _ = self
            .state
            .db
            .add_history(profile_id, started, Some(ended), status, error);
    }

    /// Обновляет состояние сессии в строке состояния.
    pub fn on_session_state(&self, title: &str, state: SessionState) {
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(item) = sessions.iter_mut().find(|(name, _)| name == title) {
                item.1 = state.clone();
            } else {
                sessions.push((title.to_string(), state.clone()));
            }
        }

        let text = format!("{title}: {}", state.text());
        self.reset_status_style();
        self.status.add_css_class(state.css_class());
        self.status.set_text(&text);
    }

    /// Пишет сообщение в строку состояния.
    pub fn set_status(&self, text: &str) {
        self.reset_status_style();
        self.status.set_text(text);
    }

    /// Убирает классы состояния из строки состояния.
    fn reset_status_style(&self) {
        for class in [
            "remotix-status-ok",
            "remotix-status-error",
            "remotix-status-busy",
        ] {
            self.status.remove_css_class(class);
        }
    }
}

/// Главное меню приложения.
fn build_main_menu() -> gio::Menu {
    let menu = gio::Menu::new();

    let profiles = gio::Menu::new();
    profiles.append(Some("Новый профиль"), Some("win.new-profile"));
    profiles.append(Some("Дублировать профиль"), Some("win.duplicate-profile"));
    profiles.append(Some("Удалить профиль"), Some("win.delete-profile"));
    menu.append_section(None, &profiles);

    let services = gio::Menu::new();
    services.append(Some("Журнал подключений"), Some("win.history"));
    services.append(Some("SFTP-клиент"), Some("win.sftp"));
    menu.append_section(None, &services);

    let app = gio::Menu::new();
    app.append(Some("Параметры…"), Some("win.settings"));
    app.append(Some("О программе"), Some("win.about"));
    app.append(Some("Выход"), Some("win.quit"));
    menu.append_section(None, &app);

    menu
}

/// Разбор быстрого подключения "user@host" или "host".
fn quick_profile(text: &str) -> Option<Profile> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let (username, host) = match text.split_once('@') {
        Some((u, h)) => (Some(u.to_string()), h.to_string()),
        None => (None, text.to_string()),
    };
    Some(Profile {
        id: 0,
        name: host.clone(),
        protocol: Protocol::Ssh,
        host,
        port: 22,
        username,
        password: None,
        ssh_key_path: None,
        ssh_key_passphrase: None,
        root_password: None,
        group_id: None,
        tags: vec![],
        icon: None,
        notes: None,
        rdp_options: Default::default(),
        vnc_options: Default::default(),
        ssh_options: Default::default(),
        created_at: 0,
        updated_at: 0,
        last_connected_at: None,
    })
}
