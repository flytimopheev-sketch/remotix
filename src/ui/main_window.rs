//! Главное окно Remotix.
//!
//! Оформление повторяет макет `mockup.html`: шапка окна с поиском, боковая
//! панель со списком подключений, вкладки активных сессий и строка состояния.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    Box as GtkBox, Button, Entry, HeaderBar, Image, Label, ListBox, ListBoxRow, Notebook,
    Orientation, Overlay, Paned, ScrolledWindow, SearchEntry,
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
    /// Шапка окна (заголовок, кнопки, поиск).
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

        win.refresh_profiles();
        win
    }

    /// Переводит фокус в поле поиска (Ctrl+F).
    pub fn focus_search(&self) {
        self.search.grab_focus();
    }

    /// Открывает редактор профиля (None — создание нового).
    pub fn open_profile_editor(&self, profile_id: Option<i64>) {
        let win = self.clone();
        let editor = ProfileEditor::new(self.state.as_ref(), profile_id, move || {
            win.refresh_profiles();
        });
        editor.present_transient_for(
            self.root
                .root()
                .and_then(|w| w.downcast::<gtk4::Window>().ok())
                .as_ref(),
        );
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
        row
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

        match TerminalTab::new_ssh(&title, SshConnection::new(profile), on_state) {
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

        let tab = SftpTab::new(profile, on_state);
        self.append_session(&title, "folder-remote-symbolic", &tab.root);
        self.set_status(&format!("{title}: подключение…"));
    }

    /// Профиль, выбранный в боковой панели.
    fn selected_profile(&self) -> Option<Profile> {
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

        let page = widget.clone().upcast::<gtk4::Widget>();
        self.notebook.append_page(&page, Some(&tab_box));
        self.notebook.set_tab_reorderable(&page, true);
        self.notebook.next_page();

        self.welcome.set_visible(false);
        self.on_session_state(title, SessionState::Connecting);
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
        for class in [
            "remotix-status-ok",
            "remotix-status-error",
            "remotix-status-busy",
        ] {
            self.status.remove_css_class(class);
        }
        self.status.add_css_class(state.css_class());
        self.status.set_text(&text);
    }

    /// Пишет сообщение в строку состояния.
    pub fn set_status(&self, text: &str) {
        for class in [
            "remotix-status-ok",
            "remotix-status-error",
            "remotix-status-busy",
        ] {
            self.status.remove_css_class(class);
        }
        self.status.set_text(text);
    }
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
