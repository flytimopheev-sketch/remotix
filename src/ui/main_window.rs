use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{Button, Entry, Label, ListBox, Notebook, ScrolledWindow, SearchEntry, Window};

use crate::app::AppState;
use crate::models::{Profile, Protocol};
use crate::protocols::ssh::SshConnection;
use crate::ui::profile_editor::ProfileEditor;
use crate::ui::terminal::TerminalTab;

/// Главное окно: список профилей, поиск, быстрое подключение, сессии.
#[derive(Clone)]
pub struct MainWindow {
    pub root: gtk4::Box,
    state: Rc<AppState>,
    notebook: Notebook,
    search: SearchEntry,
    quick_entry: Entry,
    status: Label,
    list: ListBox,
    /// Профили, соответствующие строкам списка (с учётом фильтра поиска).
    profiles: Rc<RefCell<Vec<Profile>>>,
}

impl MainWindow {
    pub fn new(state: AppState) -> Self {
        let state = Rc::new(state);
        let root = gtk4::Box::new(gtk4::Orientation::Vertical, 6);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            root.set_property(m, 6);
        }

        // Панель инструментов
        let toolbar = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        let new_btn = Button::with_label("Новый профиль");
        let quick_entry = Entry::new();
        quick_entry.set_placeholder_text(Some("Быстрое подключение: user@host (SSH)"));
        let quick_btn = Button::with_label("Быстрое подключение");
        toolbar.append(&new_btn);
        toolbar.append(&quick_entry);
        toolbar.append(&quick_btn);
        root.append(&toolbar);

        // Поиск
        let search = SearchEntry::new();
        search.set_placeholder_text(Some("Поиск профиля по названию или адресу"));
        root.append(&search);

        // Вкладки: слева список подключений, дальше — открытые сессии
        let notebook = Notebook::new();
        let list = ListBox::new();
        list.set_selection_mode(gtk4::SelectionMode::Single);
        list.add_css_class("navigation-sidebar");
        let scroll = ScrolledWindow::new();
        scroll.set_child(Some(&list));
        notebook.append_page(&scroll, Some(&gtk4::Label::new(Some("Подключения"))));
        root.append(&notebook);

        // Статусная строка (онлайн/оффлайн/ошибка)
        let status = Label::new(Some("Готово"));
        status.set_halign(gtk4::Align::Start);
        root.append(&status);

        let win = Self {
            root,
            state,
            notebook,
            search: search.clone(),
            quick_entry: quick_entry.clone(),
            status,
            list: list.clone(),
            profiles: Rc::new(RefCell::new(Vec::new())),
        };

        let win_clone = win.clone();
        new_btn.connect_clicked(move |_| win_clone.open_profile_editor(None));
        let win_quick = win.clone();
        quick_btn.connect_clicked(move |_| {
            // Берём текст из поля быстрого подключения, а не из строки поиска.
            let text = win_quick.quick_entry.text().to_string();
            win_quick.status.set_text(&format!("Подключение к {text}…"));
            match quick_profile(&text) {
                Some(p) => win_quick.open_ssh_terminal(p),
                None => win_quick.status.set_text("Формат: user@host (SSH)"),
            }
        });

        // Поиск фильтрует список профилей.
        {
            let win = win.clone();
            search.connect_search_changed(move |_| win.refresh_profiles());
        }

        // Двойной щелчок по профилю — подключение.
        {
            let win = win.clone();
            list.connect_row_activated(move |_, row| {
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
                .and_then(|w| w.downcast::<Window>().ok())
                .as_ref(),
        );
    }

    /// Перечитывает профили из базы и обновляет список.
    pub fn refresh_profiles(&self) {
        let key = self.state.unlocked_key();
        let all = match self.state.db.list_profiles(&key) {
            Ok(profiles) => profiles,
            Err(e) => {
                self.status.set_text(&format!("Ошибка чтения профилей: {e}"));
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

        self.clear_list();
        for profile in &visible {
            let row = gtk4::ListBoxRow::new();

            let box_ = gtk4::Box::new(gtk4::Orientation::Vertical, 2);
            box_.set_margin_start(6);
            box_.set_margin_end(6);
            box_.set_margin_top(4);
            box_.set_margin_bottom(4);

            let title = gtk4::Label::new(Some(&profile.name));
            title.set_xalign(0.0);
            box_.append(&title);

            let details = gtk4::Label::new(Some(&format!(
                "{} · {}:{} · {}",
                profile.protocol.as_str(),
                profile.host,
                profile.port,
                profile.username.clone().unwrap_or_else(|| "—".to_string())
            )));
            details.set_xalign(0.0);
            details.add_css_class("dim-label");
            box_.append(&details);

            row.set_child(Some(&box_));
            self.list.append(&row);
        }

        let empty = visible.is_empty();
        *self.profiles.borrow_mut() = visible;

        if empty {
            self.status
                .set_text("Профилей пока нет — нажмите «Новый профиль»");
        }
    }

    /// Удаляет все строки списка.
    ///
    /// `gtk_list_box_remove_all()` появился только в GTK 4.12, а РЕД ОС
    /// собирается с GTK 4.6+, поэтому строки удаляются вручную.
    fn clear_list(&self) {
        while let Some(row) = self.list.first_child() {
            self.list.remove(&row);
        }
    }

    /// Открывает подключение к выбранному профилю.
    pub fn connect_profile(&self, profile: Profile) {
        match profile.protocol {
            Protocol::Ssh => self.open_ssh_terminal(profile),
            Protocol::Rdp => self
                .status
                .set_text("RDP: графический просмотрщик в разработке"),
            Protocol::Vnc => self
                .status
                .set_text("VNC: графический просмотрщик в разработке"),
        }
    }

    /// Открывает вкладку SSH-терминала (VTE) для профиля.
    pub fn open_ssh_terminal(&self, profile: Profile) {
        match TerminalTab::new_ssh(
            &format!(
                "ssh {}@{}",
                profile.username.as_deref().unwrap_or("?"),
                profile.host
            ),
            SshConnection::new(profile.clone()),
        ) {
            Ok(tab) => {
                self.notebook.append_page(
                    &tab.root,
                    Some(&gtk4::Label::new(Some(&format!("🗄 {}", tab.title)))),
                );
                self.notebook.next_page();
                self.status.set_text(&format!(
                    "● ssh {}@{}: подключение…",
                    profile.username.as_deref().unwrap_or("?"),
                    profile.host
                ));
            }
            Err(e) => self.status.set_text(&format!("● Ошибка: {e}")),
        }
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
