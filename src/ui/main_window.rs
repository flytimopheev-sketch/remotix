use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::glib::clone;
use gtk4::{Button, Entry, Label, Notebook, SearchEntry, Window};

use crate::app::AppState;
use crate::models::{Profile, Protocol};
use crate::protocols::ssh::SshConnection;
use crate::ui::profile_editor::ProfileEditor;
use crate::ui::terminal::TerminalTab;

/// Главное окно: дерево групп/профилей, поиск, журнал, быстрое подключение.
#[derive(Clone)]
pub struct MainWindow {
    pub root: gtk4::Box,
    state: Rc<AppState>,
    notebook: Notebook,
    search: SearchEntry,
    status: Label,
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
        root.append(&search);

        // Вкладки: слева список-заготовка дерева, дальше — открытые сессии
        let notebook = Notebook::new();
        let tree = gtk4::TreeView::new();
        let scroll = gtk4::ScrolledWindow::new();
        scroll.set_child(Some(&tree));
        notebook.append_page(&scroll, Some(&gtk4::Label::new(Some("Подключения"))));
        root.append(&notebook);

        // Статусная строка (онлайн/оффлайн/ошибка)
        let status = Label::new(Some("Готово"));
        status.set_halign(gtk4::Align::Start);
        root.append(&status);

        let win = Self { root, state, notebook, search, status };

        new_btn.connect_clicked(clone!(@weak win => move |_| win.open_profile_editor(None)));
        quick_btn.connect_clicked(clone!(@weak win => move |_| {
            let text = win.search.text().to_string(); // быстрый ввод берём из поля поиска
            win.status.set_text(&format!("Подключение к {text}…"));
            match quick_profile(&text) {
                Some(p) => win.open_ssh_terminal(p),
                None => win.status.set_text("Формат: user@host (SSH)"),
            }
        }));

        win
    }

    pub fn open_profile_editor(&self, profile_id: Option<i64>) {
        let editor = ProfileEditor::new(&self.state, profile_id);
        editor.present_transient_for(self.root.root().and_then(|w| w.downcast::<Window>().ok()).as_ref());
    }

    /// Открывает вкладку SSH-терминала (VTE) для профиля.
    pub fn open_ssh_terminal(&self, profile: Profile) {
        match TerminalTab::new_ssh(&format!("ssh {}@{}", profile.username.as_deref().unwrap_or("?"), profile.host), SshConnection::new(profile.clone())) {
            Ok(tab) => {
                self.notebook.append_page(
                    &tab.root,
                    Some(&gtk4::Label::new(Some(&format!("🗄 {}", tab.title)))),
                );
                self.notebook.next_page();
                self.status.set_text(&format!("● ssh {}@{}: подключение…", profile.username.as_deref().unwrap_or("?"), profile.host));
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
