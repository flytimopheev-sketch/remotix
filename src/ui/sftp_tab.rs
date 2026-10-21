//! Вкладка SFTP: две панели — локальный каталог и каталог на сервере.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use gtk4::prelude::*;
use gtk4::{glib, Box as GtkBox, Button, Label, ListBox, ListBoxRow, Paned, ScrolledWindow};

use crate::models::Profile;
use crate::ui::sftp_client::SftpPanel;
use crate::ui::SessionState;

/// События от потока SFTP в интерфейс.
enum ToUi {
    Remote(Vec<(String, u64, i64)>),
    Local(Vec<(String, u64, i64)>),
    Error(String),
    Status(String),
}

/// Команды интерфейса потоку SFTP.
enum ToSftp {
    Refresh,
    Upload(String),
    Download(String),
    Mkdir(String),
    Remove(String),
}

/// Вкладка SFTP-клиента.
pub struct SftpTab {
    pub root: GtkBox,
}

impl SftpTab {
    /// Создаёт вкладку SFTP для профиля.
    pub fn new(profile: Profile, on_state: Rc<dyn Fn(SessionState)>) -> Self {
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);

        // ---------------- Панель инструментов ----------------
        let toolbar = GtkBox::new(gtk4::Orientation::Horizontal, 8);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            toolbar.set_property(m, 8);
        }
        let refresh = Button::with_label("Обновить");
        let upload = Button::with_label("⇩ Загрузить на сервер");
        let download = Button::with_label("⇧ Скачать с сервера");
        let mkdir = Button::with_label("Новая папка");
        let remove = Button::with_label("Удалить");
        let status = Label::new(Some(""));
        status.set_xalign(0.0);
        status.set_hexpand(true);
        status.add_css_class("remotix-field-caption");
        toolbar.append(&refresh);
        toolbar.append(&upload);
        toolbar.append(&download);
        toolbar.append(&mkdir);
        toolbar.append(&remove);
        toolbar.append(&status);

        // ---------------- Списки ----------------
        let local_list = ListBox::new();
        local_list.set_selection_mode(gtk4::SelectionMode::Single);
        local_list.add_css_class("remotix-sidebar");

        let remote_list = ListBox::new();
        remote_list.set_selection_mode(gtk4::SelectionMode::Single);
        remote_list.add_css_class("remotix-sidebar");

        let local_title = Label::new(Some("Локальный каталог"));
        local_title.set_xalign(0.0);
        local_title.add_css_class("remotix-group");
        let remote_title = Label::new(Some("Каталог на сервере"));
        remote_title.set_xalign(0.0);
        remote_title.add_css_class("remotix-group");

        let local_pane = GtkBox::new(gtk4::Orientation::Vertical, 0);
        local_pane.append(&local_title);
        let local_scroll = ScrolledWindow::new();
        local_scroll.set_child(Some(&local_list));
        local_scroll.set_vexpand(true);
        local_pane.append(&local_scroll);

        let remote_pane = GtkBox::new(gtk4::Orientation::Vertical, 0);
        remote_pane.append(&remote_title);
        let remote_scroll = ScrolledWindow::new();
        remote_scroll.set_child(Some(&remote_list));
        remote_scroll.set_vexpand(true);
        remote_pane.append(&remote_scroll);

        let paned = Paned::new(gtk4::Orientation::Horizontal);
        paned.set_start_child(Some(&local_pane));
        paned.set_end_child(Some(&remote_pane));
        paned.set_position(420);
        paned.set_vexpand(true);

        root.append(&toolbar);
        root.append(&paned);

        // ---------------- Поток SFTP ----------------
        let (tx_ui, rx_ui) = mpsc::channel::<ToUi>();
        let (tx_sftp, rx_sftp) = mpsc::channel::<ToSftp>();
        let local_names: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let remote_names: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));

        {
            let tx_ui = tx_ui.clone();
            std::thread::spawn(move || {
                let mut panel = match SftpPanel::new(&profile) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx_ui.send(ToUi::Error(format!("Не удалось подключиться: {e}")));
                        return;
                    }
                };
                let _ = tx_ui.send(ToUi::Status("SFTP-сессия установлена".to_string()));

                loop {
                    // Команды интерфейса.
                    while let Ok(cmd) = rx_sftp.try_recv() {
                        let result: Result<String, String> = match cmd {
                            ToSftp::Refresh => Ok(String::new()),
                            ToSftp::Upload(name) => panel
                                .upload(&crate::config::home_dir().join(&name), &name)
                                .map(|_| format!("Файл {name} загружен")),
                            ToSftp::Download(name) => {
                                let target = crate::config::home_dir().join(&name);
                                panel.download(&name, &target).map(|_| format!("Файл {name} скачан"))
                            }
                            ToSftp::Mkdir(name) => {
                                panel.mkdir(&name).map(|_| format!("Каталог {name} создан"))
                            }
                            ToSftp::Remove(name) => {
                                panel.remove(&name).map(|_| format!("Объект {name} удалён"))
                            }
                        };
                        match result {
                            Ok(msg) => {
                                if !msg.is_empty() {
                                    let _ = tx_ui.send(ToUi::Status(msg));
                                }
                            }
                            Err(e) => {
                                let _ = tx_ui.send(ToUi::Error(e));
                            }
                        }
                    }

                    // Списки.
                    match panel.remote_list() {
                        Ok(files) => {
                            let _ = tx_ui.send(ToUi::Remote(files));
                        }
                        Err(e) => {
                            let _ = tx_ui.send(ToUi::Error(e));
                        }
                    }
                    let _ = tx_ui.send(ToUi::Local(list_local()));

                    std::thread::sleep(Duration::from_millis(400));
                }
            });
        }

        // ---------------- Отрисовка ----------------
        {
            let local_list = local_list.clone();
            let remote_list = remote_list.clone();
            let status = status.clone();
            let on_state = on_state.clone();
            let local_names = local_names.clone();
            let remote_names = remote_names.clone();

            glib::timeout_add_local(Duration::from_millis(150), move || {
                loop {
                    match rx_ui.try_recv() {
                        Ok(ToUi::Remote(files)) => {
                            fill_list(&remote_list, &files, &remote_names);
                        }
                        Ok(ToUi::Local(files)) => {
                            fill_list(&local_list, &files, &local_names);
                        }
                        Ok(ToUi::Error(e)) => {
                            status.set_text(&e);
                        }
                        Ok(ToUi::Status(s)) => {
                            status.set_text(&s);
                            on_state(SessionState::Connected);
                        }
                        Err(_) => return glib::ControlFlow::Continue,
                    }
                }
            });
        }

        // ---------------- Кнопки ----------------
        {
            let tx = tx_sftp.clone();
            refresh.connect_clicked(move |_| {
                let _ = tx.send(ToSftp::Refresh);
            });
        }
        {
            let tx = tx_sftp.clone();
            let local_list = local_list.clone();
            let local_names = local_names.clone();
            upload.connect_clicked(move |_| {
                if let Some(name) = selected_name(&local_list, &local_names) {
                    let _ = tx.send(ToSftp::Upload(name));
                }
            });
        }
        {
            let tx = tx_sftp.clone();
            let remote_list = remote_list.clone();
            let remote_names = remote_names.clone();
            download.connect_clicked(move |_| {
                if let Some(name) = selected_name(&remote_list, &remote_names) {
                    let _ = tx.send(ToSftp::Download(name));
                }
            });
        }
        {
            let tx = tx_sftp.clone();
            mkdir.connect_clicked(move |_| {
                let _ = tx.send(ToSftp::Mkdir("new-folder".to_string()));
            });
        }
        {
            let tx = tx_sftp.clone();
            let remote_list = remote_list.clone();
            let remote_names = remote_names.clone();
            remove.connect_clicked(move |_| {
                if let Some(name) = selected_name(&remote_list, &remote_names) {
                    let _ = tx.send(ToSftp::Remove(name));
                }
            });
        }

        Self { root }
    }
}

/// Имя выбранного элемента списка.
fn selected_name(list: &ListBox, names: &Rc<RefCell<Vec<String>>>) -> Option<String> {
    let row = list.selected_row()?;
    let index = row.index();
    if index < 0 {
        return None;
    }
    names.borrow().get(index as usize).cloned()
}

/// Заполняет список файлами.
fn fill_list(list: &ListBox, files: &[(String, u64, i64)], names: &Rc<RefCell<Vec<String>>>) {
    crate::ui::clear_list(list);
    let mut collected = Vec::with_capacity(files.len());
    for (name, size, _) in files {
        collected.push(name.clone());
        let row = ListBoxRow::new();
        let label = Label::new(Some(&format!("{name}  ({})", human_size(*size))));
        label.set_xalign(0.0);
        label.set_margin_start(8);
        label.set_margin_end(8);
        label.set_margin_top(3);
        label.set_margin_bottom(3);
        row.set_child(Some(&label));
        list.append(&row);
    }
    *names.borrow_mut() = collected;
}

/// Список файлов локального каталога.
fn list_local() -> Vec<(String, u64, i64)> {
    let dir = crate::config::home_dir();
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let mtime = entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            out.push((name, size, mtime));
        }
    }
    out.sort();
    out
}

/// «Человекочитаемый» размер файла.
fn human_size(size: u64) -> String {
    const UNITS: [&str; 4] = ["Б", "КБ", "МБ", "ГБ"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
