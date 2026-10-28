//! Вкладка SFTP: двухпанельный файловый менеджер в духе Far/Midnight Commander.
//!
//! Управление с клавиатуры:
//!   * `↑` / `↓`      — выбор элемента;
//!   * `Enter`        — войти в каталог;
//!   * `Backspace`    — перейти в родительский каталог;
//!   * `Tab`          — переключить панель;
//!   * `F5`           — скопировать из активной панели в другую;
//!   * `F6`           — переименовать;
//!   * `F7`           — создать каталог;
//!   * `F8`           — удалить;
//!   * `F10`          — закрыть вкладку;
//!   * `Ctrl+R`       — обновить;
//!   * `Ctrl+C`       — скопировать объект в буфер обмена;
//!   * `Ctrl+V`       — вставить объекты из буфера обмена;
//!   * `Delete`       — удалить выделенный объект.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gtk4::prelude::*;
use gtk4::{glib, Box as GtkBox, Label, ListBox, ListBoxRow, Paned, ScrolledWindow};

use crate::models::Profile;
use crate::protocols::ssh::{HostKeyConfig, HostKeyPrompt};
use crate::ui::sftp_client::{local_list as list_local_dir, Entry, SftpPanel};
use crate::ui::SessionState;

/// События от интерфейса к потоку SFTP.
enum ToSftp {
    Refresh,
    Cd(String),
    CdUp,
    Upload(String),
    Download(String),
    Mkdir(String),
    Remove(String),
    Rename(String, String),
    /// Копирование файла на сервере (из текущего каталога в текущий).
    CopyRemote(String, String),
}

/// Объект в буфере обмена файлового менеджера.
#[derive(Clone, Debug)]
enum ClipItem {
    /// Файл в локальном каталоге.
    Local(String),
    /// Файл на сервере.
    Remote(String),
}

/// События от потока SFTP к интерфейсу.
enum ToUi {
    /// Список удалённого каталога и его путь.
    Remote(Vec<Entry>, String),
    Status(String),
    Error(String),
}

/// Выполняет команду файлового менеджера в потоке SFTP.
fn run_sftp_command(
    panel: &mut SftpPanel,
    local_dir: &Mutex<std::path::PathBuf>,
    cmd: ToSftp,
) -> Result<String, String> {
    match cmd {
        ToSftp::Refresh => Ok(String::new()),
        ToSftp::Cd(path) => panel.cd(&path).map(|_| String::new()),
        ToSftp::CdUp => panel.cd_up().map(|_| String::new()),
        ToSftp::Upload(name) => {
            let from = local_dir.lock().unwrap().join(&name);
            panel
                .upload(&from, &name)
                .map(|_| format!("Файл {name} загружен на сервер"))
        }
        ToSftp::Download(name) => {
            let to = local_dir.lock().unwrap().join(&name);
            panel
                .download(&name, &to)
                .map(|_| format!("Файл {name} скачан"))
        }
        ToSftp::Mkdir(name) => panel.mkdir(&name).map(|_| format!("Каталог {name} создан")),
        ToSftp::Remove(name) => panel.remove(&name).map(|_| format!("Объект {name} удалён")),
        ToSftp::Rename(from, to) => {
            panel.rename(&from, &to).map(|_| format!("Переименовано в {to}"))
        }
        ToSftp::CopyRemote(from, to) => panel
            .copy(&from, &to)
            .map(|_| format!("Файл {to} создан на сервере")),
    }
}

/// Панель файлового менеджера.
struct Pane {
    /// Список элементов.
    list: ListBox,
    /// Заголовок с путём.
    path: Label,
    /// Содержимое каталога (в списке индекс 0 — пункт «..»).
    entries: Rc<RefCell<Vec<Entry>>>,
    /// Контейнер панели.
    box_: GtkBox,
}

impl Pane {
    fn new(title: &str, remote: bool) -> Self {
        let header = gtk4::Box::new(gtk4::Orientation::Horizontal, 6);
        header.set_margin_start(8);
        header.set_margin_end(8);
        header.set_margin_top(4);
        header.set_margin_bottom(4);

        let path = Label::new(Some(title));
        path.set_xalign(0.0);
        path.set_hexpand(true);
        path.set_ellipsize(gtk4::pango::EllipsizeMode::Start);
        path.add_css_class("remotix-pane-path");
        header.append(&path);

        let list = ListBox::new();
        list.set_selection_mode(gtk4::SelectionMode::Single);
        // В GTK4 список по умолчанию активируется одиночным щелчком. В
        // файловом менеджере это мешает выделить каталог для копирования
        // или удаления: щелчок сразу входил бы в него. Вход — двойным
        // щелчком или Enter.
        list.set_activate_on_single_click(false);
        // Список должен получать фокус — иначе стрелки не перемещают выделение.
        list.set_focusable(true);
        list.add_css_class("remotix-file-list");

        let scrolled = ScrolledWindow::new();
        scrolled.set_child(Some(&list));
        scrolled.set_vexpand(true);
        scrolled.set_hscrollbar_policy(gtk4::PolicyType::Never);

        let box_ = GtkBox::new(gtk4::Orientation::Vertical, 0);
        box_.add_css_class(if remote {
            "remotix-pane-remote"
        } else {
            "remotix-pane-local"
        });
        box_.append(&header);
        box_.append(&scrolled);

        Self {
            list,
            path,
            entries: Rc::new(RefCell::new(Vec::new())),
            box_,
        }
    }
}

/// Вкладка SFTP-клиента.
pub struct SftpTab {
    pub root: GtkBox,
}

impl SftpTab {
    /// Создаёт вкладку SFTP для профиля.
    pub fn new(
        profile: Profile,
        on_state: Rc<dyn Fn(SessionState)>,
        on_close: Rc<dyn Fn()>,
    ) -> Self {
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);

        let (tx_ui, rx_ui) = mpsc::channel::<ToUi>();
        let (tx_sftp, rx_sftp) = mpsc::channel::<ToSftp>();
        let (tx_hk_prompt, rx_hk_prompt) = mpsc::channel::<HostKeyPrompt>();
        let (tx_hk_answer, rx_hk_answer) = mpsc::channel::<bool>();

        // Текущий локальный каталог — общий для интерфейса и потока.
        let local_dir = Arc::new(Mutex::new(crate::config::home_dir()));

        // Буфер обмена файлового менеджера (Ctrl+C / Ctrl+V).
        let clip: Rc<RefCell<Vec<ClipItem>>> = Rc::new(RefCell::new(Vec::new()));

        // ---------------- Строка состояния ----------------
        let status = Label::new(Some("Готово"));
        status.set_xalign(0.0);
        // Фиксированная ширина: длинный текст не должен растягивать окно.
        status.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        status.set_lines(1);
        status.set_width_chars(60);
        status.add_css_class("remotix-field-caption");
        let statusbar = GtkBox::new(gtk4::Orientation::Horizontal, 8);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            statusbar.set_property(m, 6);
        }
        statusbar.append(&status);
        root.append(&statusbar);

        // ---------------- Панели ----------------
        let local = Pane::new("Локальный", false);
        let remote = Pane::new("Сервер", true);

        let local_box = local.box_.clone();
        let remote_box = remote.box_.clone();
        let local_list = local.list.clone();
        let remote_list = remote.list.clone();
        let local_path = local.path.clone();
        let remote_path = remote.path.clone();
        let local_entries = local.entries.clone();
        let remote_entries = remote.entries.clone();

        let paned = Paned::new(gtk4::Orientation::Horizontal);
        paned.set_start_child(Some(&local_box));
        paned.set_end_child(Some(&remote_box));
        paned.set_position(480);
        paned.set_vexpand(true);
        root.append(&paned);

        // Фокус на удалённой панели: сразу доступны стрелки и Enter.
        remote_list.grab_focus();

        // Вкладку показывают позже, и ноутбук забирает фокус на себя —
        // поэтому возвращаем фокус в список, как только панель показана.
        {
            let remote_list = remote_list.clone();
            remote_list.connect_map(move |list| {
                list.grab_focus();
            });
        }

        // ---------------- Поток SFTP ----------------
        {
            let tx_ui = tx_ui.clone();
            let local_dir = local_dir.clone();
            std::thread::spawn(move || {
                let verifier = move |prompt: &HostKeyPrompt| {
                    tx_hk_prompt.send(prompt.clone()).is_ok()
                        && rx_hk_answer
                            .recv_timeout(Duration::from_secs(300))
                            .unwrap_or(false)
                };
                let host_key = HostKeyConfig {
                    accept_new: false,
                    verifier: Some(&verifier),
                    ..Default::default()
                };
                let mut panel = match SftpPanel::new_with_host_key(&profile, &host_key) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = tx_ui.send(ToUi::Error(format!("Не удалось подключиться: {e}")));
                        return;
                    }
                };
                let _ = tx_ui.send(ToUi::Status("SFTP-сессия установлена".to_string()));

                // Список перерисовывается только при реальном изменении:
                // постоянная перестройка ломала двойной щелчок по каталогу
                // и сбрасывала прокрутку.
                let mut last_listing: Option<(String, Vec<Entry>)> = None;
                let mut last_error: Option<String> = None;

                loop {
                    panel.keepalive();
                    // Ждём команду, но просыпаемся и сами, чтобы заметить
                    // изменения каталога, сделанные снаружи.
                    let first = match rx_sftp.recv_timeout(Duration::from_millis(1000)) {
                        Ok(cmd) => Some(cmd),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };

                    let mut changed = false;
                    for cmd in first.into_iter().chain(rx_sftp.try_iter()) {
                        changed = true;
                        match run_sftp_command(&mut panel, &local_dir, cmd) {
                            Ok(msg) if !msg.is_empty() => {
                                let _ = tx_ui.send(ToUi::Status(msg));
                            }
                            Ok(_) => {}
                            Err(e) => {
                                let _ = tx_ui.send(ToUi::Error(e));
                            }
                        }
                    }

                    match panel.remote_list() {
                        Ok(files) => {
                            let path = panel.remote_path();
                            let listing_changed = changed
                                || last_listing
                                    .as_ref()
                                    .is_none_or(|(last_path, last_files)| {
                                        last_path != &path || last_files != &files
                                    });
                            if listing_changed {
                                last_listing = Some((path.clone(), files.clone()));
                                let _ = tx_ui.send(ToUi::Remote(files, path));
                            }
                            last_error = None;
                        }
                        Err(e) => {
                            if last_error.as_deref() != Some(e.as_str()) {
                                last_error = Some(e.clone());
                                let _ = tx_ui.send(ToUi::Error(e));
                            }
                        }
                    }
                }
            });
        }

        // ---------------- Отрисовка удалённого списка ----------------
        {
            let status_out = status.clone();
            let on_state = on_state.clone();
            let list_ref = remote_list.clone();
            let entries_ref = remote_entries.clone();

            glib::timeout_add_local(Duration::from_millis(150), move || {
                loop {
                    match rx_ui.try_recv() {
                        Ok(ToUi::Remote(files, path)) => {
                            let title = format!("Сервер: {path}");
                            if remote_path.text().as_str() != title {
                                // После входа в другой каталог выделяем «..»:
                                // прежний номер строки может указывать в
                                // пустоту или на случайный файл.
                                list_ref.select_row(None::<&ListBoxRow>);
                            }
                            fill_list(&list_ref, &files);
                            remote_path.set_text(&title);
                            *entries_ref.borrow_mut() = files;
                        }
                        Ok(ToUi::Status(s)) => {
                            status_out.set_text(&s);
                            on_state(SessionState::Connected);
                        }
                        Ok(ToUi::Error(e)) => {
                            status_out.set_text(&crate::logging::sanitize(&e));
                            if crate::protocols::ssh::is_host_key_mismatch(&e) {
                                on_state(SessionState::Failed(e.clone()));
                            }
                        }
                        Err(_) => return glib::ControlFlow::Continue,
                    }
                }
            });
        }

        // ---------------- Проверка ключа SSH-хоста ----------------
        {
            let tx_hk_answer = tx_hk_answer.clone();
            let parent_weak = root.downgrade();
            glib::timeout_add_local(Duration::from_millis(100), move || loop {
                match rx_hk_prompt.try_recv() {
                    Ok(prompt) => {
                        let tx_answer = tx_hk_answer.clone();
                        let parent = parent_weak
                            .upgrade()
                            .and_then(|widget| widget.root())
                            .and_then(|root| root.downcast::<gtk4::Window>().ok());
                        crate::ui::host_key::ask_unknown(
                            parent.as_ref(),
                            prompt,
                            move |accepted| {
                                let _ = tx_answer.send(accepted);
                            },
                        );
                    }
                    Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                    Err(mpsc::TryRecvError::Disconnected) => return glib::ControlFlow::Break,
                }
            });
        }

        // ---------------- Локальная панель ----------------
        {
            let dir = local_dir.clone();
            let list = local_list.clone();
            let path = local_path.clone();
            let entries = local_entries.clone();
            let tx = tx_sftp.clone();

            // Перечитать локальный каталог.
            let reload = {
                let dir = dir.clone();
                let list = list.clone();
                let path = path.clone();
                let entries = entries.clone();
                move || {
                    let current = dir.lock().unwrap().clone();
                    let files = list_local_dir(&current);
                    let title = format!("Локальный: {}", current.display());
                    if path.text().as_str() != title {
                        // Новый каталог — выделяем «..», а не строку с тем же
                        // номером из прежнего каталога.
                        list.select_row(None::<&ListBoxRow>);
                    }
                    fill_list(&list, &files);
                    path.set_text(&title);
                    *entries.borrow_mut() = files;
                }
            };
            reload();

            // Вход в каталог.
            let activate: Rc<dyn Fn(i32)> = {
                let reload = reload.clone();
                let dir = dir.clone();
                let entries = entries.clone();
                Rc::new(move |index: i32| {
                    let mut current = dir.lock().unwrap();
                    if index <= 0 {
                        // «..» — в родительский каталог.
                        if let Some(parent) = current.parent() {
                            *current = parent.to_path_buf();
                        }
                        drop(current);
                        reload();
                        return;
                    }
                    let items = entries.borrow();
                    let Some(entry) = items.get(index as usize - 1) else {
                        return;
                    };
                    if !entry.is_dir {
                        return;
                    }
                    let name = entry.name.clone();
                    drop(items);
                    *current = current.join(&name);
                    drop(current);
                    reload();
                })
            };

            {
                let activate = activate.clone();
                list.connect_row_activated(move |_, row| {
                    activate(row.index());
                });
            }

            // Клавиши локальной панели.
            let controller = gtk4::EventControllerKey::new();
            controller.connect_key_pressed({
                let dir = dir.clone();
                let entries = entries.clone();
                let list = list.clone();
                let reload = reload.clone();
                let tx = tx.clone();
                let other = remote_list.clone();
                let activate = activate.clone();
                let clip = clip.clone();
                move |_, key, _, state| {
                    let ctrl = state.contains(gtk4::gdk::ModifierType::CONTROL_MASK);
                    let selected = selected_name(&list, &entries);
                    match key.name().as_deref() {
                        Some("Tab") => {
                            // Переключаемся на соседнюю панель.
                            other.grab_focus();
                            return glib::Propagation::Stop;
                        }
                        Some("Up") | Some("Down") | Some("Home") | Some("End") => {
                            // GTK4 не листает список стрелками — делаем сами.
                            move_selection(&list, key.name().as_deref().unwrap_or("Down"));
                            return glib::Propagation::Stop;
                        }
                        Some("Return") | Some("KP_Enter") => {
                            // Открыть выделенный каталог.
                            if let Some(row) = list.selected_row() {
                                activate(row.index());
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("c") | Some("C") if ctrl => {
                            // Скопировать объект в буфер обмена.
                            if let Some(name) = selected {
                                clip.borrow_mut().push(ClipItem::Local(name));
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("v") | Some("V") if ctrl => {
                            // Вставить объекты из буфера обмена.
                            let items = clip.borrow().clone();
                            for item in items {
                                match item {
                                    ClipItem::Local(name) => {
                                        let current = dir.lock().unwrap().clone();
                                        let src = current.join(&name);
                                        let dst = current.join(unique_copy_name(&current, &name));
                                        let _ = std::fs::copy(&src, &dst);
                                    }
                                    ClipItem::Remote(name) => {
                                        let _ = tx.send(ToSftp::Download(name));
                                    }
                                }
                            }
                            reload();
                            return glib::Propagation::Stop;
                        }
                        Some("Delete") => {
                            // Удалить выделенный объект.
                            if let Some(name) = selected {
                                let path = dir.lock().unwrap().join(&name);
                                let _ = if path.is_dir() {
                                    std::fs::remove_dir_all(&path)
                                } else {
                                    std::fs::remove_file(&path)
                                };
                                reload();
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("BackSpace") => {
                            let mut current = dir.lock().unwrap();
                            if let Some(parent) = current.parent() {
                                *current = parent.to_path_buf();
                            }
                            drop(current);
                            reload();
                            return glib::Propagation::Stop;
                        }
                        Some("F5") => {
                            // Скопировать на сервер.
                            if let Some(name) = selected {
                                let _ = tx.send(ToSftp::Upload(name));
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("F6") => {
                            // Переименовать локально.
                            if let Some(name) = selected {
                                let new_name = format!("{name}.renamed");
                                let from = dir.lock().unwrap().join(&name);
                                let to = dir.lock().unwrap().join(&new_name);
                                if std::fs::rename(&from, &to).is_ok() {
                                    reload();
                                }
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("F7") => {
                            let _ = tx.send(ToSftp::Mkdir("new-folder".to_string()));
                            return glib::Propagation::Stop;
                        }
                        Some("F8") => {
                            // Удалить локально.
                            if let Some(name) = selected {
                                let path = dir.lock().unwrap().join(&name);
                                let _ = if path.is_dir() {
                                    std::fs::remove_dir_all(&path)
                                } else {
                                    std::fs::remove_file(&path)
                                };
                                reload();
                            }
                            return glib::Propagation::Stop;
                        }
                        _ => {}
                    }
                    glib::Propagation::Proceed
                }
            });
            list.add_controller(controller);
        }

        // ---------------- Удалённая панель ----------------
        {
            // Вход в каталог на сервере.
            let activate: Rc<dyn Fn(i32)> = {
                let entries = remote_entries.clone();
                let tx = tx_sftp.clone();
                Rc::new(move |index: i32| {
                    if index <= 0 {
                        let _ = tx.send(ToSftp::CdUp);
                        return;
                    }
                    let items = entries.borrow();
                    let Some(entry) = items.get(index as usize - 1) else {
                        return;
                    };
                    // Признак «каталог» у некоторых серверов недоступен,
                    // поэтому пробуем перейти всегда: если это файл,
                    // панель сообщит об ошибке.
                    let name = entry.name.clone();
                    drop(items);
                    let _ = tx.send(ToSftp::Cd(name));
                })
            };

            {
                let activate = activate.clone();
                remote_list.connect_row_activated(move |_, row| {
                    activate(row.index());
                });
            }

            // Клавиши удалённой панели.
            let controller = gtk4::EventControllerKey::new();
            controller.connect_key_pressed({
                let entries = remote_entries.clone();
                let list = remote_list.clone();
                let tx = tx_sftp.clone();
                let other = local_list.clone();
                let activate = activate.clone();
                let clip = clip.clone();
                move |_, key, _, state| {
                    let ctrl = state.contains(gtk4::gdk::ModifierType::CONTROL_MASK);
                    let selected = selected_name(&list, &entries);
                    match key.name().as_deref() {
                        Some("Tab") => {
                            // Переключаемся на соседнюю панель.
                            other.grab_focus();
                            return glib::Propagation::Stop;
                        }
                        Some("Up") | Some("Down") | Some("Home") | Some("End") => {
                            // GTK4 не листает список стрелками — делаем сами.
                            move_selection(&list, key.name().as_deref().unwrap_or("Down"));
                            return glib::Propagation::Stop;
                        }
                        Some("Return") | Some("KP_Enter") => {
                            // Открыть выделенный каталог на сервере.
                            if let Some(row) = list.selected_row() {
                                activate(row.index());
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("BackSpace") => {
                            let _ = tx.send(ToSftp::CdUp);
                            return glib::Propagation::Stop;
                        }
                        Some("F5") => {
                            if let Some(name) = selected {
                                let _ = tx.send(ToSftp::Download(name));
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("F6") => {
                            // Переименовать на сервере.
                            if let Some(name) = selected {
                                let _ = tx.send(ToSftp::Rename(
                                    name.clone(),
                                    format!("{name}.renamed"),
                                ));
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("F7") => {
                            let _ = tx.send(ToSftp::Mkdir("new-folder".to_string()));
                            return glib::Propagation::Stop;
                        }
                        Some("F8") => {
                            if let Some(name) = selected {
                                let _ = tx.send(ToSftp::Remove(name));
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("c") | Some("C") if ctrl => {
                            // Скопировать объект в буфер обмена.
                            if let Some(name) = selected {
                                clip.borrow_mut().push(ClipItem::Remote(name));
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("v") | Some("V") if ctrl => {
                            // Вставить объекты из буфера обмена на сервер.
                            let items = clip.borrow().clone();
                            for item in items {
                                match item {
                                    ClipItem::Local(name) => {
                                        let _ = tx.send(ToSftp::Upload(name));
                                    }
                                    ClipItem::Remote(name) => {
                                        let _ = tx.send(ToSftp::CopyRemote(
                                            name.clone(),
                                            unique_copy_name(
                                                &std::path::PathBuf::from("."),
                                                &name,
                                            ),
                                        ));
                                    }
                                }
                            }
                            return glib::Propagation::Stop;
                        }
                        Some("Delete") => {
                            if let Some(name) = selected {
                                let _ = tx.send(ToSftp::Remove(name));
                            }
                            return glib::Propagation::Stop;
                        }
                        _ => {}
                    }
                    glib::Propagation::Proceed
                }
            });
            remote_list.add_controller(controller);
        }

        // ---------------- Общие горячие клавиши ----------------
        {
            let tx = tx_sftp.clone();
            let on_close = on_close.clone();
            let controller = gtk4::EventControllerKey::new();
            controller.connect_key_pressed(move |_, key, _, state| {
                let ctrl = state.contains(gtk4::gdk::ModifierType::CONTROL_MASK);
                match key.name().as_deref() {
                    Some("F10") => {
                        on_close();
                        return glib::Propagation::Stop;
                    }
                    Some("r") | Some("R") if ctrl => {
                        let _ = tx.send(ToSftp::Refresh);
                        return glib::Propagation::Stop;
                    }
                    _ => {}
                }
                glib::Propagation::Proceed
            });
            root.add_controller(controller);
        }

        // Первичная загрузка удалённого каталога.
        let _ = tx_sftp.send(ToSftp::Refresh);

        Self { root }
    }
}

/// Заполняет список элементами каталога.
fn fill_list(list: &ListBox, entries: &[Entry]) {
    // Прежнее выделение: список обновляется каждые 300 мс, и без этого
    // выделение постоянно возвращалось бы на первую строку.
    let selected = list.selected_row().map(|row| row.index()).unwrap_or(-1);

    crate::ui::clear_list(list);
    let mut rows: Vec<ListBoxRow> = Vec::new();

    // Строка «вверх» — как в файловом менеджере.
    let up = ListBoxRow::new();
    let up_label = Label::new(Some("..  (вверх)"));
    up_label.set_xalign(0.0);
    up_label.set_margin_start(8);
    up_label.add_css_class("remotix-dir-up");
    up.set_child(Some(&up_label));
    list.append(&up);
    rows.push(up);

    for entry in entries {
        let row = ListBoxRow::new();
        let row_box = GtkBox::new(gtk4::Orientation::Horizontal, 8);
        row_box.set_margin_start(8);
        row_box.set_margin_end(8);
        row_box.set_margin_top(2);
        row_box.set_margin_bottom(2);

        let icon = Label::new(Some(if entry.is_dir { "📁" } else { "📄" }));
        row_box.append(&icon);

        let name = Label::new(Some(&entry.name));
        name.set_xalign(0.0);
        name.set_hexpand(true);
        name.set_ellipsize(gtk4::pango::EllipsizeMode::Middle);
        name.add_css_class(if entry.is_dir {
            "remotix-dir"
        } else {
            "remotix-file"
        });
        row_box.append(&name);

        if !entry.is_dir {
            let size = Label::new(Some(&human_size(entry.size)));
            size.add_css_class("remotix-file-size");
            row_box.append(&size);
        }

        row.set_child(Some(&row_box));
        list.append(&row);
        rows.push(row);
    }

    // Восстанавливаем выделение; если прежняя строка исчезла (удалили файл,
    // вошли в пустой каталог) — выделяем первую, иначе в списке остаётся
    // невидимое выделение на несуществующей строке.
    let index = if selected >= 0 { selected as usize } else { 0 };
    match rows.get(index).or_else(|| rows.first()) {
        Some(row) => list.select_row(Some(row)),
        None => list.select_row(None::<&ListBoxRow>),
    }
}

/// Имя файла для копии: если имя уже занято, добавляем «(копия)».
///
/// Используется при вставке из буфера обмена — существующий файл
/// перезаписывать нельзя.
fn unique_copy_name(dir: &std::path::Path, name: &str) -> String {
    if !dir.join(name).exists() {
        return name.to_string();
    }
    let path = std::path::Path::new(name);
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());
    let ext = path.extension().map(|s| format!(".{}", s.to_string_lossy()));
    match ext {
        Some(e) => format!("{stem} (копия){e}"),
        None => format!("{stem} (копия)"),
    }
}

/// Перемещает выделение в списке файлов.
///
/// GTK4 не обрабатывает стрелки в `GtkListBox` сам (в отличие от GTK3),
/// поэтому навигацию по списку приходится делать вручную — иначе выделение
/// не двигается клавишами.
fn move_selection(list: &ListBox, key: &str) {
    // Собираем строки списка.
    let mut rows: Vec<ListBoxRow> = Vec::new();
    let mut child = list.first_child();
    while let Some(widget) = child {
        if let Some(row) = widget.downcast_ref::<ListBoxRow>() {
            rows.push((*row).clone());
        }
        child = widget.next_sibling();
    }
    if rows.is_empty() {
        return;
    }

    let current = list.selected_row().map(|row| row.index()).unwrap_or(-1);
    let last_index = (rows.len() - 1) as i32;
    let next = match key {
        "Up" => {
            if current <= 0 {
                0
            } else {
                current - 1
            }
        }
        "Down" => {
            if current < 0 {
                0
            } else {
                (current + 1).min(last_index)
            }
        }
        "Home" => 0,
        "End" => last_index,
        _ => return,
    };

    if next >= 0 {
        list.select_row(Some(&rows[next as usize]));
    }
}

/// Имя выбранного элемента списка (None — «..» или ничего не выбрано).
fn selected_name(list: &ListBox, entries: &Rc<RefCell<Vec<Entry>>>) -> Option<String> {
    let row = list.selected_row()?;
    let index = row.index();
    if index <= 0 {
        return None;
    }
    entries
        .borrow()
        .get(index as usize - 1)
        .map(|e| e.name.clone())
}

/// «Человекочитаемый» размер файла.
fn human_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
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
