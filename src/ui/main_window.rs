//! Главное окно Remotix.
//!
//! Оформление повторяет макет `mockup.html`: шапка окна с поиском, боковая
//! панель со списком подключений, вкладки активных сессий и строка состояния.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use gtk4::prelude::*;
use gtk4::{
    gio, glib, Box as GtkBox, Button, DropDown, Entry, HeaderBar, Image, Label, ListBox, ListBoxRow,
    MenuButton, Notebook, Orientation, Overlay, Paned, Popover, ScrolledWindow, SearchEntry,
    StringList,
};

use crate::app::AppState;
use crate::host_check;
use crate::models::{Profile, Protocol};
use crate::wol;
use crate::protocols::ssh::SshConnection;
use crate::ui::history_tab::HistoryTab;
use crate::ui::profile_editor::ProfileEditor;
use crate::ui::rdp_viewer::RdpViewer;
use crate::ui::sftp_tab::SftpTab;
use crate::ui::terminal::TerminalTab;
use crate::ui::SessionState;

/// Что открыть после успешной проверки доступности узла.
#[derive(Clone, Copy, Debug)]
enum ConnectAction {
    /// Обычная сессия: SSH-терминал или RDP-просмотрщик.
    Session,
    /// Двухпанельный SFTP-клиент.
    Sftp,
}

/// Строка боковой панели: заголовок группы или подключение.
#[derive(Clone, Debug)]
enum SideRow {
    Group {
        id: i64,
        name: String,
        depth: usize,
    },
    // В коробке: Profile заметно крупнее Group, Box держит enum компактным.
    Profile(Box<Profile>),
}

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
    /// Все профили из базы (до фильтрации) — для списка тегов.
    all: Rc<RefCell<Vec<Profile>>>,
    /// Строки боковой панели: индекс строки → группа/подключение.
    rows: Rc<RefCell<Vec<SideRow>>>,
    /// Свёрнутые группы (persist в настройках приложения).
    collapsed: Rc<RefCell<std::collections::HashSet<i64>>>,
    /// Выбранный тег-фильтр (None — показывать все).
    tag_filter: Rc<RefCell<Option<String>>>,
    /// Защита от рекурсии: пересборка списка тегов снова вызывает
    /// `selected_notify`, а тот — `refresh_profiles`.
    tag_updating: Rc<Cell<bool>>,
    tags_combo: DropDown,
    tags_list: StringList,
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
        // В GTK4 список по умолчанию активируется одиночным щелчком. Для
        // профилей это неудобно: чтобы выбрать профиль для SFTP или
        // редактирования, приходилось бы каждый раз открывать сессию.
        // Подключаемся по двойному щелчку, как написано в README.
        sidebar.set_activate_on_single_click(false);
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

        // Фильтр по тегу + кнопка создания группы.
        let tags_list = StringList::new(&["Все теги"]);
        let tags_combo = DropDown::builder()
            .model(&tags_list)
            .selected(0)
            .build();
        tags_combo.set_hexpand(true);
        tags_combo.set_tooltip_text(Some("Показать подключения только с этим тегом"));
        let new_group_btn = Button::from_icon_name("folder-new-symbolic");
        new_group_btn.set_tooltip_text(Some("Новая группа подключений"));

        let tag_label = Label::new(Some("Тег:"));
        tag_label.add_css_class("remotix-field-caption");
        let filter_row = GtkBox::new(Orientation::Horizontal, 6);
        for m in ["margin-bottom", "margin-start", "margin-end"] {
            filter_row.set_property(m, 8);
        }
        filter_row.append(&tag_label);
        filter_row.append(&tags_combo);
        filter_row.append(&new_group_btn);

        let scroll = ScrolledWindow::new();
        scroll.set_child(Some(&sidebar));
        scroll.set_vexpand(true);
        scroll.set_hscrollbar_policy(gtk4::PolicyType::Never);

        let sidebar_box = GtkBox::new(Orientation::Vertical, 0);
        sidebar_box.append(&quick_box);
        sidebar_box.append(&gtk4::Separator::new(Orientation::Horizontal));
        sidebar_box.append(&filter_row);
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
        // Фиксированная ширина: иначе длинный текст (например, ошибка
        // подключения) растягивает строку состояния и сдвигает кнопки —
        // и растягивает всё окно. Полный текст — во всплывающей подсказке.
        status.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        status.set_lines(1);
        status.set_width_chars(60);

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

        let collapsed0 = Self::load_collapsed(&state);
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
            all: Rc::new(RefCell::new(Vec::new())),
            rows: Rc::new(RefCell::new(Vec::new())),
            collapsed: Rc::new(RefCell::new(collapsed0)),
            tag_filter: Rc::new(RefCell::new(None)),
            tag_updating: Rc::new(Cell::new(false)),
            tags_combo: tags_combo.clone(),
            tags_list: tags_list.clone(),
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
            tags_combo.connect_selected_notify(move |_| {
                if win.tag_updating.get() {
                    return;
                }
                let index = win.tags_combo.selected();
                let tag = if index > 0 {
                    win.tags_list.string(index).map(|item| item.to_string())
                } else {
                    None
                };
                *win.tag_filter.borrow_mut() = tag;
                win.refresh_profiles();
            });
        }
        {
            let win = win.clone();
            new_group_btn.connect_clicked(move |_| win.ask_create_group(None));
        }
        {
            let win = win.clone();
            sidebar.connect_row_activated(move |_, row| {
                let index = row.index();
                if index < 0 {
                    return;
                }
                if let Some(SideRow::Group { id, .. }) = win.rows.borrow().get(index as usize) {
                    win.toggle_group(*id);
                }
                let profile = match win.rows.borrow().get(index as usize) {
                    Some(SideRow::Profile(p)) => Some((**p).clone()),
                    _ => None,
                };
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
        editor.present_transient_for(self.window().as_ref());
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
            mac_address: profile.mac_address.clone(),
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

    /// Стирает расшифрованные профили из памяти при блокировке.
    ///
    /// Активные вкладки сессий уже держат собственные копии профиля и
    /// продолжают работать; их секреты очистятся при закрытии вкладки.
    pub fn lock_secrets(&self) {
        self.all.borrow_mut().clear();
        self.rows.borrow_mut().clear();
        crate::ui::clear_list(&self.sidebar);
    }

    /// Перечитывает профили из базы и обновляет боковую панель.
    pub fn refresh_profiles(&self) {
        let key = self.state.unlocked_key();
        let all_profiles = match self.state.db.list_profiles(&key) {
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
        let tag = self.tag_filter.borrow().clone();
        let visible: Vec<Profile> = all_profiles
            .iter()
            .filter(|p| {
                let text_match = filter.is_empty()
                    || p.name.to_lowercase().contains(&filter)
                    || p.host.to_lowercase().contains(&filter)
                    || p.username
                        .as_ref()
                        .map(|u| u.to_lowercase().contains(&filter))
                        .unwrap_or(false);
                let tag_match = tag.as_ref().is_none_or(|want| {
                    p.tags.iter().any(|have| have == want)
                });
                text_match && tag_match
            })
            .cloned()
            .collect();

        // Список тегов в фильтре: пересобираем, сохраняя выбранный тег.
        self.update_tag_filter(&all_profiles);
        self.tag_updating.set(false);

        let groups = self.state.db.list_groups().unwrap_or_default();
        self.rebuild_sidebar(&groups, &visible, filter.is_empty() && tag.is_none());

        // Восстанавливаем выделение прежнего профиля.
        if let Some(id) = selected_id {
            if let Some(index) = self.rows.borrow().iter().position(|row| {
                matches!(row, SideRow::Profile(p) if p.id == id)            }) {
                if let Some(r) = self.sidebar.row_at_index(index as i32) {
                    self.sidebar.select_row(Some(&r));
                }
            }
        }

        *self.all.borrow_mut() = all_profiles;
    }

    /// Пересобирает список тегов в фильтре: уникальные значения из всех
    /// профилей, по алфавиту. Выбранный тег сохраняется, если он ещё есть.
    fn update_tag_filter(&self, all_profiles: &[Profile]) {
        let mut tags: Vec<String> = Vec::new();
        for profile in all_profiles {
            for tag in &profile.tags {
                let tag = tag.trim().to_string();
                if !tag.is_empty() && !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
        }
        tags.sort();

        let selected: Option<String> = self.tag_filter.borrow().clone();
        let selected_index = match &selected {
            Some(tag) => tags
                .iter()
                .position(|t| t == tag)
                .map(|i| i + 1)
                .unwrap_or(0),
            None => 0,
        };
        if selected.is_some() && selected_index == 0 {
            // Тег пропал из базы (профиль удалён/переименован) — сброс.
            *self.tag_filter.borrow_mut() = None;
        }

        // Пересборка модели сбрасывает выделение: подписка сработает, но
        // флаг гасит рекурсию (notify вызывается синхронно внутри set_selected).
        let items: Vec<String> = std::iter::once("Все теги".to_string())
            .chain(tags)
            .collect();
        let additions: Vec<&str> = items.iter().map(String::as_str).collect();
        self.tag_updating.set(true);
        self.tags_list.splice(0, self.tags_list.n_items(), &additions);
        self.tags_combo.set_selected(selected_index as u32);
        self.tag_updating.set(false);
    }

    /// Строит строки боковой панели: дерево групп + плоский список профилей
    /// без группы. Если групп нет вовсе — прежний плоский список.
    fn rebuild_sidebar(&self, groups: &[(i64, String, Option<i64>)], visible: &[Profile], flat: bool) {
        self.clear_sidebar();

        let mut rows = self.rows.borrow_mut();
        rows.clear();

        if flat {
            // Группы не заданы — прежний плоский список.
            for profile in visible {
                let row = self.build_profile_row(profile, 0);
                self.sidebar.append(&row);
                rows.push(SideRow::Profile(Box::new(profile.clone())));
            }
            return;
        }

        if visible.is_empty() {
            let empty = Label::new(Some("Ничего не найдено."));
            empty.set_justify(gtk4::Justification::Center);
            empty.set_margin_top(18);
            empty.set_margin_bottom(12);
            empty.add_css_class("remotix-empty");
            self.sidebar.append(&empty);
            return;
        }

        // Профили по группам.
        let mut orphans: Vec<&Profile> = Vec::new();
        let mut by_group: std::collections::HashMap<i64, Vec<&Profile>> =
            std::collections::HashMap::new();
        for profile in visible {
            match profile.group_id {
                Some(id) if groups.iter().any(|(gid, _, _)| *gid == id) => {
                    by_group.entry(id).or_default().push(profile);
                }
                _ => orphans.push(profile),
            }
        }

        let collapsed = self.collapsed.borrow();
        let mut emit_group = |rows: &mut Vec<SideRow>, id: i64, name: &str, depth: usize, direct: usize| {
            let is_collapsed = collapsed.contains(&id);
            let row = self.build_group_row(id, name, depth, direct, is_collapsed);
            self.sidebar.append(&row);
            rows.push(SideRow::Group {
                id,
                name: name.to_string(),
                depth,
            });
            is_collapsed
        };
        let emit_group = &mut emit_group;

        // Рекурсивный обход сверху вниз (children выбираются из полного
        // списка групп по parent_id). Виджеты и строки передаются одним
        // комплектом, чтобы не тянуть через walk длинный хвост аргументов.
        struct SideSink<'a> {
            sidebar: &'a ListBox,
            rows: &'a mut Vec<SideRow>,
            emit_group: EmitGroup<'a>,
            build_profile_row: &'a dyn Fn(&Profile, usize) -> ListBoxRow,
        }

        type EmitGroup<'a> = &'a mut dyn FnMut(&mut Vec<SideRow>, i64, &str, usize, usize) -> bool;

        fn walk(
            parent: Option<i64>,
            groups: &[(i64, String, Option<i64>)],
            by_group: &std::collections::HashMap<i64, Vec<&Profile>>,
            ui: &mut SideSink<'_>,
            depth: usize,
        ) {
            // Сначала подгруппы (по алфавиту), затем подключения.
            let mut children: Vec<&(i64, String, Option<i64>)> = groups
                .iter()
                .filter(|(_, _, p)| *p == parent)
                .collect();
            children.sort_by_key(|g| g.1.to_lowercase());

            for (id, name, _) in children.iter() {
                let direct = by_group.get(id).map(|v| v.len()).unwrap_or(0);
                let is_collapsed = (ui.emit_group)(ui.rows, *id, name, depth, direct);
                if !is_collapsed {
                    walk(Some(*id), groups, by_group, ui, depth + 1);
                }
            }

            if let Some(profiles) = parent.and_then(|id| by_group.get(&id)) {
                for profile in profiles {
                    let row = (ui.build_profile_row)(profile, depth + 1);
                    ui.sidebar.append(&row);
                    ui.rows.push(SideRow::Profile(Box::new((**profile).clone())));
                }
            }
        }
        let _ = &mut rows;
        walk(
            None,
            groups,
            &by_group,
            &mut SideSink {
                sidebar: &self.sidebar,
                rows: &mut rows,
                emit_group,
                build_profile_row: &|p, d| self.build_profile_row(p, d),
            },
            0,
        );

        // Подключения без группы — после всех групп.
        if !orphans.is_empty() {
            let mut sorted: Vec<&&Profile> = orphans.iter().collect();
            sorted.sort_by_key(|p| p.name.to_lowercase());
            for profile in sorted {
                let row = self.build_profile_row(profile, 0);
                self.sidebar.append(&row);
                rows.push(SideRow::Profile(Box::new((**profile).clone())));
            }
        }
    }

    /// Свёрнутые группы из настроек (id через запятую).
    fn load_collapsed(state: &AppState) -> std::collections::HashSet<i64> {
        state
            .db
            .get_setting("ui.collapsed_groups")
            .map(|value| {
                value
                    .split(',')
                    .filter_map(|v| v.trim().parse::<i64>().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn save_collapsed(&self) {
        let ids = self.collapsed.borrow();
        let value = ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let _ = self.state.db.set_setting("ui.collapsed_groups", &value);
    }

    /// Строка профиля в боковой панели: название, протокол, адрес.
    fn build_profile_row(&self, profile: &Profile, depth: usize) -> ListBoxRow {
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

        // Теги — отдельной строкой мелким шрифтом.
        let tags_text = profile.tags.join(" · ");
        let tags_label = if tags_text.is_empty() {
            None
        } else {
            let label = Label::new(Some(&tags_text));
            label.set_xalign(0.0);
            label.set_ellipsize(gtk4::pango::EllipsizeMode::End);
            label.add_css_class("remotix-profile-details");
            Some(label)
        };

        let box_ = GtkBox::new(Orientation::Vertical, 2);
        box_.set_margin_start(8 + 16 * depth as i32);
        box_.append(&title_row);
        box_.append(&details);
        if let Some(tags_label) = &tags_label {
            box_.append(tags_label);
        }

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
                    .translate_coordinates(&toplevel, x, y)
                    .unwrap_or((x, y));
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
        add_item(&box_, "Переместить в группу…", Box::new(move |p: &Profile| {
            win.move_profile_to_group(p.clone());
        }));

        let win = self.clone();
        add_item(&box_, "Удалить", Box::new(move |p: &Profile| {
            win.delete_profile(p);
        }));

        popover.set_child(Some(&box_));
        popover
    }

    /// Строка группы: стрелка раскрытия, название и число подключений.
    fn build_group_row(
        &self,
        id: i64,
        name: &str,
        depth: usize,
        count: usize,
        is_collapsed: bool,
    ) -> ListBoxRow {
        let row = ListBoxRow::new();

        let arrow = Label::new(Some(if is_collapsed { "▸" } else { "▾" }));
        let title = Label::new(Some(name));
        title.set_xalign(0.0);
        title.set_ellipsize(gtk4::pango::EllipsizeMode::End);
        title.set_hexpand(true);
        title.add_css_class("remotix-profile-name");

        let counter = Label::new(Some(count.to_string().as_str()));
        counter.add_css_class("remotix-field-caption");

        let box_ = GtkBox::new(Orientation::Horizontal, 6);
        box_.set_margin_start(4 + 16 * depth as i32);
        box_.set_margin_top(4);
        box_.set_margin_bottom(4);
        box_.append(&arrow);
        box_.append(&title);
        box_.append(&counter);
        row.set_child(Some(&box_));
        row.set_activatable(false);

        // Одиночный щелчок по строке группы — раскрыть/свернуть.
        {
            let win = self.clone();
            let click = gtk4::GestureClick::new();
            click.set_button(1);
            click.connect_pressed(move |gesture, _, _, _| {
                gesture.set_state(gtk4::EventSequenceState::Claimed);
                win.toggle_group(id);
            });
            row.add_controller(click);
        }

        // Контекстное меню группы (правая кнопка мыши).
        {
            let popover = self.group_popover(id, name);

            let controller = gtk4::GestureClick::new();
            controller.set_button(3);
            let popup = popover.clone();
            let row_ref = row.clone();
            controller.connect_pressed(move |_, _, x, y| {
                let Some(toplevel) = row_ref.root() else {
                    return;
                };
                if popup.parent().is_none() {
                    popup.set_parent(&toplevel);
                }
                let (px, py) = row_ref
                    .translate_coordinates(&toplevel, x, y)
                    .unwrap_or((x, y));
                popup.set_pointing_to(Some(&gtk4::gdk::Rectangle::new(
                    px as i32, py as i32, 1, 1,
                )));
                popup.popup();
            });
            row.add_controller(controller);
        }

        row
    }

    /// Контекстное меню группы: подгруппа, переименование, удаление.
    fn group_popover(&self, id: i64, name: &str) -> Popover {
        let popover = Popover::new();
        popover.set_autohide(true);

        let box_ = GtkBox::new(Orientation::Vertical, 0);
        box_.set_margin_top(4);
        box_.set_margin_bottom(4);
        box_.set_margin_start(4);
        box_.set_margin_end(4);

        let add_item = |container: &GtkBox, label: &str, action: Box<dyn Fn()>| {
            let button = Button::new();
            button.add_css_class("flat");
            button.add_css_class("remotix-menu-item");
            button.set_hexpand(true);
            let text = Label::new(Some(label));
            text.set_xalign(0.0);
            button.set_child(Some(&text));
            button.connect_clicked(move |_| action());
            container.append(&button);
        };

        let win = self.clone();
        add_item(&box_, "Добавить подгруппу…", Box::new(move || {
            win.ask_create_group(Some(id));
        }));

        let win = self.clone();
        add_item(&box_, "Добавить подгруппу…", Box::new(move || {
            win.ask_create_group(Some(id));
        }));

        let win = self.clone();
        add_item(&box_, "Переименовать…", Box::new({
            let name = name.to_string();
            move || {
                win.ask_rename_group(id, &name);
            }
        }));

        let win = self.clone();
        add_item(&box_, "Удалить группу", Box::new({
            let name = name.to_string();
            move || {
                win.confirm_delete_group(id, &name);
            }
        }));

        popover.set_child(Some(&box_));
        popover
    }

    /// Раскрывает или сворачивает группу (с persist).
    fn toggle_group(&self, id: i64) {
        let inserted = self.collapsed.borrow_mut().insert(id);
        if !inserted {
            self.collapsed.borrow_mut().remove(&id);
        }
        self.save_collapsed();
        self.refresh_profiles();
    }

    /// Диалог «название группы» (None — корневая группа).
    fn ask_create_group(&self, parent_id: Option<i64>) {
        let caption = match parent_id {
            Some(_) => "Новая подгруппа",
            None => "Новая группа",
        };
        self.ask_text(caption, "Название группы:", "", move |win, name| {
            let result = win.state.db.create_group(&name, parent_id);
            match result {
                Ok(_) => {
                    win.set_status(&format!("Группа «{name}» создана"));
                    win.refresh_profiles();
                }
                Err(e) => win.set_status(&format!("Не удалось создать группу: {e}")),
            }
        });
    }

    fn ask_rename_group(&self, id: i64, current: &str) {
        self.ask_text("Переименовать группу", "Название группы:", current, move |win, name| {
            match win.state.db.rename_group(id, &name) {
                Ok(()) => {
                    win.set_status(&format!("Группа переименована в «{name}»"));
                    win.refresh_profiles();
                }
                Err(e) => win.set_status(&format!("Не удалось переименовать: {e}")),
            }
        });
    }

    fn confirm_delete_group(&self, id: i64, name: &str) {
        // Строка уходит в замыкание 'static — владеем ею.
        let name = name.to_string();
        let dialog = gtk4::MessageDialog::builder()
            .modal(true)
            .message_type(gtk4::MessageType::Warning)
            .buttons(gtk4::ButtonsType::None)
            .text(format!("Удалить группу «{name}»?").as_str())
            .secondary_text(
                "Подключения останутся в списке (без группы), \
                 а подгруппы поднимутся на уровень выше.",
            )
            .build();
        dialog.set_transient_for(self.window().as_ref());
        dialog.add_button("Удалить", gtk4::ResponseType::Accept);
        dialog.add_button("Отмена", gtk4::ResponseType::Cancel);

        let win = self.clone();
        dialog.connect_response(move |dialog, response| {
            dialog.destroy();
            if response == gtk4::ResponseType::Accept {
                match win.state.db.delete_group(id) {
                    Ok(_) => {
                        win.set_status(&format!("Группа «{name}» удалена"));
                        win.refresh_profiles();
                    }
                    Err(e) => win.set_status(&format!("Не удалось удалить группу: {e}")),
                }
            }
        });
        dialog.present();
    }

    /// Диалог перемещения подключения в группу.
    fn move_profile_to_group(&self, profile: Profile) {
        let groups = self.state.db.list_groups().unwrap_or_default();
        // Плоский список с отступами по глубине вложенности: родители
        // идут раньше детей.
        let ordered = order_groups(&groups);

        let mut items: Vec<String> = vec!["Без группы".to_string()];
        for (gid, gname, _) in &ordered {
            let depth = group_depth(*gid, &groups);
            items.push(format!("{}{}", "  ".repeat(depth), gname));
        }

        let dialog = gtk4::Window::builder()
            .title("Переместить в группу")
            .modal(true)
            .default_width(420)
            .build();
        dialog.set_transient_for(self.window().as_ref());

        let model = StringList::new(
            &items.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        let combo = DropDown::builder().model(&model).build();
        combo.set_hexpand(true);

        // Текущая группа профиля.
        let current_index = profile.group_id.and_then(|gid| {
            ordered
                .iter()
                .position(|(id, _, _)| *id == gid)
                .map(|i| i + 1)
        });
        combo.set_selected(current_index.unwrap_or(0) as u32);

        let label = Label::new(Some(&format!("Подключение: {}", profile.name)));
        label.set_xalign(0.0);
        label.set_margin_top(16);
        label.set_margin_start(16);
        label.set_margin_end(16);

        let combo_row = GtkBox::new(Orientation::Horizontal, 8);
        combo_row.set_margin_top(8);
        combo_row.set_margin_start(16);
        combo_row.set_margin_end(16);
        combo_row.append(&combo);

        let ok = Button::with_label("Переместить");
        ok.add_css_class("suggested-action");
        let cancel = Button::with_label("Отмена");
        let buttons = GtkBox::new(Orientation::Horizontal, 8);
        buttons.set_margin_top(16);
        buttons.set_margin_bottom(16);
        buttons.set_margin_start(16);
        buttons.set_margin_end(16);
        buttons.set_halign(gtk4::Align::End);
        buttons.append(&cancel);
        buttons.append(&ok);

        let content = GtkBox::new(Orientation::Vertical, 0);
        content.append(&label);
        content.append(&combo_row);
        content.append(&buttons);
        dialog.set_child(Some(&content));

        {
            let dialog = dialog.clone();
            let profile_id = profile.id;
            let win = self.clone();
            ok.connect_clicked(move |_| {
                let selected = combo.selected() as usize;
                let group_id = if selected == 0 {
                    None
                } else {
                    ordered.get(selected - 1).map(|(id, _, _)| *id)
                };
                match win.state.db.set_profile_group(profile_id, group_id) {
                    Ok(()) => {
                        win.set_status("Подключение перемещено");
                        win.refresh_profiles();
                        dialog.close();
                    }
                    Err(e) => win.set_status(&format!("Не удалось переместить: {e}")),
                }
            });
        }
        {
            let dialog = dialog.clone();
            cancel.connect_clicked(move |_| dialog.close());
        }

        dialog.present();
    }

    /// Универсальный диалог с одним текстовым полем.
    fn ask_text<F>(&self, title: &str, caption: &str, initial: &str, on_ok: F)
    where
        F: Fn(&MainWindow, String) + 'static,
    {
        let window = gtk4::Window::builder()
            .title(title)
            .modal(true)
            .default_width(420)
            .resizable(false)
            .build();
        window.set_transient_for(self.window().as_ref());

        let label = Label::new(Some(caption));
        label.set_xalign(0.0);
        label.set_margin_top(16);
        label.set_margin_start(16);
        label.set_margin_end(16);

        let entry = Entry::new();
        entry.set_text(initial);
        entry.set_hexpand(true);
        let entry_row = GtkBox::new(Orientation::Horizontal, 8);
        entry_row.set_margin_top(8);
        entry_row.set_margin_start(16);
        entry_row.set_margin_end(16);
        entry_row.append(&entry);

        let ok = Button::with_label("ОК");
        ok.add_css_class("suggested-action");
        let cancel = Button::with_label("Отмена");
        let buttons = GtkBox::new(Orientation::Horizontal, 8);
        buttons.set_margin_top(16);
        buttons.set_margin_bottom(16);
        buttons.set_margin_start(16);
        buttons.set_margin_end(16);
        buttons.set_halign(gtk4::Align::End);
        buttons.append(&cancel);
        buttons.append(&ok);

        let content = GtkBox::new(Orientation::Vertical, 0);
        content.append(&label);
        content.append(&entry_row);
        content.append(&buttons);
        window.set_child(Some(&content));

        let win = self.clone();
        {
            let window = window.clone();
            let entry = entry.clone();
            ok.connect_clicked(move |_| {
                let text = entry.text().trim().to_string();
                if text.is_empty() {
                    return;
                }
                window.close();
                on_ok(&win, text);
            });
        }
        {
            let window = window.clone();
            cancel.connect_clicked(move |_| window.close());
        }
        // Enter в поле = ОК.
        {
            let ok = ok.clone();
            entry.connect_activate(move |_| ok.emit_clicked());
        }

        window.present();
    }

    /// Удаляет все строки боковой панели.
    fn clear_sidebar(&self) {
        crate::ui::clear_list(&self.sidebar);
    }

    /// Открывает подключение к выбранному профилю.
    ///
    /// Сначала выполняется быстрая TCP-проба. Если узел выключен, Remotix
    /// предлагает отправить Wake-on-LAN, а не ждёт тайм-аута SSH/RDP.
    pub fn connect_profile(&self, profile: Profile) {
        if profile.protocol == Protocol::Vnc {
            self.set_status("VNC: поддержка протокола в разработке");
            return;
        }
        if profile.protocol == Protocol::Rdp && profile.rdp_options.allow_legacy_security {
            self.confirm_legacy_rdp(profile);
            return;
        }
        self.check_host_then(profile, ConnectAction::Session);
    }

    /// Предупреждает перед подключением с Standard RDP Security (RC4).
    ///
    /// Флаг включается только в профиле, но даже при нём пользователь должен
    /// каждый раз подтвердить, что понимает риск: в этом режиме нет TLS и
    /// проверки подлинности сервера.
    fn confirm_legacy_rdp(&self, profile: Profile) {
        let dialog = gtk4::MessageDialog::builder()
            .modal(true)
            .message_type(gtk4::MessageType::Warning)
            .buttons(gtk4::ButtonsType::None)
            .text("Небезопасный режим RDP")
            .secondary_text(
                "Профиль разрешает Standard RDP Security (шифр RC4 без TLS). \
                 В этом режиме Remotix не проверяет подлинность сервера, а \
                 трафик защищён устаревшим шифрованием.\n\n\
                 Продолжайте, только если доверяете сети и серверу.",
            )
            .build();
        dialog.set_transient_for(self.window().as_ref());
        dialog.add_button("Продолжить", gtk4::ResponseType::Accept);
        dialog.add_button("Отмена", gtk4::ResponseType::Cancel);

        let win = self.clone();
        dialog.connect_response(move |dialog, response| {
            dialog.destroy();
            if response == gtk4::ResponseType::Accept {
                win.check_host_then(profile.clone(), ConnectAction::Session);
            } else {
                win.set_status(&format!("{}: подключение отменено", profile.host));
            }
        });
        dialog.present();
    }

    /// Проверяет доступность узла и вызывает действие только после успеха.
    fn check_host_then(&self, profile: Profile, action: ConnectAction) {
        if profile.host.trim().is_empty() || profile.port == 0 {
            self.open_connection(profile, action);
            return;
        }

        let host = profile.host.trim().to_string();
        let port = profile.port;
        let addr = host_check::endpoint(&host, port);
        self.set_status(&format!("Проверяем доступность {addr}…"));

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(host_check::probe(&host, port));
        });

        let win = self.clone();
        let profile = Rc::new(profile);
        let _ = glib::timeout_add_local(Duration::from_millis(100), move || {
            match rx.try_recv() {
                Ok(Ok(())) => {
                    win.open_connection((*profile).clone(), action);
                    glib::ControlFlow::Break
                }
                Ok(Err(error)) => {
                    win.show_host_offline((*profile).clone(), error, action);
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(mpsc::TryRecvError::Disconnected) => {
                    win.show_host_offline(
                        (*profile).clone(),
                        "проверка доступности прервана".to_string(),
                        action,
                    );
                    glib::ControlFlow::Break
                }
            }
        });
    }

    /// Открывает сессию или SFTP после успешной проверки.
    fn open_connection(&self, profile: Profile, action: ConnectAction) {
        match action {
            ConnectAction::Session => match profile.protocol {
                Protocol::Ssh => self.open_ssh_terminal(profile),
                Protocol::Rdp => self.open_rdp_session(profile),
                Protocol::Vnc => self.set_status("VNC: поддержка протокола в разработке"),
            },
            ConnectAction::Sftp => self.open_sftp_for_profile(profile),
        }
    }

    /// Диалог для выключенного/недоступного узла.
    fn show_host_offline(&self, profile: Profile, error: String, action: ConnectAction) {
        let mac = profile
            .mac_address
            .as_deref()
            .and_then(|value| wol::normalize_mac(value).ok());
        let can_wake = mac.is_some();

        let title = format!("Хост {} не отвечает", profile.host);
        let secondary = match mac.as_deref() {
            Some(mac) => format!(
                "{error}\n\nВозможно, хост выключен. Разбудить его по Wake-on-LAN \
                 (MAC {mac})?"
            ),
            None => format!(
                "{error}\n\nВозможно, хост выключен. MAC-адрес не задан — укажите его \
                 в свойствах профиля, чтобы использовать Wake-on-LAN."
            ),
        };

        let dialog = gtk4::MessageDialog::builder()
            .modal(true)
            .message_type(gtk4::MessageType::Warning)
            .buttons(gtk4::ButtonsType::None)
            .text(title.as_str())
            .secondary_text(secondary.as_str())
            .build();
        dialog.set_transient_for(self.window().as_ref());

        if can_wake {
            dialog.add_button("Разбудить", gtk4::ResponseType::Yes);
            dialog.add_button("Подключиться всё равно", gtk4::ResponseType::No);
        } else {
            dialog.add_button("Подключиться всё равно", gtk4::ResponseType::Yes);
        }
        dialog.add_button("Отмена", gtk4::ResponseType::Cancel);

        let win = self.clone();
        let profile = profile.clone();
        dialog.connect_response(move |dialog, response| {
            dialog.destroy();
            let wake = can_wake && response == gtk4::ResponseType::Yes;
            let connect_anyway = response == gtk4::ResponseType::No
                || (!can_wake && response == gtk4::ResponseType::Yes);

            if wake {
                win.wake_and_connect(profile.clone(), action);
            } else if connect_anyway {
                win.open_connection(profile.clone(), action);
            } else {
                win.set_status(&format!("{}: подключение отменено", profile.host));
            }
        });
        dialog.present();
    }

    /// Отправляет magic packet и ждёт, пока узел снова станет доступен.
    fn wake_and_connect(&self, profile: Profile, action: ConnectAction) {
        let raw_mac = profile.mac_address.clone();
        let Some(raw_mac) = raw_mac else {
            self.show_wake_failed(profile, "в профиле не задан MAC-адрес", action);
            return;
        };
        let mac = match wol::normalize_mac(&raw_mac) {
            Ok(mac) => mac,
            Err(error) => {
                self.show_wake_failed(profile, &error, action);
                return;
            }
        };

        let (progress, status, cancelled) = self.wake_progress_dialog(&profile, &mac);
        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let host = profile.host.clone();
        let port = profile.port;
        let cancel_flag = cancelled.clone();
        let mac_for_thread = mac.clone();

        std::thread::spawn(move || {
            let mut sent = false;
            let mut last_error = None;
            for attempt in 0..3 {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }
                match wol::send_magic_packet(&mac_for_thread) {
                    Ok(()) => sent = true,
                    Err(error) => last_error = Some(error),
                }
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(300));
                }
            }

            if cancel_flag.load(Ordering::Relaxed) {
                let _ = tx.send(Err("отменено".to_string()));
                return;
            }
            if !sent {
                let error = last_error
                    .unwrap_or_else(|| "не удалось отправить magic packet".to_string());
                let _ = tx.send(Err(error));
                return;
            }

            let outcome = host_check::wait_until_online(
                &host,
                port,
                host_check::WAKE_WAIT,
                host_check::RETRY_INTERVAL,
                || cancel_flag.load(Ordering::Relaxed),
            );
            let result = match outcome {
                host_check::WaitOutcome::Online => Ok(()),
                host_check::WaitOutcome::TimedOut { last_error } => {
                    Err(format!("хост не стал доступен: {last_error}"))
                }
                host_check::WaitOutcome::Cancelled => Err("отменено".to_string()),
            };
            let _ = tx.send(result);
        });

        let win = self.clone();
        let profile = Rc::new(profile);
        let started = Instant::now();
        let _ = glib::timeout_add_local(Duration::from_millis(250), move || {
            match rx.try_recv() {
                Ok(Ok(())) => {
                    progress.close();
                    win.set_status(&format!(
                        "{}: хост проснулся, подключаемся…",
                        profile.host
                    ));
                    win.open_connection((*profile).clone(), action);
                    glib::ControlFlow::Break
                }
                Ok(Err(error)) => {
                    let was_cancelled = cancelled.load(Ordering::Relaxed);
                    progress.close();
                    if was_cancelled {
                        win.set_status(&format!("{}: ожидание отменено", profile.host));
                    } else {
                        win.set_status(&format!("{}: {error}", profile.host));
                        win.show_wake_failed((*profile).clone(), &error, action);
                    }
                    glib::ControlFlow::Break
                }
                Err(mpsc::TryRecvError::Empty) => {
                    let left = host_check::WAKE_WAIT
                        .saturating_sub(started.elapsed())
                        .as_secs();
                    status.set_text(&format!(
                        "Magic packet отправлен. Ждём, пока откроется порт {}… \
                         Осталось {} с.",
                        profile.port, left
                    ));
                    glib::ControlFlow::Continue
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    progress.close();
                    win.set_status(&format!("{}: ожидание прервано", profile.host));
                    glib::ControlFlow::Break
                }
            }
        });
    }

    /// Окно ожидания пробуждения с кнопкой отмены.
    fn wake_progress_dialog(
        &self,
        profile: &Profile,
        mac: &str,
    ) -> (Rc<gtk4::Window>, Label, Arc<AtomicBool>) {
        let window = gtk4::Window::builder()
            .title("Wake-on-LAN")
            .modal(true)
            .resizable(false)
            .default_width(480)
            .build();
        window.set_transient_for(self.window().as_ref());

        let heading = Label::new(Some(&format!("Хост {} не отвечает", profile.host)));
        heading.add_css_class("remotix-dialog-header");
        heading.set_xalign(0.0);

        let detail = Label::new(Some(&format!(
            "Отправляем magic packet на {mac}.\n\
             Ожидаем, пока откроется порт {} (до 10 минут).",
            profile.port
        )));
        detail.set_wrap(true);
        detail.set_xalign(0.0);
        detail.set_max_width_chars(56);

        let status = Label::new(Some("Отправляем magic packet…"));
        status.set_wrap(true);
        status.set_xalign(0.0);

        let spinner = gtk4::Spinner::new();
        spinner.start();
        let progress_row = GtkBox::new(Orientation::Horizontal, 8);
        progress_row.append(&spinner);
        progress_row.append(&status);

        let cancel = Button::with_label("Отмена");
        cancel.set_halign(gtk4::Align::End);

        let content = GtkBox::new(Orientation::Vertical, 12);
        for margin in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            content.set_property(margin, 16);
        }
        content.append(&heading);
        content.append(&detail);
        content.append(&progress_row);
        content.append(&cancel);
        window.set_child(Some(&content));

        let cancelled = Arc::new(AtomicBool::new(false));
        {
            let cancelled = cancelled.clone();
            window.connect_close_request(move |_| {
                cancelled.store(true, Ordering::Relaxed);
                glib::Propagation::Proceed
            });
        }
        {
            let cancelled = cancelled.clone();
            let window = window.clone();
            cancel.connect_clicked(move |_| {
                cancelled.store(true, Ordering::Relaxed);
                window.close();
            });
        }

        window.present();
        (Rc::new(window), status, cancelled)
    }

    /// Сообщение после неудачного ожидания или ошибки magic packet.
    fn show_wake_failed(&self, profile: Profile, error: &str, action: ConnectAction) {
        let secondary = format!(
            "{error}\n\nМожно попробовать подключиться всё равно — например, если \
             Wake-on-LAN на этом хосте не настроен."
        );
        let dialog = gtk4::MessageDialog::builder()
            .modal(true)
            .message_type(gtk4::MessageType::Warning)
            .buttons(gtk4::ButtonsType::None)
            .text("Не удалось разбудить хост")
            .secondary_text(secondary.as_str())
            .build();
        dialog.set_transient_for(self.window().as_ref());
        dialog.add_button("Подключиться всё равно", gtk4::ResponseType::Yes);
        dialog.add_button("Отмена", gtk4::ResponseType::Cancel);

        let win = self.clone();
        let profile = profile.clone();
        dialog.connect_response(move |dialog, response| {
            dialog.destroy();
            if response == gtk4::ResponseType::Yes {
                win.open_connection(profile.clone(), action);
            } else {
                win.set_status(&format!("{}: подключение отменено", profile.host));
            }
        });
        dialog.present();
    }

    /// Окно приложения — родитель для диалогов.
    fn window(&self) -> Option<gtk4::Window> {
        self.root
            .root()
            .and_then(|w| w.downcast::<gtk4::Window>().ok())
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
        let metrics_enabled = settings.terminal_metrics();

        match TerminalTab::new_ssh(
            &title,
            SshConnection::new(profile),
            on_state,
            font_size,
            metrics_enabled,
        ) {
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
        self.check_host_then(profile, ConnectAction::Sftp);
    }

    /// Создаёт вкладку SFTP после проверки доступности узла.
    fn open_sftp_for_profile(&self, profile: Profile) {
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
        match self.rows.borrow().get(index as usize) {
            Some(SideRow::Profile(profile)) => Some((**profile).clone()),
            _ => None,
        }
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
        if let SessionState::Failed(error) = &state {
            if crate::protocols::ssh::is_host_key_mismatch(error) {
                self.show_host_key_mismatch(error);
            }
        }
        {
            let mut sessions = self.sessions.borrow_mut();
            if let Some(item) = sessions.iter_mut().find(|(name, _)| name == title) {
                item.1 = state.clone();
            } else {
                sessions.push((title.to_string(), state.clone()));
            }
        }

        let text = format!("{title}: {}", crate::logging::sanitize(&state.text()));
        self.reset_status_style();
        self.status.add_css_class(state.css_class());
        self.status.set_text(&text);
        self.status.set_tooltip_text(Some(&text));
    }

    /// Показывает диалог при изменении ключа SSH-хоста.
    ///
    /// Подключение к этому моменту уже прервано; диалог нужен, чтобы
    /// пользователь не пропустил предупреждение в строке состояния.
    fn show_host_key_mismatch(&self, error: &str) {
        let message = crate::logging::sanitize(error);
        let dialog = gtk4::MessageDialog::builder()
            .modal(true)
            .message_type(gtk4::MessageType::Error)
            .buttons(gtk4::ButtonsType::None)
            .text("Ключ SSH-хоста изменился")
            .secondary_text(message.as_str())
            .build();
        dialog.set_transient_for(self.window().as_ref());
        dialog.add_button("Закрыть", gtk4::ResponseType::Close);
        dialog.connect_response(|dialog, _| dialog.destroy());
        dialog.present();
    }

    /// Пишет сообщение в строку состояния.
    pub fn set_status(&self, text: &str) {
        self.reset_status_style();
        self.status.set_text(text);
        // Полный текст — во всплывающей подсказке: в строке состояния он
        // обрезается, чтобы окно не разъезжалось.
        self.status.set_tooltip_text(Some(text));
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
    profiles.append(Some("Импорт подключений…"), Some("win.import"));
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

/// Плоский порядок групп «родители раньше детей», по алфавиту на каждом
/// уровне. Используется в диалогах выбора группы.
fn order_groups(groups: &[(i64, String, Option<i64>)]) -> Vec<(i64, String, Option<i64>)> {
    let mut result = Vec::with_capacity(groups.len());

    fn walk(
        parent: Option<i64>,
        groups: &[(i64, String, Option<i64>)],
        result: &mut Vec<(i64, String, Option<i64>)>,
    ) {
        let mut children: Vec<&(i64, String, Option<i64>)> = groups
            .iter()
            .filter(|(_, _, p)| *p == parent)
            .collect();
        children.sort_by_key(|g| g.1.to_lowercase());
        for child in children {
            result.push(child.clone());
            walk(Some(child.0), groups, result);
        }
    }

    walk(None, groups, &mut result);
    result
}

/// Глубина вложенности группы (0 — корневая).
fn group_depth(id: i64, groups: &[(i64, String, Option<i64>)]) -> usize {
    let mut depth = 0usize;
    let mut current = Some(id);
    while let Some(gid) = current {
        if depth > 32 {
            break; // защита от циклов
        }
        match groups.iter().find(|entry| entry.0 == gid) {
            Some((_, _, Some(parent))) => {
                depth += 1;
                current = Some(*parent);
            }
            _ => break,
        }
    }
    depth
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
        mac_address: None,
        rdp_options: Default::default(),
        vnc_options: Default::default(),
        ssh_options: Default::default(),
        created_at: 0,
        updated_at: 0,
        last_connected_at: None,
    })
}
