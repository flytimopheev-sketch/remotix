pub mod connection_dialog;
pub mod history_tab;
pub mod host_key;
pub mod main_window;
pub mod master_password;
pub mod profile_editor;
pub mod rdp_viewer;
pub mod settings_window;
pub mod sftp_client;
pub mod sftp_tab;
pub mod terminal;
pub mod theme;

/// Очищает список виджетов.
///
/// `gtk_list_box_remove_all()` появился только в GTK 4.12, а РЕД ОС
/// собирается с GTK 4.6+, поэтому элементы удаляются по одному.
pub fn clear_list(list: &gtk4::ListBox) {
    use gtk4::prelude::*;
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

/// Состояние сессии — отображается в строке состояния и заголовке вкладки.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionState {    /// Идёт подключение.
    Connecting,
    /// Сессия установлена.
    Connected,
    /// Подключение не удалось.
    Failed(String),
    /// Сессия закрыта.
    Closed,
}

impl SessionState {
    /// Текст для строки состояния.
    pub fn text(&self) -> String {
        match self {
            SessionState::Connecting => "подключение…".to_string(),
            SessionState::Connected => "онлайн".to_string(),
            SessionState::Failed(e) => format!("ошибка: {e}"),
            SessionState::Closed => "сессия закрыта".to_string(),
        }
    }

    /// CSS-класс для подсветки состояния.
    pub fn css_class(&self) -> &'static str {
        match self {
            SessionState::Connecting => "remotix-status-busy",
            SessionState::Connected => "remotix-status-ok",
            SessionState::Failed(_) => "remotix-status-error",
            SessionState::Closed => "remotix-hint",
        }
    }
}
