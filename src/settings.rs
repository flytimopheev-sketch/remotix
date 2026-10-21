//! Настройки приложения: тема оформления, параметры терминала и RDP.
//!
//! Хранятся в таблице `meta` базы данных (ключи с префиксом `settings.`),
//! поэтому переживают перезапуск и не требуют отдельного файла конфигурации.

use std::rc::Rc;

use crate::db::repository::Database;

/// Доступ к настройкам приложения.
#[derive(Clone)]
pub struct Settings {
    db: Rc<Database>,
}

/// Значение настройки: строка, число или переключатель.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Text(String),
    Number(i64),
    Flag(bool),
}

impl Value {
    /// Значение как строка.
    pub fn as_text(&self) -> String {
        match self {
            Value::Text(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Flag(b) => b.to_string(),
        }
    }

    /// Значение как число.
    pub fn as_number(&self) -> i64 {
        match self {
            Value::Text(s) => s.parse().unwrap_or(0),
            Value::Number(n) => *n,
            Value::Flag(b) => i64::from(*b),
        }
    }

    /// Значение как переключатель.
    pub fn as_flag(&self) -> bool {
        match self {
            Value::Text(s) => s == "true" || s == "1",
            Value::Number(n) => *n != 0,
            Value::Flag(b) => *b,
        }
    }
}

impl Settings {
    /// Создаёт доступ к настройкам.
    pub fn new(db: Rc<Database>) -> Self {
        Self { db }
    }

    /// Читает настройку или возвращает значение по умолчанию.
    pub fn get(&self, key: &str, default: Value) -> Value {
        match self.db.get_setting(key) {
            Some(v) => match default {
                Value::Text(_) => Value::Text(v),
                Value::Number(_) => Value::Number(v.parse().unwrap_or(default.as_number())),
                Value::Flag(_) => Value::Flag(v == "true" || v == "1"),
            },
            None => default,
        }
    }

    /// Сохраняет настройку.
    pub fn set(&self, key: &str, value: &Value) -> Result<(), String> {
        self.db.set_setting(key, &value.as_text())
    }

    /// Строковая настройка.
    pub fn text(&self, key: &str, default: &str) -> String {
        self.get(key, Value::Text(default.to_string())).as_text()
    }

    /// Числовая настройка.
    pub fn number(&self, key: &str, default: i64) -> i64 {
        self.get(key, Value::Number(default)).as_number()
    }

    /// Переключатель.
    pub fn flag(&self, key: &str, default: bool) -> bool {
        self.get(key, Value::Flag(default)).as_flag()
    }

    // ---------------- Тема оформления ----------------

    /// Идентификатор выбранной темы.
    pub fn theme(&self) -> String {
        self.text("theme", crate::ui::theme::DEFAULT_THEME)
    }

    /// Сохраняет выбранную тему.
    pub fn set_theme(&self, theme: &str) -> Result<(), String> {
        self.set("theme", &Value::Text(theme.to_string()))
    }

    // ---------------- Терминал ----------------

    /// Семейство шрифта терминала.
    pub fn terminal_font(&self) -> String {
        self.text("terminal.font", "Monospace")
    }

    /// Размер шрифта терминала, в пунктах.
    pub fn terminal_font_size(&self) -> i64 {
        self.number("terminal.font_size", 12).clamp(8, 32)
    }

    /// Мигание курсора.
    pub fn terminal_cursor_blink(&self) -> bool {
        self.flag("terminal.cursor_blink", true)
    }

    /// Цветовая схема терминала: `system`, `light`, `dark`.
    pub fn terminal_color_scheme(&self) -> String {
        self.text("terminal.color_scheme", "dark")
    }

    /// Копировать выделение по Ctrl+Shift+C.
    pub fn terminal_copy_selection(&self) -> bool {
        self.flag("terminal.copy_selection", true)
    }

    // ---------------- RDP ----------------

    /// Разрешение экрана по умолчанию: `ШИРИНАxВЫСОТА`.
    pub fn rdp_resolution(&self) -> String {
        self.text("rdp.resolution", "1024x768")
    }

    /// Использовать NLA (CredSSP) при подключении.
    pub fn rdp_nla(&self) -> bool {
        self.flag("rdp.nla", true)
    }

    /// Двусторонний буфер обмена в RDP-сессии.
    pub fn rdp_clipboard(&self) -> bool {
        self.flag("rdp.clipboard", true)
    }

    /// Глубина цвета в RDP-сессии.
    pub fn rdp_color_depth(&self) -> i64 {
        self.number("rdp.color_depth", 32).clamp(16, 32)
    }

    /// Отправлять `Ctrl+Alt+Del` в удалённую сессию.
    pub fn rdp_send_ctrl_alt_del(&self) -> bool {
        self.flag("rdp.send_ctrl_alt_del", true)
    }
}
