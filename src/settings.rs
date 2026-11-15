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

    /// Панель метрик хоста в SSH-вкладке (CPU, память, сеть, load, диск).
    pub fn terminal_metrics(&self) -> bool {
        self.flag("terminal.metrics", true)
    }

    /// Запись вывода SSH-сессий в формат script(1)/scriptreplay(1)
    /// (каталог `<данные>/recordings`). По умолчанию выключена: это осознанный
    /// выбор в пользу приватности — включается в настройках.
    pub fn terminal_recording(&self) -> bool {
        self.flag("terminal.recording", false)
    }

    // ---------------- Восстановление вкладок ----------------

    /// Открывать при запуске вкладки сессий, которые были открыты при выходе.
    pub fn session_restore(&self) -> bool {
        self.flag("session.restore", true)
    }

    /// Сохранённый список вкладок в формате `ssh:12,sftp:3`.
    pub fn session_tabs(&self) -> String {
        self.text("session.tabs", "")
    }

    /// Сохраняет список вкладок (пустая строка — вкладок не было).
    pub fn set_session_tabs(&self, tabs: &str) -> Result<(), String> {
        self.set("session.tabs", &Value::Text(tabs.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::repository::Database;

    fn settings() -> Settings {
        Settings::new(Rc::new(Database::open(":memory:").expect("БД")))
    }

    #[test]
    fn defaults_are_sane() {
        let s = settings();
        assert_eq!(s.terminal_font(), "Monospace");
        assert_eq!(s.terminal_font_size(), 12);
        assert!(s.terminal_cursor_blink());
        assert_eq!(s.terminal_color_scheme(), "dark");
        assert!(s.terminal_metrics());
        assert!(
            !s.terminal_recording(),
            "запись сессий по умолчанию выключена"
        );
        assert!(s.session_restore());
        assert_eq!(s.session_tabs(), "");
        assert_eq!(s.rdp_resolution(), "1024x768");
        assert!(s.rdp_nla());
        assert_eq!(s.rdp_color_depth(), 32);
        assert_eq!(s.theme(), crate::ui::theme::DEFAULT_THEME);
    }

    #[test]
    fn text_number_flag_roundtrip() {
        let s = settings();
        s.set("x.text", &Value::Text("привет".into())).unwrap();
        s.set("x.num", &Value::Number(-7)).unwrap();
        s.set("x.flag", &Value::Flag(true)).unwrap();
        assert_eq!(s.text("x.text", ""), "привет");
        assert_eq!(s.number("x.num", 0), -7);
        assert!(s.flag("x.flag", false));
    }

    #[test]
    fn font_size_is_clamped() {
        let s = settings();
        s.set("terminal.font_size", &Value::Number(100)).unwrap();
        assert_eq!(s.terminal_font_size(), 32);
        s.set("terminal.font_size", &Value::Number(2)).unwrap();
        assert_eq!(s.terminal_font_size(), 8);
    }

    #[test]
    fn broken_number_falls_back_to_default() {
        let s = settings();
        s.set("terminal.font_size", &Value::Text("abc".into()))
            .unwrap();
        assert_eq!(s.terminal_font_size(), 12);
    }

    #[test]
    fn flag_accepts_one_and_true_only() {
        let s = settings();
        for v in ["1", "true"] {
            s.set("x", &Value::Text(v.into())).unwrap();
            assert!(s.flag("x", false), "{v} должно быть true");
        }
        s.set("x", &Value::Text("no".into())).unwrap();
        assert!(!s.flag("x", true));
    }

    #[test]
    fn color_depth_is_clamped() {
        let s = settings();
        s.set("rdp.color_depth", &Value::Number(8)).unwrap();
        assert_eq!(s.rdp_color_depth(), 16);
        s.set("rdp.color_depth", &Value::Number(64)).unwrap();
        assert_eq!(s.rdp_color_depth(), 32);
    }

    #[test]
    fn session_tabs_roundtrip() {
        let s = settings();
        s.set_session_tabs("ssh:12,sftp:3").unwrap();
        assert_eq!(s.session_tabs(), "ssh:12,sftp:3");
    }

    #[test]
    fn value_conversions() {
        assert_eq!(Value::Text("42".into()).as_number(), 42);
        assert_eq!(Value::Text("oops".into()).as_number(), 0);
        assert_eq!(Value::Flag(true).as_text(), "true");
        assert!(Value::Number(2).as_flag());
        assert!(!Value::Number(0).as_flag());
        assert!(Value::Text("1".into()).as_flag());
    }
}
