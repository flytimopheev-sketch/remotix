//! Санитайзер сообщений перед записью в stderr и журнал.
//!
//! Ошибки протоколов и серверов попадают в stderr и журнал подключений,
//! а диагностика RDP — в отдельный файл [`rdp_log_path`]. Сервер (или
//! библиотека) может вернуть в тексте пароль, токен или приватный ключ,
//! поэтому все сообщения проходят через [`sanitize`].
//!
//! `SanitizeConfig` позволяет дополнительно вырезать известные значения
//! секретов (например, пароль root) и ограничивать длину записи.

use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Mutex;

const REDACTED: &str = "[REDACTED]";
const DEFAULT_MAX_LEN: usize = 8192;
/// Диагностический журнал RDP ограничен по размеру: старый файл
/// переименовывается в `rdp.log.1` при превышении.
const RDP_LOG_MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Настройки санитайзера.
#[derive(Debug, Clone)]
pub struct SanitizeConfig {
    /// Дополнительные значения, которые нужно вырезать целиком.
    ///
    /// Короткие строки (меньше 4 символов) игнорируются, чтобы не испортить
    /// обычный текст случайными совпадениями.
    pub secrets: Vec<String>,
    /// Максимальная длина сообщения в символах.
    pub max_len: usize,
}

impl Default for SanitizeConfig {
    fn default() -> Self {
        Self {
            secrets: Vec::new(),
            max_len: DEFAULT_MAX_LEN,
        }
    }
}

/// Убирает из текста значения секретных полей, приватные ключи и лишнюю длину.
pub fn sanitize(text: &str) -> String {
    sanitize_with(text, &SanitizeConfig::default())
}

/// То же, что [`sanitize`], но с дополнительными настройками.
pub fn sanitize_with(text: &str, config: &SanitizeConfig) -> String {
    let without_keys = redact_private_key_blocks(text);
    let mut out = redact_sensitive_values(&without_keys);

    for secret in &config.secrets {
        if secret.chars().count() >= 4 && out.contains(secret) {
            out = out.replace(secret, REDACTED);
        }
    }

    truncate(out, config.max_len)
}

/// Пишет предупреждение в stderr уже очищенным от секретов.
pub fn warn(message: &str) {
    eprintln!("Remotix: {}", sanitize(message));
}

/// Пишет информационное сообщение в stderr уже очищенным от секретов.
pub fn info(message: &str) {
    eprintln!("Remotix: {}", sanitize(message));
}

/// Пишет сообщение об ошибке в stderr уже очищенным от секретов.
pub fn error(message: &str) {
    eprintln!("Remotix: ошибка: {}", sanitize(message));
}

/// Уровень диагностического журнала RDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
        }
    }
}

/// Файловый журнал RDP с простой ротацией.
///
/// Содержимое буфера обмена сюда не передаётся: вызывающий код пишет только
/// направление, формат и размер. Дополнительно каждая строка проходит через
/// [`sanitize`] — на случай, если сервер вернул секрет в тексте ошибки.
#[derive(Debug)]
struct RdpLog {
    path: PathBuf,
    file: Option<std::fs::File>,
    failed: bool,
}

impl RdpLog {
    fn new(path: PathBuf) -> Self {
        let mut log = Self {
            path,
            file: None,
            failed: false,
        };
        log.open();
        log
    }

    fn open(&mut self) {
        if self.failed {
            return;
        }
        if let Some(parent) = self.path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!(
                    "Remotix: не удалось создать каталог журнала RDP {}: {e}",
                    parent.display()
                );
                self.failed = true;
                return;
            }
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => self.file = Some(file),
            Err(e) => {
                eprintln!(
                    "Remotix: не удалось открыть журнал RDP {}: {e}",
                    self.path.display()
                );
                self.failed = true;
            }
        }
    }

    fn rotate(&mut self) {
        self.file = None;
        let rotated = self.path.with_file_name("rdp.log.1");
        let _ = fs::remove_file(&rotated);
        if let Err(e) = fs::rename(&self.path, &rotated) {
            eprintln!(
                "Remotix: не удалось ротировать журнал RDP {}: {e}",
                self.path.display()
            );
        }
        self.failed = false;
        self.open();
    }

    fn write(&mut self, level: Level, message: &str) {
        if self.failed {
            return;
        }
        if self.file.is_none() {
            self.open();
        }
        let Some(file) = self.file.as_mut() else {
            return;
        };

        let too_big = file
            .metadata()
            .map(|meta| meta.len() >= RDP_LOG_MAX_BYTES)
            .unwrap_or(false);
        if too_big {
            self.rotate();
            if self.failed {
                return;
            }
        }

        let Some(file) = self.file.as_mut() else {
            return;
        };
        let line = format!(
            "{} {:<5} {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            level.label(),
            sanitize(message)
        );
        if let Err(e) = file.write_all(line.as_bytes()) {
            eprintln!("Remotix: не удалось записать журнал RDP: {e}");
            self.failed = true;
        } else if let Err(e) = file.flush() {
            eprintln!("Remotix: не удалось сбросить журнал RDP: {e}");
        }
    }
}

static RDP_LOG: Mutex<Option<RdpLog>> = Mutex::new(None);

/// Путь диагностического журнала RDP.
pub fn rdp_log_path() -> PathBuf {
    crate::config::data_dir().join("logs").join("rdp.log")
}

/// Создаёт файл журнала (если его ещё нет) и возвращает путь.
///
/// Используется кнопкой «Лог» в просмотрщике, чтобы открыть журнал даже до
/// первого сообщения.
pub fn ensure_rdp_log_file() -> Result<PathBuf, String> {
    let path = rdp_log_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("не удалось создать {}: {e}", parent.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("не удалось открыть {}: {e}", path.display()))?;
    Ok(path)
}

/// Записывает сообщение в stderr и диагностический журнал RDP.
pub fn rdp(level: Level, message: &str) {
    let clean = sanitize(message);
    match level {
        Level::Error => eprintln!("Remotix: ошибка: {clean}"),
        Level::Warn | Level::Info => eprintln!("Remotix: {clean}"),
    }

    let mut guard = RDP_LOG.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_none() {
        *guard = Some(RdpLog::new(rdp_log_path()));
    }
    if let Some(log) = guard.as_mut() {
        log.write(level, &clean);
    }
}

/// Информационное сообщение RDP.
pub fn rdp_info(message: &str) {
    rdp(Level::Info, message);
}

/// Предупреждение RDP.
pub fn rdp_warn(message: &str) {
    rdp(Level::Warn, message);
}

/// Ошибка RDP.
pub fn rdp_error(message: &str) {
    rdp(Level::Error, message);
}

/// Заменяет блоки PEM-ключей целиком, не оставляя даже строк тела.
fn redact_private_key_blocks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_key = false;

    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !in_key && lower.contains("-----begin") && lower.contains("private key-----") {
            in_key = true;
            out.push_str("-----BEGIN PRIVATE KEY----- [REDACTED]\n");
            continue;
        }
        if in_key {
            if lower.contains("-----end") && lower.contains("private key-----") {
                in_key = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }

    if !text.ends_with('\n') && !out.is_empty() {
        out.pop();
    }
    out
}

/// Ключи, после которых значение считается секретом.
const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "ssh_key_passphrase",
    "key_passphrase",
    "root_password",
    "master_password",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "private_key",
    "authorization",
    "пароль",
    "токен",
];

/// Строки, содержащие секретное поле в формате `key=value` или `key: value`,
/// обрезаются после разделителя: так значение не попадает в лог целиком.
fn redact_sensitive_values(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (content, newline) = match line.strip_suffix('\n') {
            Some(content) => (content, "\n"),
            None => (line, ""),
        };
        out.push_str(&redact_line(content));
        out.push_str(newline);
    }
    out
}

/// Нижний регистр для поиска ключей: ASCII + базовая кириллица.
/// В отличие от str::to_lowercase длина в байтах не меняется, поэтому
/// индексы совпадают с исходной строкой.
fn fold_lower(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for ch in line.chars() {
        if ch.is_ascii() {
            out.push(ch.to_ascii_lowercase());
        } else if matches!(ch, 'А'..='Я' | 'Ё') {
            out.push(char::from_u32(ch as u32 + 0x20).unwrap_or(ch));
        } else {
            out.push(ch);
        }
    }
    out
}

fn redact_line(line: &str) -> String {
    let lower = fold_lower(line);
    let bytes = lower.as_bytes();

    for key in SENSITIVE_KEYS {
        let mut search_from = 0;
        while let Some(relative) = lower[search_from..].find(key) {
            let start = search_from + relative;
            let end = start + key.len();
            let before_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
            let after_ok = end >= bytes.len() || !is_identifier_byte(bytes[end]);

            if before_ok && after_ok {
                if let Some(value_start) = value_start(line, end) {
                    let mut redacted = String::with_capacity(value_start + REDACTED.len());
                    redacted.push_str(&line[..value_start]);
                    redacted.push_str(REDACTED);
                    return redacted;
                }
            }
            search_from = end;
        }
    }

    line.to_string()
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Находит начало значения после `key`, `key:`, `key=` или JSON-пары.
fn value_start(line: &str, mut index: usize) -> Option<usize> {
    let bytes = line.as_bytes();

    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'"' | b'\'') {
        index += 1;
    }
    if index >= bytes.len() || !matches!(bytes[index], b':' | b'=') {
        return None;
    }
    index += 1;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b'"' | b'\'') {
        index += 1;
    }
    Some(index)
}

fn truncate(mut text: String, max_len: usize) -> String {
    if text.chars().count() <= max_len {
        return text;
    }
    let cut = text
        .char_indices()
        .nth(max_len)
        .map(|(index, _)| index)
        .unwrap_or(text.len());
    text.truncate(cut);
    let _ = write!(text, "… [сообщение обрезано]");
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_password_and_token_values() {
        let text = "вход не удался: password=hunter2\ntoken: abc123\n\
                    ssh_key_passphrase=key-secret\nПароль: hunter3\nhost=example.org";
        let clean = sanitize(text);
        assert!(!clean.contains("hunter2"));
        assert!(!clean.contains("abc123"));
        assert!(!clean.contains("key-secret"));
        assert!(!clean.contains("hunter3"));
        assert!(clean.contains("password="));
        assert!(clean.contains("token:"));
        assert!(clean.contains("host=example.org"));
    }

    #[test]
    fn redacts_json_style_secrets() {
        let clean = sanitize(r#"{"password":"s3cret","user":"alice"}"#);
        assert!(!clean.contains("s3cret"));
        assert!(clean.contains(REDACTED));
    }

    #[test]
    fn redacts_private_key_block() {
        let text = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretbody\n-----END OPENSSH PRIVATE KEY-----\nafter";
        let clean = sanitize(text);
        assert!(!clean.contains("AAAAsecretbody"));
        assert!(clean.contains("before"));
        assert!(clean.contains("after"));
        assert!(clean.contains("[REDACTED]"));
    }

    #[test]
    fn safe_text_is_unchanged() {
        assert_eq!(
            sanitize("подключение к example.org:22"),
            "подключение к example.org:22"
        );
    }

    #[test]
    fn config_removes_exact_secret_and_truncates() {
        let config = SanitizeConfig {
            secrets: vec!["root-secret".to_string()],
            max_len: 12,
        };
        let clean = sanitize_with("root-secret и ещё немного текста", &config);
        assert!(!clean.contains("root-secret"));
        assert!(clean.contains("обрезано"));
    }

    #[test]
    fn rdp_log_has_levels_and_redacts_secrets() {
        let dir = std::env::temp_dir().join(format!("remotix-rdp-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("rdp.log");
        let mut log = RdpLog::new(path.clone());
        log.write(Level::Warn, "password=hunter2");
        log.write(Level::Info, "кадр 10 байт");

        let text = fs::read_to_string(&path).expect("log");
        assert!(text.contains("WARN"), "нет уровня WARN: {text}");
        assert!(text.contains("INFO"), "нет уровня INFO: {text}");
        assert!(!text.contains("hunter2"), "пароль попал в журнал: {text}");
        assert!(text.contains(REDACTED), "нет маскировки: {text}");

        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    /// РЕГРЕССИЯ: кириллические ключи в верхнем регистре.
    #[test]
    fn redacts_uppercase_cyrillic_keys() {
        let clean = sanitize("ПАРОЛЬ: hunter2\nТОКЕН=abc123");
        assert!(!clean.contains("hunter2"), "ПАРОЛЬ не замаскирован");
        assert!(!clean.contains("abc123"), "ТОКЕН не замаскирован");
    }

    #[test]
    fn identifier_boundaries_are_respected() {
        assert_eq!(sanitize("mypasswordx=12345"), "mypasswordx=12345");
        assert_eq!(sanitize("passwords: list"), "passwords: list");
    }

    #[test]
    fn truncation_is_char_safe() {
        let config = SanitizeConfig {
            secrets: vec![],
            max_len: 5,
        };
        let clean = sanitize_with(&"ю".repeat(20), &config);
        assert!(clean.starts_with("ююююю"));
        assert!(clean.contains("обрезано"));
    }

    #[test]
    fn short_config_secrets_are_ignored() {
        let config = SanitizeConfig {
            secrets: vec!["abc".into()],
            max_len: 8192,
        };
        assert_eq!(sanitize_with("abc def", &config), "abc def");
    }
}
