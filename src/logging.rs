//! Санитайзер сообщений перед записью в stderr и журнал.
//!
//! В приложении нет отдельного файлового логгера, но ошибки протоколов и
//! серверов попадают в stderr и журнал подключений. Сервер (или библиотека)
//! может вернуть в тексте пароль, токен или приватный ключ, поэтому все
//! сообщения проходят через [`sanitize`].
//!
//! `SanitizeConfig` позволяет дополнительно вырезать известные значения
//! секретов (например, пароль root) и ограничивать длину записи.

use std::fmt::Write as _;

const REDACTED: &str = "[REDACTED]";
const DEFAULT_MAX_LEN: usize = 8192;

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

/// Пишет сообщение об ошибке в stderr уже очищенным от секретов.
pub fn error(message: &str) {
    eprintln!("Remotix: ошибка: {}", sanitize(message));
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
    "Пароль",
    "токен",
    "Токен",
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

fn redact_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
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
}
