//! Нормализация импортированных профилей и удаление дублей.
//!
//! Парсеры (`ssh_config`, `remmina`, `rdp`, `json`) не пишут в базу сами:
//! они создают черновики, а этот модуль приводит их к одному виду, очищает
//! секреты и объясняет, почему запись пропущена.

use std::collections::HashSet;

use crate::models::{NewProfile, Protocol};

/// Откуда взят профиль.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    SshConfig,
    Remmina,
    Rdp,
    RemotixJson,
    Csv,
}

impl Source {
    /// Название источника для интерфейса.
    pub fn label(self) -> &'static str {
        match self {
            Source::SshConfig => "SSH config",
            Source::Remmina => "Remmina",
            Source::Rdp => "RDP-файл",
            Source::RemotixJson => "JSON Remotix",
            Source::Csv => "CSV",
        }
    }
}

/// Профиль, готовый к показу в предпросмотре.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub source: Source,
    /// Файл/секция, откуда взята запись (для подробностей в диалоге).
    pub origin: String,
    pub profile: NewProfile,
    /// Путь вложенных групп («Прод» / «Прод/Сервера»), создаётся при записи.
    /// Пустой — профиль без группы.
    pub group_path: Vec<String>,
}

/// Пропущенная запись с понятной причиной.
#[derive(Debug, Clone)]
pub struct Skipped {
    pub source: Source,
    pub name: String,
    pub reason: String,
}

/// Результат разбора до записи в базу.
#[derive(Debug, Default)]
pub struct ImportPreview {
    pub candidates: Vec<Candidate>,
    pub skipped: Vec<Skipped>,
    /// Общие предупреждения: пароли не импортируются, Include не найден и т.п.
    pub notes: Vec<String>,
}

impl ImportPreview {
    /// Добавляет черновик, нормализуя поля. Ошибки становятся причинами
    /// пропуска, а не прерывают весь импорт.
    pub fn push(&mut self, source: Source, origin: impl Into<String>, profile: NewProfile) {
        self.push_grouped(source, origin, profile, Vec::new());
    }

    /// Вариант `push` с путём групп: группы создаются при подтверждении.
    pub fn push_grouped(
        &mut self,
        source: Source,
        origin: impl Into<String>,
        profile: NewProfile,
        group_path: Vec<String>,
    ) {
        match normalize_profile(profile) {
            Ok(profile) => self.candidates.push(Candidate {
                source,
                origin: origin.into(),
                profile,
                group_path,
            }),
            Err((name, reason)) => self.skip(source, name, reason),
        }
    }

    /// Добавляет запись в список пропущенных.
    pub fn skip(&mut self, source: Source, name: impl Into<String>, reason: impl Into<String>) {
        self.skipped.push(Skipped {
            source,
            name: name.into(),
            reason: reason.into(),
        });
    }

    /// Добавляет общее предупреждение без дублей.
    pub fn note(&mut self, note: impl Into<String>) {
        let note = note.into();
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    /// Сколько профилей будет добавлено.
    pub fn imported(&self) -> usize {
        self.candidates.len()
    }

    /// Сколько записей пропущено.
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Убирает профили, которые уже есть в базе или повторяются в источнике.
    ///
    /// `existing` — тройка «протокол, хост, порт, логин» из базы. Пароли для
    /// сравнения не нужны и не расшифровываются.
    pub fn dedupe_against(&mut self, existing: &[(Protocol, String, u16, Option<String>)]) {
        let mut existing_keys: HashSet<Identity> = HashSet::new();
        for (protocol, host, port, username) in existing {
            existing_keys.insert(identity(*protocol, host, *port, username.as_deref()));
        }
        let mut seen = existing_keys.clone();

        let mut kept = Vec::with_capacity(self.candidates.len());
        for candidate in self.candidates.drain(..) {
            let key = identity(
                candidate.profile.protocol.unwrap_or(Protocol::Ssh),
                &candidate.profile.host,
                candidate.profile.port,
                candidate.profile.username.as_deref(),
            );
            if existing_keys.contains(&key) {
                self.skipped.push(Skipped {
                    source: candidate.source,
                    name: candidate.profile.name.clone(),
                    reason: "такой профиль уже есть в Remotix".to_string(),
                });
                continue;
            }
            if seen.contains(&key) {
                self.skipped.push(Skipped {
                    source: candidate.source,
                    name: candidate.profile.name.clone(),
                    reason: "повторяется в источнике импорта".to_string(),
                });
                continue;
            }
            seen.insert(key);
            kept.push(candidate);
        }
        self.candidates = kept;
    }

    /// Строка для заголовка диалога предпросмотра.
    pub fn summary(&self) -> String {
        format!(
            "Импортируется: {} · пропущено: {}",
            self.imported(),
            self.skipped_count()
        )
    }

    /// Причины пропуска, сгруппированные с количеством.
    pub fn skip_reasons(&self) -> Vec<(String, usize)> {
        let mut result: Vec<(String, usize)> = Vec::new();
        for item in &self.skipped {
            if let Some((_, count)) = result.iter_mut().find(|(reason, _)| reason == &item.reason) {
                *count += 1;
            } else {
                result.push((item.reason.clone(), 1));
            }
        }
        result
    }
}

type Identity = (String, String, u16, String);

fn identity(protocol: Protocol, host: &str, port: u16, username: Option<&str>) -> Identity {
    (
        protocol.as_str().to_string(),
        host.trim().to_ascii_lowercase(),
        port,
        username.unwrap_or("").trim().to_ascii_lowercase(),
    )
}

/// Приводит черновик к безопасному виду.
///
/// * убирает пароли и парольные фразы (политика: импорт без секретов);
/// * подставляет имя и порт по умолчанию;
/// * разворачивает `~` в пути к ключу;
/// * отклоняет пустые адреса и шаблоны вида `*`/`?`.
fn normalize_profile(mut profile: NewProfile) -> Result<NewProfile, (String, String)> {
    let name = profile.name.trim().to_string();
    let host = profile.host.trim().to_string();
    let display_name = if name.is_empty() {
        host.clone()
    } else {
        name.clone()
    };

    if host.is_empty() {
        return Err((display_name, "пустой адрес сервера".to_string()));
    }
    if host == "*" || host.contains('*') || host.contains('?') {
        return Err((
            display_name,
            "шаблон хоста (содержит * или ?) — конкретный сервер не определён".to_string(),
        ));
    }

    let protocol = profile.protocol.unwrap_or(Protocol::Ssh);
    let port = if profile.port == 0 {
        protocol.default_port()
    } else {
        profile.port
    };

    profile.name = if name.is_empty() { host.clone() } else { name };
    profile.host = host;
    profile.protocol = Some(protocol);
    profile.port = port;
    profile.username = clean_optional(profile.username);
    profile.password = None;
    profile.ssh_key_passphrase = None;
    profile.root_password = None;
    profile.ssh_key_path = profile.ssh_key_path.and_then(|path| {
        let path = path.trim();
        if path.is_empty() {
            None
        } else {
            Some(expand_home(path))
        }
    });
    profile.notes = clean_optional(profile.notes);
    profile.icon = clean_optional(profile.icon);
    profile.tags = profile
        .tags
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect();

    Ok(profile)
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    })
}

/// Разворачивает `~` и `~/…` в домашний каталог.
pub fn expand_home(path: &str) -> String {
    if path == "~" {
        return crate::config::home_dir().display().to_string();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return crate::config::home_dir().join(rest).display().to_string();
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn draft(name: &str, host: &str) -> NewProfile {
        NewProfile {
            name: name.to_string(),
            host: host.to_string(),
            protocol: Some(Protocol::Ssh),
            port: 22,
            password: Some(SecretString::from("secret".to_string())),
            ssh_key_passphrase: Some(SecretString::from("passphrase".to_string())),
            root_password: Some(SecretString::from("root".to_string())),
            ..Default::default()
        }
    }

    #[test]
    fn normalize_removes_secrets_and_defaults() {
        let mut preview = ImportPreview::default();
        preview.push(Source::SshConfig, "test", draft("", " example.org "));
        assert_eq!(preview.candidates.len(), 1);
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.name, "example.org");
        assert_eq!(profile.host, "example.org");
        assert_eq!(profile.port, 22);
        assert!(profile.password.is_none());
        assert!(profile.ssh_key_passphrase.is_none());
        assert!(profile.root_password.is_none());
    }

    #[test]
    fn empty_and_wildcard_hosts_are_skipped() {
        let mut preview = ImportPreview::default();
        preview.push(Source::SshConfig, "test", draft("empty", " "));
        preview.push(Source::SshConfig, "test", draft("wild", "*.example.org"));
        assert!(preview.candidates.is_empty());
        assert_eq!(preview.skipped_count(), 2);
        assert!(preview.skipped[1].reason.contains("шаблон"));
    }

    #[test]
    fn dedupe_uses_protocol_host_port_and_user() {
        let mut preview = ImportPreview::default();
        preview.push(Source::SshConfig, "a", draft("one", "example.org"));
        preview.push(Source::Remmina, "b", draft("two", "EXAMPLE.ORG"));
        preview.dedupe_against(&[(Protocol::Ssh, "example.org".to_string(), 22, None)]);
        assert!(preview.candidates.is_empty());
        assert_eq!(preview.skipped_count(), 2);
        assert!(preview
            .skipped
            .iter()
            .all(|s| s.reason.contains("уже есть")));
    }

    #[test]
    fn dedupe_reports_duplicates_within_source() {
        let mut preview = ImportPreview::default();
        preview.push(Source::SshConfig, "a", draft("one", "example.org"));
        preview.push(Source::Remmina, "b", draft("two", "EXAMPLE.ORG"));
        preview.dedupe_against(&[]);
        assert_eq!(preview.candidates.len(), 1);
        assert_eq!(preview.skipped_count(), 1);
        assert!(preview.skipped[0].reason.contains("источнике"));
    }

    #[test]
    fn port_zero_uses_protocol_default() {
        let mut profile = draft("rdp", "server");
        profile.protocol = Some(Protocol::Rdp);
        profile.port = 0;
        let normalized = normalize_profile(profile).unwrap();
        assert_eq!(normalized.port, 3389);
    }

    #[test]
    fn home_path_is_expanded() {
        let normalized = expand_home("~/keys/id_ed25519");
        assert!(normalized.contains("keys"));
        assert!(!normalized.starts_with('~'));
    }
}
