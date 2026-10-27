//! Разбор `~/.ssh/config`.
//!
//! Поддерживаются основные директивы OpenSSH: `Host`, `HostName`, `User`,
//! `Port`, `IdentityFile` и `Include`. Блоки `Match`, шаблоны хостов,
//! `ProxyJump`/`ProxyCommand` не превращаются в рабочий профиль Remotix:
//! они попадают в список пропущенных с понятной причиной.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::import::normalize::{ImportPreview, Source};
use crate::models::{NewProfile, Protocol};

/// Путь к пользовательскому конфигу SSH.
pub fn default_path() -> PathBuf {
    crate::config::home_dir().join(".ssh").join("config")
}

/// Разбирает `~/.ssh/config`.
pub fn scan_default() -> Result<ImportPreview, String> {
    parse_file(&default_path())
}

/// Разбирает файл и рекурсивно подключённые через `Include` файлы.
pub fn parse_file(path: &Path) -> Result<ImportPreview, String> {
    if !path.exists() {
        return Err(format!("Файл не найден: {}", path.display()));
    }
    let mut context = Context {
        preview: ImportPreview::default(),
        visited: HashSet::new(),
        depth: 0,
    };
    context
        .parse_file(path)
        .map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))?;
    Ok(context.preview)
}

/// Разбирает уже прочитанный текст. Нужен для тестов и для `Include`.
pub fn parse_text(text: &str, origin: &str) -> ImportPreview {
    let mut context = Context {
        preview: ImportPreview::default(),
        visited: HashSet::new(),
        depth: 0,
    };
    context.parse_text(text, Path::new(origin));
    context.preview
}

struct Context {
    preview: ImportPreview,
    visited: HashSet<PathBuf>,
    depth: usize,
}

#[derive(Default)]
struct Block {
    patterns: Vec<String>,
    host_name: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity: Option<String>,
    extra_identities: usize,
    skip_reason: Option<String>,
}

impl Context {
    fn parse_file(&mut self, path: &Path) -> std::io::Result<()> {
        if self.depth > 8 {
            self.preview.note("Слишком глубокая вложенность Include — разбор остановлен");
            return Ok(());
        }
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !self.visited.insert(canonical) {
            self.preview
                .note(format!("Циклический Include пропущен: {}", path.display()));
            return Ok(());
        }

        let text = std::fs::read_to_string(path)?;
        self.depth += 1;
        self.parse_text(&text, path);
        self.depth -= 1;
        Ok(())
    }

    fn parse_text(&mut self, text: &str, origin: &Path) {
        let mut block = Block::default();
        let mut in_match = false;
        let origin_text = origin.display().to_string();

        for raw_line in text.lines() {
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }
            let Some((key, value)) = split_key_value(line) else {
                continue;
            };
            let key_lower = key.to_ascii_lowercase();

            if key_lower == "host" {
                self.flush(&mut block, &origin_text);
                in_match = false;
                block.patterns = value
                    .split_whitespace()
                    .map(unquote)
                    .filter(|p| !p.is_empty())
                    .collect();
                if block.patterns.is_empty() {
                    self.preview
                        .note(format!("{origin_text}: пустая директива Host"));
                }
                continue;
            }

            if key_lower == "match" {
                self.flush(&mut block, &origin_text);
                in_match = true;
                self.preview.note(format!(
                    "{origin_text}: блок Match пропущен (условные правила не импортируются)"
                ));
                continue;
            }

            if key_lower == "include" {
                // Include не сбрасывает текущий Host: строки после него в
                // основном файле всё ещё относятся к этому блоку. Параметры
                // без Host внутри включённого файла не переносим — это
                // отдельный контекст.
                for include in expand_include(value, origin) {
                    if include.exists() {
                        if let Err(e) = self.parse_file(&include) {
                            self.preview.note(format!(
                                "Include {} не прочитан: {e}",
                                include.display()
                            ));
                        }
                    } else {
                        self.preview
                            .note(format!("Include не найден: {}", include.display()));
                    }
                }
                continue;
            }

            if in_match || block.patterns.is_empty() {
                continue;
            }

            match key_lower.as_str() {
                "hostname" => block.host_name = non_empty(unquote(value)),
                "user" => block.user = non_empty(unquote(value)),
                "port" => match value.trim().parse::<u16>() {
                    Ok(port) if port > 0 => block.port = Some(port),
                    _ => self.preview.note(format!(
                        "{origin_text}: некорректный Port «{}» — будет 22",
                        value.trim()
                    )),
                },
                "identityfile" => {
                    if let Some(path) = non_empty(unquote(value)) {
                        if block.identity.is_none() {
                            block.identity = Some(path);
                        } else {
                            block.extra_identities += 1;
                        }
                    }
                }
                "proxyjump" | "proxycommand" => {
                    let value = unquote(value);
                    if !value.is_empty() && !value.eq_ignore_ascii_case("none") {
                        block.skip_reason =
                            Some("ProxyJump/ProxyCommand не поддерживается".to_string());
                    }
                }
                _ => {}
            }
        }

        self.flush(&mut block, &origin_text);
    }

    fn flush(&mut self, block: &mut Block, origin: &str) {
        let block = std::mem::take(block);
        if block.patterns.is_empty() {
            return;
        }

        for pattern in &block.patterns {
            let name = pattern.trim().to_string();
            if name.is_empty() {
                continue;
            }
            if block.skip_reason.is_some() {
                self.preview.skip(
                    Source::SshConfig,
                    name,
                    block.skip_reason.clone().unwrap_or_default(),
                );
                continue;
            }
            if name.contains('*')
                || name.contains('?')
                || name.contains('!')
                || name.contains('%')
            {
                self.preview.skip(
                    Source::SshConfig,
                    name,
                    "шаблон или динамическое имя Host — конкретный сервер не определён",
                );
                continue;
            }

            let host = block
                .host_name
                .clone()
                .unwrap_or_else(|| name.clone());
            if host.contains('%') {
                self.preview.skip(
                    Source::SshConfig,
                    name,
                    "динамический HostName (%) не поддерживается",
                );
                continue;
            }

            let profile = NewProfile {
                name: name.clone(),
                protocol: Some(Protocol::Ssh),
                host,
                port: block.port.unwrap_or(22),
                username: block.user.clone(),
                ssh_key_path: block.identity.clone(),
                ..Default::default()
            };
            self.preview
                .push(Source::SshConfig, format!("{origin}: Host {name}"), profile);
        }

        if block.extra_identities > 0 {
            self.preview.note(format!(
                "{origin}: для Host {} использован первый IdentityFile, остальные ({}) не импортированы",
                block.patterns.join(", "),
                block.extra_identities
            ));
        }
    }
}

/// Убирает комментарий `#`, не трогая `#` внутри кавычек.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (index, ch) in line.char_indices() {
        match ch {
            '\'' | '"' => {
                if quote == Some(ch) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(ch);
                }
            }
            '#' if quote.is_none() => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Делит строку на ключ и значение (`Key value` или `Key=value`).
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let index = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let key = line[..index].trim();
    if key.is_empty() {
        return None;
    }
    let value = line[index..]
        .trim_start_matches(|c: char| c.is_whitespace() || c == '=')
        .trim();
    Some((key, value))
}

fn unquote(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 {
        let first = value.chars().next().unwrap_or('\0');
        let last = value.chars().last().unwrap_or('\0');
        if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Раскрывает `~` и простые маски `*`/`?` в `Include`.
fn expand_include(value: &str, config: &Path) -> Vec<PathBuf> {
    let base = config.parent().unwrap_or_else(|| Path::new("."));
    let mut result = Vec::new();
    for token in value.split_whitespace() {
        let token = unquote(token);
        let expanded = crate::import::normalize::expand_home(&token);
        let path = PathBuf::from(expanded);
        let path = if path.is_absolute() {
            path
        } else {
            base.join(path)
        };

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.contains('*') || name.contains('?') {
            if let Some(parent) = path.parent() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    let mut matches: Vec<PathBuf> = entries
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|candidate| {
                            candidate
                                .file_name()
                                .map(|n| glob_match(&name, &n.to_string_lossy()))
                                .unwrap_or(false)
                        })
                        .collect();
                    matches.sort();
                    result.extend(matches);
                }
            }
        } else {
            result.push(path);
        }
    }
    result
}

/// Простая маска для имён файлов: `*` — любая последовательность, `?` — один
/// символ. Пути каталогов уже выделены заранее.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut dp = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;
    for i in 1..=pattern.len() {
        if pattern[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }
    for i in 1..=pattern.len() {
        for j in 1..=text.len() {
            dp[i][j] = match pattern[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                ch => dp[i - 1][j - 1] && ch == text[j - 1],
            };
        }
    }
    dp[pattern.len()][text.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_hosts_and_skips_patterns() {
        let text = "\
Host web
    HostName 192.0.2.10
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host db
    HostName db.example.org

Host *
    User root
";
        let preview = parse_text(text, "test-config");
        assert_eq!(preview.imported(), 2);
        let web = &preview.candidates[0].profile;
        assert_eq!(web.name, "web");
        assert_eq!(web.host, "192.0.2.10");
        assert_eq!(web.port, 2222);
        assert_eq!(web.username.as_deref(), Some("admin"));
        assert!(web.ssh_key_path.is_some());
        assert!(web.password.is_none());

        assert!(preview
            .skipped
            .iter()
            .any(|s| s.name == "*" && s.reason.contains("шаблон")));
    }

    #[test]
    fn proxyjump_is_skipped_with_reason() {
        let preview = parse_text(
            "Host behind\n HostName 10.0.0.5\n ProxyJump bastion\n",
            "test",
        );
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("ProxyJump"));
    }

    #[test]
    fn match_block_is_ignored() {
        let preview = parse_text(
            "Host direct\n HostName 10.0.0.1\nMatch host 10.0.0.1\n User root\n",
            "test",
        );
        assert_eq!(preview.imported(), 1);
        assert!(preview.notes.iter().any(|n| n.contains("Match")));
    }

    #[test]
    fn comments_and_equals_are_supported() {
        let preview = parse_text(
            "Host=quoted # comment\n HostName=\"10.0.0.9\"\n User = bob\n",
            "test",
        );
        assert_eq!(preview.imported(), 1);
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.host, "10.0.0.9");
        assert_eq!(profile.username.as_deref(), Some("bob"));
    }

    #[test]
    fn glob_matches_file_names() {
        assert!(glob_match("config.d/*.conf", "config.d/a.conf"));
        assert!(glob_match("*.conf", "a.conf"));
        assert!(!glob_match("*.conf", "a.txt"));
    }
}
