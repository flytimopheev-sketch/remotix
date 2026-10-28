//! Импорт подключений из CSV (стандартный RFC 4180 с вольностями).
//!
//! Ожидается первая строка-заголовок. Разделитель определяется автоматически:
//! запятая, точка с запятой или табуляция — по тому, чего больше в заголовке.
//! Кавычки обрабатываются (`"адрес, 1"` — одно поле), BOM и CRLF — тоже.
//!
//! Политика секретов: столбцы `password`/`пароль` игнорируются, даже если в
//! них что-то есть. Пароли в Remotix попадают только вручную.
//!
//! Распознаваемые столбцы (русские и английские псевдонимы):
//! `host/адрес/server`, `name/название`, `protocol/протокол`, `port/порт`,
//! `username/user/логин`, `tags/теги`, `notes/комментарий`,
//! `group/группа` (можно вложенно: `Прод/Сервера`), `url` (`ssh://user@h:22`).

use crate::import::normalize::{ImportPreview, Source};
use crate::import::split_host_port;
use crate::models::{NewProfile, Protocol};

/// Разбирает выбранные пользователем CSV-файлы.
pub fn scan_paths(paths: &[std::path::PathBuf]) -> Result<ImportPreview, String> {
    let mut preview = ImportPreview::default();
    preview.note("Пароли из CSV не импортируются");
    if paths.is_empty() {
        preview.note("CSV-файлы не выбраны");
        return Ok(preview);
    }

    for path in paths {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                preview.skip(
                    Source::Csv,
                    file_name(path),
                    format!("не удалось прочитать файл: {e}"),
                );
                continue;
            }
        };
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let name = file_name(path);
        let mut item = parse_text(&text, &name);
        preview.candidates.append(&mut item.candidates);
        preview.skipped.append(&mut item.skipped);
        for note in item.notes {
            preview.note(note);
        }
    }
    Ok(preview)
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Разбирает текст CSV (для тестов и `scan_paths`).
pub fn parse_text(text: &str, origin: &str) -> ImportPreview {
    let mut preview = ImportPreview::default();
    preview.note("Пароли из CSV не импортируются");

    // BOM (UTF-8) не должен попадать в имя первого столбца.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);

    let rows = parse_rows(text, sniff_delimiter(text));
    let mut rows = rows.into_iter().peekable();

    // Заголовок: первая строка, в которой узнаётся столбец `host`.
    // Строки до него (комментарии/пустые) просто пропускаются.
    let header = loop {
        let Some(row) = rows.peek() else {
            preview.skip(
                Source::Csv,
                origin.to_string(),
                "не найдена строка заголовка со столбцом «host»",
            );
            return preview;
        };
        if let Some(mapping) = HeaderMapping::parse(row) {
            break mapping;
        }
        rows.next();
    };
    let _ = rows.next(); // сам заголовок из итератора убираем

    let mut skipped_columns: Vec<String> = Vec::new();
    for row in rows {
        if row.iter().all(|cell| cell.trim().is_empty()) {
            continue;
        }
        let profile = match row_profile(&header, &row, &mut skipped_columns) {
            Ok(profile) => profile,
            Err(reason) => {
                let name = header
                    .name_at(&row)
                    .or_else(|| header.host_at(&row).map(|h| h.to_string()))
                    .unwrap_or_else(|| format!("строка {}", row[0].trim()));
                preview.skip(Source::Csv, name, reason);
                continue;
            }
        };
        preview.push_grouped(
            Source::Csv,
            origin.to_string(),
            profile,
            header.group_at(&row),
        );
    }

    if !skipped_columns.is_empty() {
        preview.note(format!(
            "Столбцы {} не распознаны и не перенесены",
            skipped_columns.join(", ")
        ));
    }
    preview
}

/// Соответствие столбцов заголовка и их индексов в строках.
#[derive(Debug)]
struct HeaderMapping {
    host: Option<usize>,
    name: Option<usize>,
    protocol: Option<usize>,
    port: Option<usize>,
    username: Option<usize>,
    tags: Option<usize>,
    notes: Option<usize>,
    group: Option<usize>,
    url: Option<usize>,
    /// Столбцы с паролями: их значения не читаются.
    password: Option<usize>,
    unknown: Vec<String>,
}

/// Сопоставляет название столбца с полем заголовка.
fn column_kind(raw: &str) -> Option<&'static str> {
    let name = raw.trim().to_lowercase();
    let name = name.trim_matches('"').to_string();
    match name.as_str() {
        "host" | "hostname" | "server" | "address" | "ip" | "адрес" | "сервер" | "хост" => {
            Some("host")
        }
        "name" | "profile" | "title" | "название" | "имя" | "профиль" => Some("name"),
        "protocol" | "протокол" | "тип" => Some("protocol"),
        "port" | "порт" => Some("port"),
        "username" | "user" | "login" | "логин" | "пользователь" => Some("username"),
        "tags" | "tag" | "теги" | "тег" => Some("tags"),
        "notes" | "note" | "comment" | "description" | "заметки" | "комментарий" | "описание" => {
            Some("notes")
        }
        "group" | "группа" => Some("group"),
        "url" | "ссылка" => Some("url"),
        "password" | "pass" | "pwd" | "пароль" => Some("password"),
        _ => None,
    }
}

impl HeaderMapping {
    /// Разбирает строку заголовка. `None`, если столбца `host`/`url` нет:
    /// тогда строка не считается заголовком.
    fn parse(row: &[String]) -> Option<Self> {
        let mut map = Self {
            host: None,
            name: None,
            protocol: None,
            port: None,
            username: None,
            tags: None,
            notes: None,
            group: None,
            url: None,
            password: None,
            unknown: Vec::new(),
        };
        let mut has_host = false;
        for (index, cell) in row.iter().enumerate() {
            match column_kind(cell) {
                Some("host") => {
                    map.host = Some(index);
                    has_host = true;
                }
                Some("name") => map.name = Some(index),
                Some("protocol") => map.protocol = Some(index),
                Some("port") => map.port = Some(index),
                Some("username") => map.username = Some(index),
                Some("tags") => map.tags = Some(index),
                Some("notes") => map.notes = Some(index),
                Some("group") => map.group = Some(index),
                Some("url") => {
                    map.url = Some(index);
                    has_host = true;
                }
                Some("password") => map.password = Some(index),
                Some(_) => {}
                None if !cell.trim().is_empty() => {
                    map.unknown.push(cell.trim().to_string());
                }
                None => {}
            }
        }
        has_host.then_some(map)
    }

    fn value(&self, row: &[String], index: Option<usize>) -> Option<String> {
        index
            .and_then(|i| row.get(i))
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn host_at(&self, row: &[String]) -> Option<String> {
        self.value(row, self.host)
    }

    fn name_at(&self, row: &[String]) -> Option<String> {
        self.value(row, self.name)
    }

    fn group_at(&self, row: &[String]) -> Vec<String> {
        self.value(row, self.group)
            .map(|g| {
                g.split(['/', '\\'])
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Собирает черновик профиля из строки. `Err` — понятная причина пропуска.
fn row_profile(
    header: &HeaderMapping,
    row: &[String],
    skipped_columns: &mut Vec<String>,
) -> Result<NewProfile, String> {
    for column in &header.unknown {
        if !skipped_columns.contains(column) {
            skipped_columns.push(column.clone());
        }
    }

    let mut username = header.value(row, header.username);
    let mut host = header.host_at(row).unwrap_or_default();

    // Порт: столбец или ссылка (например, из url: ssh://user@h:2222).
    let mut port = header
        .value(row, header.port)
        .and_then(|raw| raw.parse::<u16>().ok())
        .unwrap_or(0);

    // Столбец url может задать и адрес, и порт, и логин.
    if let Some(url) = header.value(row, header.url) {
        if let Some((url_host, url_port, url_user)) = parse_url(&url) {
            if host.is_empty() {
                host = url_host;
            }
            if port == 0 {
                port = url_port;
            }
            if username.is_none() {
                username = url_user;
            }
        } else {
            return Err(format!("не удалось разобрать ссылку: {url}"));
        }
    }

    let protocol = match header.value(row, header.protocol) {
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "ssh" | "sftp" => Protocol::Ssh,
            "rdp" => Protocol::Rdp,
            "vnc" => Protocol::Vnc,
            other => return Err(format!("неизвестный протокол: {other}")),
        },
        // Протокол не задан: угадываем по порту.
        None => match port {
            3389 => Protocol::Rdp,
            5900..=5999 => Protocol::Vnc,
            _ => Protocol::Ssh,
        },
    };

    Ok(NewProfile {
        name: header.name_at(row).unwrap_or_else(|| host.clone()),
        protocol: Some(protocol),
        host,
        port: if port != 0 {
            port
        } else {
            protocol.default_port()
        },
        username,
        tags: tags_value(header, row),
        notes: header.value(row, header.notes),
        ..Default::default()
    })
}

/// Теги: разделитель внутри ячейки — любой из `;`, `|`, `,` (нужное для
/// конкретного файла выбирается ячейкой: чаще всего это точка с запятой).
fn tags_value(header: &HeaderMapping, row: &[String]) -> Vec<String> {
    let Some(raw) = header.value(row, header.tags) else {
        return Vec::new();
    };
    raw.split([';', '|', ','])
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect()
}

/// Разбирает `scheme://user@host:port`.
fn parse_url(url: &str) -> Option<(String, u16, Option<String>)> {
    let rest = url.split("://").nth(1)?;
    let rest = rest.trim_start_matches('/').trim();
    let (authority, _path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, path),
        None => (rest, ""),
    };
    let (userinfo, host_part) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user.to_string()), host),
        None => (None, authority),
    };
    let protocol = url.split("://").next().unwrap_or("ssh").to_ascii_lowercase();
    let default_port = match protocol.as_str() {
        "rdp" => Protocol::Rdp.default_port(),
        "vnc" => Protocol::Vnc.default_port(),
        _ => Protocol::Ssh.default_port(),
    };
    let (host, port) = split_host_port(host_part, default_port);
    if host.is_empty() {
        return None;
    }
    Some((host, port, userinfo.filter(|u| !u.trim().is_empty())))
}

/// Определяет разделитель по заголовочной строке: тот, чего в ней больше.
fn sniff_delimiter(text: &str) -> char {
    let head = text.lines().find(|line| !line.trim().is_empty());
    let Some(head) = head else { return ',' };
    let counts = [
        (',', head.matches(',').count()),
        (';', head.matches(';').count()),
        ('\t', head.matches('\t').count()),
    ];
    counts
        .into_iter()
        .max_by_key(|(_, count)| *count)
        .filter(|(_, count)| *count > 0)
        .map(|(delim, _)| delim)
        .unwrap_or(',')
}

/// Разбирает CSV в таблицу строк: кавычки, CRLF, переводы строк в кавычках.
fn parse_rows(text: &str, delimiter: char) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' => in_quotes = true,
            c if c == delimiter => {
                row.push(field.clone());
                field.clear();
            }
            '\n' => {
                row.push(field.clone());
                field.clear();
                rows.push(row);
                row = Vec::new();
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                    row.push(field.clone());
                    field.clear();
                    rows.push(row);
                    row = Vec::new();
                } else {
                    field.push(c);
                }
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts(preview: &ImportPreview) -> Vec<String> {
        preview
            .candidates
            .iter()
            .map(|c| c.profile.host.clone())
            .collect()
    }

    #[test]
    fn basic_rows_with_semicolon_header() {
        let text = "host;name;port;username\nexample.org;Сервер;2222;root\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(hosts(&preview), vec!["example.org".to_string()]);
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.port, 2222);
        assert_eq!(profile.username.as_deref(), Some("root"));
        assert_eq!(profile.name, "Сервер");
    }

    #[test]
    fn quoted_comma_and_newline_are_one_field() {
        let text = "host,name,notes\n\"a.org\",\"Имя, с запятой\",\"строка1\nстрока2\"\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(hosts(&preview), vec!["a.org".to_string()]);
        assert_eq!(preview.candidates[0].profile.name, "Имя, с запятой");
        assert!(preview.candidates[0]
            .profile
            .notes
            .as_deref()
            .unwrap()
            .contains('\n'));
    }

    #[test]
    fn bom_and_crlf_are_handled() {
        let text = "\u{feff}host,username\r\nb.org,u1\r\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(hosts(&preview), vec!["b.org".to_string()]);
        assert_eq!(preview.candidates[0].profile.username.as_deref(), Some("u1"));
    }

    #[test]
    fn password_column_is_ignored_with_note() {
        let text = "host,password\nsecret.org,secret-password\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(hosts(&preview), vec!["secret.org".to_string()]);
        assert!(preview.candidates[0].profile.password.is_none());
        assert!(preview.notes.iter().any(|n| n.contains("не импортируются")));
    }

    #[test]
    fn unknown_protocol_is_skipped_with_reason() {
        let text = "host,protocol\na.org,telnet\n";
        let preview = parse_text(text, "test.csv");
        assert!(preview.candidates.is_empty());
        assert_eq!(preview.skipped_count(), 1);
        assert!(preview.skipped[0].reason.contains("telnet"));
    }

    #[test]
    fn missing_host_is_skipped() {
        let text = "host,name\n,broken\n";
        let preview = parse_text(text, "test.csv");
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("адрес"));
    }

    #[test]
    fn no_header_at_all_is_reported() {
        let preview = parse_text("some;text\n", "test.csv");
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("заголовка"));
    }

    #[test]
    fn url_column_sets_host_port_user() {
        let text = "url\nssh://admin@host.org:2222\n";
        let preview = parse_text(text, "test.csv");
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.host, "host.org");
        assert_eq!(profile.port, 2222);
        assert_eq!(profile.username.as_deref(), Some("admin"));
        assert_eq!(profile.protocol, Some(Protocol::Ssh));
    }

    #[test]
    fn group_path_is_parsed_nested() {
        let text = "host;group\na.org;Прод/Сервера\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(preview.candidates[0].group_path, vec!["Прод", "Сервера"]);
    }

    #[test]
    fn tags_split_by_semicolon_pipe_and_comma() {
        let text = "host,tags\na.org,\"тег один; тег два | три\"\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(
            preview.candidates[0].profile.tags,
            vec!["тег один".to_string(), "тег два".to_string(), "три".to_string()]
        );
    }

    #[test]
    fn protocol_by_port_when_column_absent() {
        let text = "host,port\nwin.org,3389\nvnc.org,5900\nplain.org,\n";
        let preview = parse_text(text, "test.csv");
        let protocols: Vec<_> = preview
            .candidates
            .iter()
            .map(|c| c.profile.protocol.unwrap())
            .collect();
        assert_eq!(protocols, vec![Protocol::Rdp, Protocol::Vnc, Protocol::Ssh]);
    }

    #[test]
    fn russian_aliases_are_recognized() {
        let text = "адрес;название;порт;логин\nexample.org;Сервер;2222;root\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(hosts(&preview), vec!["example.org".to_string()]);
    }

    #[test]
    fn empty_lines_and_comments_are_skipped() {
        let text = "# ручной список\n\nhost,name\na.org,One\n\nb.org,Two\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(hosts(&preview), vec!["a.org".to_string(), "b.org".to_string()]);
    }

    #[test]
    fn doubled_quotes_inside_field() {
        let text = "host,name\na.org,\"Он сказал \"\"привет\"\"\"\n";
        let preview = parse_text(text, "test.csv");
        assert_eq!(preview.candidates[0].profile.name, "Он сказал \"привет\"");
    }
}
