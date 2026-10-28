//! Импорт подключений Remmina (`.remmina`, INI-подобный формат).
//!
//! Пароли Remmina хранит отдельно/в зашифрованном виде; мы их не читаем и не
//! переносим. Всё, что нужно для подключения (адрес, порт, логин, ключ,
//! параметры протокола), преобразуется в `NewProfile`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::import::normalize::{ImportPreview, Source};
use crate::import::split_host_port;
use crate::models::profile::{RdpOptions, VncOptions};
use crate::models::{NewProfile, Protocol};

/// Каталог подключений Remmina.
pub fn default_dir() -> PathBuf {
    crate::config::home_dir()
        .join(".local")
        .join("share")
        .join("remmina")
}

/// Разбирает все `.remmina` из каталога по умолчанию.
pub fn scan_default() -> Result<ImportPreview, String> {
    let dir = default_dir();
    if !dir.exists() {
        return Err(format!(
            "Каталог Remmina не найден: {}\n\
             Ожидаются файлы подключений *.remmina.",
            dir.display()
        ));
    }
    scan_dir(&dir)
}

/// Разбирает все `.remmina` из указанного каталога.
pub fn scan_dir(dir: &Path) -> Result<ImportPreview, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("не удалось прочитать {}: {e}", dir.display()))?;
    let mut preview = ImportPreview::default();
    preview.note("Пароли из Remmina не импортируются");

    let mut files = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file()
            || path
                .extension()
                .map(|ext| !ext.eq_ignore_ascii_case("remmina"))
                .unwrap_or(true)
        {
            continue;
        }
        files += 1;
        match parse_file(&path) {
            Ok(mut item) => {
                preview.candidates.append(&mut item.candidates);
                preview.skipped.append(&mut item.skipped);
                for note in item.notes {
                    preview.note(note);
                }
            }
            Err(e) => preview.skip(
                Source::Remmina,
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                e,
            ),
        }
    }

    if files == 0 {
        preview.note(format!("В {} не найдено файлов *.remmina", dir.display()));
    }
    Ok(preview)
}

/// Разбирает один файл Remmina.
pub fn parse_file(path: &Path) -> Result<ImportPreview, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))?;
    Ok(parse_text(&text, &path.display().to_string()))
}

/// Разбирает текст `.remmina` (для тестов и `scan_dir`).
pub fn parse_text(text: &str, origin: &str) -> ImportPreview {
    let mut preview = ImportPreview::default();
    let values = parse_ini(text);

    let protocol_raw = values.get("protocol").map(String::as_str).unwrap_or("");
    let protocol = match protocol_raw.to_ascii_lowercase().as_str() {
        "ssh" | "sftp" => Protocol::Ssh,
        "rdp" => Protocol::Rdp,
        "vnc" | "vnc-any" | "vnc-tls" | "vnc-stunnel" => Protocol::Vnc,
        "" => {
            preview.skip(
                Source::Remmina,
                origin.to_string(),
                "в файле Remmina не указан протокол",
            );
            return preview;
        }
        other => {
            preview.skip(
                Source::Remmina,
                origin.to_string(),
                format!("неизвестный протокол Remmina: {other}"),
            );
            return preview;
        }
    };

    if values
        .get("gateway")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        preview.skip(
            Source::Remmina,
            display_name(&values, origin),
            "используется шлюз Remmina (Gateway) — импорт не поддерживается",
        );
        return preview;
    }
    if protocol == Protocol::Vnc
        && values
            .get("ssh_tunnel")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    {
        preview.skip(
            Source::Remmina,
            display_name(&values, origin),
            "VNC через SSH-туннель Remmina не импортируется",
        );
        return preview;
    }

    let (server, server_port) = values
        .get("server")
        .map(|s| split_host_port(s, protocol.default_port()))
        .unwrap_or_else(|| (String::new(), protocol.default_port()));
    let port = values
        .get("port")
        .and_then(|p| p.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(server_port);
    if server.trim().is_empty() {
        preview.skip(
            Source::Remmina,
            display_name(&values, origin),
            "не указан адрес сервера",
        );
        return preview;
    }

    let mut username = clean(values.get("username"));
    let mut rdp_options = RdpOptions::default();
    if protocol == Protocol::Rdp {
        rdp_options.domain = clean(values.get("domain")).unwrap_or_default();
        if let Some((domain, user)) = username.as_deref().and_then(|u| u.split_once('\\')) {
            if rdp_options.domain.is_empty() {
                rdp_options.domain = domain.to_string();
            }
            username = Some(user.to_string());
        }
        if let Some(depth) = values
            .get("colordepth")
            .and_then(|v| v.trim().parse::<u32>().ok())
        {
            if matches!(depth, 8 | 15 | 16 | 24 | 32) {
                rdp_options.color_depth = depth;
            }
        }
        if let Some((width, height)) = values.get("resolution").and_then(|v| parse_resolution(v)) {
            rdp_options.width = width;
            rdp_options.height = height;
        }
        if values.get("disableclipboard").map(String::as_str) == Some("1") {
            rdp_options.clipboard = false;
            rdp_options.clipboard_to_remote = false;
            rdp_options.clipboard_from_remote = false;
        }
        rdp_options.redirect_printers = is_true(values.get("redirectprinters"));
        rdp_options.redirect_drives = is_true(values.get("redirectdrives"));
    }

    let mut vnc_options = VncOptions::default();
    if protocol == Protocol::Vnc {
        vnc_options.view_only = is_true(values.get("viewonly"));
        if let Some(quality) = values
            .get("quality")
            .and_then(|v| v.trim().parse::<u32>().ok())
        {
            vnc_options.compression_quality = quality.min(9);
        }
    }

    let profile = NewProfile {
        name: display_name(&values, origin),
        protocol: Some(protocol),
        host: server,
        port,
        username,
        ssh_key_path: clean(values.get("ssh_privatekey")),
        notes: clean(values.get("notes"))
            .or_else(|| clean(values.get("description")))
            .map(|notes| format!("{notes}\nИмпортировано из Remmina")),
        rdp_options,
        vnc_options,
        ..Default::default()
    };
    preview.push(Source::Remmina, origin.to_string(), profile);
    preview
}

fn parse_ini(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    let mut in_remmina = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let section = line.trim_matches(['[', ']']).trim();
            in_remmina = section.eq_ignore_ascii_case("remmina");
            continue;
        }
        if !in_remmina {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    values
}

fn display_name(values: &HashMap<String, String>, origin: &str) -> String {
    clean(values.get("name"))
        .or_else(|| values.get("server").and_then(|server| clean(Some(server))))
        .unwrap_or_else(|| {
            Path::new(origin)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| origin.to_string())
        })
}

fn clean(value: Option<&String>) -> Option<String> {
    value.and_then(|v| {
        let v = v.trim().to_string();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    })
}

fn is_true(value: Option<&String>) -> bool {
    value
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn parse_resolution(value: &str) -> Option<(u32, u32)> {
    let (width, height) = value.trim().split_once(['x', 'X'])?;
    let width = width.trim().parse::<u32>().ok()?;
    let height = height.trim().parse::<u32>().ok()?;
    if width > 0 && height > 0 {
        Some((width, height))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ssh_connection_without_password() {
        let text = "\
[remmina]
name=Web server
protocol=SSH
server=192.0.2.10:2222
username=admin
ssh_privatekey=~/.ssh/id_ed25519
password=secret
";
        let preview = parse_text(text, "web.remmina");
        assert_eq!(preview.imported(), 1);
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.name, "Web server");
        assert_eq!(profile.host, "192.0.2.10");
        assert_eq!(profile.port, 2222);
        assert_eq!(profile.username.as_deref(), Some("admin"));
        assert!(profile.password.is_none());
        assert!(profile.ssh_key_path.is_some());
    }

    #[test]
    fn parses_rdp_resolution_and_domain() {
        let text = "\
[remmina]
name=Desktop
protocol=RDP
server=win.example.org
username=CORP\\alice
colordepth=24
resolution=1600x900
disableclipboard=1
";
        let preview = parse_text(text, "desktop.remmina");
        assert_eq!(preview.imported(), 1);
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.protocol, Some(Protocol::Rdp));
        assert_eq!(profile.port, 3389);
        assert_eq!(profile.username.as_deref(), Some("alice"));
        assert_eq!(profile.rdp_options.domain, "CORP");
        assert_eq!(profile.rdp_options.color_depth, 24);
        assert_eq!(profile.rdp_options.width, 1600);
        assert_eq!(profile.rdp_options.height, 900);
        assert!(!profile.rdp_options.clipboard);
    }

    #[test]
    fn unknown_protocol_is_skipped() {
        let preview = parse_text("[remmina]\nprotocol=spice\nserver=x\n", "x.remmina");
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("протокол"));
    }

    #[test]
    fn gateway_is_skipped() {
        let preview = parse_text(
            "[remmina]\nprotocol=RDP\nserver=x\ngateway=gw.example.org\n",
            "x.remmina",
        );
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("шлюз"));
    }
}
