//! Импорт профилей из файлов `.rdp` (формат xfreerdp / mstsc).
//!
//! Строки вида `full address:s:server:3389` и параметры сессии преобразуются
//! в RDP-профиль Remotix. Пароли (`password 51:b:…`) не читаются.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::import::normalize::{ImportPreview, Source};
use crate::import::split_host_port;
use crate::models::profile::RdpOptions;
use crate::models::{NewProfile, Protocol};

/// Разбирает выбранные пользователем `.rdp`-файлы.
pub fn scan_paths(paths: &[PathBuf]) -> Result<ImportPreview, String> {
    let mut preview = ImportPreview::default();
    preview.note("Пароли из .rdp-файлов не импортируются");
    if paths.is_empty() {
        preview.note("Файлы .rdp не выбраны");
        return Ok(preview);
    }

    for path in paths {
        match parse_file(path) {
            Ok(mut item) => {
                preview.candidates.append(&mut item.candidates);
                preview.skipped.append(&mut item.skipped);
                for note in item.notes {
                    preview.note(note);
                }
            }
            Err(e) => preview.skip(
                Source::Rdp,
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
                e,
            ),
        }
    }
    Ok(preview)
}

/// Разбирает один `.rdp`-файл.
pub fn parse_file(path: &Path) -> Result<ImportPreview, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))?;
    let text = decode_text(&bytes)?;
    let name = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| path.display().to_string());
    Ok(parse_text(&text, &name, &path.display().to_string()))
}

/// Разбирает текст `.rdp` (для тестов).
pub fn parse_text(text: &str, name: &str, origin: &str) -> ImportPreview {
    let mut preview = ImportPreview::default();
    let values = parse_values(text);

    let address = values
        .get("full address")
        .or_else(|| values.get("server address"))
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    if address.is_empty() {
        preview.skip(
            Source::Rdp,
            name.to_string(),
            "в .rdp-файле нет адреса сервера (full address)",
        );
        return preview;
    }
    if values
        .get("gatewayhostname")
        .map(|g| !g.trim().is_empty())
        .unwrap_or(false)
    {
        preview.skip(
            Source::Rdp,
            name.to_string(),
            "используется RD Gateway — импорт не поддерживается",
        );
        return preview;
    }

    let (host, port) = split_host_port(address, 3389);
    if host.is_empty() {
        preview.skip(Source::Rdp, name.to_string(), "пустой адрес RDP-сервера");
        return preview;
    }

    let mut username = clean(values.get("username"));
    let mut domain = clean(values.get("domain")).unwrap_or_default();
    if let Some((domain_prefix, user)) = username.as_deref().and_then(|u| u.split_once('\\')) {
        // Явно заданный domain имеет приоритет; встроенный префикс всё равно
        // убираем из логина, иначе сервер получит «CORP\alice» как имя.
        if domain.is_empty() {
            domain = domain_prefix.to_string();
        }
        username = Some(user.to_string());
    }
    let mut options = RdpOptions {
        domain,
        ..RdpOptions::default()
    };

    if let Some(width) = int_value(&values, "desktopwidth") {
        options.width = width;
    }
    if let Some(height) = int_value(&values, "desktopheight") {
        options.height = height;
    }
    if let Some(depth) = int_value(&values, "session bpp") {
        if matches!(depth, 8 | 15 | 16 | 24 | 32) {
            options.color_depth = depth;
        }
    }
    if let Some(value) = values.get("redirectclipboard") {
        options.clipboard = flag(value);
        options.clipboard_to_remote = options.clipboard;
        options.clipboard_from_remote = options.clipboard;
    }
    options.redirect_drives = flag(values.get("redirectdrives").map(String::as_str).unwrap_or("0"));
    options.redirect_printers =
        flag(values.get("redirectprinters").map(String::as_str).unwrap_or("0"));

    if let Some(credssp) = values.get("enablecredsspsupport") {
        options.nla = flag(credssp);
    } else if let Some(level) = values.get("authentication level") {
        // 0 — «не требовать аутентификацию сервера», остальное — NLA/сертификат.
        options.nla = level.trim() != "0";
    }

    if let Some(shell) = clean(values.get("alternate shell")) {
        preview.note(format!(
            "{origin}: альтернативная оболочка «{shell}» не импортируется"
        ));
    }

    let profile = NewProfile {
        name: if name.trim().is_empty() {
            host.clone()
        } else {
            name.trim().to_string()
        },
        protocol: Some(Protocol::Rdp),
        host,
        port,
        username,
        notes: Some(format!("Импортировано из {origin}")),
        rdp_options: options,
        ..Default::default()
    };
    preview.push(Source::Rdp, origin.to_string(), profile);
    preview
}

fn parse_values(text: &str) -> HashMap<String, String> {
    let mut values = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // key:type:value; значение может содержать двоеточия (IPv6, путь).
        let mut parts = line.splitn(3, ':');
        let key = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let _kind = parts.next();
        let value = parts.next().unwrap_or("").trim();
        if !key.is_empty() {
            values.insert(key, value.to_string());
        }
    }
    values
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

fn int_value(values: &HashMap<String, String>, key: &str) -> Option<u32> {
    values
        .get(key)
        .and_then(|v| v.trim().parse::<u32>().ok())
}

fn flag(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "TRUE" | "True")
}

/// Читает UTF-8 (с BOM) и UTF-16LE (типичный формат mstsc).
fn decode_text(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        if !(bytes.len() - 2).is_multiple_of(2) {
            return Err("неверная кодировка UTF-16: нечётная длина файла".to_string());
        }
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16(&units).map_err(|e| format!("неверная кодировка UTF-16: {e}"))
    } else if bytes.starts_with(&[0xFE, 0xFF]) {
        if !(bytes.len() - 2).is_multiple_of(2) {
            return Err("неверная кодировка UTF-16: нечётная длина файла".to_string());
        }
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair))
            .collect();
        String::from_utf16(&units).map_err(|e| format!("неверная кодировка UTF-16BE: {e}"))
    } else if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8(bytes[3..].to_vec())
            .map_err(|e| format!("неверная кодировка UTF-8: {e}"))
    } else {
        String::from_utf8(bytes.to_vec()).map_err(|e| format!("неверная кодировка файла: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_rdp_file() {
        let text = "\
full address:s:win.example.org:3389
username:s:CORP\\alice
domain:s:CORP
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:24
redirectclipboard:i:1
redirectdrives:i:1
enablecredsspsupport:i:0
password 51:b:010203
";
        let preview = parse_text(text, "Desktop", "desktop.rdp");
        assert_eq!(preview.imported(), 1);
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.name, "Desktop");
        assert_eq!(profile.protocol, Some(Protocol::Rdp));
        assert_eq!(profile.host, "win.example.org");
        assert_eq!(profile.port, 3389);
        assert_eq!(profile.username.as_deref(), Some("alice"));
        assert_eq!(profile.rdp_options.domain, "CORP");
        assert_eq!(profile.rdp_options.width, 1920);
        assert_eq!(profile.rdp_options.height, 1080);
        assert_eq!(profile.rdp_options.color_depth, 24);
        assert!(profile.rdp_options.redirect_drives);
        assert!(!profile.rdp_options.nla);
        assert!(profile.password.is_none());
    }

    #[test]
    fn parses_ipv6_and_nonstandard_port() {
        let preview = parse_text(
            "full address:s:[2001:db8::5]:3390\n",
            "ipv6",
            "ipv6.rdp",
        );
        let profile = &preview.candidates[0].profile;
        assert_eq!(profile.host, "2001:db8::5");
        assert_eq!(profile.port, 3390);
    }

    #[test]
    fn gateway_is_skipped() {
        let preview = parse_text(
            "full address:s:server\ngatewayhostname:s:gw.example.org\n",
            "gw",
            "gw.rdp",
        );
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("Gateway"));
    }

    #[test]
    fn missing_address_is_skipped() {
        let preview = parse_text("username:s:alice\n", "empty", "empty.rdp");
        assert!(preview.candidates.is_empty());
        assert!(preview.skipped[0].reason.contains("адрес"));
    }

    #[test]
    fn decodes_utf16le() {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "full address:s:server\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        assert!(decode_text(&bytes).unwrap().contains("full address"));
    }
}
