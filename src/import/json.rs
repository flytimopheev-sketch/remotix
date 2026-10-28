//! Импорт JSON-файла Remotix (тот же формат, что и экспорт).
//!
//! `ProfileExport` не содержит полей паролей, поэтому даже специально
//! подготовленный файл не сможет подсунуть секрет: лишние поля serde
//! игнорирует, а нормализация всё равно обнуляет секреты.

use std::path::Path;

use crate::import::normalize::{ImportPreview, Source};
use crate::models::{NewProfile, Protocol};
use crate::profiles_io::{self, VERSION};

/// Разбирает JSON-файл Remotix.
pub fn scan_file(path: &Path) -> Result<ImportPreview, String> {
    let file = profiles_io::read_export(path)?;
    let mut preview = ImportPreview::default();
    preview.note("Пароли из JSON-файла не импортируются");
    if file.version > VERSION {
        preview.note(format!(
            "Файл создан более новой версией Remotix (формат {}), возможны потери параметров",
            file.version
        ));
    }

    for item in file.profiles {
        let protocol = match item.protocol.to_ascii_uppercase().as_str() {
            "RDP" => Protocol::Rdp,
            "VNC" => Protocol::Vnc,
            "SSH" => Protocol::Ssh,
            other => {
                preview.skip(
                    Source::RemotixJson,
                    item.name,
                    format!("неизвестный протокол: {other}"),
                );
                continue;
            }
        };
        let profile = NewProfile {
            name: item.name,
            protocol: Some(protocol),
            host: item.host,
            port: item.port,
            username: item.username,
            ssh_key_path: item.ssh_key_path,
            notes: item.notes,
            mac_address: item.mac_address,
            tags: item.tags,
            rdp_options: item.rdp_options,
            vnc_options: item.vnc_options,
            ssh_options: item.ssh_options,
            // Явно: даже если формат когда-нибудь расширят, секреты не
            // переносим.
            password: None,
            ssh_key_passphrase: None,
            root_password: None,
            ..Default::default()
        };
        preview.push(Source::RemotixJson, path.display().to_string(), profile);
    }
    Ok(preview)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_export_and_drops_unknown_protocol() {
        let text = r#"{
            "format": "remotix-profiles",
            "version": 1,
            "exported_at": "2026-01-01T00:00:00+00:00",
            "profiles": [
                {"name":"ssh","protocol":"SSH","host":"a","port":22,"password":"secret"},
                {"name":"bad","protocol":"TELNET","host":"b","port":23}
            ]
        }"#;
        let file = profiles_io::parse_export_text(text).unwrap();
        assert_eq!(file.profiles.len(), 2);
        // Проверяем через временный файл, чтобы не дублировать разбор.
        let path = std::env::temp_dir().join(format!(
            "remotix-import-json-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, text).unwrap();
        let preview = scan_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(preview.imported(), 1);
        assert_eq!(preview.skipped_count(), 1);
        assert!(preview.candidates[0].profile.password.is_none());
    }
}
