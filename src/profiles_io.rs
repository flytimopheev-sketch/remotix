//! Импорт и экспорт профилей подключений (JSON).
//!
//! Экспортируются адреса, порты, протоколы и параметры протоколов. Пароли
//! намеренно **не** выгружаются: файл с профилями может попасть в чужие
//! руки, а учётные данные в Remotix и так хранятся зашифрованными.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::db::repository::Database;
use crate::models::profile::{RdpOptions, SshOptions, VncOptions};
use crate::models::NewProfile;

/// Формат файла экспорта.
pub const FORMAT: &str = "remotix-profiles";
/// Версия формата.
pub const VERSION: u32 = 1;

/// Описание одного профиля в файле экспорта.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileExport {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub ssh_key_path: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub rdp_options: RdpOptions,
    #[serde(default)]
    pub vnc_options: VncOptions,
    #[serde(default)]
    pub ssh_options: SshOptions,
}

/// Файл экспорта профилей.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFile {
    pub format: String,
    pub version: u32,
    pub exported_at: String,
    pub profiles: Vec<ProfileExport>,
}

/// Выгружает профили в JSON-файл. Возвращает количество профилей.
pub fn export_profiles(db: &Database, key: &[u8; 32], path: &Path) -> Result<usize, String> {
    let profiles = db.list_profiles(key)?;
    let file = ExportFile {
        format: FORMAT.to_string(),
        version: VERSION,
        exported_at: chrono::Local::now().to_rfc3339(),
        profiles: profiles
            .iter()
            .map(|p| ProfileExport {
                name: p.name.clone(),
                protocol: p.protocol.as_str().to_string(),
                host: p.host.clone(),
                port: p.port,
                username: p.username.clone(),
                ssh_key_path: p.ssh_key_path.clone(),
                notes: p.notes.clone(),
                tags: p.tags.clone(),
                rdp_options: p.rdp_options.clone(),
                vnc_options: p.vnc_options.clone(),
                ssh_options: p.ssh_options.clone(),
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("не удалось записать файл: {e}"))?;
    Ok(file.profiles.len())
}

/// Загружает профили из JSON-файла. Возвращает количество добавленных профилей.
///
/// Существующие профили не изменяются — импортированные добавляются как новые.
pub fn import_profiles(db: &Database, key: &[u8; 32], path: &Path) -> Result<usize, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("не удалось прочитать файл: {e}"))?;
    let file: ExportFile =
        serde_json::from_str(&text).map_err(|e| format!("неверный формат файла: {e}"))?;

    if file.format != FORMAT {
        return Err(format!("неожиданный формат файла: {}", file.format));
    }

    let mut added = 0;
    for item in file.profiles {
        let protocol = match item.protocol.as_str() {
            "RDP" => crate::models::Protocol::Rdp,
            "VNC" => crate::models::Protocol::Vnc,
            _ => crate::models::Protocol::Ssh,
        };
        let profile = NewProfile {
            name: item.name,
            protocol: Some(protocol),
            host: item.host,
            port: item.port,
            username: item.username,
            ssh_key_path: item.ssh_key_path,
            notes: item.notes,
            tags: item.tags,
            rdp_options: item.rdp_options,
            vnc_options: item.vnc_options,
            ssh_options: item.ssh_options,
            ..Default::default()
        };
        db.add_profile(key, &profile)?;
        added += 1;
    }

    Ok(added)
}
