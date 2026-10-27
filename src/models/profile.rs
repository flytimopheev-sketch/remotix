use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Протокол подключения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    #[serde(rename = "RDP")]
    Rdp,
    #[serde(rename = "VNC")]
    Vnc,
    #[serde(rename = "SSH")]
    Ssh,
}

impl Protocol {
    /// Порт по умолчанию: 3389 RDP, 5900 VNC, 22 SSH.
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Rdp => 3389,
            Protocol::Vnc => 5900,
            Protocol::Ssh => 22,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Rdp => "RDP",
            Protocol::Vnc => "VNC",
            Protocol::Ssh => "SSH",
        }
    }
}

/// Дополнительные параметры RDP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdpOptions {
    #[serde(default)]
    pub width: u32,
    #[serde(default)]
    pub height: u32,
    #[serde(default = "default_color_depth")]
    pub color_depth: u32,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub redirect_drives: bool,
    #[serde(default)]
    pub redirect_printers: bool,
    /// Двунаправленный буфер обмена: локальный <-> удалённый (канал cliprdr).
    #[serde(default = "default_true")]
    pub clipboard: bool,
    #[serde(default)]
    pub clipboard_to_remote: bool,
    #[serde(default)]
    pub clipboard_from_remote: bool,
    /// Аутентификация NLA (CredSSP). Современные серверы Windows требуют её.
    #[serde(default = "default_true")]
    pub nla: bool,
}

fn default_color_depth() -> u32 {
    32
}

fn default_true() -> bool {
    true
}

/// По умолчанию буфер обмена включён в обе стороны.
impl Default for RdpOptions {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            color_depth: default_color_depth(),
            domain: String::new(),
            redirect_drives: false,
            redirect_printers: false,
            clipboard: true,
            clipboard_to_remote: true,
            clipboard_from_remote: true,
            nla: true,
        }
    }
}

/// Дополнительные параметры VNC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VncOptions {
    #[serde(default)]
    pub view_only: bool,
    #[serde(default = "default_quality")]
    pub compression_quality: u32,
    #[serde(default)]
    pub via_ssh_tunnel: bool,
}

fn default_quality() -> u32 {
    6
}

/// Дополнительные параметры SSH.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshOptions {
    #[serde(default)]
    pub connect_command: String,
    #[serde(default)]
    pub use_agent: bool,
    /// Двухступенчатый вход: сначала аутентификация под локальным
    /// администратором, затем в интерактивной сессии `su -` под root
    /// (root_password передаётся автоматически в ответ на prompt "Password:").
    #[serde(default)]
    pub su_to_root: bool,
}

/// Неконфиденциальная часть профиля подключения (учётные данные шифруются отдельно).
///
/// Секреты не попадают в `Debug` и не сериализуются: даже случайный
/// `serde_json::to_string(&profile)` не выгрузит пароль в лог или файл.
#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    pub ssh_key_path: Option<String>,
    #[serde(default, skip_serializing)]
    pub ssh_key_passphrase: Option<String>,
    /// Пароль root для двухступенчатого входа (su) — зашифрован.
    #[serde(default, skip_serializing)]
    pub root_password: Option<String>,
    pub group_id: Option<i64>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub icon: Option<String>,
    pub notes: Option<String>,
    #[serde(default)]
    pub rdp_options: RdpOptions,
    #[serde(default)]
    pub vnc_options: VncOptions,
    #[serde(default)]
    pub ssh_options: SshOptions,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_connected_at: Option<i64>,
}

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("ssh_key_path", &self.ssh_key_path)
            .field(
                "ssh_key_passphrase",
                &self.ssh_key_passphrase.as_ref().map(|_| "<скрыт>"),
            )
            .field(
                "root_password",
                &self.root_password.as_ref().map(|_| "<скрыт>"),
            )
            .field("group_id", &self.group_id)
            .field("tags", &self.tags)
            .field("icon", &self.icon)
            .field("notes", &self.notes)
            .field("rdp_options", &self.rdp_options)
            .field("vnc_options", &self.vnc_options)
            .field("ssh_options", &self.ssh_options)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_connected_at", &self.last_connected_at)
            .finish()
    }
}

/// Данные для создания/редактирования профиля.
#[derive(Clone, Default)]
pub struct NewProfile {
    pub name: String,
    pub protocol: Option<Protocol>,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssh_key_path: Option<String>,
    pub ssh_key_passphrase: Option<String>,
    pub root_password: Option<String>,
    pub group_id: Option<i64>,
    pub tags: Vec<String>,
    pub icon: Option<String>,
    pub notes: Option<String>,
    /// Дополнительные параметры протоколов (сохраняются в JSON-колонках).
    pub rdp_options: RdpOptions,
    pub vnc_options: VncOptions,
    pub ssh_options: SshOptions,
}

impl fmt::Debug for NewProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewProfile")
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<скрыт>"))
            .field("ssh_key_path", &self.ssh_key_path)
            .field(
                "ssh_key_passphrase",
                &self.ssh_key_passphrase.as_ref().map(|_| "<скрыт>"),
            )
            .field(
                "root_password",
                &self.root_password.as_ref().map(|_| "<скрыт>"),
            )
            .field("group_id", &self.group_id)
            .field("tags", &self.tags)
            .field("icon", &self.icon)
            .field("notes", &self.notes)
            .field("rdp_options", &self.rdp_options)
            .field("vnc_options", &self.vnc_options)
            .field("ssh_options", &self.ssh_options)
            .finish()
    }
}

fn zeroize_opt(value: &mut Option<String>) {
    if let Some(secret) = value {
        secret.zeroize();
    }
}

impl Drop for Profile {
    fn drop(&mut self) {
        zeroize_opt(&mut self.password);
        zeroize_opt(&mut self.ssh_key_passphrase);
        zeroize_opt(&mut self.root_password);
    }
}

/// Группа подключений.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewGroup {
    pub id: i64,
    pub name: String,
    pub parent_id: Option<i64>,
}

/// Запись в журнале подключений.
#[derive(Debug, Clone)]
pub struct HistoryEntry {
    pub id: i64,
    pub profile_id: i64,
    pub profile_name: String,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub status: String,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile_with_secrets() -> Profile {
        Profile {
            id: 1,
            name: "test".to_string(),
            protocol: Protocol::Ssh,
            host: "example.org".to_string(),
            port: 22,
            username: Some("alice".to_string()),
            password: Some("password-secret".to_string()),
            ssh_key_path: None,
            ssh_key_passphrase: Some("passphrase-secret".to_string()),
            root_password: Some("root-secret".to_string()),
            group_id: None,
            tags: vec![],
            icon: None,
            notes: None,
            rdp_options: RdpOptions::default(),
            vnc_options: VncOptions::default(),
            ssh_options: SshOptions::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        }
    }

    #[test]
    fn debug_redacts_profile_secrets() {
        let text = format!("{:?}", profile_with_secrets());
        assert!(!text.contains("password-secret"));
        assert!(!text.contains("passphrase-secret"));
        assert!(!text.contains("root-secret"));
        assert!(text.contains("<скрыт>"));
    }

    #[test]
    fn serialization_omits_profile_secrets() {
        let text = serde_json::to_string(&profile_with_secrets()).expect("сериализация профиля");
        assert!(!text.contains("password-secret"));
        assert!(!text.contains("passphrase-secret"));
        assert!(!text.contains("root-secret"));
        assert!(!text.contains("password"));
        assert!(!text.contains("passphrase"));
    }

    #[test]
    fn debug_redacts_new_profile_secrets() {
        let profile = NewProfile {
            password: Some("password-secret".to_string()),
            root_password: Some("root-secret".to_string()),
            ..Default::default()
        };
        let text = format!("{profile:?}");
        assert!(!text.contains("password-secret"));
        assert!(!text.contains("root-secret"));
    }
}
