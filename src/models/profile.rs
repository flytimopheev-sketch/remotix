use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub id: i64,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub ssh_key_path: Option<String>,
    pub ssh_key_passphrase: Option<String>,
    /// Пароль root для двухступенчатого входа (su) — зашифрован.
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

/// Данные для создания/редактирования профиля.
#[derive(Debug, Clone, Default)]
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
