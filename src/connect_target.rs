//! Разбор цели запуска: `--connect`, `ssh://`, `rdp://`, `vnc://`.
//!
//! Форматы:
//!
//! * `user@host` или `host` — SSH, порт 22 (как быстрое подключение);
//! * `ssh://user@host:2222`, `rdp://user@host`, `vnc://host:5900`;
//! * IPv6 — в квадратных скобках: `ssh://user@[2001:db8::1]:22`.
//!
//! Пароль в ссылке не поддерживается: он попал бы в список процессов и
//! историю оболочки. Для сохранённых учётных данных используйте профиль —
//! если он совпадает по протоколу, хосту, порту и логину, Remotix откроет
//! именно его.

use crate::models::profile::{Profile, Protocol};

/// Куда подключиться по ссылке или `--connect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectTarget {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
}

impl ConnectTarget {
    /// Разбирает строку ссылки. Ошибки — человекочитаемые, для stderr/статуса.
    pub fn parse(value: &str) -> Result<Self, String> {
        let value = value.trim();
        if value.is_empty() {
            return Err("пустая ссылка подключения".to_string());
        }

        let (protocol, rest) = match value.split_once("://") {
            Some((scheme, rest)) => {
                let protocol = match scheme.to_ascii_lowercase().as_str() {
                    "ssh" => Protocol::Ssh,
                    "rdp" => Protocol::Rdp,
                    "vnc" => Protocol::Vnc,
                    other => {
                        return Err(format!(
                            "неподдерживаемая схема «{other}»: ожидается ssh, rdp или vnc"
                        ));
                    }
                };
                (protocol, rest)
            }
            // Без схемы — прежний формат быстрого подключения (SSH).
            None => (Protocol::Ssh, value),
        };

        // После адреса допускается только завершающий «/».
        let mut authority = rest;
        if let Some(index) = rest.find(['/', '?', '#']) {
            let tail = &rest[index..];
            if tail != "/" {
                return Err("в ссылке допустимы только хост и порт".to_string());
            }
            authority = &rest[..index];
        }
        if authority.is_empty() {
            return Err("в ссылке не указан хост".to_string());
        }

        let (username, host_port) = match authority.rsplit_once('@') {
            Some((userinfo, host_port)) => {
                if userinfo.contains(':') {
                    return Err(
                        "пароль в ссылке не поддерживается: сохраните его в профиле".to_string()
                    );
                }
                let username = if userinfo.is_empty() {
                    None
                } else {
                    let username = percent_decode(userinfo)?;
                    validate_username(&username)?;
                    Some(username)
                };
                (username, host_port)
            }
            None => (None, authority),
        };

        let (host, port) = split_host_port(host_port, protocol.default_port())?;
        Ok(Self {
            protocol,
            host,
            port,
            username,
        })
    }

    /// Канонический URI цели.
    ///
    /// `--connect` превращается в такой URI и передаётся GApplication как
    /// обычный аргумент. Благодаря этому ссылка работает и тогда, когда
    /// Remotix уже запущен: GApplication перешлёт её первичному экземпляру.
    pub fn to_uri(&self) -> String {
        let scheme = match self.protocol {
            Protocol::Ssh => "ssh",
            Protocol::Rdp => "rdp",
            Protocol::Vnc => "vnc",
        };
        // IPv6 в URI записывается в квадратных скобках.
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.username {
            Some(username) => format!(
                "{scheme}://{}@{host}:{}",
                percent_encode_userinfo(username),
                self.port
            ),
            None => format!("{scheme}://{host}:{}", self.port),
        }
    }

    /// Совпадает ли сохранённый профиль с целью.
    ///
    /// Нужно, чтобы ссылка переиспользовала сохранённые ключи и пароли.
    /// Если логин в ссылке не указан, подходит профиль с любым логином.
    pub fn matches(&self, profile: &Profile) -> bool {
        self.protocol == profile.protocol
            && self.host.eq_ignore_ascii_case(&profile.host)
            && self.port == profile.port
            && match (&self.username, &profile.username) {
                (Some(wanted), Some(have)) => wanted == have,
                (Some(_), None) => false,
                (None, _) => true,
            }
    }

    /// Временный профиль для цели без сохранённых учётных данных.
    pub fn to_profile(&self) -> Profile {
        Profile {
            id: 0,
            name: self.host.clone(),
            protocol: self.protocol,
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            password: None,
            ssh_key_path: None,
            ssh_key_passphrase: None,
            root_password: None,
            group_id: None,
            bastion_profile_id: None,
            tags: vec![],
            icon: None,
            notes: None,
            mac_address: None,
            rdp_options: Default::default(),
            vnc_options: Default::default(),
            ssh_options: Default::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        }
    }
}

/// `host`, `host:port`, `[IPv6]:port` или `IPv6` (порт по умолчанию).
fn split_host_port(value: &str, default_port: u16) -> Result<(String, u16), String> {
    let value = value.trim();

    if let Some(rest) = value.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| "не закрыта квадратная скобка в адресе IPv6".to_string())?;
        let host = &rest[..end];
        validate_host(host)?;
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            default_port
        } else {
            match after.strip_prefix(':') {
                Some(port) => parse_port(port)?,
                None => return Err(format!("некорректный адрес «{value}»")),
            }
        };
        return Ok((host.to_string(), port));
    }

    // Несколько двоеточий — IPv6 без скобок; порт в такой записи не выделяем.
    if value.matches(':').count() > 1 {
        validate_host(value)?;
        return Ok((value.to_string(), default_port));
    }

    if let Some((host, port)) = value.rsplit_once(':') {
        validate_host(host)?;
        return Ok((host.to_string(), parse_port(port)?));
    }

    validate_host(value)?;
    Ok((value.to_string(), default_port))
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("некорректный порт «{value}»"))?;
    if port == 0 {
        return Err("порт должен быть в диапазоне 1–65535".to_string());
    }
    Ok(port)
}

fn validate_username(username: &str) -> Result<(), String> {
    if username.chars().any(char::is_control) {
        return Err("некорректное имя пользователя в ссылке".to_string());
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("в ссылке не указан хост".to_string());
    }
    if host.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '?' | '#' | '[' | ']')
    }) {
        return Err(format!("некорректный хост «{host}»"));
    }
    Ok(())
}

/// Декодирует `%XX` в имени пользователя (RFC 3986).
fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err("некорректное %-кодирование в имени пользователя".to_string());
            }
            let high = hex_digit(bytes[index + 1])
                .ok_or_else(|| "некорректное %-кодирование в имени пользователя".to_string())?;
            let low = hex_digit(bytes[index + 2])
                .ok_or_else(|| "некорректное %-кодирование в имени пользователя".to_string())?;
            decoded.push(high * 16 + low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded)
        .map_err(|_| "имя пользователя в ссылке не является UTF-8".to_string())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Кодирует имя пользователя для userinfo (`%XX` для всего, кроме unreserved).
fn percent_encode_userinfo(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_host_is_ssh() {
        let target = ConnectTarget::parse("user@example.com").expect("разбор");
        assert_eq!(target.protocol, Protocol::Ssh);
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 22);
        assert_eq!(target.username.as_deref(), Some("user"));
    }

    #[test]
    fn schemes_and_ports() {
        let ssh = ConnectTarget::parse("ssh://admin@server:2222/").expect("ssh");
        assert_eq!(ssh.protocol, Protocol::Ssh);
        assert_eq!(ssh.port, 2222);
        assert_eq!(ssh.username.as_deref(), Some("admin"));

        let rdp = ConnectTarget::parse("RDP://user@server").expect("rdp");
        assert_eq!(rdp.protocol, Protocol::Rdp);
        assert_eq!(rdp.port, 3389);

        let vnc = ConnectTarget::parse("vnc://server:5901").expect("vnc");
        assert_eq!(vnc.protocol, Protocol::Vnc);
        assert_eq!(vnc.port, 5901);
        assert_eq!(vnc.username, None);
    }

    #[test]
    fn ipv6_addresses() {
        let bracketed =
            ConnectTarget::parse("ssh://user@[2001:db8::1]:2200").expect("IPv6 в скобках");
        assert_eq!(bracketed.host, "2001:db8::1");
        assert_eq!(bracketed.port, 2200);

        let plain = ConnectTarget::parse("rdp://2001:db8::1").expect("IPv6 без скобок");
        assert_eq!(plain.host, "2001:db8::1");
        assert_eq!(plain.port, 3389);
    }

    #[test]
    fn username_is_percent_decoded() {
        let target = ConnectTarget::parse("ssh://user%40example.com@server").expect("разбор");
        assert_eq!(target.username.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn invalid_targets_are_rejected() {
        for value in [
            "",
            "http://server",
            "ssh://",
            "ssh://server:0",
            "ssh://server:70000",
            "ssh://server:abc",
            "ssh://user:secret@server",
            "ssh://server/path",
            "ssh://server?query",
            "ssh://[2001:db8::1",
            "ssh://user%ZZ@server",
            "ssh://user%0A@server",
        ] {
            assert!(
                ConnectTarget::parse(value).is_err(),
                "должно быть отклонено: {value}"
            );
        }
    }

    #[test]
    fn profile_keeps_target_fields() {
        let target = ConnectTarget::parse("rdp://user@server:3390").expect("разбор");
        let profile = target.to_profile();
        assert_eq!(profile.protocol, Protocol::Rdp);
        assert_eq!(profile.host, "server");
        assert_eq!(profile.port, 3390);
        assert_eq!(profile.username.as_deref(), Some("user"));
        assert_eq!(profile.id, 0, "временный профиль не сохраняется в БД");
    }

    #[test]
    fn canonical_uri_roundtrips() {
        assert_eq!(
            ConnectTarget::parse("admin@server")
                .expect("разбор")
                .to_uri(),
            "ssh://admin@server:22"
        );
        let target =
            ConnectTarget::parse("ssh://user%40example.com@[2001:db8::1]:2222").expect("разбор");
        assert_eq!(
            target.to_uri(),
            "ssh://user%40example.com@[2001:db8::1]:2222"
        );
        assert_eq!(
            ConnectTarget::parse(&target.to_uri()).expect("повторный разбор"),
            target
        );
    }

    #[test]
    fn saved_profile_match_requires_same_endpoint_and_user() {
        let target = ConnectTarget::parse("ssh://user@Server:2222").expect("разбор");
        let mut profile = target.to_profile();
        profile.id = 42;
        assert!(target.matches(&profile));

        let mut other_host = profile.clone();
        other_host.host = "other".to_string();
        assert!(!target.matches(&other_host));

        let mut other_port = profile.clone();
        other_port.port = 22;
        assert!(!target.matches(&other_port));

        let mut other_user = profile.clone();
        other_user.username = Some("admin".to_string());
        assert!(!target.matches(&other_user));

        let no_user = ConnectTarget::parse("ssh://server:2222").expect("разбор");
        assert!(no_user.matches(&profile), "логин в ссылке не обязателен");
    }
}
