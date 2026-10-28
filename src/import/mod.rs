//! Импорт подключений из стандартных источников.
//!
//! Все источники сначала разбираются в `ImportPreview` и показываются
//! пользователю. В базу попадают только подтверждённые профили, и никогда —
//! пароли: они не читаются ни из SSH config, ни из Remmina, ни из `.rdp`.

pub mod csv;
pub mod json;
pub mod normalize;
pub mod preview;
pub mod rdp;
pub mod remmina;
pub mod ssh_config;
pub mod ui;

/// Делит `host`, `host:port`, `[IPv6]:port` на адрес и порт.
///
/// Если порт не указан, используется `default_port`. IPv6 без скобок
/// считается адресом целиком (двоеточия — часть адреса).
pub(crate) fn split_host_port(value: &str, default_port: u16) -> (String, u16) {
    let value = value.trim();
    if value.is_empty() {
        return (String::new(), default_port);
    }

    if let Some(rest) = value.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = rest[..end].to_string();
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p > 0)
                .unwrap_or(default_port);
            return (host, port);
        }
    }

    // Ровно одно двоеточие и числовой хвост — это host:port. Несколько
    // двоеточий — IPv6 без скобок, порт не выделяем.
    if value.matches(':').count() == 1 {
        if let Some((host, port)) = value.rsplit_once(':') {
            if let Ok(port) = port.parse::<u16>() {
                if port > 0 && !host.is_empty() {
                    return (host.to_string(), port);
                }
            }
        }
    }

    (value.to_string(), default_port)
}

#[cfg(test)]
mod tests {
    use super::split_host_port;

    #[test]
    fn splits_host_port() {
        assert_eq!(split_host_port("server", 22), ("server".to_string(), 22));
        assert_eq!(
            split_host_port("server:2222", 22),
            ("server".to_string(), 2222)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:2222", 22),
            ("2001:db8::1".to_string(), 2222)
        );
        assert_eq!(
            split_host_port("2001:db8::1", 22),
            ("2001:db8::1".to_string(), 22)
        );
    }
}
