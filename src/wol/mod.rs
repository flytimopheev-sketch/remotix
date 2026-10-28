//! Wake-on-LAN: разбор MAC-адреса и отправка magic packet.
//!
//! Пакет состоит из шести байтов `0xFF` и MAC-адреса, повторённого 16 раз
//! (всего 102 байта). Он отправляется UDP-broadcast на стандартные порты 9
//! и 7. Сетевой адаптер выключенного компьютера распознаёт пакет и будит
//! машину, если Wake-on-LAN включён в BIOS/UEFI и в настройках адаптера.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

/// Стандартные UDP-порты Wake-on-LAN.
pub const PORTS: [u16; 2] = [9, 7];

/// Разбирает MAC-адрес в шестибайтовый массив.
///
/// Поддерживаются записи `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`,
/// `AABB.CCDD.EEFF` и слитная `AABBCCDDEEFF`.
pub fn parse_mac(text: &str) -> Result<[u8; 6], String> {
    let cleaned: String = text
        .trim()
        .chars()
        .filter(|c| !matches!(c, ':' | '-' | '.' | ' '))
        .collect();
    if cleaned.len() != 12 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("MAC-адрес должен состоять из 12 шестнадцатеричных цифр".to_string());
    }

    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        let start = i * 2;
        *byte = u8::from_str_radix(&cleaned[start..start + 2], 16)
            .map_err(|_| "неверный MAC-адрес".to_string())?;
    }
    Ok(mac)
}

/// Приводит MAC-адрес к каноническому виду `AA:BB:CC:DD:EE:FF`.
pub fn normalize_mac(text: &str) -> Result<String, String> {
    let mac = parse_mac(text)?;
    Ok(mac
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Формирует magic packet для уже разобранного MAC-адреса.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut packet = [0xFFu8; 102];
    for chunk in packet[6..].as_chunks_mut::<6>().0 {
        chunk.copy_from_slice(&mac);
    }
    packet
}

/// Формирует magic packet по строковому MAC-адресу.
pub fn packet_for(text: &str) -> Result<[u8; 102], String> {
    Ok(magic_packet(parse_mac(text)?))
}

/// Отправляет magic packet на широковещательный адрес.
///
/// Пакет дублируется на порты 9 и 7: разные адаптеры и настройки сети
/// принимают разные порты. Успехом считается отправка хотя бы на один из них.
pub fn send_magic_packet(mac: &str) -> Result<(), String> {
    let packet = packet_for(mac)?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("не удалось открыть UDP-сокет: {e}"))?;
    socket
        .set_broadcast(true)
        .map_err(|e| format!("не удалось разрешить broadcast: {e}"))?;

    let mut sent = 0usize;
    let mut errors = Vec::new();
    for port in PORTS {
        let target = SocketAddr::from((Ipv4Addr::BROADCAST, port));
        match socket.send_to(&packet, target) {
            Ok(n) if n == packet.len() => sent += 1,
            Ok(n) => errors.push(format!("порт {port}: отправлено только {n} байт")),
            Err(e) => errors.push(format!("порт {port}: {e}")),
        }
    }

    if sent > 0 {
        Ok(())
    } else {
        Err(format!(
            "не удалось отправить magic packet: {}",
            errors.join("; ")
        ))
    }
}

/// Отправляет magic packet на конкретный адрес (используется в тестах).
pub fn send_magic_packet_to(mac: &str, target: SocketAddr) -> Result<(), String> {
    let packet = packet_for(mac)?;
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|e| format!("не удалось открыть UDP-сокет: {e}"))?;
    socket
        .send_to(&packet, target)
        .map(|_| ())
        .map_err(|e| format!("не удалось отправить magic packet: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const MAC: &str = "AA:BB:CC:DD:EE:FF";

    #[test]
    fn parses_supported_mac_formats() {
        let expected = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        for text in [
            "AA:BB:CC:DD:EE:FF",
            "aa-bb-cc-dd-ee-ff",
            "AABB.CCDD.EEFF",
            "AABBCCDDEEFF",
            " aa bb cc dd ee ff ",
        ] {
            assert_eq!(parse_mac(text).expect(text), expected, "формат {text}");
        }
    }

    #[test]
    fn rejects_invalid_mac() {
        for text in ["", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:GG", "hello"] {
            assert!(parse_mac(text).is_err(), "должен отклоняться {text:?}");
        }
    }

    #[test]
    fn normalizes_mac() {
        assert_eq!(normalize_mac("aabb.ccdd.eeff").expect("MAC"), MAC);
    }

    #[test]
    fn packet_has_six_ff_bytes_and_sixteen_mac_copies() {
        let packet = packet_for(MAC).expect("magic packet");
        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        for chunk in packet[6..].as_chunks::<6>().0 {
            assert_eq!(*chunk, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        }
    }

    #[test]
    fn sends_magic_packet_to_udp_socket() {
        let receiver = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP listener");
        receiver
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("тайм-аут чтения");
        let target = receiver.local_addr().expect("локальный адрес");

        send_magic_packet_to(MAC, target).expect("отправка magic packet");

        let mut buf = [0u8; 102];
        let (n, _) = receiver.recv_from(&mut buf).expect("приём magic packet");
        assert_eq!(n, 102);
        assert_eq!(buf, packet_for(MAC).expect("эталонный packet"));
    }
}
