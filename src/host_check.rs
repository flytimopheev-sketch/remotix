//! Проверка доступности узла по TCP.
//!
//! Перед открытием SSH/RDP/SFTP Remotix проверяет, отвечает ли порт. Это
//! позволяет за три секунды показать «хост выключен, разбудить?» вместо
//! десятисекундного ожидания и ошибки `libssh2: timeout` внутри сессии.
//!
//! После отправки magic packet [`wait_until_online`] повторяет пробу до
//! десяти минут. Проверка выполняется в фоновом потоке, а отмена передаётся
//! через замыкание, поэтому интерфейс не блокируется.

use std::net::{TcpStream, ToSocketAddrs};
use std::thread;
use std::time::{Duration, Instant};

/// Тайм-аут одной TCP-пробы.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Сколько ждать пробуждения хоста после Wake-on-LAN.
pub const WAKE_WAIT: Duration = Duration::from_secs(10 * 60);

/// Пауза между пробами во время ожидания.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Результат ожидания доступности узла.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Порт открылся — можно подключаться.
    Online,
    /// Время вышло; внутри — последняя ошибка пробы.
    TimedOut { last_error: String },
    /// Пользователь отменил ожидание.
    Cancelled,
}

/// Адрес в виде `host:port` (IPv6 — в квадратных скобках).
pub fn endpoint(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Проверяет узел с тайм-аутом [`PROBE_TIMEOUT`].
pub fn probe(host: &str, port: u16) -> Result<(), String> {
    probe_with_timeout(host, port, PROBE_TIMEOUT)
}

/// Проверяет узел с заданным тайм-аутом.
///
/// Домен разрешается через системный resolver; на все попытки подключения
/// отводится один общий тайм-аут. Успехом считается любой открытый адрес.
pub fn probe_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("пустой адрес узла".to_string());
    }

    let display = endpoint(host, port);
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{display}: не удалось разрешить адрес: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{display}: адрес не найден"));
    }

    let deadline = Instant::now() + timeout;
    let mut last_error = "тайм-аут подключения".to_string();
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => {
                // Нам нужен только факт установки соединения.
                let _ = stream.set_nodelay(true);
                return Ok(());
            }
            Err(e) => last_error = e.to_string(),
        }
    }

    Err(format!("{display}: {last_error}"))
}

/// Повторяет [`probe`] до `timeout`, пока узел не станет доступен.
///
/// `cancelled` вызывается перед каждой пробой и во время паузы, поэтому
/// закрытие диалога ожидания не заставляет поток ждать полный интервал.
pub fn wait_until_online<F>(
    host: &str,
    port: u16,
    timeout: Duration,
    interval: Duration,
    mut cancelled: F,
) -> WaitOutcome
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + timeout;
    let interval = interval.max(Duration::from_millis(100));
    let mut last_error: String;

    loop {
        if cancelled() {
            return WaitOutcome::Cancelled;
        }
        match probe(host, port) {
            Ok(()) => return WaitOutcome::Online,
            Err(e) => last_error = e,
        }

        let now = Instant::now();
        if now >= deadline {
            return WaitOutcome::TimedOut { last_error };
        }

        let mut left = interval.min(deadline.saturating_duration_since(now));
        while !left.is_zero() {
            if cancelled() {
                return WaitOutcome::Cancelled;
            }
            let step = left.min(Duration::from_millis(200));
            thread::sleep(step);
            left = left.saturating_sub(step);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn finds_open_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("тестовый listener");
        let port = listener.local_addr().expect("локальный адрес").port();

        probe_with_timeout("127.0.0.1", port, Duration::from_secs(1))
            .expect("открытый порт должен быть доступен");
    }

    #[test]
    fn reports_closed_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("тестовый listener");
        let port = listener.local_addr().expect("локальный адрес").port();
        drop(listener);

        let error = probe_with_timeout("127.0.0.1", port, Duration::from_millis(500))
            .expect_err("закрытый порт должен быть недоступен");
        assert!(error.contains(&format!("127.0.0.1:{port}")));
    }

    #[test]
    fn wait_returns_online_for_open_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("тестовый listener");
        let port = listener.local_addr().expect("локальный адрес").port();

        let outcome = wait_until_online(
            "127.0.0.1",
            port,
            Duration::from_millis(500),
            Duration::from_millis(100),
            || false,
        );
        assert_eq!(outcome, WaitOutcome::Online);
    }

    #[test]
    fn wait_times_out_for_closed_port() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("тестовый listener");
        let port = listener.local_addr().expect("локальный адрес").port();
        drop(listener);

        let outcome = wait_until_online(
            "127.0.0.1",
            port,
            Duration::from_millis(250),
            Duration::from_millis(100),
            || false,
        );
        assert!(matches!(outcome, WaitOutcome::TimedOut { .. }));
    }

    #[test]
    fn wait_can_be_cancelled() {
        let outcome = wait_until_online(
            "127.0.0.1",
            9,
            Duration::from_secs(10),
            Duration::from_secs(1),
            || true,
        );
        assert_eq!(outcome, WaitOutcome::Cancelled);
    }

    #[test]
    fn formats_ipv6_endpoint() {
        assert_eq!(endpoint("::1", 22), "[::1]:22");
        assert_eq!(endpoint("example.org", 22), "example.org:22");
    }
}
