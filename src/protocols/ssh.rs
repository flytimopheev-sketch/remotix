use std::net::TcpStream;

use crate::models::Profile;
use crate::protocols::Connection;

/// SSH-подключение на базе ssh2 (libssh2): аутентификация по паролю
/// (по защищённому каналу) или по ключу, поддержка ssh-agent.
pub struct SshConnection {
    pub profile: Profile,
    session: Option<ssh2::Session>,
    agent: Option<ssh2::Agent>,
}

impl SshConnection {
    pub fn new(profile: Profile) -> Self {
        Self { profile, session: None, agent: None }
    }

    /// Возвращает инициализированную сессию (для терминала и SFTP).
    pub fn session(&self) -> Option<&ssh2::Session> {
        self.session.as_ref()
    }
}

impl Connection for SshConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        let addr = format!("{}:{}", self.profile.host, self.profile.port);
        let tcp = TcpStream::connect(&addr).map_err(|e| format!("не удалось подключиться: {e}"))?;
        let mut session = ssh2::Session::new()
            .map_err(|e| format!("ошибка libssh2: {e}"))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| format!("ошибка SSH-рукопожатия: {e}"))?;

        let username = self
            .profile
            .username
            .clone()
            .unwrap_or_else(|| whoami());

        if let Some(key_path) = self.profile.ssh_key_path.clone() {
            // Аутентификация по ключу (ssh-agent или прямой файл ключа).
            if self.profile.ssh_options.use_agent && session.agent().is_ok() {
                let mut agent = session.agent().map_err(|e| e.to_string())?;
                agent.connect().map_err(|e| e.to_string())?;
                agent.list_identities().map_err(|e| e.to_string())?;
                for id in agent.identities().map_err(|e| e.to_string())? {
                    if agent
                        .userauth(&username, &id)
                        .map_err(|e| e.to_string())
                        .is_ok()
                    {
                        self.agent = Some(agent);
                        break;
                    }
                }
                if self.agent.is_none() {
                    return Err("ни один ключ ssh-agent не подошёл".into());
                }
            } else {
                session
                    .userauth_pubkey_file(
                        &username,
                        None,
                        std::path::Path::new(&key_path),
                        self.profile.ssh_key_passphrase.as_deref(),
                    )
                    .map_err(|e| format!("аутентификация по ключу не удалась: {e}"))?;
            }
        } else {
            // Аутентификация по паролю (передаётся по зашифрованному SSH-каналу).
            let password = self.profile.password.clone().unwrap_or_default();
            session
                .userauth_password(&username, &password)
                .map_err(|e| format!("аутентификация по паролю не удалась: {e}"))?;
        }

        if !session.authenticated() {
            return Err("аутентификация не пройдена".into());
        }
        self.session = Some(session);
        // Переход в root выполняется отдельно, в том же канале, в котором
        // будет работать терминал (см. `open_shell`).
        Ok(())
    }

    fn disconnect(&mut self) {
        if let Some(session) = self.session.take() {
            session.disconnect(None, "Пользователь закрыл сессию", None).ok();
        }
        self.agent = None;
    }
}

impl SshConnection {
    /// Открывает интерактивный PTY-канал, выполняет `su -` и автоматически
    /// отвечает на prompt "Password:" паролем root. Возвращает канал,
    /// уже залогиненный под root (для терминала/команд).
    pub fn su_to_root(&mut self) -> Result<ssh2::Channel, String> {
        let session = self.session.as_mut().ok_or("нет активной сессии")?;
        let root_password = self
            .profile
            .root_password
            .clone()
            .filter(|p| !p.is_empty())
            .ok_or("в профиле не задан пароль root")?;

        let mut channel = session.channel_session().map_err(|e| e.to_string())?;
        channel
            .request_pty("xterm", None, None)
            .map_err(|e| format!("не удалось запросить PTY: {e}"))?;
        channel.exec("su -").map_err(|e| e.to_string())?;

        // Ждём prompt "Password:" (ru/en), отвечаем паролем root.
        use std::io::{Read, Write};
        let mut buf = [0u8; 512];
        let mut seen = String::new();
        session.set_blocking(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut prompted = false;
        while std::time::Instant::now() < deadline {
            match channel.read(&mut buf) {
                Ok(n) if n > 0 => {
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if seen.contains("assword") || seen.contains("ароль") {
                        prompted = true;
                        break;
                    }
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        session.set_blocking(true);
        if !prompted {
            return Err("сервер не запросил пароль root (su заблокирован?)".into());
        }
        channel
            .write_all(root_password.as_bytes())
            .and_then(|_| channel.write_all(b"\n"))
            .map_err(|e| e.to_string())?;

        // Убеждаемся, что мы root (prompt '#' или id -u == 0 проверяется в UI).
        Ok(channel)
    }

    /// Забирает сессию (для передачи в поток терминала).
    pub fn take_session(&mut self) -> Option<ssh2::Session> {
        self.session.take()
    }

    /// Открывает интерактивную оболочку (PTY + shell) для терминала.
    /// Если в профиле включён su_to_root — выполнит `su -` с автоподстановкой
    /// пароля root (см. su_to_root).
    pub fn open_shell(&mut self) -> Result<ssh2::Channel, String> {
        let session = self.session.as_mut().ok_or("нет активной сессии")?;
        let mut channel = session.channel_session().map_err(|e| e.to_string())?;
        channel
            .request_pty("xterm", None, None)
            .map_err(|e| format!("не удалось запросить PTY: {e}"))?;
        if self.profile.ssh_options.su_to_root && self.profile.root_password.is_some() {
            channel.exec("su -").map_err(|e| e.to_string())?;
            self.su_answer_password(&mut channel)?;
        } else {
            channel.shell().map_err(|e| e.to_string())?;
        }
        Ok(channel)
    }

    /// Ждёт prompt "Password:" в канале и отвечает паролем root.
    fn su_answer_password(&mut self, channel: &mut ssh2::Channel) -> Result<(), String> {
        use std::io::Read;
        let root_password = self
            .profile
            .root_password
            .clone()
            .filter(|p| !p.is_empty())
            .ok_or("в профиле не задан пароль root")?;
        let session = self.session.as_mut().ok_or("нет активной сессии")?;
        let mut buf = [0u8; 512];
        let mut seen = String::new();
        session.set_blocking(false);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut prompted = false;
        while std::time::Instant::now() < deadline {
            match channel.read(&mut buf) {
                Ok(n) if n > 0 => {
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if seen.contains("assword") || seen.contains("ароль") {
                        prompted = true;
                        break;
                    }
                }
                _ => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        session.set_blocking(true);
        if !prompted {
            return Err("сервер не запросил пароль root (su заблокирован?)".into());
        }
        use std::io::Write;
        channel
            .write_all(root_password.as_bytes())
            .and_then(|_| channel.write_all(b"\n"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "root".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::{RdpOptions, SshOptions, VncOptions};
    use crate::models::Protocol;

    /// Профиль для тестового сервера.
    fn test_profile() -> Profile {
        Profile {
            id: 0,
            name: "test".to_string(),
            protocol: Protocol::Ssh,
            host: "127.0.0.1".to_string(),
            port: 2222,
            username: Some("tester".to_string()),
            password: Some("secret".to_string()),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            root_password: None,
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

    /// Проверяет подключение, аутентификацию по паролю и выполнение команды.
    ///
    /// Требует запущенного SSH-сервера на `127.0.0.1:2222` (в CI это
    /// контейнер с `openssh-server`). Если сервера нет — тест пропускается.
    #[test]
    fn connects_and_executes_command() {
        use std::io::Read;

        if TcpStream::connect("127.0.0.1:2222").is_err() {
            eprintln!("SSH-сервер на 127.0.0.1:2222 недоступен — тест пропущен");
            return;
        }

        let mut conn = SshConnection::new(test_profile());
        conn.connect().expect("подключение к SSH-серверу");

        let session = conn.take_session().expect("сессия должна быть активной");
        let mut channel = session.channel_session().expect("канал сессии");
        channel.exec("echo hello-remotix").expect("выполнение команды");

        let mut out = String::new();
        channel.read_to_string(&mut out).expect("чтение вывода");
        assert!(
            out.contains("hello-remotix"),
            "в выводе нет ожидаемого текста: {out:?}"
        );
    }

    /// Проверяет, что неверный пароль отклоняется.
    #[test]
    fn rejects_wrong_password() {
        if TcpStream::connect("127.0.0.1:2222").is_err() {
            eprintln!("SSH-сервер на 127.0.0.1:2222 недоступен — тест пропущен");
            return;
        }

        let mut profile = test_profile();
        profile.password = Some("wrong-password".to_string());
        let mut conn = SshConnection::new(profile);
        assert!(
            conn.connect().is_err(),
            "подключение с неверным паролем должно завершаться ошибкой"
        );
    }

    /// Проверяет путь, который использует встроенный терминал: PTY и
    /// интерактивная оболочка (shell), а не exec с одной командой.
    #[test]
    fn opens_interactive_shell() {
        use std::io::{Read, Write};

        if TcpStream::connect("127.0.0.1:2222").is_err() {
            eprintln!("SSH-сервер на 127.0.0.1:2222 недоступен — тест пропущен");
            return;
        }

        let mut conn = SshConnection::new(test_profile());
        conn.connect().expect("подключение к SSH-серверу");

        let session = conn.take_session().expect("сессия");
        let mut channel = session.channel_session().expect("канал сессии");
        channel.request_pty("xterm", None, None).expect("запрос PTY");
        channel.shell().expect("интерактивная оболочка");

        channel.write_all(b"echo shell-works\n").expect("ввод команды");

        let mut out = String::new();
        let mut buf = [0u8; 1024];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while std::time::Instant::now() < deadline {
            match channel.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    out.push_str(&String::from_utf8_lossy(&buf[..n]));
                    // Эхо терминала + вывод команды — два вхождения.
                    if out.matches("shell-works").count() >= 2 {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => panic!("ошибка чтения из канала: {e}"),
            }
        }

        assert!(
            out.contains("shell-works"),
            "в выводе терминала нет ответа на команду: {out:?}"
        );
    }
}
