use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD};
use base64::Engine as _;
use secrecy::ExposeSecret;
use ssh2::{CheckResult, HashType, KnownHostFileKind};

use crate::models::Profile;
use crate::protocols::Connection;

/// Сколько ждём установки TCP-соединения.
///
/// Раньше здесь был `TcpStream::connect` без таймаута: при недоступном
/// хосте поток подключения (а вместе с ним и интерфейс) мог зависнуть на
/// системный таймаут — минуты. Теперь общий дедлайн на все адреса хоста.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Таймаут рукопожатия и аутентификации. Сервер, который принял TCP, но
/// молчит, не должен держать вкладку в состоянии «подключение…» вечно.
const HANDSHAKE_TIMEOUT_MS: u32 = 30_000;

/// Интервал SSH keepalive. NAT/Firewall часто забывают неактивные сессии;
/// пустой пакет раз в 30 секунд не даёт им «умереть молча».
const KEEPALIVE_INTERVAL_SECS: u32 = 30;

/// Описание неизвестного ключа хоста, которое показывается пользователю.
#[derive(Clone, Debug)]
pub struct HostKeyPrompt {
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub key_type: String,
    /// Файл, в который будет добавлен ключ после подтверждения.
    pub known_hosts: PathBuf,
}

/// Решение пользователя по неизвестному ключу.
///
/// Вызывается из потока подключения. Реализация в UI отправляет запрос в
/// главный поток GTK и ждёт ответа; без UI можно вернуть `false`.
pub type HostKeyVerifier = dyn Fn(&HostKeyPrompt) -> bool + Send;

/// Настройки проверки ключа хоста.
///
/// `accept_new = true` соответствует OpenSSH `StrictHostKeyChecking=accept-new`:
/// неизвестный ключ добавляется в `known_hosts`, а изменившийся — всегда
/// отклоняется. Терминал и SFTP передают `verifier`, чтобы спросить
/// пользователя, а не доверять ключу молча.
pub struct HostKeyConfig<'a> {
    pub known_hosts: PathBuf,
    pub accept_new: bool,
    pub verifier: Option<&'a HostKeyVerifier>,
}

impl<'a> Default for HostKeyConfig<'a> {
    fn default() -> Self {
        Self {
            known_hosts: default_known_hosts_path(),
            accept_new: true,
            verifier: None,
        }
    }
}

/// Путь к пользовательскому `known_hosts`.
///
/// `REMOTIX_KNOWN_HOSTS` позволяет тестам и сценариям CI не трогать
/// настоящий файл пользователя.
pub fn default_known_hosts_path() -> PathBuf {
    if let Ok(path) = std::env::var("REMOTIX_KNOWN_HOSTS") {
        if !path.trim().is_empty() {
            return PathBuf::from(path);
        }
    }
    crate::config::home_dir().join(".ssh").join("known_hosts")
}

/// SSH-подключение на базе ssh2 (libssh2): аутентификация по паролю
/// (по защищённому каналу) или по ключу, поддержка ssh-agent.
pub struct SshConnection {
    pub profile: Profile,
    session: Option<ssh2::Session>,
}

impl SshConnection {
    pub fn new(profile: Profile) -> Self {
        Self { profile, session: None }
    }

    /// Возвращает инициализированную сессию (для терминала и SFTP).
    pub fn session(&self) -> Option<&ssh2::Session> {
        self.session.as_ref()
    }

    /// Подключение с настройками проверки ключа хоста.
    pub fn connect_with(&mut self, config: &HostKeyConfig<'_>) -> Result<(), String> {
        let username = self.profile.username.clone().unwrap_or_else(whoami);
        self.session = Some(connect_session_with(&self.profile, &username, config)?);
        // Переход в root выполняется отдельно, в том же канале, в котором
        // будет работать терминал (см. `open_shell`).
        Ok(())
    }
}

impl Connection for SshConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        self.connect_with(&HostKeyConfig::default())
    }

    fn disconnect(&mut self) {
        if let Some(session) = self.session.take() {
            session.disconnect(None, "Пользователь закрыл сессию", None).ok();
        }
    }
}

/// Открывает SSH-сессию и аутентифицируется указанным пользователем: по
/// ключу (ssh-agent или файл) либо по паролю.
///
/// Используется и терминалом, и SFTP-клиентом: если способы входа разойдутся,
/// при входе по ключу SFTP перестанет подключаться.
pub fn connect_session(profile: &Profile, username: &str) -> Result<ssh2::Session, String> {
    connect_session_with(profile, username, &HostKeyConfig::default())
}

/// Вариант `connect_session` с явной политикой проверки ключа хоста.
pub fn connect_session_with(
    profile: &Profile,
    username: &str,
    config: &HostKeyConfig<'_>,
) -> Result<ssh2::Session, String> {
    let tcp = tcp_connect(&profile.host, profile.port, CONNECT_TIMEOUT)?;
    let mut session = ssh2::Session::new().map_err(|e| format!("ошибка libssh2: {e}"))?;
    session.set_tcp_stream(tcp);
    session.set_timeout(HANDSHAKE_TIMEOUT_MS);
    session
        .handshake()
        .map_err(|e| format!("ошибка SSH-рукопожатия с {}:{}: {e}", profile.host, profile.port))?;

    // Проверяем ключ до отправки пароля/подписи: при подмене сервера
    // учётные данные не должны попасть к злоумышленнику.
    if let Err(e) = verify_host_key(&session, profile.host.as_str(), profile.port, config) {
        session.disconnect(None, "ключ хоста не подтверждён", None).ok();
        return Err(e);
    }

    if let Some(key_path) = profile.ssh_key_path.as_deref() {
        // Аутентификация по ключу (ssh-agent или прямой файл ключа).
        if profile.ssh_options.use_agent && session.agent().is_ok() {
            let mut agent = session.agent().map_err(|e| e.to_string())?;
            agent.connect().map_err(|e| e.to_string())?;
            agent.list_identities().map_err(|e| e.to_string())?;
            let mut authenticated = false;
            for id in agent.identities().map_err(|e| e.to_string())? {
                if agent.userauth(username, &id).is_ok() {
                    authenticated = true;
                    break;
                }
            }
            if !authenticated {
                return Err("ни один ключ ssh-agent не подошёл".into());
            }
        } else {
            session
                .userauth_pubkey_file(
                    username,
                    None,
                    Path::new(key_path),
                    profile
                        .ssh_key_passphrase
                        .as_ref()
                        .map(|p| p.expose_secret()),
                )
                .map_err(|e| format!("аутентификация по ключу не удалась: {e}"))?;
        }
    } else {
        // Аутентификация по паролю (передаётся по зашифрованному SSH-каналу).
        // Не клонируем пароль: libssh2 получает только ссылку на строку.
        let password = profile
            .password
            .as_ref()
            .map(|p| p.expose_secret())
            .filter(|p| !p.is_empty())
            .ok_or("в профиле не задан пароль")?;
        session
            .userauth_password(username, password)
            .map_err(|e| format!("аутентификация по паролю не удалась: {e}"))?;
    }

    if !session.authenticated() {
        return Err("аутентификация не пройдена".into());
    }

    // Блокирующие операции после входа не должны иметь 30-секундный лимит:
    // он нужен только для рукопожатия/аутентификации.
    session.set_timeout(0);
    session.set_keepalive(true, KEEPALIVE_INTERVAL_SECS);
    Ok(session)
}

/// Устанавливает TCP-соединение с общим дедлайном на все адреса хоста.
///
/// `ToSocketAddrs` может вернуть несколько адресов (IPv6 + IPv4). Идём по
/// ним по очереди, но не дольше `timeout` суммарно.
pub(crate) fn tcp_connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("не удалось разрешить {host}: {e}"))?;
    let deadline = Instant::now() + timeout;
    let mut last_error: Option<std::io::Error> = None;

    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = Some(e),
        }
    }

    let reason = last_error
        .map(|e| e.to_string())
        .unwrap_or_else(|| "нет доступных адресов".to_string());
    Err(format!(
        "не удалось подключиться к {host}:{port} за {} с: {reason}",
        timeout.as_secs()
    ))
}

/// Отличает ошибку «ключ хоста изменился» от прочих сбоев подключения.
///
/// По этому признаку интерфейс показывает отдельный диалог, а не только
/// строку состояния: изменение ключа — повод немедленно остановиться.
pub fn is_host_key_mismatch(message: &str) -> bool {
    message.contains("ключ хоста") && message.contains("изменился")
}

/// Проверяет ключ сервера по `~/.ssh/known_hosts` и системному файлу.
///
/// * совпал — продолжаем;
/// * изменился — всегда ошибка (возможна MITM-атака);
/// * неизвестен — спрашиваем пользователя либо, если verifier не задан,
///   применяем `accept_new` (TOFU) и добавляем ключ в файл.
fn verify_host_key(
    session: &ssh2::Session,
    host: &str,
    port: u16,
    config: &HostKeyConfig<'_>,
) -> Result<(), String> {
    let (key, _) = session
        .host_key()
        .ok_or("сервер не предоставил ключ хоста")?;
    let fingerprint = fingerprint_sha256(session)
        .ok_or("не удалось вычислить отпечаток ключа хоста")?;
    let key_type = key_type_name(key);

    let mut known = session
        .known_hosts()
        .map_err(|e| format!("не удалось инициализировать known_hosts: {e}"))?;

    // Пользовательский файл обязателен для чтения, если существует:
    // ошибка доступа не должна превращаться в «ключа нет — доверяем».
    if config.known_hosts.exists() {
        read_known_hosts(&mut known, &config.known_hosts)?;
    }
    // Системный файл читаем, если он есть; его отсутствие/недоступность
    // не должна ломать подключение.
    let system = Path::new("/etc/ssh/ssh_known_hosts");
    if system.exists() {
        let _ = read_known_hosts(&mut known, system);
    }

    match known.check_port(host, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(format!(
            "ключ хоста {host}:{port} изменился!\n\
             Отпечаток сервера: {fingerprint} ({key_type}).\n\
             Подключение заблокировано: возможна MITM-атака. Если сервер \
             действительно переустановлен, удалите устаревшую запись из {} \
             и подключитесь снова.",
            config.known_hosts.display()
        )),
        CheckResult::NotFound => {
            let prompt = HostKeyPrompt {
                host: host.to_string(),
                port,
                fingerprint: fingerprint.clone(),
                key_type: key_type.clone(),
                known_hosts: config.known_hosts.clone(),
            };
            let accepted = match config.verifier {
                Some(verifier) => verifier(&prompt),
                None => config.accept_new,
            };
            if !accepted {
                return Err(format!(
                    "неизвестный ключ хоста {host}:{port}\n\
                     Отпечаток: {fingerprint} ({key_type}).\n\
                     Подключение отклонено: ключ не подтверждён."
                ));
            }
            append_known_host(&config.known_hosts, host, port, key, &key_type)?;
            Ok(())
        }
        CheckResult::Failure => Err(format!(
            "не удалось проверить ключ хоста {host}:{port} \
             (файл {} повреждён или недоступен)",
            config.known_hosts.display()
        )),
    }
}

/// Читает known_hosts построчно, чтобы одна неподдерживаемая строка
/// (например, `@cert-authority`) не отменяла проверку всего файла.
fn read_known_hosts(
    known: &mut ssh2::KnownHosts,
    path: &Path,
) -> Result<(), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = format!("{line}\n");
        // Неподдерживаемые строки (маркеры, незнакомые типы ключей)
        // пропускаем: остальные записи всё равно должны работать.
        let _ = known.read_str(&line, KnownHostFileKind::OpenSSH);
    }
    Ok(())
}

/// Добавляет строку в known_hosts, не перезаписывая и не переформатируя
/// существующий файл (в нём могут быть комментарии и hashed-записи).
fn append_known_host(
    path: &Path,
    host: &str,
    port: u16,
    key: &[u8],
    key_type: &str,
) -> Result<(), String> {
    use std::io::Write;

    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("не удалось создать {}: {e}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
    }

    let host_field = known_hosts_host(host, port);
    let key_b64 = BASE64.encode(key);
    let mut line = String::new();
    line.push_str(&host_field);
    line.push(' ');
    line.push_str(key_type);
    line.push(' ');
    line.push_str(&key_b64);
    line.push('\n');

    let existing = std::fs::read(path).unwrap_or_default();
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("не удалось открыть {}: {e}", path.display()))?;
    // Если файл не заканчивается переводом строки, новая запись иначе
    // склеится с последней.
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        file.write_all(b"\n")
            .map_err(|e| format!("не удалось записать {}: {e}", path.display()))?;
    }
    file.write_all(line.as_bytes())
        .map_err(|e| format!("не удалось записать {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Формат хоста в known_hosts: `host` для 22 порта и `[host]:port` иначе.
/// Для IPv6 скобки нужны всегда, иначе двоеточия адреса не отличить от порта.
fn known_hosts_host(host: &str, port: u16) -> String {
    if port == 22 && !host.contains(':') {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// SHA256-отпечаток в формате OpenSSH: `SHA256:base64` без padding.
fn fingerprint_sha256(session: &ssh2::Session) -> Option<String> {
    let hash = session.host_key_hash(HashType::Sha256)?;
    Some(format!("SHA256:{}", STANDARD_NO_PAD.encode(hash)))
}

/// Тип ключа берём из самого SSH-блока ключа: это надёжнее, чем
/// перечисление `HostKeyType` (оно не различает ECDSA-кривые и будущие типы).
fn key_type_name(key: &[u8]) -> String {
    first_ssh_string(key)
        .unwrap_or("unknown")
        .to_string()
}

/// Читает первый SSH string (`uint32 length || bytes`) из блоба ключа.
fn first_ssh_string(data: &[u8]) -> Option<&str> {
    if data.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let start = 4usize;
    let end = start.checked_add(len)?;
    if len == 0 || end > data.len() {
        return None;
    }
    std::str::from_utf8(&data[start..end]).ok()
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
            .as_ref()
            .map(|p| p.expose_secret())
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
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut prompted = false;
        while Instant::now() < deadline {
            match channel.read(&mut buf) {
                Ok(n) if n > 0 => {
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if seen.contains("assword") || seen.contains("ароль") {
                        prompted = true;
                        break;
                    }
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
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
            .as_ref()
            .map(|p| p.expose_secret())
            .filter(|p| !p.is_empty())
            .ok_or("в профиле не задан пароль root")?;
        let session = self.session.as_mut().ok_or("нет активной сессии")?;
        let mut buf = [0u8; 512];
        let mut seen = String::new();
        session.set_blocking(false);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut prompted = false;
        while Instant::now() < deadline {
            match channel.read(&mut buf) {
                Ok(n) if n > 0 => {
                    seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if seen.contains("assword") || seen.contains("ароль") {
                        prompted = true;
                        break;
                    }
                }
                _ => std::thread::sleep(Duration::from_millis(50)),
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
    use secrecy::SecretString;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Профиль для тестового сервера.
    fn test_profile() -> Profile {
        Profile {
            id: 0,
            name: "test".to_string(),
            protocol: Protocol::Ssh,
            host: "127.0.0.1".to_string(),
            port: 2222,
            username: Some("tester".to_string()),
            password: Some(SecretString::from("secret".to_string())),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            root_password: None,
            group_id: None,
            tags: vec![],
            icon: None,
            notes: None,
            mac_address: None,
            rdp_options: RdpOptions::default(),
            vnc_options: VncOptions::default(),
            ssh_options: SshOptions::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        }
    }

    /// Свежий known_hosts на каждый тест: не трогаем файл пользователя и
    /// не зависим от ключа sshd, оставшегося от прошлого запуска.
    fn test_host_key_config() -> HostKeyConfig<'static> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        HostKeyConfig {
            known_hosts: std::env::temp_dir().join(format!(
                "remotix-known-hosts-{}-{stamp}",
                std::process::id()
            )),
            accept_new: true,
            verifier: None,
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
        conn.connect_with(&test_host_key_config())
            .expect("подключение к SSH-серверу");

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
        profile.password = Some(SecretString::from("wrong-password".to_string()));
        let mut conn = SshConnection::new(profile);
        assert!(
            conn.connect_with(&test_host_key_config()).is_err(),
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
        conn.connect_with(&test_host_key_config())
            .expect("подключение к SSH-серверу");

        let session = conn.take_session().expect("сессия");
        let mut channel = session.channel_session().expect("канал");
        channel.request_pty("xterm", None, None).expect("запрос PTY");
        channel.shell().expect("интерактивная оболочка");

        channel.write_all(b"echo shell-works\n").expect("ввод команды");

        let mut out = String::new();
        let mut buf = [0u8; 1024];
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
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
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => panic!("ошибка чтения из канала: {e}"),
            }
        }

        assert!(
            out.contains("shell-works"),
            "в выводе терминала нет ответа на команду: {out:?}"
        );
    }

    #[test]
    fn known_hosts_host_uses_brackets_for_nonstandard_port() {
        assert_eq!(known_hosts_host("example.org", 22), "example.org");
        assert_eq!(known_hosts_host("example.org", 2222), "[example.org]:2222");
        assert_eq!(known_hosts_host("2001:db8::1", 22), "[2001:db8::1]:22");
    }

    #[test]
    fn known_hosts_ipv6_default_port_roundtrip() {
        // Проверяем именно формат, который записывает append_known_host:
        // libssh2 должен находить эту строку при следующем подключении.
        let mut key = Vec::new();
        let key_type = b"ssh-ed25519";
        key.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
        key.extend_from_slice(key_type);
        key.extend_from_slice(&(32u32).to_be_bytes());
        key.extend_from_slice(&[7u8; 32]);

        let line = format!(
            "[2001:db8::1]:22 ssh-ed25519 {}\n",
            BASE64.encode(&key)
        );
        let session = ssh2::Session::new().expect("libssh2");
        let mut known = session.known_hosts().expect("known_hosts");
        known
            .read_str(&line, KnownHostFileKind::OpenSSH)
            .expect("строка known_hosts");
        assert!(
            matches!(
                known.check_port("2001:db8::1", 22, &key),
                CheckResult::Match
            ),
            "запись [IPv6]:22 должна проверяться на стандартном порту"
        );
    }

    #[test]
    fn recognizes_host_key_mismatch_error() {
        assert!(is_host_key_mismatch(
            "ключ хоста example.org:22 изменился!\nПодключение заблокировано"
        ));
        assert!(!is_host_key_mismatch("не удалось подключиться к example.org"));
        assert!(!is_host_key_mismatch("ключ хоста не предоставлен"));
    }

    #[test]
    fn key_type_is_read_from_ssh_blob() {
        // Первый SSH string блоба ed25519-ключа.
        let mut blob = Vec::new();
        let name = b"ssh-ed25519";
        blob.extend_from_slice(&(name.len() as u32).to_be_bytes());
        blob.extend_from_slice(name);
        blob.extend_from_slice(&[0u8; 32]);
        assert_eq!(key_type_name(&blob), "ssh-ed25519");
    }

    #[test]
    fn key_type_name_survives_broken_blob() {
        assert_eq!(key_type_name(b"not-a-ssh-key"), "unknown");
    }
}
