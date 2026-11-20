mod cliprdr;

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use secrecy::ExposeSecret;

use crate::models::Profile;
use crate::protocols::Connection;
use cliprdr::{ClipboardEvent, CliprdrClient};
use ironrdp_svc::{SvcMessage, SvcProcessorMessages};

/// Общий дедлайн на TCP-подключение к RDP-серверу.
const RDP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Тайм-аут чтения/записи во время рукопожатия RDP.
const RDP_IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Быстрая проверка баннера не должна задерживать сообщение об ошибке.
const RDP_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Флаги канала RDP-буфера обмена (cliprdr, VirtualChannel CLIPRDR).
/// Передаются в настройки IronRDP при создании коннектора.
#[derive(Debug, Clone, Copy)]
pub struct ClipboardConfig {
    /// Канал буфера обмена включён.
    pub enabled: bool,
    /// Локальный -> удалённый (копирование в Remotix, вставка на сервере).
    pub to_remote: bool,
    /// Удалённый -> локальный (копирование на сервере, вставка в Remotix).
    pub from_remote: bool,
}

impl ClipboardConfig {
    /// Из настроек профиля: по умолчанию двунаправленный обмен.
    pub fn from_profile(p: &Profile) -> Self {
        let o = &p.rdp_options;
        Self {
            enabled: o.clipboard,
            to_remote: o.clipboard
                && (o.clipboard_to_remote || (!o.clipboard_to_remote && !o.clipboard_from_remote)),
            from_remote: o.clipboard
                && (o.clipboard_from_remote
                    || (!o.clipboard_to_remote && !o.clipboard_from_remote)),
        }
    }
}

/// Фактически согласованный протокол безопасности RDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpSecurity {
    /// Сессия ещё не подключена или протокол неизвестен.
    Unknown,
    /// NLA (CredSSP) поверх TLS.
    Nla,
    /// TLS без CredSSP (графический вход).
    Tls,
    /// Standard RDP Security (RC4, без TLS).
    Rc4,
}

impl RdpSecurity {
    /// Короткая подпись для индикатора качества.
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "—",
            Self::Nla => "NLA",
            Self::Tls => "TLS",
            Self::Rc4 => "RC4",
        }
    }
}

/// Снимок качества активной RDP-сессии для индикатора в просмотрщике.
#[derive(Debug, Clone, Copy)]
pub struct RdpQuality {
    /// Активный протокол безопасности.
    pub security: RdpSecurity,
    /// Последняя измеренная задержка отклика на ввод, мс.
    pub latency_ms: Option<u32>,
    /// Сколько кадров не удалось декодировать за сессию.
    pub decode_errors: u32,
    /// Всего байт полезной нагрузки PDU RDP.
    pub bytes_received: u64,
}

/// Поток с префиксом — оборачивает TLS-стрим и сначала отдаёт leftover-байты,
/// прочитанные из TCP до TLS-апгрейда, а затем читает из TLS-стрима.
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }

    /// Доступ к вложенному потоку (нужен, например, чтобы перевести сокет
    /// в неблокирующий режим уже после TLS-рукопожатия).
    fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Read> Read for PrefixedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.prefix_pos < self.prefix.len() {
            let n = (&self.prefix[self.prefix_pos..]).read(buf)?;
            self.prefix_pos += n;
            Ok(n)
        } else {
            self.inner.read(buf)
        }
    }
}

impl<S: Write> Write for PrefixedStream<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Поток активной RDP-сессии: либо «голый» TCP (Standard RDP Security,
/// шифрование RC4 на уровне протокола), либо TCP поверх TLS.
///
/// Тип объединяет оба варианта, чтобы остальная часть клиента (Framed,
/// неблокирующий режим) не зависела от выбранного режима безопасности.
enum SessionStream {
    Plain(TcpStream),
    // В коробке — только большой TLS-поток; Box держит перечисление компактным
    // (Read/Write работают через авто-разыменование). `PrefixedStream` лежит
    // ВНУТРИ TLS: байты, прочитанные вместе с X.224-ответом, должны попасть
    // в TLS-рукопожатие, а не быть приняты за открытый текст RDP.
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, PrefixedStream<TcpStream>>>),
}

impl SessionStream {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_nonblocking(nonblocking),
            Self::Tls(stream) => stream.sock.inner.set_nonblocking(nonblocking),
        }
    }
}

impl Read for SessionStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

impl Write for SessionStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// Предел ответа KDC/KDC-прокси: защита от бесконечного потока.
const MAX_KDC_RESPONSE: usize = 4 * 1024 * 1024;

/// NetworkClient для CredSSP: обслуживает запросы SSPI к KDC.
///
/// NLA по NTLM выполняется целиком внутри IronRDP и этот клиент не вызывает.
/// Он нужен для Kerberos: KDC-запросы уходят по TCP/UDP либо через KDC-прокси
/// (HTTP/HTTPS, MS-KKDCP). В KDC-прокси запрос передаётся **в теле** POST,
/// а ответ читается из тела; `Authorization: Negotiate` здесь не используется.
struct RdpNetworkClient;

impl ironrdp_connector::sspi::network_client::NetworkClient for RdpNetworkClient {
    fn send(
        &self,
        request: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> Result<Vec<u8>, ironrdp_connector::sspi::Error> {
        use ironrdp_connector::sspi as Sspi;
        use Sspi::network_client::NetworkProtocol;

        let host = request.url.host_str().unwrap_or_default();
        let port = request.url.port_or_known_default().unwrap_or(88);

        let result = match request.protocol {
            NetworkProtocol::Tcp => send_kdc_tcp(host, port, &request.data),
            NetworkProtocol::Udp => send_kdc_udp(host, port, &request.data),
            NetworkProtocol::Http | NetworkProtocol::Https => {
                // KDC-прокси может жить не в корне: сохраняем путь и query.
                let path = request.url.path();
                let path = if path.is_empty() { "/" } else { path };
                let target = match request.url.query() {
                    Some(query) => format!("{path}?{query}"),
                    None => path.to_string(),
                };
                send_kdc_http(
                    host,
                    port,
                    &target,
                    &request.data,
                    request.protocol == NetworkProtocol::Https,
                )
            }
        };

        result.map_err(|e| Sspi::Error::new(Sspi::ErrorKind::NoAuthenticatingAuthority, e))
    }
}

/// KDC по TCP: запрос уже содержит 4-байтовый префикс длины (его формирует
/// SSPI); ответ приходит с таким же префиксом, его и возвращаем.
fn send_kdc_tcp(host: &str, port: u16, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut stream = tcp_connect(host, port, RDP_CONNECT_TIMEOUT)
        .map_err(|e| format!("KDC {host}:{port}: {e}"))?;
    stream
        .set_read_timeout(Some(RDP_IO_TIMEOUT))
        .map_err(|e| format!("KDC {host}:{port}: тайм-аут чтения: {e}"))?;
    stream
        .set_write_timeout(Some(RDP_IO_TIMEOUT))
        .map_err(|e| format!("KDC {host}:{port}: тайм-аут записи: {e}"))?;
    stream
        .write_all(data)
        .map_err(|e| format!("KDC {host}:{port}: отправка: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("KDC {host}:{port}: отправка: {e}"))?;

    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|e| format!("KDC {host}:{port}: чтение длины ответа: {e}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_KDC_RESPONSE {
        return Err(format!(
            "KDC {host}:{port}: недопустимая длина ответа {length}"
        ));
    }
    let mut response = vec![0u8; length + 4];
    response[..4].copy_from_slice(&(length as u32).to_be_bytes());
    stream
        .read_exact(&mut response[4..])
        .map_err(|e| format!("KDC {host}:{port}: чтение ответа: {e}"))?;
    Ok(response)
}

/// KDC по UDP. SSPI ожидает ответ с 4-байтовым префиксом длины.
fn send_kdc_udp(host: &str, port: u16, data: &[u8]) -> Result<Vec<u8>, String> {
    use std::net::UdpSocket;

    // Для IPv6-буквального адреса нужен IPv6-сокет; для имён обычно IPv4.
    let bind = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).map_err(|e| format!("KDC UDP {host}:{port}: сокет: {e}"))?;
    socket
        .set_read_timeout(Some(RDP_IO_TIMEOUT))
        .map_err(|e| format!("KDC UDP {host}:{port}: тайм-аут: {e}"))?;
    socket
        .connect((host, port))
        .map_err(|e| format!("KDC UDP {host}:{port}: {e}"))?;
    socket
        .send(data)
        .map_err(|e| format!("KDC UDP {host}:{port}: отправка: {e}"))?;

    let mut buf = vec![0u8; 0xbb80];
    let n = socket
        .recv(&mut buf)
        .map_err(|e| format!("KDC UDP {host}:{port}: чтение ответа: {e}"))?;
    let mut response = Vec::with_capacity(n + 4);
    response.extend_from_slice(&(n as u32).to_be_bytes());
    response.extend_from_slice(&buf[..n]);
    Ok(response)
}

/// KDC-прокси (MS-KKDCP): POST с KDC-сообщением в теле, ответ — тело HTTP.
fn send_kdc_http(
    host: &str,
    port: u16,
    target: &str,
    data: &[u8],
    tls: bool,
) -> Result<Vec<u8>, String> {
    let tcp = tcp_connect(host, port, RDP_CONNECT_TIMEOUT)
        .map_err(|e| format!("KDC-прокси {host}:{port}: {e}"))?;
    tcp.set_read_timeout(Some(RDP_IO_TIMEOUT))
        .map_err(|e| format!("KDC-прокси {host}:{port}: тайм-аут чтения: {e}"))?;
    tcp.set_write_timeout(Some(RDP_IO_TIMEOUT))
        .map_err(|e| format!("KDC-прокси {host}:{port}: тайм-аут записи: {e}"))?;

    if tls {
        let mut config = rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| format!("некорректное имя KDC-прокси {host}: {e}"))?;
        let client = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| format!("TLS KDC-прокси {host}:{port}: {e}"))?;
        let stream = rustls::StreamOwned::new(client, tcp);
        kdc_http_exchange(stream, host, port, target, data)
    } else {
        kdc_http_exchange(tcp, host, port, target, data)
    }
}

fn kdc_http_exchange<S: Read + Write>(
    mut stream: S,
    host: &str,
    port: u16,
    target: &str,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let request = build_kdc_http_request(host, port, target, data);
    stream
        .write_all(&request)
        .map_err(|e| format!("KDC-прокси {host}:{port}: отправка: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("KDC-прокси {host}:{port}: отправка: {e}"))?;
    let raw =
        read_http_response(&mut stream).map_err(|e| format!("KDC-прокси {host}:{port}: {e}"))?;
    parse_kdc_http_response(&raw).map_err(|e| format!("KDC-прокси {host}:{port}: {e}"))
}

/// Собирает HTTP/1.1 POST для KDC-прокси. Тело — KDC-сообщение.
fn build_kdc_http_request(host: &str, port: u16, target: &str, data: &[u8]) -> Vec<u8> {
    let host_header = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let head = format!(
        "POST {target} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        data.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(data);
    request
}

/// Читает HTTP-ответ до закрытия соединения или до полного Content-Length.
fn read_http_response<S: Read>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_KDC_RESPONSE {
                    return Err("ответ больше допустимого размера".to_string());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // Сервер вправе не закрывать соединение сразу; если заголовки уже
            // пришли, отдаём то, что успели прочитать.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) && find_header_end(&raw).is_some() =>
            {
                break;
            }
            Err(e) => return Err(format!("чтение ответа: {e}")),
        }
    }
    if raw.is_empty() {
        return Err("сервер закрыл соединение без HTTP-ответа".to_string());
    }
    Ok(raw)
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Разбирает HTTP-ответ KDC-прокси: проверяет статус и отделяет тело.
fn parse_kdc_http_response(raw: &[u8]) -> Result<Vec<u8>, String> {
    let end = find_header_end(raw).ok_or_else(|| "неполный HTTP-ответ".to_string())?;
    let head = String::from_utf8_lossy(&raw[..end]);
    let status_line = head.lines().next().unwrap_or_default().trim();
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("некорректный HTTP-ответ: {status_line}"))?;
    if !version.starts_with("HTTP/") {
        return Err(format!("некорректный HTTP-ответ: {status_line}"));
    }

    let body = &raw[end + 4..];
    if !(200..300).contains(&code) {
        let snippet: String = String::from_utf8_lossy(body)
            .trim()
            .replace(['\r', '\n'], " ")
            .chars()
            .take(200)
            .collect();
        return Err(if snippet.is_empty() {
            format!("HTTP-ответ {status_line}")
        } else {
            format!("HTTP-ответ {status_line}: {snippet}")
        });
    }

    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        let length = value
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("некорректный Content-Length: {}", value.trim()))?;
        if length > body.len() {
            return Err(format!(
                "неполный ответ: получено {} из {length} байт",
                body.len()
            ));
        }
        return Ok(body[..length].to_vec());
    }

    Ok(body.to_vec())
}

/// Событие клавиатуры для RDP-сессии.
#[derive(Debug, Clone, Copy)]
pub enum RdpKey {
    /// Служебная клавиша: X11-сканкод (set 1) и признак «расширенной» клавиши.
    Scancode { code: u8, extended: bool },
    /// Символ: Unicode-кодовая точка (запасной путь).
    Char(char),
}

/// Действие с кнопкой мыши в RDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEvent {
    /// Перемещение курсора (с зажатыми кнопками или без них).
    Move,
    /// Нажатие кнопки (в RDP — флаг DOWN).
    ButtonDown,
    /// Отпускание кнопки: кнопка остаётся в маске, но DOWN уже нет.
    ButtonUp,
}

/// Маска кнопок мыши: 1 — левая, 2 — правая, 4 — средняя.
///
/// Это порядок битов RDP (`BUTTON1`, `BUTTON2`, `BUTTON3`), а не порядок
/// кнопок GDK (1 — левая, 2 — средняя, 3 — правая).
pub const MOUSE_LEFT: u8 = 0x01;
pub const MOUSE_RIGHT: u8 = 0x02;
pub const MOUSE_MIDDLE: u8 = 0x04;

/// Верификатор TLS-сертификата, принимающий любой сертификат (аналог поведения
/// большинства RDP-клиентов — проверка отпечатка/отзыва делается отдельно).
#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Подключение RDP через IronRDP (чистый Rust, без FreeRDP FFI).
/// Использует ironrdp-blocking для синхронной работы в отдельном потоке GTK.
/// Поддерживает NLA (CredSSP через `RdpNetworkClient`) и классический
/// TLS+графический вход (PROTOCOL_SSL). Активная стадия даёт ввод (мышь —
/// slow-path с Share Data Header, клавиатура — fast-path), двунаправленный
/// буфер обмена (CLIPRDR) и декодированное изображение рабочего стола.
/// Типы активной RDP-сессии (поток поверх TCP — TLS или «голый» для RC4).
type RdpFramed = ironrdp_blocking::Framed<SessionStream>;
type RdpStage = ironrdp_session::ActiveStage;
type RdpImage = ironrdp_session::image::DecodedImage;

pub struct RdpConnection {
    profile: Profile,
    clipboard: ClipboardConfig,
    connected: bool,
    /// Живой TLS-стрим активной сессии (после успешного connect()).
    framed: Option<RdpFramed>,
    /// Активная стадия: обработка рамок, быстрый путь (fast-path), каналы.
    stage: Option<RdpStage>,
    /// Декодированное изображение рабочего стола для отрисовки.
    image: Option<RdpImage>,
    /// Сколько подряд кадров не удалось декодировать. Единичный битый
    /// графический/pointer-update не должен обрывать всю сессию, но
    /// бесконечный поток ошибок — повод остановиться.
    decode_errors: u32,
    /// Неотправленные байты ввода: сокет неблокирующий, запись может
    /// вернуть WouldBlock — кадр нельзя терять, его дописываем позже.
    outgoing: Vec<u8>,
    /// Каналы MCS: медленный путь ввода адресуется на I/O-канал от имени
    /// пользовательского канала.
    io_channel_id: u16,
    user_channel_id: u16,
    /// Идентификатор общего ресурса из ConnectionResult: нужен для Share Data
    /// Header в slow-path вводе мыши.
    share_id: u32,
    /// Сессия завершена штатно (сервер закрыл соединение). В отличие от
    /// ошибки, UI показывает «сессия закрыта», а не красный статус.
    close_reason: Option<String>,
    /// Согласованный протокол безопасности (NLA/TLS/RC4).
    security: RdpSecurity,
    /// Момент отправки последнего ввода: по нему оценивается отклик.
    input_sent_at: Option<Instant>,
    /// Последняя измеренная задержка отклика на ввод, мс.
    latency_ms: Option<u32>,
    /// Всего байт полезной нагрузки PDU RDP.
    bytes_received: u64,
    /// Ошибки декодирования за всю сессию (для индикатора потерь).
    frame_errors: u32,
    /// Текст из удалённого буфера, ожидающий передачи в GUI-поток.
    clipboard_events: VecDeque<ClipboardEvent>,
}

impl RdpConnection {
    pub fn new(profile: Profile) -> Self {
        let clipboard = ClipboardConfig::from_profile(&profile);
        Self {
            profile,
            clipboard,
            connected: false,
            framed: None,
            stage: None,
            image: None,
            decode_errors: 0,
            outgoing: Vec::new(),
            io_channel_id: 0,
            user_channel_id: 0,
            share_id: 0,
            close_reason: None,
            security: RdpSecurity::Unknown,
            input_sent_at: None,
            latency_ms: None,
            bytes_received: 0,
            frame_errors: 0,
            clipboard_events: VecDeque::new(),
        }
    }

    /// Строит активную стадию RDP-сессии из результата подключения и создаёт
    /// буфер декодированного изображения рабочего стола.
    pub fn setup_active_stage(&mut self, connection_result: ironrdp_connector::ConnectionResult) {
        let desktop_size = connection_result.desktop_size;
        // BgrA32 = байтовый порядок BGRA, совместимый с cairo ARgb32
        // (на little-endian): просмотрщик отдаёт буфер в ImageSurface без
        // конвертации. RgbA32 здесь приводил бы к перепутанным R/B.
        self.image = Some(ironrdp_session::image::DecodedImage::new(
            ironrdp_graphics::image_processing::PixelFormat::BgrA32,
            desktop_size.width,
            desktop_size.height,
        ));

        self.io_channel_id = connection_result.io_channel_id;
        self.user_channel_id = connection_result.user_channel_id;
        self.share_id = connection_result.share_id;
        self.close_reason = None;

        self.stage = Some(
            ironrdp_session::ActiveStageBuilder {
                static_channels: connection_result.static_channels,
                user_channel_id: connection_result.user_channel_id,
                io_channel_id: connection_result.io_channel_id,
                message_channel_id: connection_result.message_channel_id,
                share_id: connection_result.share_id,
                compression_type: connection_result.compression_type,
                enable_server_pointer: connection_result.enable_server_pointer,
                pointer_software_rendering: connection_result.pointer_software_rendering,
                // Криптор Standard RDP Security (RC4): коннектор уже зашифровал
                // им Client Info и лицензирование, сессия продолжает шифровать
                // fast-path/slow-path тем же потоком ключей.
                security: connection_result.security,
            }
            .build(),
        );
    }

    /// Обрабатывает один шаг активной стадии (просмотр): читает одну рамку
    /// сервера, декодирует её в изображение и отправляет ответные рамки.
    ///
    /// Возвращает `Ok(true)`, пока сессия активна, `Ok(false)` — когда данных
    /// ещё нет (would-block, вызывайте снова) или сессия штатно закрыта
    /// (см. [`Self::close_reason`]), и `Err` при ошибке/разрыве.
    pub fn run(&mut self) -> Result<bool, String> {
        if self.close_reason.is_some() {
            return Ok(false);
        }

        // Дописываем ввод, который не ушёл из-за WouldBlock.
        self.flush_outgoing();

        let Self {
            framed,
            stage,
            image,
            decode_errors,
            frame_errors,
            latency_ms,
            bytes_received,
            clipboard_events,
            input_sent_at,
            close_reason,
            ..
        } = self;
        let (
            framed,
            stage,
            image,
            decode_errors,
            frame_errors,
            latency_ms,
            bytes_received,
            clipboard_events,
            input_sent_at,
            close_reason,
        ) = match (
            framed.as_mut(),
            stage.as_mut(),
            image.as_mut(),
            decode_errors,
            frame_errors,
            latency_ms,
            bytes_received,
            clipboard_events,
            input_sent_at,
            close_reason,
        ) {
            (Some(f), Some(s), Some(i), de, fe, lat, br, ce, isa, cr) => {
                (f, s, i, de, fe, lat, br, ce, isa, cr)
            }
            _ => return Err("RDP-сессия не инициализирована (нет framed/stage/image)".to_string()),
        };

        let (action, payload) = match framed.read_pdu() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Данных пока нет — возвращаем состояние в сессию и даём GUI
                // продолжить (вызывать run() снова по таймеру / активности).
                return Ok(false);
            }
            // Сервер закрыл соединение (штатный logoff или обрыв) — это не
            // ошибка декодирования. UI покажет «сессия закрыта», а не красную
            // строку «not enough bytes».
            Err(e) if is_connection_closed(&e) => {
                *close_reason = Some("сервер закрыл соединение".to_string());
                return Ok(false);
            }
            Err(e) => return Err(format!("ошибка чтения рамки: {e}")),
        };

        // Отклик измеряем от последнего отправленного ввода до первого
        // ответа сервера. Это не ICMP-RTT, но хорошо показывает, когда
        // сессия начинает «тормозить» на действиях пользователя.
        if let Some(sent) = input_sent_at.take() {
            let elapsed = sent.elapsed();
            if elapsed <= Duration::from_secs(5) {
                *latency_ms = Some(elapsed.as_millis().min(u128::from(u32::MAX)) as u32);
            }
        }
        *bytes_received = bytes_received.saturating_add(payload.len() as u64);

        let outputs = match stage.process(image, action, &payload) {
            Ok(outputs) => {
                *decode_errors = 0;
                if let Some(client) = stage.get_svc_processor_mut::<CliprdrClient>() {
                    clipboard_events.extend(client.drain_events());
                }
                outputs
            }
            Err(e) => {
                let text = e.to_string();
                if text.to_ascii_lowercase().contains("decode") {
                    *decode_errors += 1;
                    *frame_errors = frame_errors.saturating_add(1);
                    crate::logging::rdp_warn(&format!(
                        "кадр RDP ({} байт) не декодирован ({} подряд): {text}",
                        payload.len(),
                        *decode_errors
                    ));
                    if *decode_errors <= 3 {
                        // Рамка уже прочитана целиком, поток не рассинхронизирован.
                        // Пропускаем битый графический/pointer-update и живём дальше.
                        return Ok(true);
                    }
                }
                return Err(format!("ошибка обработки рамки: {e}"));
            }
        };

        let mut terminated = None;
        for out in outputs {
            match out {
                ironrdp_session::ActiveStageOutput::ResponseFrame(frame) => {
                    if let Err(e) = framed.write_all(&frame) {
                        if is_connection_closed(&e) {
                            *close_reason = Some("сервер закрыл соединение".to_string());
                            return Ok(false);
                        }
                        return Err(format!("ошибка отправки ответа: {e}"));
                    }
                }
                ironrdp_session::ActiveStageOutput::Terminate(reason) => {
                    terminated = Some(reason);
                }
                _ => {}
            }
        }

        if let Some(reason) = terminated {
            let text = match reason {
                ironrdp_session::GracefulDisconnectReason::ServerInitiated => {
                    "сервер завершил сеанс".to_string()
                }
                ironrdp_session::GracefulDisconnectReason::UserInitiated => {
                    "сеанс завершён".to_string()
                }
                ironrdp_session::GracefulDisconnectReason::Other(description) => {
                    format!("сервер завершил сеанс: {description}")
                }
            };
            *close_reason = Some(text);
            return Ok(false);
        }

        Ok(true)
    }

    /// Причина штатного закрытия сессии; `None`, пока сессия активна.
    pub fn close_reason(&self) -> Option<&str> {
        self.close_reason.as_deref()
    }

    /// Снимок качества соединения для индикатора в GUI.
    pub fn quality(&self) -> RdpQuality {
        RdpQuality {
            security: self.security,
            latency_ms: self.latency_ms,
            decode_errors: self.frame_errors,
            bytes_received: self.bytes_received,
        }
    }

    /// Забирает текст, полученный из удалённого буфера обмена.
    ///
    /// Наружу отдаются только строки: тип события канала остаётся внутри
    /// модуля, а GUI не нужно знать про CLIPRDR-детали.
    pub fn take_clipboard_text(&mut self) -> Vec<String> {
        self.clipboard_events
            .drain(..)
            .map(|event| match event {
                ClipboardEvent::Text(text) => text,
            })
            .collect()
    }
}

impl Connection for RdpConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        // Проверяем логин до сетевых попыток. Иначе «не указан логин»
        // возвращался из каждого режима безопасности (2–3 раза подряд),
        // а вслед за ним показывались подсказки про RC4/NLA — хотя
        // проблема была не в сервере, а в профиле.
        if profile_username(&self.profile).is_none() {
            return Err("не указан логин RDP: укажите имя пользователя в свойствах \
                 профиля или введите его в диалоге подключения"
                .to_string());
        }

        // Порядок попыток: сначала NLA+TLS (CredSSP) — так требуют Windows
        // 10/11, RDS и серверы с NLA. Затем только TLS — для серверов без
        // NLA. Последний NLA-вариант без флага SSL оставлен для редких
        // серверов, которые не принимают SSL в паре с HYBRID.
        // Standard RDP Security (RC4 без TLS) пробуем только при явном
        // разрешении в профиле: молчаливый откат на устаревший режим
        // недопустим (нет проверки сервера, слабое шифрование).
        let nla = self.profile.rdp_options.nla;
        let allow_legacy = self.profile.rdp_options.allow_legacy_security;
        let modes = security_modes(nla, allow_legacy);

        let mut errors: Vec<String> = Vec::new();
        for (credssp, tls, legacy) in modes {
            match self.connect_with(credssp, tls, legacy) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    crate::logging::rdp_warn(&format!(
                        "режим RDP (NLA={credssp}, TLS={tls}, RC4={legacy}) не сработал: {e}"
                    ));
                    errors.push(e);
                }
            }
        }

        let addr = format!("{}:{}", self.profile.host, self.profile.port);
        let banner = probe_rdp_banner(&self.profile.host, self.profile.port);
        Err(connection_error_message(
            &addr,
            banner.as_deref(),
            &errors,
            allow_legacy,
            nla,
        ))
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }
}

/// Проверяет, что на порту отвечает именно RDP-сервер.
///
/// Возвращает баннер сервера, если это не RDP (например, «SSH-2.0-OpenSSH…»
/// или текст HTTP-ошибки), — по нему видно, что указан неверный порт.
fn probe_rdp_banner(host: &str, port: u16) -> Option<String> {
    let mut stream = tcp_connect(host, port, RDP_PROBE_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(RDP_PROBE_TIMEOUT)).ok()?;
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    // TPKT-заголовок RDP начинается с 0x03 0x00.
    if buf[0] == 0x03 && n > 1 && buf[1] == 0x00 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    let text = text.trim().replace(['\r', '\n'], " ");
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Предел неотправленного ввода: дальше буфер сбрасывается, чтобы сессия
/// не копила бесконечную очередь при мёртвом соединении.
const MAX_PENDING_INPUT: usize = 64 * 1024;

/// Кладёт кадр в очередь ввода. `false` — буфер переполнен и сброшен.
fn queue_input(queue: &mut Vec<u8>, frame: Vec<u8>) -> bool {
    if frame.is_empty() {
        return true;
    }
    if queue.len() + frame.len() > MAX_PENDING_INPUT {
        queue.clear();
        return false;
    }
    queue.extend_from_slice(&frame);
    true
}

/// Собирает кадр медленного пути ввода: Share Control Header + Share Data
/// Header (`PDUTYPE2_INPUT`) + `TS_INPUT_PDU_DATA`.
///
/// Именно Share Data Header отличает корректный медленный ввод от «голого»
/// `TS_INPUT_PDU` в MCS user_data: без него сервер читает первые байты как
/// заголовок общего ресурса и молча отбрасывает событие. Полные 16-битные
/// `pointerFlags` выражают DOWN и все три кнопки, чего 5-битный `eventFlags`
/// быстрого пути не умеет.
///
/// `TS_SECURITY_HEADER` здесь писать нельзя: в Enhanced RDP Security (TLS/NLA)
/// его нет вовсе, а в Standard RDP Security обёртку добавляет
/// `ActiveStage::secure_outgoing_frame`.
fn slow_path_input_frame(
    io_channel_id: u16,
    user_channel_id: u16,
    share_id: u32,
    events: Vec<ironrdp_pdu::input::InputEvent>,
) -> Vec<u8> {
    use ironrdp_pdu::input::InputEventPdu;
    use ironrdp_pdu::rdp::headers::{encode_share_data, ShareDataPdu};

    let mut buf = ironrdp_pdu::WriteBuf::new();
    match encode_share_data(
        user_channel_id,
        io_channel_id,
        share_id,
        ShareDataPdu::Input(InputEventPdu(events)),
        &mut buf,
    ) {
        Ok(_) => buf.into_inner(),
        Err(e) => {
            crate::logging::rdp_warn(&format!("не удалось собрать кадр ввода: {e}"));
            Vec::new()
        }
    }
}

/// Логин RDP из профиля; `None`, если он пуст или состоит из пробелов.
fn profile_username(profile: &Profile) -> Option<&str> {
    profile
        .username
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// Собирает итоговое сообщение об ошибке подключения из ошибок всех режимов
/// безопасности. Вынесено из `connect()`, чтобы проверять формулировки
/// unit-тестами без сетевого соединения.
///
/// `banner` — ответ порта, если это не RDP-сервер (неверный порт).
/// `nla` — включён ли NLA в профиле; `allow_legacy` — разрешён ли RC4.
fn connection_error_message(
    addr: &str,
    banner: Option<&str>,
    errors: &[String],
    allow_legacy: bool,
    nla: bool,
) -> String {
    // Самое важное — в начало: строка состояния показывает сообщение
    // обрезанным, и пользователь должен сразу увидеть причину.
    let mut message = String::new();
    if let Some(banner) = banner {
        message.push_str(&format!(
            "На порту {addr} отвечает «{banner}», а не RDP-сервер. \
             Проверьте порт (по умолчанию 3389) и адрес узла. "
        ));
    }

    let lower: Vec<String> = errors.iter().map(|e| e.to_lowercase()).collect();
    // Сервер явно требует NLA (CredSSP): откат на TLS/RC4 бессмысленен, а
    // подсказка про RC4 и «проверьте порт» только уводят в сторону.
    let requires_credssp = lower.iter().any(|e| {
        e.contains("requires enhanced rdp security with credssp")
            || e.contains("requires enhanced rdp security with tls or credssp")
    });
    let standard_security_error = lower.iter().any(|e| e.contains("standard rdp security"));

    // Настоящая причина отказа NLA — первая ошибка, не являющаяся требованием
    // CredSSP. Печатаем её один раз под «Причина:» и исключаем из хвоста,
    // иначе одна и та же причина повторялась дважды.
    let nla_cause = if requires_credssp && nla {
        errors
            .iter()
            .find(|e| !e.to_lowercase().contains("requires enhanced rdp security"))
    } else {
        None
    };

    if requires_credssp {
        if nla {
            message.push_str(
                "Сервер требует NLA (CredSSP), но подключиться с NLA не удалось. \
                 Проверьте логин/пароль и домен, а также что учётной записи разрешён \
                 вход по RDP. ",
            );
            if let Some(cause) = nla_cause {
                message.push_str(&format!("Причина: {cause} "));
            }
        } else {
            message.push_str(
                "Сервер требует NLA (CredSSP). Включите NLA в свойствах профиля \
                 и укажите логин/пароль. ",
            );
        }
    } else if standard_security_error && allow_legacy {
        message.push_str(
            "Сервер работает только со Standard RDP Security (шифр RC4), и подключиться \
             в этом режиме не удалось. Проверьте логин/пароль, а также настройки сервера: \
             в xrdp — security_layer=rdp и права пользователя; в Windows — «Уровень \
             безопасности: RDP» и членство в группе удалённых рабочих столов. ",
        );
    } else if !allow_legacy && standard_security_error {
        message.push_str(
            "Если сервер поддерживает только Standard RDP Security (устаревший RC4 \
             без TLS), включите в свойствах профиля «Разрешить незащищённый RDP (RC4)». \
             Этот режим не проверяет подлинность сервера — используйте его только \
             в доверенной сети. ",
        );
    }

    // Ошибки соединяем в одну строку: в строке состояния переносы растягивали
    // бы её на несколько строк. Одинаковые причины повторяются для каждого
    // режима безопасности — оставляем по одному разу. Причины, уже объяснённые
    // выше (требование NLA/RC4 и причина NLA), в хвосте не дублируем.
    let mut unique_errors: Vec<&str> = Vec::new();
    for error in errors {
        let error_lower = error.to_lowercase();
        if requires_credssp && error_lower.contains("requires enhanced rdp security") {
            continue;
        }
        if standard_security_error && error_lower.contains("standard rdp security") {
            continue;
        }
        if nla_cause == Some(error) {
            continue;
        }
        if !unique_errors
            .iter()
            .any(|seen| seen.eq_ignore_ascii_case(error))
        {
            unique_errors.push(error);
        }
    }

    if !unique_errors.is_empty() {
        if !message.is_empty() && !message.ends_with(' ') {
            message.push(' ');
        }
        let tail = unique_errors.join(" · ");
        message.push_str(&tail);
        if !tail.ends_with('.') {
            message.push('.');
        }
        message.push(' ');
    }

    if banner.is_none() && !requires_credssp && !standard_security_error {
        message.push_str("Проверьте адрес, порт (по умолчанию 3389) и доступность узла.");
    }

    message.trim_end().to_string()
}

/// Разрешение экрана RDP для коннектора.
///
/// `0x0` («разрешение не задано») превращаем в `1024x768`: 1x1 рендерить
/// нельзя, а серверу нужен конкретный размер.
fn effective_desktop_size(width: u32, height: u32) -> (u32, u32) {
    if width == 0 || height == 0 {
        (1024, 768)
    } else {
        (width, height)
    }
}

/// Режимы безопасности RDP в порядке попыток.
///
/// Standard RDP Security (RC4) попадает в список только при явном разрешении:
/// иначе даже последняя попытка остаётся с TLS/NLA.
fn security_modes(nla: bool, allow_legacy: bool) -> Vec<(bool, bool, bool)> {
    let mut modes = if nla {
        vec![
            // Обычный NLA: TLS + CredSSP.
            (true, true, false),
            // NLA без явного SSL — совместимость с серверами, которые
            // отвергают SSL в паре с HYBRID. Транспорт всё равно TLS.
            (true, false, false),
            // TLS без NLA: графический вход.
            (false, true, false),
        ]
    } else {
        // Если пользователь выключил NLA, CredSSP не пробуем вообще.
        vec![(false, true, false)]
    };
    if allow_legacy {
        modes.push((false, false, true));
    }
    modes
}

/// TCP-подключение с общим дедлайном на все адреса хоста.
///
/// `TcpStream::connect` использует системный тайм-аут: при выключенном хосте
/// это могут быть минуты. Здесь каждый адрес получает только оставшееся время.
fn tcp_connect(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = (host, port).to_socket_addrs()?;
    let deadline = Instant::now() + timeout;
    let mut last_error = None;

    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "истёк тайм-аут подключения")))
}

/// Разворачивает цепочку ошибок IronRDP в читаемый текст: помимо контекста
/// («read frame by hint») показывается и настоящая причина (например,
/// «not enough bytes» — сервер закрыл соединение).
fn describe_error(e: &ironrdp_connector::ConnectorError) -> String {
    use std::error::Error as _;

    let mut text = clean_error_part(&e.to_string());
    let mut source = e.source();
    while let Some(cause) = source {
        let part = clean_error_part(&cause.to_string());
        if !part.is_empty() && !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        source = cause.source();
    }
    text
}

/// Убирает из ошибки IronRDP отладочный префикс `[контекст @ файл:строка]`
/// и переводит служебные контексты на понятный язык. Пользователю нужна
/// причина, а не путь к исходнику в сборочном контейнере.
fn clean_error_part(part: &str) -> String {
    let (raw_context, kind) = match part
        .strip_prefix('[')
        .and_then(|rest| rest.split_once("] "))
    {
        Some((prefix, kind)) => (prefix.split(" @ ").next().unwrap_or(prefix), kind),
        None => ("", part),
    };

    let context = match raw_context.to_ascii_lowercase().as_str() {
        "write all" => "запись в RDP-соединение",
        "read frame by hint" => "чтение ответа RDP-сервера",
        "read pdu" => "чтение кадра RDP",
        "credssp" => "NLA (CredSSP)",
        "connection initiation" => "согласование RDP",
        "connect finalize" => "завершение RDP-подключения",
        _ => raw_context,
    };
    let kind = match kind {
        "custom error" => "",
        _ => kind,
    };
    let same = !kind.is_empty() && raw_context.eq_ignore_ascii_case(kind);

    let text = match (context, kind) {
        ("", "") => String::new(),
        ("", kind) => kind.to_string(),
        (context, "") => context.to_string(),
        (context, _) if same => context.to_string(),
        (context, kind) => format!("{context}: {kind}"),
    };
    if text.to_ascii_lowercase().contains("not enough bytes") {
        "сервер закрыл соединение до ответа".to_string()
    } else {
        text
    }
}

/// Сервер закрыл соединение: для пользователя это штатное завершение сессии,
/// а не ошибка декодирования (`not enough bytes` из Framed при EOF).
fn is_connection_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    ) || error
        .to_string()
        .to_ascii_lowercase()
        .contains("not enough bytes")
}

/// Достаёт открытый ключ сервера из его TLS-сертификата для CredSSP.
///
/// NLA подписывает `pubKeyAuth` хэшем открытого ключа сервера. Пустой ключ
/// даёт неверную подпись — сервер разрывает соединение (обычно `os error 104`)
/// сразу после проверки учётных данных.
fn extract_tls_server_public_key(
    certs: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> Result<Vec<u8>, String> {
    use x509_cert::der::Decode as _;

    let der = certs
        .and_then(|chain| chain.first())
        .ok_or_else(|| "сервер не прислал TLS-сертификат".to_string())?;
    let cert = x509_cert::Certificate::from_der(der.as_ref())
        .map_err(|e| format!("не удалось разобрать TLS-сертификат: {e}"))?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| "открытый ключ TLS-сертификата не выровнен по байтам".to_string())?
        .to_vec();
    if key.is_empty() {
        return Err("пустой открытый ключ в TLS-сертификате".to_string());
    }
    Ok(key)
}

impl RdpConnection {
    /// Подключение к RDP-серверу в выбранном режиме безопасности.
    ///
    /// `credssp = true` — NLA (CredSSP), `false` — без NLA.
    /// `tls = true` — дополнительно предлагать серверу PROTOCOL_SSL.
    /// `legacy = true` — Standard RDP Security (PROTOCOL_RDP, RC4, без TLS).
    fn connect_with(&mut self, credssp: bool, tls: bool, legacy: bool) -> Result<(), String> {
        let opts = &self.profile.rdp_options;

        // 1. TCP-подключение к RDP-серверу. connect_timeout не даёт окну
        //    висеть на системном тайм-ауте, если хост выключен или молчит.
        let addr = format!("{}:{}", self.profile.host, self.profile.port);
        let tcp_stream = tcp_connect(&self.profile.host, self.profile.port, RDP_CONNECT_TIMEOUT)
            .map_err(|e| format!("не удалось подключиться к {addr}: {e}"))?;
        tcp_stream
            .set_read_timeout(Some(RDP_IO_TIMEOUT))
            .map_err(|e| format!("не удалось задать тайм-аут чтения: {e}"))?;
        tcp_stream
            .set_write_timeout(Some(RDP_IO_TIMEOUT))
            .map_err(|e| format!("не удалось задать тайм-аут записи: {e}"))?;

        let client_addr = tcp_stream
            .local_addr()
            .map_err(|e| format!("не удалось получить локальный адрес: {e}"))?;

        // 2. Оборачиваем TCP-стрим в blocking Framed
        let mut framed = ironrdp_blocking::Framed::new(tcp_stream);

        // 3. Формируем конфигурацию коннектора IronRDP
        let username = profile_username(&self.profile).ok_or("не указан логин")?;
        let password = self
            .profile
            .password
            .as_ref()
            .map(|p| p.expose_secret())
            .unwrap_or("");
        let domain = if opts.domain.is_empty() {
            None
        } else {
            Some(opts.domain.clone())
        };
        // 0x0 = «разрешение не задано» (быстрое подключение или старый
        // профиль). Раньше такое превращалось в 1x1 и рендер падал, теперь
        // используем разумное разрешение по умолчанию.
        let (width, height) = effective_desktop_size(opts.width, opts.height);

        let connector_config = ironrdp_connector::Config {
            desktop_size: ironrdp_connector::DesktopSize {
                width: width as u16,
                height: height as u16,
            },
            desktop_scale_factor: 0,
            enable_tls: tls,
            // NLA (CredSSP) — обязателен для современных серверов Windows.
            enable_credssp: credssp,
            credentials: ironrdp_connector::Credentials::UsernamePassword {
                username: username.to_string(),
                password: password.to_string(),
            },
            domain,
            client_build: 0,
            client_name: "remotix".to_string(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IbmEnhanced,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNIX,
            hardware_id: None,
            request_data: None,
            autologon: false,
            enable_audio_playback: false,
            performance_flags: ironrdp_pdu::rdp::client_info::PerformanceFlags::default(),
            license_cache: None,
            timezone_info: ironrdp_pdu::rdp::client_info::TimezoneInfo::default(),
            compression_type: None,
            enable_server_pointer: true,
            pointer_software_rendering: false,
            multitransport_flags: None,
            enable_standard_rdp_security: legacy,
        };

        // 4. Создаём коннектор IronRDP и регистрируем CLIPRDR до отправки
        //    GCC-блоков: сервер должен увидеть канал в Channel Definition.
        let mut connector = ironrdp_connector::ClientConnector::new(connector_config, client_addr);
        if self.clipboard.enabled {
            connector.attach_static_channel(CliprdrClient::new(self.clipboard));
        }

        // 5. Запускаем процедуру подключения (до TLS-апгрейда)
        let should_upgrade = ironrdp_blocking::connect_begin(&mut framed, &mut connector)
            .map_err(|e| format!("ошибка начала RDP-подключения: {}", describe_error(&e)))?;

        // 6. Апгрейд безопасности: либо Standard RDP Security (без TLS),
        //    либо TLS-рукопожатие поверх уже открытого TCP-соединения.
        let (tcp_stream, leftover_bytes) = framed.into_inner();

        let (mut framed, upgraded, server_public_key, nla_active) = if legacy {
            let stream = SessionStream::Plain(tcp_stream);
            let framed = ironrdp_blocking::Framed::new_with_leftover(stream, leftover_bytes);
            let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
            let nla_active = connector.should_perform_credssp();
            (framed, upgraded, Vec::new(), nla_active)
        } else {
            let (tls_stream, server_public_key) = {
                let mut config = rustls::client::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_no_client_auth();

                // Поддержка SSLKEYLOGFILE для отладки (Wireshark)
                config.key_log = Arc::new(rustls::KeyLogFile::new());
                // CredSSP не поддерживает TLS session resumption — отключаем
                config.resumption = rustls::client::Resumption::disabled();

                let config = Arc::new(config);

                let server_name =
                    rustls::pki_types::ServerName::try_from(self.profile.host.clone())
                        .map_err(|e| format!("некорректное имя сервера: {e}"))?;

                let client = rustls::ClientConnection::new(config, server_name)
                    .map_err(|e| format!("ошибка создания TLS-соединения: {e}"))?;

                // PrefixedStream — ВНУТРИ TLS: leftover-байты, прочитанные
                // вместе с X.224-ответом, должны пройти через TLS-движок.
                let stream = PrefixedStream::new(leftover_bytes.to_vec(), tcp_stream);
                let mut tls_stream = rustls::StreamOwned::new(client, stream);

                // Завершаем рукопожатие до connect_finalize: для NLA нужен
                // сертификат сервера, а ошибки TLS должны быть видны сразу.
                tls_stream
                    .conn
                    .complete_io(&mut tls_stream.sock)
                    .map_err(|e| format!("ошибка TLS-рукопожатия с {addr}: {e}"))?;

                let server_public_key = if credssp {
                    extract_tls_server_public_key(tls_stream.conn.peer_certificates())?
                } else {
                    Vec::new()
                };
                (tls_stream, server_public_key)
            };

            let framed = ironrdp_blocking::Framed::new(SessionStream::Tls(Box::new(tls_stream)));
            let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);
            // После mark_as_upgraded состояние коннектора уже отражает
            // фактический выбор сервера: Credssp только при HYBRID/HYBRID_EX.
            let nla_active = connector.should_perform_credssp();
            (framed, upgraded, server_public_key, nla_active)
        };

        // 9. Завершаем процедуру подключения (NLA — через RdpNetworkClient).
        let connection_result = ironrdp_blocking::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut RdpNetworkClient,
            ironrdp_connector::ServerName::from(self.profile.host.clone()),
            server_public_key,
            None, // kerberos_config
        )
        .map_err(|e| format!("ошибка завершения RDP-подключения: {}", describe_error(&e)))?;

        // 10. Фиксируем фактический протокол безопасности для индикатора:
        //     NLA только если коннектор реально прошёл CredSSP.
        self.security = if nla_active {
            RdpSecurity::Nla
        } else if legacy {
            RdpSecurity::Rc4
        } else {
            RdpSecurity::Tls
        };

        let desktop = connection_result.desktop_size;
        crate::logging::rdp_info(&format!(
            "RDP: подключено к {}:{}, безопасность {}, экран {}x{}",
            self.profile.host,
            self.profile.port,
            self.security.label(),
            desktop.width,
            desktop.height
        ));

        // 11. Сохраняем живой TLS-стрим и строим активную стадию (просмотр):
        //     рамки сервера будут декодироваться в изображение методом run().
        self.framed = Some(framed);
        self.setup_active_stage(connection_result);
        self.connected = true;
        Ok(())
    }
}

impl RdpConnection {
    /// Переводит сокет в неблокирующий режим.
    ///
    /// Нужен циклу просмотра: пока сервер не прислал кадр, приложение должно
    /// успевать обрабатывать клавиатуру и мышь.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), String> {
        let framed = self
            .framed
            .as_mut()
            .ok_or("RDP-сессия не инициализирована")?;
        let (stream, _) = framed.get_inner_mut();
        stream
            .set_nonblocking(nonblocking)
            .map_err(|e| format!("не удалось переключить сокет в неблокирующий режим: {e}"))
    }

    /// Размер текущего кадра (ширина, высота) в пикселях; `None`, если
    /// кадр ещё не получен.
    pub fn image_size(&self) -> Option<(u16, u16)> {
        self.image.as_ref().map(|i| (i.width(), i.height()))
    }

    /// Сырые пиксели текущего кадра в порядке RGBA32 (по одному байту на
    /// компонент, построчно сверху вниз). Пустой срез, если кадр не готов.
    pub fn image_pixels(&self) -> &[u8] {
        self.image.as_ref().map(|i| i.data()).unwrap_or(&[])
    }

    /// Отправляет готовую fast-path рамку в сокет, зашифровав её при
    /// необходимости (Standard RDP Security: ввод тоже идёт в RC4-потоке).
    fn write_input_frame(&mut self, frame: Vec<u8>) {
        if frame.is_empty() {
            return;
        }

        let frame = match self.stage.as_ref() {
            Some(stage) => match stage.secure_outgoing_frame(frame) {
                Ok(frame) => frame,
                Err(e) => {
                    crate::logging::rdp_warn(&format!("не удалось зашифровать кадр ввода: {e}"));
                    return;
                }
            },
            None => frame,
        };

        if queue_input(&mut self.outgoing, frame) {
            self.input_sent_at = Some(Instant::now());
        } else {
            crate::logging::rdp_warn("очередь ввода RDP переполнена — буфер сброшен");
        }
        self.flush_outgoing();
    }

    /// Отправляет готовые сообщения статического канала (CLIPRDR).
    ///
    /// `ActiveStage::process_svc_processor_messages` уже накладывает
    /// security-конверт, поэтому кадр кладётся в очередь как есть — повторно
    /// через `write_input_frame` его пропускать нельзя (RC4 зашифровал бы
    /// его дважды).
    fn send_svc_messages(&mut self, messages: Vec<SvcMessage>) {
        if messages.is_empty() {
            return;
        }
        let Some(stage) = self.stage.as_ref() else {
            return;
        };
        let frame = match stage
            .process_svc_processor_messages(SvcProcessorMessages::<CliprdrClient>::new(messages))
        {
            Ok(frame) => frame,
            Err(e) => {
                crate::logging::rdp_warn(&format!("CLIPRDR: не удалось отправить сообщение: {e}"));
                return;
            }
        };
        if !queue_input(&mut self.outgoing, frame) {
            crate::logging::rdp_warn("очередь CLIPRDR переполнена — сообщение сброшено");
        }
        self.flush_outgoing();
    }

    /// Дописывает накопленный ввод в сокет.
    ///
    /// Сокет неблокирующий: `WouldBlock` — не ошибка, а «попробуй позже»,
    /// поэтому остаток сохраняется и уходит на следующем шаге цикла.
    /// Раньше здесь стоял `let _ = framed.write_all(...)`, и кадры ввода
    /// молча терялись — мышь и клавиатура не доходили до сервера.
    fn flush_outgoing(&mut self) {
        let Self {
            framed, outgoing, ..
        } = self;
        let Some(framed) = framed.as_mut() else {
            return;
        };
        // Framed не реализует io::Write — пишем в нижележащий поток,
        // у которого Write есть и который учитывает частичную запись.
        let (stream, _) = framed.get_inner_mut();
        while !outgoing.is_empty() {
            match stream.write(outgoing) {
                Ok(0) => break,
                Ok(n) => {
                    outgoing.drain(..n);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    crate::logging::rdp_warn(&format!("не удалось отправить ввод RDP: {e}"));
                    outgoing.clear();
                    break;
                }
            }
        }
    }

    /// Отправить нажатие/отпускание клавиши (fast-path Keyboard-событие).
    /// `code` — сканкод клавиши; для раскладок, где сканкод определить не удалось,
    /// используется Unicode-событие.
    pub fn send_key(&mut self, key: RdpKey, pressed: bool) {
        use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent, KeyboardFlags};
        let mut flags = KeyboardFlags::empty();
        if !pressed {
            flags |= KeyboardFlags::RELEASE;
        }
        let event = match key {
            RdpKey::Scancode { code, extended } => {
                if extended {
                    flags |= KeyboardFlags::EXTENDED1;
                }
                FastPathInputEvent::KeyboardEvent(flags, code)
            }
            RdpKey::Char(c) => FastPathInputEvent::UnicodeKeyboardEvent(flags, c as u16),
        };
        let pdu = FastPathInput::single(event);
        self.write_input_frame(ironrdp_pdu::encode_vec(&pdu).unwrap_or_default());
    }

    /// Отправить в удалённую сессию последовательность `Ctrl+Alt+Del`.
    ///
    /// Сервер RDP отслеживает состояние модификаторов по самим событиям
    /// клавиатуры, поэтому достаточно послать нажатие Ctrl, Alt и Delete
    /// (с флагом «расширенная клавиша»).
    pub fn send_ctrl_alt_del(&mut self) {
        const CTRL: RdpKey = RdpKey::Scancode {
            code: 0x1d,
            extended: false,
        };
        const ALT: RdpKey = RdpKey::Scancode {
            code: 0x38,
            extended: false,
        };
        const DEL: RdpKey = RdpKey::Scancode {
            code: 0x53,
            extended: true,
        };

        self.send_key(CTRL, true);
        self.send_key(ALT, true);
        self.send_key(DEL, true);
        self.send_key(DEL, false);
        self.send_key(ALT, false);
        self.send_key(CTRL, false);
    }

    /// Отправить движение/клик мыши (slow-path `TS_INPUT_PDU`).
    ///
    /// `buttons` — маска [`MOUSE_LEFT`]/[`MOUSE_RIGHT`]/[`MOUSE_MIDDLE`].
    /// При отпускании кнопки маска должна содержать отпускаемую кнопку, а
    /// `event` — быть [`MouseEvent::ButtonUp`]: RDP узнаёт отпускание по
    /// отсутствию флага DOWN у события с флагом кнопки.
    pub fn send_mouse(&mut self, x: u32, y: u32, buttons: u8, event: MouseEvent) {
        let flags = Self::mouse_flags(buttons, event);
        let pdu = ironrdp_pdu::input::MousePdu {
            flags,
            number_of_wheel_rotation_units: 0,
            x_position: x.clamp(0, u32::from(u16::MAX)) as u16,
            y_position: y.clamp(0, u32::from(u16::MAX)) as u16,
        };
        // Медленный путь: в fast-path событии Mouse флаги указателя лежат
        // в 5-битном eventFlags заголовка (MS-RDPBCGR 2.2.8.1.2.2.3) и не
        // выражают DOWN/BUTTON2/BUTTON3, а IronRDP кладёт туда тело slow-path
        // PDU — сервер видел eventFlags=0 и игнорировал событие. TS_INPUT_PDU
        // несёт полные 16-битные pointerFlags, поэтому клики, drag и колесо
        // кодируются верно.
        let frame = slow_path_input_frame(
            self.io_channel_id,
            self.user_channel_id,
            self.share_id,
            vec![ironrdp_pdu::input::InputEvent::Mouse(pdu)],
        );
        self.write_input_frame(frame);
    }

    /// Флаги fast-path mouse для маски кнопок и действия.
    ///
    /// Вынесено отдельно, чтобы проверять кодирование в unit-тестах без
    /// сетевого соединения.
    fn mouse_flags(buttons: u8, event: MouseEvent) -> ironrdp_pdu::input::mouse::PointerFlags {
        use ironrdp_pdu::input::mouse::PointerFlags;

        // MS-RDPBCGR 2.2.8.1.1.3.1.1.1: PTRFLAGS_MOVE означает «указатель
        // перемещён». Если флаг выставлен, сервер трактует событие как
        // перемещение и ИГНОРИРУЕТ нажатие/отпускание кнопки. Поэтому MOVE
        // ставится только для движения (в т.ч. drag — движение с зажатой
        // кнопкой), а для ButtonDown/ButtonUp его быть не должно.
        let mut flags = match event {
            MouseEvent::Move => PointerFlags::MOVE,
            MouseEvent::ButtonDown => PointerFlags::DOWN,
            MouseEvent::ButtonUp => PointerFlags::empty(),
        };
        if buttons & MOUSE_LEFT != 0 {
            flags |= PointerFlags::LEFT_BUTTON;
        }
        if buttons & MOUSE_RIGHT != 0 {
            flags |= PointerFlags::RIGHT_BUTTON;
        }
        if buttons & MOUSE_MIDDLE != 0 {
            flags |= PointerFlags::MIDDLE_BUTTON_OR_WHEEL;
        }
        flags
    }

    /// Отправить колесо мыши (slow-path Mouse-событие с вертикальным колесом).
    /// `delta` — условные единицы прокрутки (положительные — вверх).
    pub fn send_wheel(&mut self, x: u32, y: u32, delta: i32) {
        // WheelRotationMask — 9-битное число в дополнительном коде, диапазон
        // [-256, 255]. Знак и величину кодирует сам MousePdu::encode; вручную
        // выставлять WHEEL_NEGATIVE при положительной величине нельзя — сервер
        // прочитает такое как -136 вместо -120.
        let units = delta.clamp(-256, 255) as i16;
        let pdu = ironrdp_pdu::input::MousePdu {
            flags: ironrdp_pdu::input::mouse::PointerFlags::VERTICAL_WHEEL,
            number_of_wheel_rotation_units: units,
            x_position: x.clamp(0, u32::from(u16::MAX)) as u16,
            y_position: y.clamp(0, u32::from(u16::MAX)) as u16,
        };
        // Медленный путь: в fast-path событии Mouse флаги указателя лежат
        // в 5-битном eventFlags заголовка (MS-RDPBCGR 2.2.8.1.2.2.3) и не
        // выражают DOWN/BUTTON2/BUTTON3, а IronRDP кладёт туда тело slow-path
        // PDU — сервер видел eventFlags=0 и игнорировал событие. TS_INPUT_PDU
        // несёт полные 16-битные pointerFlags, поэтому клики, drag и колесо
        // кодируются верно.
        let frame = slow_path_input_frame(
            self.io_channel_id,
            self.user_channel_id,
            self.share_id,
            vec![ironrdp_pdu::input::InputEvent::Mouse(pdu)],
        );
        self.write_input_frame(frame);
    }

    /// Загрузить текст в удалённый буфер обмена (уходит на сервер RDP).
    ///
    /// Содержимое не логируется: CLIPRDR пишет только направление, формат и
    /// размер. Если канал ещё не получил Monitor Ready, текст сохраняется в
    /// клиенте и будет объявлен сразу после готовности канала.
    pub fn set_clipboard(&mut self, text: &str) {
        if !self.clipboard.enabled || !self.clipboard.to_remote {
            return;
        }
        let messages = match self.stage.as_mut() {
            Some(stage) => match stage.get_svc_processor_mut::<CliprdrClient>() {
                Some(client) => client.set_local_text(Some(text.to_string())),
                None => {
                    crate::logging::rdp_warn("CLIPRDR: канал не зарегистрирован в сессии");
                    return;
                }
            },
            None => return,
        };
        self.send_svc_messages(messages);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::{RdpOptions, SshOptions, VncOptions};
    use crate::models::Protocol;
    use secrecy::SecretString;
    use std::time::Duration;

    /// Профиль для тестового RDP-сервера.
    fn test_profile() -> Profile {
        Profile {
            id: 0,
            name: "rdp-test".to_string(),
            protocol: Protocol::Rdp,
            host: "127.0.0.1".to_string(),
            port: 3389,
            username: Some("tester".to_string()),
            password: Some(SecretString::from("secret".to_string())),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            root_password: None,
            group_id: None,
            bastion_profile_id: None,
            tags: vec![],
            icon: None,
            notes: None,
            mac_address: None,
            rdp_options: RdpOptions {
                width: 1024,
                height: 768,
                ..Default::default()
            },
            vnc_options: VncOptions::default(),
            ssh_options: SshOptions::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        }
    }

    #[test]
    fn zero_resolution_uses_sensible_default() {
        assert_eq!(effective_desktop_size(0, 0), (1024, 768));
        assert_eq!(effective_desktop_size(1920, 1080), (1920, 1080));
        assert_eq!(effective_desktop_size(1280, 0), (1024, 768));
    }

    #[test]
    fn blank_username_is_rejected_before_connecting() {
        let mut profile = test_profile();
        assert_eq!(profile_username(&profile), Some("tester"));

        profile.username = Some("  tester  ".to_string());
        assert_eq!(profile_username(&profile), Some("tester"));

        profile.username = None;
        assert_eq!(profile_username(&profile), None);

        profile.username = Some("   ".to_string());
        assert_eq!(profile_username(&profile), None, "пробелы — не логин");
    }

    #[test]
    fn mouse_release_has_button_without_down_flag() {
        use ironrdp_pdu::input::mouse::PointerFlags;

        let press = RdpConnection::mouse_flags(MOUSE_LEFT, MouseEvent::ButtonDown);
        assert!(press.contains(PointerFlags::LEFT_BUTTON));
        assert!(press.contains(PointerFlags::DOWN));
        assert!(
            !press.contains(PointerFlags::MOVE),
            "нажатие кнопки — не перемещение"
        );

        let release = RdpConnection::mouse_flags(MOUSE_LEFT, MouseEvent::ButtonUp);
        assert!(release.contains(PointerFlags::LEFT_BUTTON));
        assert!(!release.contains(PointerFlags::DOWN));
        assert!(
            !release.contains(PointerFlags::MOVE),
            "отпускание кнопки — не перемещение"
        );

        // Перетаскивание: движение с зажатой кнопкой должно нести её флаг.
        let drag = RdpConnection::mouse_flags(MOUSE_LEFT, MouseEvent::Move);
        assert!(drag.contains(PointerFlags::LEFT_BUTTON));
        assert!(!drag.contains(PointerFlags::DOWN));
        assert!(drag.contains(PointerFlags::MOVE), "drag — это перемещение");
    }

    #[test]
    fn mouse_button_bits_are_rdp_order_not_gdk_order() {
        use ironrdp_pdu::input::mouse::PointerFlags;

        let middle = RdpConnection::mouse_flags(MOUSE_MIDDLE, MouseEvent::ButtonDown);
        assert!(middle.contains(PointerFlags::MIDDLE_BUTTON_OR_WHEEL));
        assert!(!middle.contains(PointerFlags::RIGHT_BUTTON));

        let right = RdpConnection::mouse_flags(MOUSE_RIGHT, MouseEvent::ButtonDown);
        assert!(right.contains(PointerFlags::RIGHT_BUTTON));
        assert!(!right.contains(PointerFlags::MIDDLE_BUTTON_OR_WHEEL));
    }

    #[test]
    fn legacy_security_requires_explicit_opt_in() {
        for nla in [true, false] {
            let modes = security_modes(nla, false);
            assert!(
                modes.iter().all(|(_, _, legacy)| !legacy),
                "RC4 не должен включаться без разрешения (NLA={nla})"
            );

            let modes = security_modes(nla, true);
            assert!(
                modes.contains(&(false, false, true)),
                "с разрешением должен быть режим Standard RDP Security"
            );
        }
    }

    /// Проверяет подключение к RDP-серверу и получение кадра рабочего стола.
    ///
    /// Требует запущенного RDP-сервера на `127.0.0.1:3389` (в CI это
    /// контейнер с `xrdp`). Если сервера нет — тест пропускается.
    #[test]
    fn connects_and_receives_frame() {
        if TcpStream::connect("127.0.0.1:3389").is_err() {
            eprintln!("RDP-сервер на 127.0.0.1:3389 недоступен — тест пропущен");
            return;
        }

        let mut conn = RdpConnection::new(test_profile());
        if let Err(e) = conn.connect() {
            panic!("подключение к RDP-серверу не удалось: {e}");
        }
        // Неблокирующий режим: иначе ожидание кадра блокировало бы тест.
        conn.set_nonblocking(true)
            .expect("неблокирующий режим сокета");

        // Ждём первый кадр рабочего стола.
        let mut got_frame = false;
        for _ in 0..100 {
            match conn.run() {
                Ok(true) => {
                    got_frame = true;
                    break;
                }
                Ok(false) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("ошибка обработки кадра: {e}"),
            }
        }

        let size = conn
            .image_size()
            .expect("размер кадра должен быть известен");
        assert!(
            size.0 > 0 && size.1 > 0,
            "некорректный размер кадра: {size:?}"
        );
        assert!(!conn.image_pixels().is_empty(), "кадр пустой");
        assert!(got_frame, "кадр не получен");

        // Обратное направление: проверяем, что slow-path ввод мыши
        // (Share Control + Share Data) не разрывает сессию.
        conn.send_mouse(10, 10, 0, MouseEvent::Move);
        conn.send_mouse(10, 10, MOUSE_LEFT, MouseEvent::ButtonDown);
        conn.send_mouse(10, 10, MOUSE_LEFT, MouseEvent::ButtonUp);
        for _ in 0..20 {
            match conn.run() {
                Ok(_) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => panic!("сессия разорвана после отправки ввода: {e}"),
            }
        }
    }

    /// Проверяет Standard RDP Security (RC4) и license exchange без
    /// сертификата в `SERVER_LICENSE_REQUEST` — путь xrdp с
    /// `security_layer=rdp`.
    ///
    /// Запускать вручную против такого сервера:
    /// `cargo test connects_with_standard_rdp_security -- --ignored`.
    #[test]
    #[ignore = "требует xrdp с security_layer=rdp на 127.0.0.1:3389"]
    fn connects_with_standard_rdp_security() {
        if TcpStream::connect("127.0.0.1:3389").is_err() {
            eprintln!("RDP-сервер на 127.0.0.1:3389 недоступен — тест пропущен");
            return;
        }

        let mut conn = RdpConnection::new(test_profile());
        conn.connect_with(false, false, true)
            .expect("подключение через Standard RDP Security");
        conn.set_nonblocking(true)
            .expect("неблокирующий режим сокета");

        let mut got_frame = false;
        for _ in 0..100 {
            match conn.run() {
                Ok(true) => {
                    got_frame = true;
                    break;
                }
                Ok(false) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => panic!("ошибка обработки кадра: {e}"),
            }
        }

        assert!(got_frame, "кадр не получен через Standard RDP Security");
        let size = conn
            .image_size()
            .expect("размер кадра должен быть известен");
        assert!(
            size.0 > 0 && size.1 > 0,
            "некорректный размер кадра: {size:?}"
        );
    }

    #[test]
    fn plain_move_has_no_button_flags() {
        use ironrdp_pdu::input::mouse::PointerFlags;
        let mv = RdpConnection::mouse_flags(0, MouseEvent::Move);
        assert!(mv.contains(PointerFlags::MOVE));
        assert!(!mv.contains(PointerFlags::DOWN));
        assert!(!mv.contains(PointerFlags::LEFT_BUTTON));
        assert!(!mv.contains(PointerFlags::RIGHT_BUTTON));
        assert!(!mv.contains(PointerFlags::MIDDLE_BUTTON_OR_WHEEL));
    }

    #[test]
    fn button_events_never_carry_move_flag() {
        use ironrdp_pdu::input::mouse::PointerFlags;
        for (bit, flag) in [
            (MOUSE_LEFT, PointerFlags::LEFT_BUTTON),
            (MOUSE_RIGHT, PointerFlags::RIGHT_BUTTON),
            (MOUSE_MIDDLE, PointerFlags::MIDDLE_BUTTON_OR_WHEEL),
        ] {
            let down = RdpConnection::mouse_flags(bit, MouseEvent::ButtonDown);
            assert!(down.contains(flag));
            assert!(down.contains(PointerFlags::DOWN));
            assert!(
                !down.contains(PointerFlags::MOVE),
                "клик с MOVE сервер игнорирует"
            );

            let up = RdpConnection::mouse_flags(bit, MouseEvent::ButtonUp);
            assert!(up.contains(flag));
            assert!(!up.contains(PointerFlags::DOWN));
            assert!(!up.contains(PointerFlags::MOVE));
        }
    }

    #[test]
    fn credssp_required_with_nla_points_to_credentials_not_rc4() {
        let errors = vec![
            "ошибка завершения RDP-подключения: Соединение разорвано другой стороной (os error 104)"
                .to_string(),
            "ошибка начала RDP-подключения: negotiation failure: server requires Enhanced RDP Security with CredSSP"
                .to_string(),
        ];
        let msg = connection_error_message("host:3389", None, &errors, false, true);
        assert!(msg.contains("требует NLA"), "должно сказать про NLA: {msg}");
        assert!(
            msg.contains("логин/пароль"),
            "должно указать на учётные данные: {msg}"
        );
        assert!(
            msg.contains("os error 104"),
            "нужна настоящая причина отказа NLA: {msg}"
        );
        assert!(
            !msg.contains("RC4"),
            "подсказка про RC4 здесь вредна: {msg}"
        );
        assert!(
            !msg.contains("Проверьте порт"),
            "порт в порядке — сервер требует NLA: {msg}"
        );
    }

    #[test]
    fn credssp_required_without_nla_suggests_enabling_it() {
        let errors = vec![
            "negotiation failure: server requires Enhanced RDP Security with CredSSP".to_string(),
        ];
        let msg = connection_error_message("host:3389", None, &errors, false, false);
        assert!(
            msg.contains("Включите NLA"),
            "NLA выключен — предложить включить: {msg}"
        );
        assert!(!msg.contains("RC4"), "подсказка про RC4 неуместна: {msg}");
    }

    #[test]
    fn standard_security_error_suggests_rc4_when_not_allowed() {
        let errors =
            vec!["negotiation failure: server only supports Standard RDP Security".to_string()];
        let msg = connection_error_message("host:3389", None, &errors, false, true);
        assert!(
            msg.contains("RC4"),
            "для Standard RDP Security нужна подсказка про RC4: {msg}"
        );
        assert!(!msg.contains("требует NLA"), "это не случай NLA: {msg}");
    }

    #[test]
    fn standard_security_with_legacy_allowed_gives_server_hints() {
        let errors = vec!["server only supports Standard RDP Security".to_string()];
        let msg = connection_error_message("host:3389", None, &errors, true, true);
        assert!(
            msg.contains("security_layer=rdp"),
            "нужны подсказки по настройке сервера: {msg}"
        );
    }

    #[test]
    fn wrong_port_banner_is_reported_first() {
        let errors = vec!["не удалось подключиться".to_string()];
        let msg =
            connection_error_message("host:22", Some("SSH-2.0-OpenSSH_8.0"), &errors, false, true);
        assert!(
            msg.contains("не RDP-сервер"),
            "баннер чужого протокола — в начало: {msg}"
        );
        assert!(msg.contains("SSH-2.0-OpenSSH_8.0"));
    }

    #[test]
    fn duplicate_mode_errors_are_joined_once() {
        let e = "Соединение разорвано другой стороной (os error 104)".to_string();
        let msg = connection_error_message("host:3389", None, &[e.clone(), e], false, true);
        assert_eq!(
            msg.matches("os error 104").count(),
            1,
            "одинаковые ошибки — один раз: {msg}"
        );
    }

    #[test]
    fn input_queue_accumulates_and_overflows_safely() {
        let mut q = Vec::new();
        assert!(queue_input(&mut q, vec![1, 2, 3]));
        assert!(queue_input(&mut q, vec![4]));
        assert_eq!(q, vec![1, 2, 3, 4]);
        assert!(
            queue_input(&mut q, Vec::new()),
            "пустой кадр не меняет очередь"
        );
        assert_eq!(q.len(), 4);
        assert!(!queue_input(&mut q, vec![0u8; MAX_PENDING_INPUT + 1]));
        assert!(q.is_empty(), "после переполнения буфер сброшен");
    }

    #[test]
    fn input_queue_accepts_exact_limit() {
        let mut q = vec![0u8; 10];
        assert!(queue_input(&mut q, vec![0u8; MAX_PENDING_INPUT - 10]));
        assert_eq!(q.len(), MAX_PENDING_INPUT);
    }

    /// Разбирает slow-path кадр до `TS_INPUT_PDU_DATA`, проверяя обёртку
    /// Share Control + Share Data. Возвращает `(share_id, pdu_source, events)`.
    fn decode_slow_path_input(frame: &[u8]) -> (u32, u16, ironrdp_pdu::input::InputEventPdu) {
        use ironrdp_pdu::mcs::McsMessage;
        use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu, ShareDataPdu};
        use ironrdp_pdu::x224::X224;

        let X224(McsMessage::SendDataRequest(req)) =
            ironrdp_pdu::decode::<X224<McsMessage<'_>>>(frame).expect("не SendDataRequest")
        else {
            panic!("ожидался MCS SendDataRequest");
        };
        let control: ShareControlHeader =
            ironrdp_pdu::decode(req.user_data.as_ref()).expect("нет Share Control Header");
        let share_id = control.share_id;
        let pdu_source = control.pdu_source;
        let ShareControlPdu::Data(data) = control.share_control_pdu else {
            panic!("ожидался Share Data PDU");
        };
        let ShareDataPdu::Input(events) = data.share_data_pdu else {
            panic!("ожидался Input PDU");
        };
        (share_id, pdu_source, events)
    }

    /// Кадр мыши — медленный путь: MCS + Share Control Header + Share Data
    /// Header (`PDUTYPE2_INPUT`) + TS_INPUT_PDU с полными pointerFlags.
    #[test]
    fn mouse_frame_has_share_data_header_and_full_pointer_flags() {
        use ironrdp_pdu::input::mouse::PointerFlags;
        use ironrdp_pdu::input::InputEvent;

        let pdu = ironrdp_pdu::input::MousePdu {
            flags: PointerFlags::LEFT_BUTTON | PointerFlags::DOWN,
            number_of_wheel_rotation_units: 0,
            x_position: 0x1234,
            y_position: 0x0abc,
        };
        let frame = slow_path_input_frame(1003, 1002, 0x1020_3040, vec![InputEvent::Mouse(pdu)]);
        assert!(frame.len() > 20, "кадр слишком короткий: {}", frame.len());
        assert_eq!(&frame[..2], &[0x03, 0x00], "TPKT");
        let len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
        assert_eq!(len, frame.len(), "длина TPKT совпадает с кадром");

        let (share_id, pdu_source, events) = decode_slow_path_input(&frame);
        assert_eq!(share_id, 0x1020_3040, "shareId должен попасть в заголовок");
        assert_eq!(pdu_source, 1002, "pdu_source — пользовательский канал");
        assert_eq!(
            events.0.len(),
            1,
            "сервер должен увидеть ровно одно событие"
        );
        match &events.0[0] {
            InputEvent::Mouse(m) => {
                assert_eq!((m.x_position, m.y_position), (0x1234, 0x0abc));
                assert_eq!(m.flags, PointerFlags::LEFT_BUTTON | PointerFlags::DOWN);
                assert_eq!(m.number_of_wheel_rotation_units, 0);
            }
            other => panic!("ожидалось событие мыши, получено {other:?}"),
        }
    }

    #[test]
    fn mouse_frame_encodes_wheel_rotation() {
        use ironrdp_pdu::input::mouse::PointerFlags;
        use ironrdp_pdu::input::InputEvent;

        for delta in [120i16, -120i16] {
            let pdu = ironrdp_pdu::input::MousePdu {
                flags: PointerFlags::VERTICAL_WHEEL,
                number_of_wheel_rotation_units: delta,
                x_position: 1,
                y_position: 2,
            };
            let frame =
                slow_path_input_frame(1003, 1002, 0x1020_3040, vec![InputEvent::Mouse(pdu)]);
            let (_, _, events) = decode_slow_path_input(&frame);
            match &events.0[0] {
                InputEvent::Mouse(m) => {
                    assert!(
                        m.flags.contains(PointerFlags::VERTICAL_WHEEL),
                        "потерян флаг колеса для {delta}"
                    );
                    assert_eq!(
                        m.number_of_wheel_rotation_units, delta,
                        "вращение {delta} не пережило кодирование"
                    );
                    assert_eq!(
                        m.flags.contains(PointerFlags::WHEEL_NEGATIVE),
                        delta < 0,
                        "знак колеса для {delta}"
                    );
                }
                other => panic!("ожидалось событие мыши, получено {other:?}"),
            }
        }
    }

    /// Регрессия 1.9.1: в MCS user_data не должно быть лишнего
    /// `TS_SECURITY_HEADER` — первым идёт Share Control Header.
    ///
    /// Разбираем кадр по структуре: при лишних 4 байтах заголовка сервер
    /// прочитает их как `shareId` и не увидит событие ввода.
    #[test]
    fn mouse_frame_starts_with_share_control_header() {
        use ironrdp_pdu::input::mouse::PointerFlags;
        use ironrdp_pdu::input::InputEvent;
        use ironrdp_pdu::mcs::McsMessage;
        use ironrdp_pdu::x224::X224;

        let pdu = ironrdp_pdu::input::MousePdu {
            flags: PointerFlags::MOVE,
            number_of_wheel_rotation_units: 0,
            x_position: 640,
            y_position: 480,
        };
        let frame = slow_path_input_frame(1003, 1002, 0x1020_3040, vec![InputEvent::Mouse(pdu)]);

        let X224(McsMessage::SendDataRequest(req)) =
            ironrdp_pdu::decode::<X224<McsMessage<'_>>>(&frame).expect("не SendDataRequest")
        else {
            panic!("ожидался MCS SendDataRequest");
        };
        assert_eq!(req.channel_id, 1003, "ввод должен идти в I/O-канал");
        let (_, _, events) = decode_slow_path_input(&frame);
        assert_eq!(events.0.len(), 1);
    }

    #[test]
    fn send_wheel_round_trips_negative_rotation() {
        use ironrdp_pdu::input::mouse::PointerFlags;
        use ironrdp_pdu::input::InputEvent;

        for delta in [120, -120] {
            let mut conn = RdpConnection::new(test_profile());
            conn.io_channel_id = 1003;
            conn.user_channel_id = 1002;
            conn.share_id = 0x1020_3040;
            conn.send_wheel(10, 20, delta);
            let (_, _, events) = decode_slow_path_input(&conn.outgoing);
            match &events.0[0] {
                InputEvent::Mouse(m) => {
                    assert_eq!(m.number_of_wheel_rotation_units, delta as i16);
                    assert_eq!(
                        m.flags.contains(PointerFlags::WHEEL_NEGATIVE),
                        delta < 0,
                        "знак колеса для {delta}"
                    );
                    assert_eq!((m.x_position, m.y_position), (10, 20));
                }
                other => panic!("ожидалось событие мыши, получено {other:?}"),
            }
        }
    }

    #[test]
    fn extracts_server_public_key_from_tls_certificate() {
        use x509_cert::der::Decode as _;

        let der = include_bytes!("../../tests/fixtures/rsa2048-crt.der");
        let cert = x509_cert::Certificate::from_der(&der[..]).expect("сертификат");
        let expected = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .expect("BIT STRING")
            .to_vec();

        let cert_der = rustls::pki_types::CertificateDer::from(der.to_vec());
        let chain = [cert_der];
        let key = extract_tls_server_public_key(Some(&chain)).expect("ключ сервера");
        assert!(!key.is_empty());
        assert_eq!(key, expected);
        assert_eq!(key[0], 0x30, "ожидался DER PKCS#1 RSAPublicKey");
    }

    #[test]
    fn missing_tls_certificate_is_reported() {
        let err = extract_tls_server_public_key(None).expect_err("без цепочки — ошибка");
        assert!(err.contains("сертификат"), "{err}");
    }

    #[test]
    fn connection_closed_errors_are_classified() {
        assert!(is_connection_closed(&io::Error::from(
            io::ErrorKind::UnexpectedEof
        )));
        assert!(is_connection_closed(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
        assert!(is_connection_closed(&io::Error::new(
            io::ErrorKind::InvalidData,
            "not enough bytes"
        )));
        assert!(!is_connection_closed(&io::Error::new(
            io::ErrorKind::InvalidData,
            "bad pdu"
        )));
    }

    #[test]
    fn debug_location_is_stripped_from_error() {
        assert_eq!(
            clean_error_part("[write all @ /build/connector.rs:162] custom error"),
            "запись в RDP-соединение"
        );
        assert_eq!(
            clean_error_part("[CredSSP @ /build/connector.rs:90] CredSSP"),
            "NLA (CredSSP)"
        );
        assert_eq!(
            clean_error_part("[read frame by hint @ /build/framed.rs:42] custom error"),
            "чтение ответа RDP-сервера"
        );
        assert_eq!(
            clean_error_part("not enough bytes"),
            "сервер закрыл соединение до ответа"
        );
    }

    #[test]
    fn nla_cause_is_printed_once() {
        let cause = "ошибка завершения RDP-подключения: запись в RDP-соединение: \
                     Соединение разорвано другой стороной (os error 104)"
            .to_string();
        let errors = vec![
            cause.clone(),
            cause,
            "ошибка начала RDP-подключения: negotiation failure: server requires \
             Enhanced RDP Security with CredSSP"
                .to_string(),
        ];
        let msg = connection_error_message("host:3389", None, &errors, false, true);
        assert_eq!(msg.matches("os error 104").count(), 1, "{msg}");
        assert_eq!(msg.matches("Причина:").count(), 1, "{msg}");
        assert_eq!(msg.matches("требует NLA").count(), 1, "{msg}");
    }

    #[test]
    fn connection_refused_hint_is_printed_once() {
        let error =
            "не удалось подключиться к host:3389: В соединении отказано (os error 111)".to_string();
        let msg = connection_error_message("host:3389", None, &[error.clone(), error], false, true);
        assert_eq!(msg.matches("os error 111").count(), 1, "{msg}");
        assert_eq!(
            msg.matches("Проверьте адрес, порт").count(),
            1,
            "подсказка про порт не должна дублироваться: {msg}"
        );
    }

    #[test]
    fn kdc_http_request_puts_token_in_body() {
        let data = b"\x01\x02\x03";
        let request = build_kdc_http_request("dc.example.com", 443, "/KdcProxy", data);
        let text = String::from_utf8_lossy(&request);
        assert!(
            text.starts_with("POST /KdcProxy HTTP/1.1\r\n"),
            "неверный request-target: {text}"
        );
        assert!(
            text.contains("Content-Length: 3\r\n"),
            "нет длины тела: {text}"
        );
        assert!(
            !text.contains("Authorization:"),
            "KDC-прокси не использует Negotiate: {text}"
        );
        assert!(
            request.ends_with(&data[..]),
            "KDC-сообщение должно быть в теле запроса"
        );
    }

    #[test]
    fn kdc_http_response_parses_body_and_status() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n\x01\x02\x03";
        assert_eq!(
            parse_kdc_http_response(ok).expect("ответ 200"),
            vec![1, 2, 3]
        );

        let short = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nabc";
        assert_eq!(
            parse_kdc_http_response(short).expect("Content-Length"),
            b"ab".to_vec()
        );

        let unauthorized = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
        let err = parse_kdc_http_response(unauthorized).expect_err("401 — ошибка");
        assert!(err.contains("401"), "{err}");
    }
}
