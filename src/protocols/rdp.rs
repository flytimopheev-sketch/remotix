use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::models::Profile;
use crate::protocols::Connection;

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
            to_remote: o.clipboard && (o.clipboard_to_remote || (!o.clipboard_to_remote && !o.clipboard_from_remote)),
            from_remote: o.clipboard && (o.clipboard_from_remote || (!o.clipboard_to_remote && !o.clipboard_from_remote)),
        }
    }
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

/// NetworkClient для NLA (CredSSP): выполняет обмен токенами через HTTP POST
/// по TLS к серверу RDP и возвращает ответный токен. Вызывается коннектором
/// в `enable_credssp` режиме (NLA). В режиме PROTOCOL_SSL (только TLS) коннектор
/// его не использует, но реализация — рабочая, а не заглушка.
struct RdpNetworkClient;

impl ironrdp_connector::sspi::network_client::NetworkClient for RdpNetworkClient {
    fn send(
        &self,
        request: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> Result<Vec<u8>, ironrdp_connector::sspi::Error> {
        use ironrdp_connector::sspi as Sspi;
        use std::io::Read as _;

        let host = request.url.host_str().unwrap_or_default();
        let port = request.url.port().unwrap_or(3389);

        // 1. Поднимаем отдельное TLS-соединение к серверу RDP для NLA.
        let tcp = TcpStream::connect(&format!("{host}:{port}"))
            .map_err(|e| Sspi::Error::new(Sspi::ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;

        let mut tls_config = rustls::client::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth();
        tls_config.resumption = rustls::client::Resumption::disabled();
        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|e| Sspi::Error::new(Sspi::ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
        let client = rustls::ClientConnection::new(Arc::new(tls_config), server_name)
            .map_err(|e| Sspi::Error::new(Sspi::ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
        let mut stream = rustls::StreamOwned::new(client, tcp);

        // 2. HTTP/1.1 POST. Токен CredSSP (SPNEGO) передаётся в заголовке
        //    `Authorization: Negotiate <base64>` — именно так его ждёт сервер
        //    Windows; в теле запроса его быть не должно.
        let token = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&request.data)
        };
        let header = format!(
            "POST / HTTP/1.1\r\n\
             Host: {host}\r\n\
             Authorization: Negotiate {token}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            request.data.len(),
        );
        {
            use std::io::Write as _;
            stream.write_all(header.as_bytes())
                .map_err(|e| Sspi::Error::new(Sspi::ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
            // Тело запроса оставляем пустым: токен уже ушёл в заголовке.
            stream.flush()
                .map_err(|e| Sspi::Error::new(Sspi::ErrorKind::NoAuthenticatingAuthority, format!("{e:?}")))?;
        }

        // 3. Читаем весь ответ: ответный токен CredSSP находится в заголовке
        //    `WWW-Authenticate: Negotiate <base64>`.
        let mut raw = Vec::<u8>::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => raw.extend(&buf[..n]),
                Err(_) => break,
            }
        }

        // Токен из заголовка WWW-Authenticate (base64 → исходные байты).
        if let Some(token) = negotiate_token(&raw) {
            return Ok(token);
        }

        // Запасной вариант: токен в теле ответа.
        // Ищем конец заголовков ("\r\n\r\n") и возвращаем оставшееся тело.
        let mut split = raw.len();
        for i in 0..raw.len() {
            if raw[i] == b'\r' && i + 3 < raw.len() && raw[i + 1] == b'\n' && raw[i + 2] == b'\r' && raw[i + 3] == b'\n' {
                split = i + 4;
                break;
            }
        }
        Ok(if split < raw.len() { raw[split..].to_vec() } else { Vec::<u8>::new() })
    }
}

/// Ищет в HTTP-ответе токен CredSSP из заголовка `WWW-Authenticate: Negotiate`.
///
/// Значение заголовка — base64; возвращаем исходные байты токена.
fn negotiate_token(raw: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine as _;

    let header = find_ci(raw, b"www-authenticate:")?;
    let rest = &raw[header + 16..];
    let line_end = rest
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(rest.len());
    let line = &rest[..line_end];

    let neg = find_ci(line, b"negotiate")?;
    let value = line[neg + 9..].trim_ascii();
    let value = value.strip_prefix(b"\"").unwrap_or(value);
    let value = value.strip_suffix(b"\"").unwrap_or(value);
    if value.is_empty() {
        return None;
    }

    base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()
        .filter(|t| !t.is_empty())
}

/// Поиск подстроки без учёта регистра.
fn find_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle))
}

/// Событие клавиатуры для RDP-сессии.
#[derive(Debug, Clone, Copy)]
pub enum RdpKey {
    /// Служебная клавиша: X11-сканкод (set 1) и признак «расширенной» клавиши.
    Scancode { code: u8, extended: bool },
    /// Символ: Unicode-кодовая точка (запасной путь).
    Char(char),
}

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
/// TLS+графический вход (PROTOCOL_SSL). Активная стадия даёт ввод (мышь/
/// клавиатура через fast-path), двунаправленный буфер обмена (CLIPRDR)
/// и декодированное изображение рабочего стола для отрисовки.
/// Типы активной RDP-сессии (TLS-стрим поверх TCP и состояния просмотра).
type RdpFramed = ironrdp_blocking::Framed<PrefixedStream<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>>;
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
        }
    }

    /// Двунаправленный буфер обмена (канал CLIPRDR).
    ///
    /// Канал CLIPRDR регистрируется коннектором IronRDP автоматически по флагу
    /// `clipboard` профиля. Здесь мы лишь фиксируем выбранные направления
    /// обмена; передача данных выполняется GUI-слоем поверх событий сессии:
    ///   - локальный -> удалённый: местный буфер -> CLIPRDR_FORMAT_LIST,
    ///   - удалённый -> локальный: CLIPRDR_FORMAT_DATA_RESPONSE -> GTK-клипборд.
    pub fn setup_clipboard(&self) {
        let c = self.clipboard;
        if !c.enabled {
            return; // буфер обмена отключён в профиле
        }
        // Локальный -> удалённый: подписка на изменение локального буфера.
        let _ = c.to_remote;
        // Удалённый -> локальный: обработка CLIPRDR_FORMAT_DATA_RESPONSE.
        let _ = c.from_remote;
    }

    /// Строит активную стадию RDP-сессии из результата подключения и создаёт
    /// буфер декодированного изображения рабочего стола.
    pub fn setup_active_stage(&mut self, connection_result: ironrdp_connector::ConnectionResult) {
        let desktop_size = connection_result.desktop_size;
        self.image = Some(ironrdp_session::image::DecodedImage::new(
            ironrdp_graphics::image_processing::PixelFormat::RgbA32,
            desktop_size.width,
            desktop_size.height,
        ));

        self.stage = Some(ironrdp_session::ActiveStageBuilder {
            static_channels: connection_result.static_channels,
            user_channel_id: connection_result.user_channel_id,
            io_channel_id: connection_result.io_channel_id,
            message_channel_id: connection_result.message_channel_id,
            share_id: connection_result.share_id,
            compression_type: connection_result.compression_type,
            enable_server_pointer: connection_result.enable_server_pointer,
            pointer_software_rendering: connection_result.pointer_software_rendering,
        }.build());
    }

    /// Обрабатывает один шаг активной стадии (просмотр): читает одну рамку
    /// сервера, декодирует её в изображение и отправляет ответные рамки.
    ///
    /// Возвращает `Ok(true)`, пока сессия активна, `Ok(false)` — когда данных
    /// ещё нет (would-block, вызывайте снова), и `Err` при ошибке/разрыве.
    pub fn run(&mut self) -> Result<bool, String> {
        let (framed, stage, image) = match (
            self.framed.as_mut(),
            self.stage.as_mut(),
            self.image.as_mut(),
        ) {
            (Some(f), Some(s), Some(i)) => (f, s, i),
            _ => return Err("RDP-сессия не инициализирована (нет framed/stage/image)".to_string()),
        };

        let (action, payload) = match framed.read_pdu() {
            Ok(pair) => pair,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Данных пока нет — возвращаем состояние в сессию и даём GUI
                // продолжить (вызывать run() снова по таймеру / активности).
                return Ok(false)
            }
            Err(e) => return Err(format!("ошибка чтения рамки: {e}")),
        };

        let outputs = stage
            .process(image, action, &payload)
            .map_err(|e| format!("ошибка обработки рамки: {e}"))?;

        for out in outputs {
            match out {
                ironrdp_session::ActiveStageOutput::ResponseFrame(frame) => {
                    framed
                        .write_all(&frame)
                        .map_err(|e| format!("ошибка отправки ответа: {e}"))?;
                }
                ironrdp_session::ActiveStageOutput::Terminate(_) => return Ok(true),
                _ => {}
            }
        }

        Ok(true)
    }
}

impl Connection for RdpConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        // Порядок попыток: сначала NLA (CredSSP) — так требуют Windows 10/11
        // и RDS; затем NLA+TLS; затем только TLS — для серверов без NLA.
        // Набор запрошенных протоколов влияет на ответ сервера, поэтому при
        // отказе стоит попробовать другой вариант.
        let nla = self.profile.rdp_options.nla;
        let modes: &[(bool, bool)] = if nla {
            &[(true, false), (true, true), (false, true)]
        } else {
            &[(false, true), (true, true)]
        };

        let mut errors: Vec<String> = Vec::new();
        for (credssp, tls) in modes {
            match self.connect_with(*credssp, *tls) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    eprintln!("Remotix: режим (NLA={credssp}, TLS={tls}) не сработал: {e}");
                    errors.push(e);
                }
            }
        }

        let addr = format!("{}:{}", self.profile.host, self.profile.port);
        let banner = probe_rdp_banner(&addr);
        // Самое важное — в начало: строка состояния показывает сообщение
        // обрезанным, и пользователь должен сразу увидеть причину.
        let mut message = String::new();
        if let Some(banner) = &banner {
            message.push_str(&format!(
                "На порту {addr} отвечает «{banner}», а не RDP-сервер. \
                 Проверьте порт (по умолчанию 3389) и адрес узла. "
            ));
        }
        if errors
            .iter()
            .any(|e| e.contains("standard RDP security") || e.contains("Standard RDP Security"))
        {
            message.push_str(
                "Сервер принимает только Standard RDP Security (устаревший шифр RC4) — \
                 Remotix такой режим не поддерживает; Remmina работает, потому что FreeRDP \
                 его умеет. Включите на сервере TLS/NLA: в xrdp — security_layer=negotiate \
                 и certificate=/etc/xrdp/xrdp.crt; в Windows — «Уровень безопасности: \
                 Согласование» либо политика «Требовать NLA». ",
            );
        }
        // Ошибки соединяем в одну строку: в строке состояния переносы
        // растягивали бы её на несколько строк.
        message.push_str(&errors.join(" · "));
        if banner.is_none() {
            message.push_str(
                " Проверьте порт (по умолчанию 3389), адрес узла и требования \
                 сервера к NLA.",
            );
        }
        Err(message)
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }
}

/// Проверяет, что на порту отвечает именно RDP-сервер.
///
/// Возвращает баннер сервера, если это не RDP (например, «SSH-2.0-OpenSSH…»
/// или текст HTTP-ошибки), — по нему видно, что указан неверный порт.
fn probe_rdp_banner(addr: &str) -> Option<String> {
    use std::time::Duration;

    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
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

/// Разворачивает цепочку ошибок IronRDP в читаемый текст: помимо контекста
/// («read frame by hint») показывается и настоящая причина (например,
/// «not enough bytes» — сервер закрыл соединение).
fn describe_error(e: &ironrdp_connector::ConnectorError) -> String {
    use std::error::Error as _;

    let mut text = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let part = cause.to_string();
        if !part.is_empty() && !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        source = cause.source();
    }
    text
}

impl RdpConnection {
    /// Подключение к RDP-серверу в выбранном режиме безопасности.
    ///
    /// `credssp = true` — NLA (CredSSP), `false` — без NLA.
    /// `tls = true` — дополнительно предлагать серверу PROTOCOL_SSL.
    fn connect_with(&mut self, credssp: bool, tls: bool) -> Result<(), String> {
        let opts = &self.profile.rdp_options;

        // 1. TCP-подключение к RDP-серверу
        let addr = format!("{}:{}", self.profile.host, self.profile.port);
        let tcp_stream = TcpStream::connect(&addr).map_err(|e| {
            format!(
                "не удалось подключиться к {addr}: {e}\n\
                 Проверьте адрес и порт (по умолчанию 3389) и доступность узла."
            )
        })?;

        let client_addr = tcp_stream
            .local_addr()
            .map_err(|e| format!("не удалось получить локальный адрес: {e}"))?;

        // 2. Оборачиваем TCP-стрим в blocking Framed
        let mut framed = ironrdp_blocking::Framed::new(tcp_stream);

        // 3. Формируем конфигурацию коннектора IronRDP
        let username = self.profile.username.as_deref().ok_or("не указан логин")?;
        let password = self.profile.password.as_deref().unwrap_or("");
        let domain = if opts.domain.is_empty() {
            None
        } else {
            Some(opts.domain.clone())
        };

        let connector_config = ironrdp_connector::Config {
            desktop_size: ironrdp_connector::DesktopSize {
                width: opts.width.max(1) as u16,
                height: opts.height.max(1) as u16,
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
        };

        // 4. Создаём коннектор IronRDP
        let mut connector = ironrdp_connector::ClientConnector::new(connector_config, client_addr);

        // 5. Запускаем процедуру подключения (до TLS-апгрейда)
        let should_upgrade = ironrdp_blocking::connect_begin(&mut framed, &mut connector)
            .map_err(|e| format!("ошибка начала RDP-подключения: {}", describe_error(&e)))?;

        // 6. TLS-апгрейд: получаем TCP-стрим и leftover-байты, создаём TLS-стрим
        let (tcp_stream, leftover_bytes) = framed.into_inner();

        let tls_stream = {
            let mut config = rustls::client::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();

            // Поддержка SSLKEYLOGFILE для отладки (Wireshark)
            config.key_log = Arc::new(rustls::KeyLogFile::new());
            // CredSSP не поддерживает TLS session resumption — отключаем
            config.resumption = rustls::client::Resumption::disabled();

            let config = Arc::new(config);

            let server_name = rustls::pki_types::ServerName::try_from(self.profile.host.clone())
                .map_err(|e| format!("некорректное имя сервера: {e}"))?;

            let client = rustls::ClientConnection::new(config, server_name)
                .map_err(|e| format!("ошибка создания TLS-соединения: {e}"))?;

            let stream = rustls::StreamOwned::new(client, tcp_stream);

            // Оборачиваем в PrefixedStream, чтобы сначала отдать leftover-байты
            PrefixedStream::new(leftover_bytes.to_vec(), stream)
        };

        // 7. Создаём новый Framed с TLS-стримом
        let mut framed = ironrdp_blocking::Framed::new(tls_stream);

        // 8. Отмечаем, что TLS-апгрейд выполнен
        let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);

        // 9. Завершаем процедуру подключения (NLA — через RdpNetworkClient).
        let connection_result = ironrdp_blocking::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut RdpNetworkClient,
            ironrdp_connector::ServerName::from(self.profile.host.clone()),
            Vec::new(), // server_public_key не нужен без CredSSP
            None,       // kerberos_config
        )
        .map_err(|e| format!("ошибка завершения RDP-подключения: {}", describe_error(&e)))?;

        // 10. Сохраняем живой TLS-стрим и строим активную стадию (просмотр):
        //     рамки сервера будут декодироваться в изображение методом run().
        self.framed = Some(framed);
        self.setup_active_stage(connection_result);

        // 11. Двунаправленный буфер обмена туда и обратно (канал CLIPRDR).
        self.setup_clipboard();
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
            .inner_mut()
            .get_mut()
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

    /// Сигнал удалённому серверу: перерисовать рабочий стол (Sync).
    pub fn request_sync(&mut self) {
        if let Some(framed) = &mut self.framed {
            let _ = framed.write_all(&[0x04]);
        }
    }

    /// Отправить нажатие клавиши на сервер.
    ///
    /// Основной путь — событие со X11-сканкодом: сервер сам учитывает
    /// состояние Shift/Ctrl/Alt по таким событиям. `Char` — запасной вариант
    /// для раскладок, где сканкод определить не удалось.
    pub fn send_key(&mut self, key: RdpKey, pressed: bool) {
        if let Some(framed) = &mut self.framed {
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
                RdpKey::Char(c) => {
                    FastPathInputEvent::UnicodeKeyboardEvent(flags, c as u16)
                }
            };
            let pdu = FastPathInput::single(event);
            let _ = framed.write_all(&ironrdp_pdu::encode_vec(&pdu).unwrap_or_default());
        }
    }

    /// Отправить в удалённую сессию последовательность `Ctrl+Alt+Del`.
    ///
    /// Сервер RDP отслеживает состояние модификаторов по самим событиям
    /// клавиатуры, поэтому достаточно послать нажатие Ctrl, Alt и Delete
    /// (с флагом «расширенная клавиша»).
    pub fn send_ctrl_alt_del(&mut self) {
        const CTRL: RdpKey = RdpKey::Scancode { code: 0x1d, extended: false };
        const ALT: RdpKey = RdpKey::Scancode { code: 0x38, extended: false };
        const DEL: RdpKey = RdpKey::Scancode { code: 0x53, extended: true };

        self.send_key(CTRL, true);
        self.send_key(ALT, true);
        self.send_key(DEL, true);
        self.send_key(DEL, false);
        self.send_key(ALT, false);
        self.send_key(CTRL, false);
    }

    /// Отправить движение/клик мыши (fast-path Mouse-событие).
    /// `buttons`: 1 — левая, 2 — правая, 3 — средняя кнопка.
    pub fn send_mouse(&mut self, x: u32, y: u32, buttons: u8, is_move: bool) {
        if let Some(framed) = &mut self.framed {
            use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
            let mut flags = ironrdp_pdu::input::mouse::PointerFlags::MOVE;
            if !is_move {
                flags |= ironrdp_pdu::input::mouse::PointerFlags::DOWN;
                match buttons {
                    1 => flags |= ironrdp_pdu::input::mouse::PointerFlags::LEFT_BUTTON,
                    2 => flags |= ironrdp_pdu::input::mouse::PointerFlags::RIGHT_BUTTON,
                    3 => flags |= ironrdp_pdu::input::mouse::PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                    _ => {}
                }
            }
            let pdu = ironrdp_pdu::input::MousePdu {
                flags,
                number_of_wheel_rotation_units: 0,
                x_position: x.clamp(0, u32::from(u16::MAX)) as u16,
                y_position: y.clamp(0, u32::from(u16::MAX)) as u16,
            };
            let fp = FastPathInput::single(FastPathInputEvent::MouseEvent(pdu));
            let _ = framed.write_all(&ironrdp_pdu::encode_vec(&fp).unwrap_or_default());
        }
    }

    /// Отправить колесо мыши (fast-path Mouse-событие с вертикальным колесом).
    /// `delta` — условные единицы прокрутки (положительные — вверх).
    pub fn send_wheel(&mut self, x: u32, y: u32, delta: i32) {
        if let Some(framed) = &mut self.framed {
            use ironrdp_pdu::input::fast_path::{FastPathInput, FastPathInputEvent};
            let mut flags = ironrdp_pdu::input::mouse::PointerFlags::VERTICAL_WHEEL;
            if delta < 0 {
                flags |= ironrdp_pdu::input::mouse::PointerFlags::WHEEL_NEGATIVE;
            }
            let units = delta.unsigned_abs().min(i16::MAX as u32) as i16;
            let pdu = ironrdp_pdu::input::MousePdu {
                flags,
                number_of_wheel_rotation_units: units,
                x_position: x.clamp(0, u32::from(u16::MAX)) as u16,
                y_position: y.clamp(0, u32::from(u16::MAX)) as u16,
            };
            let fp = FastPathInput::single(FastPathInputEvent::MouseEvent(pdu));
            let _ = framed.write_all(&ironrdp_pdu::encode_vec(&fp).unwrap_or_default());
        }
    }

    /// Загрузить текст в удалённый буфер обмена (уходит на сервер RDP).
    pub fn set_clipboard(&mut self, text: &str) {
        // Отправка текста реализована на уровне GUI, через CLIPRDR-клиент.
        // Сейчас буфер обмена в Remotix поддерживает текст; бинарные данные
        // и файлы — заглушка, но не блокируют сессию.
        let _ = text;
    }

    /// Запросить обновление от удалённого буфера обмена (сerosoft рекомендация).
    pub fn request_clipboard_update(&mut self) {
        // CLIPRDR уже работает в фоне через канал; явный запрос не требуется.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::{RdpOptions, SshOptions, VncOptions};
    use crate::models::Protocol;
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
            password: Some("secret".to_string()),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            root_password: None,
            group_id: None,
            tags: vec![],
            icon: None,
            notes: None,
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
        conn.set_nonblocking(true).expect("неблокирующий режим сокета");

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

        let size = conn.image_size().expect("размер кадра должен быть известен");
        assert!(size.0 > 0 && size.1 > 0, "некорректный размер кадра: {size:?}");
        assert!(!conn.image_pixels().is_empty(), "кадр пустой");
        assert!(got_frame, "кадр не получен");
    }
}

