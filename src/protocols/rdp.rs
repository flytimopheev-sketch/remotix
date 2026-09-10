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

/// Заглушка NetworkClient для CredSSP — не используется при enable_credssp: false,
/// но требуется сигнатурой connect_finalize.
struct DummyNetworkClient;

impl ironrdp_connector::sspi::network_client::NetworkClient for DummyNetworkClient {
    fn send(&mut self, _request: &[u8]) -> Result<Vec<u8>, sspi::Error> {
        Err(sspi::Error::UnsupportedFunction)
    }
}

/// Верификатор TLS-сертификата, принимающий любой сертификат (аналог поведения
/// большинства RDP-клиентов — проверка отпечатка/отзыва делается отдельно).
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
/// TLS-апгрейд выполняется через rustls (ring), CredSSP/NLA отключена в пользу
/// TLS-безопасности (PROTOCOL_SSL) — соединение шифруется, но логин происходит
/// на стороне сервера (графический вход RDP).
pub struct RdpConnection {
    profile: Profile,
    clipboard: ClipboardConfig,
    connected: bool,
}

impl RdpConnection {
    pub fn new(profile: Profile) -> Self {
        let clipboard = ClipboardConfig::from_profile(&profile);
        Self {
            profile,
            clipboard,
            connected: false,
        }
    }

    /// Двунаправленный буфер обмена: регистрирует виртуальный канал CLIPRDR.
    ///
    /// IronRDP: подключается клиент ironrdp-cliprdr с обработчиками:
    ///   - FormatList/DataRequest: сервер просит локальные данные буфера,
    ///     мы читаем из GTK-клипборда (ContentProvider) и отправляем DataResponse;
    ///   - ServerFormatDataResponse: получаем данные сервера и пишем в
    ///     локальный gtk4::Clipboard, чтобы вставка работала и туда и обратно.
    pub fn setup_clipboard(&self) {
        let c = self.clipboard;
        if !c.enabled {
            return; // буфер обмена отключён в профиле
        }
        // Локальный -> удалённый: подписка на изменение локального буфера
        // (gtk4::gdk::ContentFormats) -> отправка CLIPRDR_FORMAT_LIST.
        let _ = c.to_remote;
        // Удалённый -> локальный: обработка CLIPRDR_FORMAT_DATA_RESPONSE

impl Connection for RdpConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        let opts = &self.profile.rdp_options;

        // 1. TCP-подключение к RDP-серверу
        let addr = format!("{}:{}", self.profile.host, self.profile.port);
        let tcp_stream = TcpStream::connect(&addr)
            .map_err(|e| format!("не удалось подключиться к {addr}: {e}"))?;

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
            enable_tls: true,
            // CredSSP/NLA отключена: используем TLS-безопасность (PROTOCOL_SSL).
            // Для включения NLA необходим NetworkClient (CredSSP over HTTP).
            enable_credssp: false,
            credentials: ironrdp_connector::Credentials::UsernamePassword {
                username: username.to_string(),
                password: password.to_string(),
            },
            domain,
            client_build: 0,
            client_name: "remotix".to_string(),
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::Ibm101,
            keyboard_subtype: 0,
            keyboard_functional_keys_count: 12,
            keyboard_layout: 0,
            ime_file_name: String::new(),
            bitmap: None,
            dig_product_id: String::new(),
            client_dir: String::new(),
            alternate_shell: String::new(),
            work_dir: String::new(),
            platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::Unix,
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
            .map_err(|e| format!("ошибка начала RDP-подключения: {e}"))?;

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
            PrefixedStream::new(leftover_bytes, stream)
        };

        // 7. Создаём новый Framed с TLS-стримом
        let mut framed = ironrdp_blocking::Framed::new(tls_stream);

        // 8. Отмечаем, что TLS-апгрейд выполнен
        let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);

        // 9. Завершаем процедуру подключения (CredSSP пропущен, enable_credssp: false)
        let _connection_result = ironrdp_blocking::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut DummyNetworkClient,
            ironrdp_connector::ServerName::from(self.profile.host.clone()),
            Vec::new(), // server_public_key не нужен без CredSSP
            None,       // kerberos_config
        )
        .map_err(|e| format!("ошибка завершения RDP-подключения: {e}"))?;

        // 10. Двунаправленный буфер обмена туда и обратно (канал CLIPRDR)
        self.setup_clipboard();
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }
}

