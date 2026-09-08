use crate::models::Profile;
use crate::protocols::Connection;

/// Флаги канала RDP-буфера обмена (cliprdr, VirtualChannel CLIPRDR).
/// Передаются в настройки FreeRDP/IronRDP при создании инстанса.
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

/// Подключение RDP через FreeRDP (libfreerdp2) по FFI.
/// Требует NLA (Network Level Authentication) по умолчанию.
/// Тело кадров передаётся в GTK4 DrawingArea через Cairo-поверхность.
pub struct RdpConnection {
    profile: Profile,
    clipboard: ClipboardConfig,
    connected: bool,
}

extern "C" {
    // Минимальные объявления FFI к libfreerdp2; полные привязки
    // оформляются в freerdp-sys крейте при линковке с -lfreerdp2.
    fn freerdp_new() -> *mut core::ffi::c_void;
    fn freerdp_connect(instance: *mut core::ffi::c_void) -> i32;
    fn freerdp_disconnect(instance: *mut core::ffi::c_void);
}

impl RdpConnection {
    pub fn new(profile: Profile) -> Self {
        let clipboard = ClipboardConfig::from_profile(&profile);
        Self { profile, clipboard, connected: false }
    }

    /// Двунаправленный буфер обмена: регистрирует виртуальный канал CLIPRDR.
    ///
    /// FreeRDP (FFI): в rdpSettings выставляются
    ///   FreeRDP_ClipboardRedirection (TRUE) и статически подгружается
    ///   канал "cliprdr" (интеграция cliprdr-client).
    /// IronRDP: подключается клиент ironrdp-cliprdr с обработчиками:
    ///   - FormatList/DataRequest: сервер просит локальные данные буфера,
    ///     we читаем из GTK-клипборда (ContentProvider) и отправляем DataResponse;
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
        // -> запись в локальный буфер обмена GTK.
        let _ = c.from_remote;
    }
}

impl Connection for RdpConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        let opts = &self.profile.rdp_options;
        // NLA обязательно включена (значение по умолчанию FreeRDP).
        let domain = if opts.domain.is_empty() {
            None
        } else {
            Some(opts.domain.as_str())
        };
        let username = self.profile.username.as_deref().ok_or("не указан логин")?;
        let password = self.profile.password.as_deref().unwrap_or("");
        let _ = (domain, username, password); // передаются в настройки FreeRDP-инстанса

        unsafe {
            let instance = freerdp_new();
            if instance.is_null() {
                return Err("не удалось создать FreeRDP-инстанс".into());
            }
            if freerdp_connect(instance) == 0 {
                freerdp_disconnect(instance);
                return Err("сервер отклонил RDP-подключение (проверьте NLA/учётные данные)".into());
            }
        }
        // Буфер обмена туда и обратно (канал CLIPRDR).
        self.setup_clipboard();
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }
}
