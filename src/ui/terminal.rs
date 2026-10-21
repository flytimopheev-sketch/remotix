//! Вкладка SSH-терминала.
//!
//! Эмулятор VTE (`libvte-2.91-gtk4.so.0`) подключается динамически через
//! `libloading`: RPM не требует пакет VTE для GTK4 (в EL9/RHEL9 его нет),
//! а приложение всё равно получает полноценный терминал там, где VTE есть
//! (ANSI-цвета, vim/htop/mc). Если библиотеки нет — используется упрощённый
//! терминал на `GtkTextView`: вывод команд, ввод с клавиатуры,
//! копирование/вставка, масштаб шрифта.

use std::rc::Rc;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, CssProvider, EventControllerKey, Label, ScrolledWindow, TextView};

use crate::protocols::ssh::SshConnection;
use crate::protocols::Connection;

const PROMPT_MS: u64 = 10;
const BASE_FONT_PX: f64 = 12.0;
const FONT_SCALE_MIN: f64 = 0.3;
const FONT_SCALE_MAX: f64 = 4.0;

/// Вкладка SSH-терминала.
pub struct TerminalTab {
    pub root: GtkBox,
    pub title: String,
}

enum ToThread {
    Data(Vec<u8>),
    Resize(u32, u32),
}

enum ToUi {
    Out(Vec<u8>),
    State(crate::ui::SessionState),
}

/// Динамическая (во время выполнения) загрузка VTE для GTK4.
///
/// Жёсткая линковка с `libvte-2.91-gtk4` недопустима: RHEL 9 / AlmaLinux 9
/// (и построенные на них сборки РЕД ОС) не поставляют VTE для GTK4, и
/// приложение падало бы ещё до `main()` с «error while loading shared
/// libraries: libvte-2.91-gtk4.so.0».
mod vte_dynamic {
    use gtk4::glib;
    use std::os::raw::{c_char, c_double, c_int, c_long};
    use std::sync::OnceLock;

    /// `VteTerminal *`: GObject, наследник `GtkWidget`.
    type GObjectPtr = *mut glib::gobject_ffi::GObject;

    type TerminalNew = unsafe extern "C" fn() -> GObjectPtr;
    type TerminalFeed = unsafe extern "C" fn(GObjectPtr, *const c_char, isize);
    type TerminalSetFontScale = unsafe extern "C" fn(GObjectPtr, c_double);
    type TerminalGetFontScale = unsafe extern "C" fn(GObjectPtr) -> c_double;
    type TerminalCopyClipboard = unsafe extern "C" fn(GObjectPtr, c_int);
    type TerminalGetCharWidth = unsafe extern "C" fn(GObjectPtr) -> c_long;
    type TerminalGetCharHeight = unsafe extern "C" fn(GObjectPtr) -> c_long;

    /// `VTE_FORMAT_TEXT` из `enum VteFormat`.
    const VTE_FORMAT_TEXT: c_int = 1;

    struct Api {
        /// Библиотека должна жить столько же, сколько указатели на функции.
        _lib: libloading::Library,
        new_terminal: TerminalNew,
        feed: TerminalFeed,
        set_font_scale: TerminalSetFontScale,
        get_font_scale: TerminalGetFontScale,
        copy_clipboard: TerminalCopyClipboard,
        char_width: TerminalGetCharWidth,
        char_height: TerminalGetCharHeight,
    }

    // Библиотека используется только из главного потока GTK.
    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    static API: OnceLock<Option<Api>> = OnceLock::new();

    fn load() -> Option<Api> {
        const NAMES: [&str; 2] = ["libvte-2.91-gtk4.so.0", "libvte-2.91-gtk4.so"];
        for name in NAMES {
            // SAFETY: библиотека только загружается; вызовы — ниже.
            if let Ok(lib) = unsafe { libloading::Library::new(name) } {
                // SAFETY: имена символов соответствуют публичному C API VTE.
                if let Some(api) = unsafe { bind(lib) } {
                    return Some(api);
                }
            }
        }
        None
    }

    /// # Safety
    /// `lib` — загруженная библиотека VTE для GTK4.
    unsafe fn bind(lib: libloading::Library) -> Option<Api> {
        macro_rules! sym {
            ($name:literal, $ty:ty) => {
                match lib.get::<$ty>($name) {
                    Ok(s) => *s,
                    Err(_) => return None,
                }
            };
        }

        let new_terminal = sym!(b"vte_terminal_new\0", TerminalNew);
        let feed = sym!(b"vte_terminal_feed\0", TerminalFeed);
        let set_font_scale = sym!(b"vte_terminal_set_font_scale\0", TerminalSetFontScale);
        let get_font_scale = sym!(b"vte_terminal_get_font_scale\0", TerminalGetFontScale);
        let copy_clipboard = sym!(b"vte_terminal_copy_clipboard_format\0", TerminalCopyClipboard);
        let char_width = sym!(b"vte_terminal_get_char_width\0", TerminalGetCharWidth);
        let char_height = sym!(b"vte_terminal_get_char_height\0", TerminalGetCharHeight);

        Some(Api {
            _lib: lib,
            new_terminal,
            feed,
            set_font_scale,
            get_font_scale,
            copy_clipboard,
            char_width,
            char_height,
        })
    }

    fn api() -> Option<&'static Api> {
        API.get_or_init(load).as_ref()
    }

    /// Терминал VTE, доступный как обычный виджет GTK.
    pub struct Terminal {
        api: &'static Api,
        widget: gtk4::Widget,
    }

    impl Terminal {
        pub fn new() -> Option<Self> {
            let api = api()?;
            // SAFETY: `vte_terminal_new()` создаёт новый VteTerminal.
            let ptr = unsafe { (api.new_terminal)() };
            if ptr.is_null() {
                return None;
            }
            // SAFETY: получен новый объект (владение наше); VteTerminal —
            // наследник GtkWidget, поэтому указатель совместим.
            let widget: gtk4::Widget =
                unsafe { glib::translate::from_glib_full(ptr as *mut gtk4::ffi::GtkWidget) };
            Some(Self { api, widget })
        }

        pub fn widget(&self) -> &gtk4::Widget {
            &self.widget
        }

        fn raw(&self) -> GObjectPtr {
            use glib::translate::ToGlibPtr;
            let ptr = ToGlibPtr::<*mut gtk4::ffi::GtkWidget>::to_glib_none(&self.widget).0;
            ptr as GObjectPtr
        }

        pub fn feed(&self, data: &[u8]) {
            // SAFETY: терминал жив (держим ссылку), данные — валидный срез.
            unsafe {
                (self.api.feed)(self.raw(), data.as_ptr() as *const c_char, data.len() as isize);
            }
        }

        pub fn set_font_scale(&self, scale: f64) {
            // SAFETY: терминал жив.
            unsafe { (self.api.set_font_scale)(self.raw(), scale) }
        }

        pub fn copy_clipboard_text(&self) {
            // SAFETY: терминал жив.
            unsafe { (self.api.copy_clipboard)(self.raw(), VTE_FORMAT_TEXT) }
        }

        pub fn char_size(&self) -> (i32, i32) {
            // SAFETY: терминал жив.
            unsafe {
                let w = (self.api.char_width)(self.raw()) as i32;
                let h = (self.api.char_height)(self.raw()) as i32;
                (w, h)
            }
        }
    }
}

/// Терминальный виджет с единым интерфейсом: VTE или запасной `GtkTextView`.
struct TerminalView {
    widget: gtk4::Widget,
    kind: Kind,
    scale: std::cell::Cell<f64>,
    /// Базовый размер шрифта терминала (в пунктах) — из настроек.
    base_font_px: f64,
    /// Текущее оформление вывода (цвет и начертание) для запасного терминала.
    ansi: std::cell::Cell<AnsiState>,
}

/// Оформление вывода терминала: цвет символов и жирное начертание.
#[derive(Clone, Copy, Default)]
struct AnsiState {
    /// Цвет символов (16-битный RGB).
    color: Option<(u16, u16, u16)>,
    /// Жирное начертание.
    bold: bool,
}

/// Базовые цвета ANSI для тёмной темы.
const ANSI_BASE: [(u8, u8, u8); 8] = [
    (0x2e, 0x2e, 0x3a), // чёрный
    (0xe8, 0x5c, 0x5c), // красный
    (0x6f, 0xd0, 0x6f), // зелёный
    (0xe0, 0xc0, 0x60), // жёлтый
    (0x6f, 0xa8, 0xe8), // синий
    (0xc8, 0x7f, 0xe0), // пурпурный
    (0x60, 0xd0, 0xd0), // голубой
    (0xd0, 0xd0, 0xd0), // белый
];

/// Переводит 8-битный цвет в 16-битный.
fn rgb16(r: u8, g: u8, b: u8) -> (u16, u16, u16) {
    (
        u16::from(r) * 257,
        u16::from(g) * 257,
        u16::from(b) * 257,
    )
}

/// Базовый цвет ANSI (0..7) или светлый вариант (8..15).
fn ansi_color(index: u32, bright: bool) -> (u16, u16, u16) {
    let (r, g, b) = ANSI_BASE[(index as usize) % 8];
    let boost = if bright { 0x30 } else { 0 };
    rgb16(r.saturating_add(boost), g.saturating_add(boost), b.saturating_add(boost))
}

/// Цвет из палитры xterm-256.
fn xterm256(index: u8) -> (u16, u16, u16) {
    if index < 8 {
        let (r, g, b) = ANSI_BASE[index as usize];
        return rgb16(r, g, b);
    }
    if index < 16 {
        let (r, g, b) = ANSI_BASE[(index - 8) as usize];
        return rgb16(r + 0x30, g + 0x30, b + 0x30);
    }
    if index < 232 {
        const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
        let i = (index - 16) as usize;
        return rgb16(
            STEPS[i / 36],
            STEPS[(i % 36) / 6],
            STEPS[i % 6],
        );
    }
    let gray = (8 + (index as u16 - 232) * 10) as u8;
    rgb16(gray, gray, gray)
}

/// Применяет последовательность SGR (параметры без `ESC[` и `m`).
fn apply_sgr(mut state: AnsiState, params: &str) -> AnsiState {
    let parts: Vec<&str> = params.split(';').collect();
    let mut i = 0;
    while i < parts.len() {
        let code: u32 = parts[i].parse().unwrap_or(0);
        match code {
            0 => state = AnsiState::default(),
            1 => state.bold = true,
            22 => state.bold = false,
            30..=37 => state.color = Some(ansi_color(code - 30, false)),
            90..=97 => state.color = Some(ansi_color(code - 90, true)),
            39 => state.color = None,
            38 => {
                if parts.get(i + 1) == Some(&"5") {
                    if let Some(n) = parts.get(i + 2).and_then(|v| v.parse::<u8>().ok()) {
                        state.color = Some(xterm256(n));
                    }
                    i += 2;
                } else if parts.get(i + 1) == Some(&"2") {
                    let r = parts.get(i + 2).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0);
                    let g = parts.get(i + 3).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0);
                    let b = parts.get(i + 4).and_then(|v| v.parse::<u8>().ok()).unwrap_or(0);
                    state.color = Some(rgb16(r, g, b));
                    i += 4;
                }
            }
            _ => {}
        }
        i += 1;
    }
    state
}

/// Вставляет накопленный текст в буфер с учётом цвета и начертания.
fn flush_text(view: &TextView, end: &mut gtk4::TextIter, text: &mut Vec<u8>, state: AnsiState) {
    if text.is_empty() {
        return;
    }
    let content = String::from_utf8_lossy(text).into_owned();
    text.clear();

    let escaped = content
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");

    let markup = match state.color {
        Some((r, g, b)) => {
            let bold = if state.bold { "<b>" } else { "" };
            let bold_end = if state.bold { "</b>" } else { "" };
            format!("<span foreground=\"#{r:04x}{g:04x}{b:04x}\">{bold}{escaped}{bold_end}</span>")
        }
        None => {
            if state.bold {
                format!("<b>{escaped}</b>")
            } else {
                escaped
            }
        }
    };

    let buffer = view.buffer();
    buffer.insert_markup(end, &markup);
}

/// Разбирает поток с ANSI-последовательностями и выводит текст с цветами.
fn feed_ansi(view: &TextView, data: &[u8], state: &std::cell::Cell<AnsiState>) {
    let buffer = view.buffer();
    let mut end = buffer.end_iter();
    let mut text: Vec<u8> = Vec::with_capacity(data.len());
    let mut iter = data.iter().copied().peekable();

    while let Some(byte) = iter.next() {
        match byte {
            0x1b => {
                if iter.peek() == Some(&b'[') {
                    // CSI: ESC [ параметры Final
                    iter.next();
                    let mut params = String::new();
                    while let Some(&b) = iter.peek() {
                        iter.next();
                        if (0x40..=0x7e).contains(&b) {
                            break;
                        }
                        params.push(b as char);
                    }
                    flush_text(view, &mut end, &mut text, state.get());
                    state.set(apply_sgr(state.get(), &params));
                    continue;
                }
                if iter.peek() == Some(&b']') {
                    // OSC: пропускаем до BEL или ST.
                    iter.next();
                    while let Some(&b) = iter.peek() {
                        iter.next();
                        if b == 0x07 {
                            break;
                        }
                        if b == 0x1b && iter.peek() == Some(&b'\\') {
                            iter.next();
                            break;
                        }
                    }
                    continue;
                }
                // Прочие escape-последовательности — игнорируем.
                iter.next();
            }
            0x0d => flush_text(view, &mut end, &mut text, state.get()),
            0x07 => {}
            0x08 => {
                // Забой — удаляем предыдущий символ.
                flush_text(view, &mut end, &mut text, state.get());
                let buffer = view.buffer();
                let mut end_iter = buffer.end_iter();
                let mut start_iter = end_iter.clone();
                if start_iter.backward_char() {
                    buffer.delete(&mut start_iter, &mut end_iter);
                }
            }
            b if b >= 0x20 => text.push(b),
            _ => {}
        }
    }

    flush_text(view, &mut end, &mut text, state.get());
    view.scroll_to_iter(&mut end, 0.0, false, 0.0, 1.0);
}

enum Kind {
    Vte(vte_dynamic::Terminal),
    Text { view: TextView, provider: CssProvider },
}

impl TerminalView {
    /// Создаёт терминал внутри `scroll`: VTE, если библиотека доступна.
    fn new(scroll: &ScrolledWindow, font_size: i64) -> Self {
        let base_font_px = (font_size.clamp(8, 32) as f64).max(8.0);
        // Масштаб VTE приводим к базовому размеру шрифта.
        let scale = (base_font_px / BASE_FONT_PX).clamp(0.5, 3.0);
        if let Some(vte) = vte_dynamic::Terminal::new() {
            let widget = vte.widget().clone();
            scroll.set_child(Some(&widget));
            return Self {
                widget,
                kind: Kind::Vte(vte),
                scale: std::cell::Cell::new(scale),
                base_font_px,
                ansi: std::cell::Cell::new(AnsiState::default()),
            };
        }

        // Запасной вариант: простой терминал на GtkTextView.
        let view = TextView::new();
        view.set_editable(false);
        view.set_cursor_visible(false);
        view.set_monospace(true);
        view.add_css_class("remotix-terminal");
        view.set_wrap_mode(gtk4::WrapMode::Char);
        let provider = CssProvider::new();
        apply_text_style(&view, &provider, 1.0, base_font_px);
        scroll.set_child(Some(&view));
        let widget = view.clone().upcast::<gtk4::Widget>();
        Self {
            widget,
            kind: Kind::Text { view, provider },
            scale: std::cell::Cell::new(1.0),
            base_font_px,
            ansi: std::cell::Cell::new(AnsiState::default()),
        }
    }

    fn widget(&self) -> &gtk4::Widget {
        &self.widget
    }

    /// true, если используется полноценный эмулятор VTE.
    fn has_vte(&self) -> bool {
        matches!(self.kind, Kind::Vte(_))
    }

    /// Выводит данные, полученные от удалённой стороны.
    fn feed(&self, data: &[u8]) {
        match &self.kind {
            Kind::Vte(term) => term.feed(data),
            Kind::Text { view, .. } => {
                // ANSI-последовательности разбираются и превращаются в цвет
                // и начертание символов.
                feed_ansi(view, data, &self.ansi);
            }
        }
    }

    /// Изменяет масштаб шрифта (Ctrl + «+» / Ctrl + «-»).
    fn zoom(&self, factor: f64) {
        let next = (self.scale.get() * factor).clamp(FONT_SCALE_MIN, FONT_SCALE_MAX);
        self.scale.set(next);
        match &self.kind {
            Kind::Vte(term) => term.set_font_scale(next),
            Kind::Text { view, provider } => { let base = self.base_font_px; apply_text_style(view, provider, next, base) },
        }
    }

    /// Копирует текст терминала в буфер обмена.
    fn copy_clipboard(&self) {
        match &self.kind {
            Kind::Vte(term) => term.copy_clipboard_text(),
            Kind::Text { view, .. } => {
                let buffer = view.buffer();
                let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
                self.widget.clipboard().set_text(&text);
            }
        }
    }

    /// Вставляет текст из буфера обмена в удалённую сессию.
    fn paste_clipboard(&self, tx: Sender<ToThread>) {
        let clipboard = self.widget.clipboard();
        glib::spawn_future_local(async move {
            if let Ok(Some(text)) = clipboard.read_text_future().await {
                let _ = tx.send(ToThread::Data(text.replace('\n', "\r").into_bytes()));
            }
        });
    }

    /// Размер символа в пикселях — для расчёта колонок и строк PTY.
    fn char_size(&self) -> (i32, i32) {
        match &self.kind {
            Kind::Vte(term) => {
                let (w, h) = term.char_size();
                (w.max(1), h.max(1))
            }
            // Для TextView размер оценивается по кеглю моноширинного шрифта.
            Kind::Text { .. } => {
                let scale = self.scale.get();
                let base = self.base_font_px;
                let w = (base * 0.6 * scale).round() as i32;
                let h = (base * 1.3 * scale).round() as i32;
                (w.max(1), h.max(1))
            }
        }
    }
}

/// Применяет моноширинный шрифт нужного размера к резервному TextView.
fn apply_text_style(view: &TextView, provider: &CssProvider, scale: f64, base_font_px: f64) {
    let size = (base_font_px * scale).round() as i32;
    let css = format!("textview {{ font-family: monospace; font-size: {size}px; }}");
    provider.load_from_data(&css);
    #[allow(deprecated)]
    view.style_context()
        .add_provider(provider, gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION);
}

impl TerminalTab {
    /// Открывает SSH-сессию в новом терминале: VTE, если библиотека есть в
    /// системе, иначе — упрощённый терминал с тем же вводом/выводом.
    ///
    /// `on_state` сообщает об изменении состояния сессии (подключение,
    /// ошибка, закрытие) — её вывод показывается в строке состояния окна.
    pub fn new_ssh(
        title: &str,
        conn: SshConnection,
        on_state: Rc<dyn Fn(crate::ui::SessionState)>,
        font_size: i64,
    ) -> Result<Self, String> {
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);
        let scroll = ScrolledWindow::new();
        scroll.set_vexpand(true);
        root.append(&scroll);

        let term = Rc::new(TerminalView::new(&scroll, font_size));

        let (tx_in, rx_in) = mpsc::channel::<ToThread>();
        let (tx_out, rx_out) = mpsc::channel::<ToUi>();

        // Поток: подключение, shell/su → root, неблокирующий цикл обмена.
        std::thread::spawn(move || {
            let mut conn = conn;
            if let Err(e) = conn.connect() {
                let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Failed(e)));
                return;
            }
            let Some(mut session) = conn.take_session() else {
                let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Failed(
                    "сессия потеряна".into(),
                )));
                return;
            };
            session.set_blocking(true);
            let su = conn.profile.ssh_options.su_to_root && conn.profile.root_password.is_some();
            use std::io::Read;
            let open = (|| -> Result<ssh2::Channel, String> {
                let mut ch = session.channel_session().map_err(|e| e.to_string())?;
                ch.request_pty("xterm", None, None).map_err(|e| e.to_string())?;
                if su {
                    ch.exec("su -").map_err(|e| e.to_string())?;
                    wait_password(
                        &mut ch,
                        &mut session,
                        conn.profile.root_password.clone().unwrap_or_default(),
                    )?;
                } else {
                    ch.shell().map_err(|e| e.to_string())?;
                }
                Ok(ch)
            })();
            let mut ch = match open {
                Ok(c) => c,
                Err(e) => {
                    let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Failed(e)));
                    return;
                }
            };

            // Канал открыт — сессия работает.
            let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Connected));

            session.set_blocking(false);
            let mut buf = [0u8; 8192];
            loop {
                match ch.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Closed));
                        break;
                    }
                    Ok(n) => {
                        if tx_out.send(ToUi::Out(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Failed(
                            e.to_string(),
                        )));
                        break;
                    }
                }
                match rx_in.recv_timeout(Duration::from_millis(PROMPT_MS)) {
                    Ok(ToThread::Data(d)) => {
                        use std::io::Write;
                        let _ = ch.write_all(&d);
                    }
                    Ok(ToThread::Resize(c, r)) => {
                        let _ = ch.request_pty_size(c, r, None, None);
                    }
                    Err(_) => {}
                }
                if ch.eof() {
                    let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Closed));
                    break;
                }
            }
            let _ = session.disconnect(None, "закрыто пользователем", None);
        });

        // Опрос вывода канала (главный поток) → кормим терминал.
        let term_out = term.clone();
        let status = Label::new(None);
        status.set_halign(gtk4::Align::Start);
        let status_out = status.clone();
        let state_cb = on_state.clone();
        glib::timeout_add_local(Duration::from_millis(PROMPT_MS), move || {
            loop {
                match rx_out.try_recv() {
                    Ok(ToUi::Out(data)) => term_out.feed(&data),
                    Ok(ToUi::State(state)) => {
                        let text = match &state {
                            crate::ui::SessionState::Failed(e) => format!("● Ошибка: {e}"),
                            crate::ui::SessionState::Closed => "● Сессия закрыта".to_string(),
                            _ => String::new(),
                        };
                        if !text.is_empty() {
                            if !term_out.has_vte() {
                                term_out.feed(format!("\n{text}\n").as_bytes());
                            }
                            status_out.set_text(&text);
                            state_cb(state);
                            return glib::ControlFlow::Break;
                        }
                        state_cb(state);
                    }
                    Err(_) => return glib::ControlFlow::Continue,
                }
            }
        });
        root.append(&status);

        setup_input(&term, &scroll, tx_in);
        Ok(Self {
            root,
            title: title.to_string(),
        })
    }
}

/// Ввод с клавиатуры: буквы/символы → UTF-8, служебные клавиши → escape-
/// последовательности, Ctrl+буква → управляющий байт. Плюс горячие клавиши
/// терминала: Ctrl+Shift+C/V (копия/вставка), Ctrl+«+»/«-» (масштаб шрифта).
fn setup_input(term: &Rc<TerminalView>, scroll: &ScrolledWindow, tx_in: Sender<ToThread>) {
    use gtk4::gdk::ModifierType;

    let controller = EventControllerKey::new();
    let term_ref = term.clone();
    let tx_key = tx_in.clone();
    controller.connect_key_pressed(move |_, keyval, _code, state| {
        let ctrl = state.contains(ModifierType::CONTROL_MASK);
        let shift = state.contains(ModifierType::SHIFT_MASK);

        if ctrl && shift {
            match keyval.name().as_deref() {
                Some("c") => {
                    term_ref.copy_clipboard();
                    return glib::Propagation::Stop;
                }
                Some("v") => {
                    term_ref.paste_clipboard(tx_key.clone());
                    return glib::Propagation::Stop;
                }
                _ => {}
            }
        }
        if ctrl && !shift {
            match keyval.name().as_deref() {
                Some("plus") | Some("equal") => {
                    term_ref.zoom(1.1);
                    return glib::Propagation::Stop;
                }
                Some("minus") => {
                    term_ref.zoom(1.0 / 1.1);
                    return glib::Propagation::Stop;
                }
                _ => {}
            }
        }

        let bytes: Vec<u8> = match keyval.name().as_deref() {
            Some("Return") | Some("KP_Enter") => b"\r".to_vec(),
            Some("BackSpace") => b"\x7f".to_vec(),
            Some("Tab") | Some("ISO_Left_Tab") => b"\t".to_vec(),
            Some("Escape") => b"\x1b".to_vec(),
            Some("Up") => b"\x1b[A".to_vec(),
            Some("Down") => b"\x1b[B".to_vec(),
            Some("Right") => b"\x1b[C".to_vec(),
            Some("Left") => b"\x1b[D".to_vec(),
            Some("Home") => b"\x1b[H".to_vec(),
            Some("End") => b"\x1b[F".to_vec(),
            Some("Delete") => b"\x1b[3~".to_vec(),
            _ => {
                if ctrl {
                    // Ctrl+буква → управляющий символ (Ctrl+C = 0x03 и т.д.)
                    keyval
                        .to_unicode()
                        .filter(|c| c.is_ascii_alphabetic())
                        .map(|c| vec![c.to_ascii_uppercase() as u8 - b'A' + 1])
                        .unwrap_or_default()
                } else {
                    keyval
                        .to_unicode()
                        .map(|c| c.to_string().into_bytes())
                        .unwrap_or_default()
                }
            }
        };
        if bytes.is_empty() {
            return glib::Propagation::Proceed;
        }
        let _ = tx_key.send(ToThread::Data(bytes));
        glib::Propagation::Stop
    });
    term.widget().add_controller(controller);

    // Размер PTY при изменении размеров терминала: опрос по таймеру —
    // сигнала size-allocate в gtk4-rs 0.9 нет, а это работает на любых
    // версиях GTK (окно терминала меняется редко, 500 мс достаточно).
    let term_resize = term.clone();
    let tx_resize = tx_in;
    let last = std::cell::Cell::new((0u32, 0u32));
    let scroll_w = scroll.clone();
    glib::timeout_add_local(Duration::from_millis(500), move || {
        let w = scroll_w.width().max(1);
        let h = scroll_w.height().max(1);
        let (char_w, char_h) = term_resize.char_size();
        let cols = (w / char_w.max(1)) as u32;
        let rows = (h / char_h.max(1)) as u32;
        let key = (cols, rows);
        if key != last.get() && cols > 1 && rows > 1 {
            last.set(key);
            let _ = tx_resize.send(ToThread::Resize(cols.max(2), rows.max(2)));
        }
        glib::ControlFlow::Continue
    });
}

/// Ожидание prompt "Password:" и ответ паролем root.
fn wait_password(
    ch: &mut ssh2::Channel,
    session: &mut ssh2::Session,
    password: String,
) -> Result<(), String> {
    use std::io::{Read, Write};
    let mut buf = [0u8; 512];
    let mut seen = String::new();
    session.set_blocking(false);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut prompted = false;
    while std::time::Instant::now() < deadline {
        match ch.read(&mut buf) {
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
    if !prompted && seen.trim().is_empty() {
        return Err("сервер не запросил пароль root".into());
    }
    ch.write_all(password.as_bytes())
        .and_then(|_| ch.write_all(b"\n"))
        .map_err(|e| e.to_string())
}

