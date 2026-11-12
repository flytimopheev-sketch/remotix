//! Вкладка SSH-терминала.
//!
//! Эмулятор VTE (`libvte-2.91-gtk4.so.0`) подключается динамически через
//! `libloading`: RPM не требует пакет VTE для GTK4 (в EL9/RHEL9 его нет),
//! а приложение всё равно получает полноценный терминал там, где VTE есть
//! (ANSI-цвета, vim/htop/mc). Если библиотеки нет — используется упрощённый
//! терминал на `GtkTextView`: вывод команд, ввод с клавиатуры,
//! копирование/вставка, масштаб шрифта.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    pango, Box as GtkBox, Button, CssProvider, DrawingArea, EventControllerKey,
    EventControllerMotion, EventControllerScroll, EventControllerScrollFlags, GestureClick, Label,
    MenuButton, Popover, PropagationPhase, ScrolledWindow, Stack, TextView,
};
use secrecy::ExposeSecret;

use crate::protocols::ssh::{HostKeyConfig, HostKeyPrompt, SshConnection};
use crate::ui::palette::{self, Palette};

mod alt_screen;

/// Отрисовка `PangoLayout` в `cairo::Context`.
///
/// В `pango`-крейте нет cairo-интеграции, а `pangocairo` уже является
/// зависимостью GTK4. Небольшой extern-вызов дешевле, чем тащить ещё один
/// Rust-крейт и пересобирать vendor.tar.
mod pango_cairo {
    #![allow(unsafe_code)]

    use gtk4::cairo;
    use gtk4::glib::translate::ToGlibPtr;
    use gtk4::pango;

    #[link(name = "pangocairo-1.0")]
    extern "C" {
        fn pango_cairo_show_layout(
            cr: *mut cairo::ffi::cairo_t,
            layout: *mut pango::ffi::PangoLayout,
        );
    }

    pub fn show_layout(cr: &cairo::Context, layout: &pango::Layout) {
        // SAFETY: оба указателя получены из живых объектов; вызов только
        // рисует layout и не сохраняет указатели.
        unsafe {
            pango_cairo_show_layout(cr.to_glib_none().0, layout.to_glib_none().0);
        }
    }
}

const PROMPT_MS: u64 = 10;
const BASE_FONT_PX: f64 = 12.0;
const FONT_SCALE_MIN: f64 = 0.3;
const FONT_SCALE_MAX: f64 = 4.0;

/// Режим передачи мыши, включённый приложением через xterm mouse reporting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum MouseMode {
    /// Приложение мышь не запрашивало — работает выделение текста.
    #[default]
    Off,
    /// X10: только нажатия кнопок.
    X10,
    /// 1000: нажатия и отпускания.
    Normal,
    /// 1002: плюс движение с зажатой кнопкой.
    Button,
    /// 1003: любое движение.
    Any,
}

/// Состояние терминальных режимов, которые влияют на ввод.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TerminalModes {
    /// DECCKM: стрелки в режиме приложения (`ESC O A`, а не `ESC [ A`).
    app_cursor: bool,
    mouse: MouseMode,
    /// 1006: SGR-кодирование координат мыши.
    sgr_mouse: bool,
    /// 2004: вставка обрамляется `ESC[200~` / `ESC[201~`.
    bracketed_paste: bool,
}

/// Вкладка SSH-терминала.
pub struct TerminalTab {
    pub root: GtkBox,
    pub title: String,
}

/// Дополнительные данные сессии, которые не являются её параметрами
/// подключения: автоответы и сохранённые команды.
pub struct TerminalExtras {
    pub expect_rules: Vec<crate::expect::Rule>,
    pub snippets: Vec<crate::db::repository::SnippetRow>,
    pub palette: Palette,
}

enum ToThread {
    Data(Vec<u8>),
    Resize(u32, u32),
    /// Снять показатели хоста (вызывается таймером раз в N секунд).
    Metrics,
}

enum ToUi {
    Out(Vec<u8>),
    State(crate::ui::SessionState),
    /// Показатели хоста: None — опрос не удался.
    Metrics(crate::protocols::metrics::HostMetrics),
    MetricsFailed,
}

/// Динамическая (во время выполнения) загрузка VTE для GTK4.
///
/// Жёсткая линковка с `libvte-2.91-gtk4` недопустима: RHEL 9 / AlmaLinux 9
/// (и построенные на них сборки РЕД ОС) не поставляют VTE для GTK4, и
/// приложение падало бы ещё до `main()` с «error while loading shared
/// libraries: libvte-2.91-gtk4.so.0».
// Единственная зона unsafe в проекте (см. #![deny(unsafe_code)] в main.rs):
// динамическая загрузка VTE для GTK4. Жёсткая линковка недопустима — в EL9/
// РЕД ОС пакета libvte-2.91-gtk4 нет, поэтому сырой C API через libloading.
mod vte_dynamic {
    #![allow(unsafe_code)]
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
    type TerminalSetColors =
        unsafe extern "C" fn(GObjectPtr, *const Rgba, *const Rgba, *const Rgba, usize);

    /// `GdkRGBA`: четыре `float` подряд.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Rgba {
        red: f32,
        green: f32,
        blue: f32,
        alpha: f32,
    }

    fn rgba((r, g, b): (u8, u8, u8)) -> Rgba {
        Rgba {
            red: f32::from(r) / 255.0,
            green: f32::from(g) / 255.0,
            blue: f32::from(b) / 255.0,
            alpha: 1.0,
        }
    }

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
        set_colors: TerminalSetColors,
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
        let copy_clipboard = sym!(
            b"vte_terminal_copy_clipboard_format\0",
            TerminalCopyClipboard
        );
        let char_width = sym!(b"vte_terminal_get_char_width\0", TerminalGetCharWidth);
        let char_height = sym!(b"vte_terminal_get_char_height\0", TerminalGetCharHeight);
        let set_colors = sym!(b"vte_terminal_set_colors\0", TerminalSetColors);

        Some(Api {
            _lib: lib,
            new_terminal,
            feed,
            set_font_scale,
            get_font_scale,
            copy_clipboard,
            char_width,
            char_height,
            set_colors,
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
                (self.api.feed)(
                    self.raw(),
                    data.as_ptr() as *const c_char,
                    data.len() as isize,
                );
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

        /// Задаёт фон, основной текст и 16 цветов ANSI.
        pub fn set_colors(&self, palette: &crate::ui::palette::Palette) {
            let foreground = rgba(palette.foreground);
            let background = rgba(palette.background);
            let ansi: Vec<Rgba> = palette.ansi.iter().copied().map(rgba).collect();
            // SAFETY: терминал жив; указатели валидны на время вызова,
            // GdkRGBA имеет тот же layout, что и наша структура.
            unsafe {
                (self.api.set_colors)(
                    self.raw(),
                    &foreground,
                    &background,
                    ansi.as_ptr(),
                    ansi.len(),
                );
            }
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
    scale: Rc<Cell<f64>>,
    /// Базовый размер шрифта терминала (в пунктах) — из настроек.
    base_font_px: f64,
    /// Текущее оформление вывода (цвет и начертание) для запасного терминала.
    ansi: std::cell::Cell<AnsiState>,
    /// Палитра фона, текста и ANSI-цветов.
    palette: Palette,
    /// Режимы DECCKM/mouse/bracketed paste, разобранные из вывода.
    modes: Cell<TerminalModes>,
    /// Маршрутизатор вывода: обычный TextView или полноэкранная сетка.
    router: RefCell<alt_screen::OutputRouter>,
}

/// Оформление вывода терминала: цвет символов и жирное начертание.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct AnsiState {
    /// Цвет символов (16-битный RGB).
    pub color: Option<(u16, u16, u16)>,
    /// Жирное начертание.
    pub bold: bool,
    /// Предыдущий chunk закончился символом `\r`. Нужен, чтобы отличить
    /// конец строки CRLF от возврата каретки для перерисовки строки.
    pub pending_cr: bool,
}

/// Фрагмент вывода: текст и его оформление.
#[derive(Clone, Debug, PartialEq)]
pub struct Segment {
    /// Текст фрагмента.
    pub text: String,
    /// Цвет символов.
    pub color: Option<(u16, u16, u16)>,
    /// Жирное начертание.
    pub bold: bool,
    /// Текст начинается после возврата каретки: перед вставкой нужно
    /// удалить текущую строку TextView (`readline` и `top` перерисовывают её
    /// через `\r`, а не через CRLF).
    pub clear_line: bool,
}

/// Переводит 8-битный цвет в 16-битный.
fn rgb16(r: u8, g: u8, b: u8) -> (u16, u16, u16) {
    (u16::from(r) * 257, u16::from(g) * 257, u16::from(b) * 257)
}

/// Базовый цвет ANSI (0..7) или яркий вариант (8..15) из палитры.
fn ansi_color(index: u32, bright: bool, palette: &Palette) -> (u16, u16, u16) {
    let slot = (index as usize % 8) + if bright { 8 } else { 0 };
    let (r, g, b) = palette.ansi[slot];
    rgb16(r, g, b)
}

/// Цвет из палитры xterm-256.
fn xterm256(index: u8, palette: &Palette) -> (u16, u16, u16) {
    // Первые 16 цветов задаются схемой терминала.
    if let Some(&(r, g, b)) = palette.ansi.get(index as usize) {
        return rgb16(r, g, b);
    }
    if index < 232 {
        const STEPS: [u8; 6] = [0, 95, 135, 175, 215, 255];
        let i = (index - 16) as usize;
        return rgb16(STEPS[i / 36], STEPS[(i % 36) / 6], STEPS[i % 6]);
    }
    let gray = (8 + (index as u16 - 232) * 10) as u8;
    rgb16(gray, gray, gray)
}

/// Применяет последовательность SGR (параметры без `ESC[` и `m`).
fn apply_sgr(mut state: AnsiState, params: &str, palette: &Palette) -> AnsiState {
    let parts: Vec<&str> = params.split(';').collect();
    let mut i = 0;
    while i < parts.len() {
        let code: u32 = parts[i].parse().unwrap_or(0);
        match code {
            0 => {
                let pending_cr = state.pending_cr;
                state = AnsiState::default();
                state.pending_cr = pending_cr;
            }
            1 => state.bold = true,
            22 => state.bold = false,
            30..=37 => state.color = Some(ansi_color(code - 30, false, palette)),
            90..=97 => state.color = Some(ansi_color(code - 90, true, palette)),
            39 => state.color = None,
            38 => {
                if parts.get(i + 1) == Some(&"5") {
                    if let Some(n) = parts.get(i + 2).and_then(|v| v.parse::<u8>().ok()) {
                        state.color = Some(xterm256(n, palette));
                    }
                    i += 2;
                } else if parts.get(i + 1) == Some(&"2") {
                    let r = parts
                        .get(i + 2)
                        .and_then(|v| v.parse::<u8>().ok())
                        .unwrap_or(0);
                    let g = parts
                        .get(i + 3)
                        .and_then(|v| v.parse::<u8>().ok())
                        .unwrap_or(0);
                    let b = parts
                        .get(i + 4)
                        .and_then(|v| v.parse::<u8>().ok())
                        .unwrap_or(0);
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

/// Разбирает поток с ANSI-последовательностями в сегменты текста.
///
/// `state` — текущее оформление (оно сохраняется между вызовами, поэтому
/// цвет, заданный в одной части потока, действует и в следующей).
pub fn parse_ansi(data: &[u8], state: &mut AnsiState) -> Vec<Segment> {
    parse_ansi_with_palette(data, state, &palette::DARK)
}

/// То же, но с явной палитрой терминала (для ANSI-цветов 0..15).
fn parse_ansi_with_palette(data: &[u8], state: &mut AnsiState, palette: &Palette) -> Vec<Segment> {
    let mut segments: Vec<Segment> = Vec::new();
    let mut text: Vec<u8> = Vec::with_capacity(data.len());
    let mut iter = data.iter().copied().peekable();
    // `\r` в конце chunk не даёт понять, будет ли дальше `\n` (CRLF) или
    // перерисовка строки. Храним его в состоянии до следующего байта.
    let mut pending_cr = state.pending_cr;
    state.pending_cr = false;
    let mut clear_next = false;

    while let Some(byte) = iter.next() {
        if pending_cr {
            match byte {
                b'\n' => pending_cr = false,
                0x1b | 0x0d => {}
                b'\t' | 0x08 => {
                    clear_next = true;
                    pending_cr = false;
                }
                b if b >= 0x20 => {
                    clear_next = true;
                    pending_cr = false;
                }
                _ => pending_cr = false,
            }
        }

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
                    if push_segment(&mut segments, &mut text, *state, clear_next) {
                        clear_next = false;
                    }
                    *state = apply_sgr(*state, &params, palette);
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
                // Двухбайтовые обозначения набора символов: ESC ( B,
                // ESC ) 0 и т.п. Второй байт — не текст, а выбор charset.
                match iter.peek().copied() {
                    Some(b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' | b'#' | b'%') => {
                        iter.next();
                        iter.next();
                    }
                    // Прочие escape-последовательности — игнорируем.
                    Some(_) => {
                        iter.next();
                    }
                    None => {}
                }
            }
            0x0d => {
                if push_segment(&mut segments, &mut text, *state, clear_next) {
                    clear_next = false;
                }
                pending_cr = true;
            }
            0x07 => {}
            0x08 => {
                // Забой — удаляем предыдущий символ.
                if push_segment(&mut segments, &mut text, *state, clear_next) {
                    clear_next = false;
                }
                if let Some(last) = segments.last_mut() {
                    let mut chars: Vec<char> = last.text.chars().collect();
                    chars.pop();
                    last.text = chars.into_iter().collect();
                }
            }
            b'\n' | b'\t' => text.push(byte),
            b if b >= 0x20 => text.push(b),
            _ => {}
        }
    }

    let _ = push_segment(&mut segments, &mut text, *state, clear_next);
    state.pending_cr = pending_cr;
    segments
}

/// Добавляет накопленный текст в список сегментов.
///
/// Возвращает `true`, если сегмент был добавлен.
fn push_segment(
    segments: &mut Vec<Segment>,
    text: &mut Vec<u8>,
    state: AnsiState,
    clear_line: bool,
) -> bool {
    if text.is_empty() {
        return false;
    }
    let content = String::from_utf8_lossy(text).into_owned();
    text.clear();
    segments.push(Segment {
        text: content,
        color: state.color,
        bold: state.bold,
        clear_line,
    });
    true
}

/// Разбирает поток с ANSI-последовательностями и выводит текст с цветами.
fn feed_ansi(view: &TextView, data: &[u8], state: &std::cell::Cell<AnsiState>, palette: &Palette) {
    let mut current = state.get();
    let segments = parse_ansi_with_palette(data, &mut current, palette);
    state.set(current);

    let buffer = view.buffer();

    for segment in segments {
        if segment.clear_line {
            truncate_current_line(&buffer);
        }
        let mut end = buffer.end_iter();
        let escaped = segment
            .text
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;");
        let markup = match segment.color {
            Some((r, g, b)) => {
                let bold = if segment.bold { "<b>" } else { "" };
                let bold_end = if segment.bold { "</b>" } else { "" };
                format!(
                    "<span foreground=\"#{r:04x}{g:04x}{b:04x}\">{bold}{escaped}{bold_end}</span>"
                )
            }
            None => {
                if segment.bold {
                    format!("<b>{escaped}</b>")
                } else {
                    escaped
                }
            }
        };
        buffer.insert_markup(&mut end, &markup);
    }

    let mut end = buffer.end_iter();
    view.scroll_to_iter(&mut end, 0.0, false, 0.0, 1.0);
}

/// Удаляет текущую (последнюю) строку TextView перед перерисовкой через `\r`.
fn truncate_current_line(buffer: &gtk4::TextBuffer) {
    let mut end = buffer.end_iter();
    let mut start = end;
    while !start.starts_line() {
        if !start.backward_char() {
            break;
        }
    }
    buffer.delete(&mut start, &mut end);
}

enum Kind {
    Vte(vte_dynamic::Terminal),
    Text {
        view: TextView,
        provider: CssProvider,
        /// Обычный TextView и полноэкранная сетка лежат в Stack.
        stack: Stack,
        draw: DrawingArea,
        screen: Rc<RefCell<alt_screen::Screen>>,
    },
}

impl TerminalView {
    /// Создаёт терминал внутри `scroll`: VTE, если библиотека доступна.
    fn new(scroll: &ScrolledWindow, font_size: i64, palette: Palette) -> Self {
        let base_font_px = (font_size.clamp(8, 32) as f64).max(8.0);
        // Масштаб VTE приводим к базовому размеру шрифта.
        let scale_value = (base_font_px / BASE_FONT_PX).clamp(0.5, 3.0);
        let scale = Rc::new(Cell::new(scale_value));
        if let Some(vte) = vte_dynamic::Terminal::new() {
            vte.set_colors(&palette);
            let widget = vte.widget().clone();
            scroll.set_child(Some(&widget));
            return Self {
                widget,
                kind: Kind::Vte(vte),
                scale,
                base_font_px,
                ansi: Cell::new(AnsiState::default()),
                palette,
                modes: Cell::new(TerminalModes::default()),
                router: RefCell::new(alt_screen::OutputRouter::new()),
            };
        }

        // Запасной вариант: TextView для обычного вывода + DrawingArea для
        // полноэкранных приложений (mc/vim/top). Без второй страницы
        // TextView не умеет cursor addressing и `mc` выглядит «мёртвым».
        let view = TextView::new();
        view.set_editable(false);
        view.set_cursor_visible(false);
        view.set_monospace(true);
        view.set_focusable(true);
        view.set_can_focus(true);
        view.add_css_class("remotix-terminal");
        view.set_wrap_mode(gtk4::WrapMode::Char);
        let provider = CssProvider::new();
        apply_text_style(&view, &provider, 1.0, base_font_px, &palette);

        let screen = Rc::new(RefCell::new(alt_screen::Screen::new(80, 24)));
        let draw = DrawingArea::new();
        draw.set_hexpand(true);
        draw.set_vexpand(true);
        draw.set_focusable(true);
        draw.set_can_focus(true);
        draw.add_css_class("remotix-terminal-alt");

        {
            let screen = screen.clone();
            let scale = scale.clone();
            draw.set_draw_func(move |area, cr, width, height| {
                let screen = screen.borrow();
                let font_px = base_font_px * scale.get();
                render_alt_screen(area, cr, width, height, &screen, &palette, font_px);
            });
        }

        let stack = Stack::new();
        stack.set_hexpand(true);
        stack.set_vexpand(true);
        stack.add_named(&view, Some("text"));
        stack.add_named(&draw, Some("alt"));
        stack.set_visible_child_name("text");
        scroll.set_child(Some(&stack));
        let widget = stack.clone().upcast::<gtk4::Widget>();
        Self {
            widget,
            kind: Kind::Text {
                view,
                provider,
                stack,
                draw,
                screen,
            },
            scale,
            base_font_px,
            ansi: Cell::new(AnsiState::default()),
            palette,
            modes: Cell::new(TerminalModes::default()),
            router: RefCell::new(alt_screen::OutputRouter::new()),
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
    ///
    /// Возвращает ответы терминала (например, CPR `ESC[row;colR`), которые
    /// нужно отправить в SSH-канал. Ответы нужны полноэкранным приложениям:
    /// без них `mc` не может определить позицию курсора.
    fn feed(&self, data: &[u8]) -> Vec<u8> {
        match &self.kind {
            Kind::Vte(term) => {
                // VTE сам разбирает альтернативный экран, но режимы (DECCKM,
                // mouse reporting, bracketed paste) нам нужны для ввода.
                let _ = self.router.borrow_mut().route(data);
                self.modes.set(self.router.borrow().modes());
                term.feed(data);
                Vec::new()
            }
            Kind::Text {
                view,
                stack,
                draw,
                screen,
                ..
            } => {
                let chunks = self.router.borrow_mut().route(data);
                self.modes.set(self.router.borrow().modes());
                let mut responses = Vec::new();
                let mut visible_alt = stack.visible_child_name().as_deref() == Some("alt");

                for chunk in chunks {
                    if chunk.alt != visible_alt {
                        visible_alt = chunk.alt;
                        if visible_alt {
                            // Входим в полноэкранный режим: старый текст
                            // остаётся в TextView, сетка начинается с чистого
                            // экрана (как ?1049).
                            screen.borrow_mut().reset();
                            stack.set_visible_child_name("alt");
                            draw.grab_focus();
                        } else {
                            stack.set_visible_child_name("text");
                            view.grab_focus();
                        }
                    }

                    if chunk.alt {
                        let mut screen = screen.borrow_mut();
                        screen.feed(&chunk.data);
                        responses.extend_from_slice(&screen.take_responses());
                        drop(screen);
                        draw.queue_draw();
                    } else {
                        // ANSI-последовательности разбираются и превращаются
                        // в цвет и начертание символов обычного вывода.
                        feed_ansi(view, &chunk.data, &self.ansi, &self.palette);
                    }
                }
                responses
            }
        }
    }

    /// Изменяет масштаб шрифта (Ctrl + «+» / Ctrl + «-»).
    fn zoom(&self, factor: f64) {
        let next = (self.scale.get() * factor).clamp(FONT_SCALE_MIN, FONT_SCALE_MAX);
        self.scale.set(next);
        match &self.kind {
            Kind::Vte(term) => term.set_font_scale(next),
            Kind::Text {
                view,
                provider,
                draw,
                ..
            } => {
                let base = self.base_font_px;
                apply_text_style(view, provider, next, base, &self.palette);
                draw.queue_draw();
            }
        }
    }

    /// Копирует текст терминала в буфер обмена.
    fn copy_clipboard(&self) {
        match &self.kind {
            Kind::Vte(term) => term.copy_clipboard_text(),
            Kind::Text {
                view,
                stack,
                screen,
                ..
            } => {
                if stack.visible_child_name().as_deref() == Some("alt") {
                    self.widget.clipboard().set_text(&screen.borrow().text());
                } else {
                    let buffer = view.buffer();
                    let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
                    self.widget.clipboard().set_text(&text);
                }
            }
        }
    }

    /// Вставляет текст из буфера обмена в удалённую сессию.
    fn paste_clipboard(&self, tx: Sender<ToThread>) {
        let clipboard = self.widget.clipboard();
        let bracketed = self.modes.get().bracketed_paste;
        glib::spawn_future_local(async move {
            if let Ok(Some(text)) = clipboard.read_text_future().await {
                let text = text.replace('\n', "\r");
                let bytes = if bracketed {
                    format!("\x1b[200~{text}\x1b[201~").into_bytes()
                } else {
                    text.into_bytes()
                };
                let _ = tx.send(ToThread::Data(bytes));
            }
        });
    }

    /// Подгоняет сетку полноэкранного терминала под размер PTY.
    fn resize(&self, cols: u32, rows: u32) {
        if let Kind::Text { screen, draw, .. } = &self.kind {
            screen
                .borrow_mut()
                .resize(cols.max(2) as usize, rows.max(2) as usize);
            draw.queue_draw();
        }
    }

    /// Размер символа в пикселях — для расчёта колонок и строк PTY.
    fn char_size(&self) -> (i32, i32) {
        match &self.kind {
            Kind::Vte(term) => {
                let (w, h) = term.char_size();
                (w.max(1), h.max(1))
            }
            Kind::Text { .. } => {
                let font_px = self.base_font_px * self.scale.get();
                measure_char(self.widget(), font_px)
            }
        }
    }

    /// Передаёт фокус активной странице терминала.
    fn focus(&self) {
        match &self.kind {
            Kind::Vte(term) => {
                term.widget().grab_focus();
            }
            Kind::Text {
                view, stack, draw, ..
            } => {
                if stack.visible_child_name().as_deref() == Some("alt") {
                    draw.grab_focus();
                } else {
                    view.grab_focus();
                }
            }
        }
    }
}

/// Размер моноширинного символа в пикселях через Pango.
fn measure_char(widget: &gtk4::Widget, font_px: f64) -> (i32, i32) {
    let layout = widget.create_pango_layout(Some("MMMMMMMMMM"));
    let mut desc = pango::FontDescription::from_string("monospace");
    desc.set_absolute_size(font_px * f64::from(pango::SCALE));
    layout.set_font_description(Some(&desc));
    let (width, height) = layout.pixel_size();
    ((width / 10).max(1), height.max(1))
}

/// Цвет ячейки в RGBA (0..1).
fn cell_color(
    color: alt_screen::Color,
    palette: &Palette,
    default: (u8, u8, u8),
) -> (f64, f64, f64) {
    match color {
        alt_screen::Color::Default => (
            f64::from(default.0) / 255.0,
            f64::from(default.1) / 255.0,
            f64::from(default.2) / 255.0,
        ),
        alt_screen::Color::Indexed(index) => {
            let (r, g, b) = xterm256(index, palette);
            (
                f64::from(r) / 65535.0,
                f64::from(g) / 65535.0,
                f64::from(b) / 65535.0,
            )
        }
        alt_screen::Color::Rgb(r, g, b) => (
            f64::from(r) / 255.0,
            f64::from(g) / 255.0,
            f64::from(b) / 255.0,
        ),
    }
}

/// Рисует полноэкранную сетку (альтернативный экран) в `DrawingArea`.
fn render_alt_screen(
    area: &DrawingArea,
    cr: &gtk4::cairo::Context,
    width: i32,
    height: i32,
    screen: &alt_screen::Screen,
    palette: &Palette,
    font_px: f64,
) {
    let (char_w, char_h) = measure_char(area.upcast_ref(), font_px);
    let (char_w, char_h) = (char_w.max(1) as f64, char_h.max(1) as f64);
    let (br, bg, bb) = palette.background;
    cr.set_source_rgb(
        f64::from(br) / 255.0,
        f64::from(bg) / 255.0,
        f64::from(bb) / 255.0,
    );
    cr.rectangle(0.0, 0.0, f64::from(width), f64::from(height));
    let _ = cr.fill();

    let mut desc = pango::FontDescription::from_string("monospace");
    desc.set_absolute_size(font_px * f64::from(pango::SCALE));

    for y in 0..screen.rows() {
        for x in 0..screen.cols() {
            let cell = screen.cell(x, y);
            if cell.ch == '\0' {
                continue;
            }
            let style = cell.style;
            let (_, bg_color) = if style.reverse {
                (style.bg, style.fg)
            } else {
                (style.fg, style.bg)
            };
            let (bg_r, bg_g, bg_b) = cell_color(bg_color, palette, palette.background);
            let default_bg = !style.reverse && bg_color == alt_screen::Color::Default;
            if !default_bg {
                cr.set_source_rgb(bg_r, bg_g, bg_b);
                cr.rectangle(x as f64 * char_w, y as f64 * char_h, char_w, char_h);
                let _ = cr.fill();
            }
        }
    }

    // Текстовые прогоны: рисуем подряд идущие ячейки с одинаковым стилем
    // одним PangoLayout, чтобы не создавать layout на каждый символ.
    for y in 0..screen.rows() {
        let mut x = 0;
        while x < screen.cols() {
            let first = screen.cell(x, y);
            if first.ch == '\0' {
                x += 1;
                continue;
            }
            let style = first.style;
            let mut run = String::new();
            let mut width_cells = 0;
            while x + width_cells < screen.cols() {
                let cell = screen.cell(x + width_cells, y);
                if cell.ch == '\0' {
                    width_cells += 1;
                    continue;
                }
                if cell.style != style {
                    break;
                }
                run.push(cell.ch);
                width_cells += 1;
            }
            if run.is_empty() {
                x += width_cells.max(1);
                continue;
            }

            let (fg, bg) = if style.reverse {
                (style.bg, style.fg)
            } else {
                (style.fg, style.bg)
            };
            let (fr, fg_g, fb) = cell_color(fg, palette, palette.foreground);
            let (br, bg_g, bb) = cell_color(bg, palette, palette.background);
            if style.reverse {
                cr.set_source_rgb(br, bg_g, bb);
                cr.rectangle(
                    x as f64 * char_w,
                    y as f64 * char_h,
                    width_cells as f64 * char_w,
                    char_h,
                );
                let _ = cr.fill();
            }

            let layout = area.create_pango_layout(Some(&run));
            let mut desc = desc.clone();
            if style.bold {
                desc.set_weight(pango::Weight::Bold);
            }
            layout.set_font_description(Some(&desc));
            cr.set_source_rgb(fr, fg_g, fb);
            cr.move_to(x as f64 * char_w, y as f64 * char_h);
            pango_cairo::show_layout(cr, &layout);
            if style.underline {
                let underline_y = (y as f64 + 1.0) * char_h - 1.0;
                cr.set_line_width(1.0);
                cr.move_to(x as f64 * char_w, underline_y);
                cr.line_to((x + width_cells) as f64 * char_w, underline_y);
                let _ = cr.stroke();
            }
            x += width_cells.max(1);
        }
    }

    if screen.cursor_visible() {
        let (cx, cy) = screen.cursor();
        if cx < screen.cols() && cy < screen.rows() {
            let (fr, fg, fb) = palette.foreground;
            cr.set_source_rgb(
                f64::from(fr) / 255.0,
                f64::from(fg) / 255.0,
                f64::from(fb) / 255.0,
            );
            cr.rectangle(cx as f64 * char_w, cy as f64 * char_h, char_w, char_h);
            let _ = cr.fill();
        }
    }
}

/// Применяет моноширинный шрифт нужного размера к резервному TextView.
fn apply_text_style(
    view: &TextView,
    provider: &CssProvider,
    scale: f64,
    base_font_px: f64,
    palette: &Palette,
) {
    let size = (base_font_px * scale).round() as i32;
    let (br, bg, bb) = palette.background;
    let (fr, fg, fb) = palette.foreground;
    let css = format!(
        "textview.remotix-terminal {{ \
             font-family: monospace; font-size: {size}px; \
             background-color: #{br:02x}{bg:02x}{bb:02x}; \
             color: #{fr:02x}{fg:02x}{fb:02x}; \
         }}"
    );
    provider.load_from_data(&css);
    #[allow(deprecated)]
    view.style_context()
        .add_provider(provider, gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION);
}

/// Снимает показатели хоста отдельным exec-каналом в той же SSH-сессии.
///
/// Сессия переведена в неблокирующий режим, поэтому каждый шаг может вернуть
/// `WouldBlock` — повторяем с паузой до дедлайна `METRICS_TIMEOUT`. Вывод
/// ограничен 1 МБ. Главный канал терминала при этом не трогаем: его данные
/// буферизуются на транспорте.
/// В неблокирующем режиме libssh2 сигнализирует «пока не готово» кодом EAGAIN.
fn ssh_would_block(e: &ssh2::Error) -> bool {
    e.code() == ssh2::ErrorCode::Session(libssh2_sys::LIBSSH2_ERROR_EAGAIN)
}

fn collect_metrics(
    session: &ssh2::Session,
    prev: Option<crate::protocols::metrics::Counters>,
    elapsed: Duration,
) -> Result<crate::protocols::metrics::MetricsSample, String> {
    use std::io::Read;

    let deadline = std::time::Instant::now() + crate::protocols::metrics::METRICS_TIMEOUT;
    let expired = |step: &str| {
        Err(format!(
            "не дождались {step} за {} с",
            crate::protocols::metrics::METRICS_TIMEOUT.as_secs()
        ))
    };

    let mut ch = loop {
        match session.channel_session() {
            Ok(ch) => break ch,
            Err(e) if ssh_would_block(&e) => {
                if std::time::Instant::now() >= deadline {
                    return expired("открытия канала");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    };
    loop {
        match ch.exec(crate::protocols::metrics::METRICS_COMMAND) {
            Ok(()) => break,
            Err(e) if ssh_would_block(&e) => {
                if std::time::Instant::now() >= deadline {
                    return expired("запуска команды");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; 16384];
        match ch.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > 1024 * 1024 {
                    return Err("слишком большой вывод команды метрик".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    // Отдаём накопленное: если ==END== уже пришёл, sample()
                    // разберёт; иначе вернёт понятную ошибку.
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e.to_string()),
        }
    }

    let text = String::from_utf8_lossy(&out);
    crate::protocols::metrics::sample(&text, prev.as_ref(), elapsed)
}

impl TerminalTab {
    /// Открывает SSH-сессию в новом терминале: VTE, если библиотека есть в
    /// системе, иначе — упрощённый терминал с тем же вводом/выводом.
    ///
    /// `on_state` сообщает об изменении состояния сессии (подключение,
    /// ошибка, закрытие) — её вывод показывается в строке состояния окна.
    /// `metrics_enabled` включает панель метрик хоста (опрос раз в 5 с).
    /// `recording_enabled` включает запись вывода сессии в формат
    /// script(1)/scriptreplay(1) — файлы в `<данные>/recordings`.
    /// `expect_rules` — автоответы: при совпадении шаблона с окном вывода
    /// в канал отправляется строка правила (см. `crate::expect`).
    pub fn new_ssh(
        title: &str,
        conn: SshConnection,
        on_state: Rc<dyn Fn(crate::ui::SessionState)>,
        font_size: i64,
        metrics_enabled: bool,
        recording_enabled: bool,
        extras: TerminalExtras,
    ) -> Result<Self, String> {
        let TerminalExtras {
            expect_rules,
            snippets,
            palette,
        } = extras;
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);

        // Панель метрик: полоса загрузки CPU + краткий текст.
        let metrics_box = GtkBox::new(gtk4::Orientation::Horizontal, 8);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            metrics_box.set_property(m, 4);
        }
        let metrics_bar = gtk4::LevelBar::builder()
            .min_value(0.0)
            .max_value(100.0)
            .value(0.0)
            .valign(gtk4::Align::Center)
            .width_request(120)
            .height_request(6)
            .build();
        let metrics_label = Label::new(None);
        metrics_label.add_css_class("remotix-field-caption");
        metrics_label.set_hexpand(true);
        metrics_label.set_xalign(0.0);
        metrics_box.append(&metrics_bar);
        metrics_box.append(&metrics_label);
        metrics_box.set_visible(false);

        let scroll = ScrolledWindow::new();
        scroll.set_vexpand(true);
        root.append(&metrics_box);
        root.append(&scroll);

        let term = Rc::new(TerminalView::new(&scroll, font_size, palette));

        let (tx_in, rx_in) = mpsc::channel::<ToThread>();
        let (tx_out, rx_out) = mpsc::channel::<ToUi>();
        let (tx_hk_prompt, rx_hk_prompt) = mpsc::channel::<HostKeyPrompt>();
        let (tx_hk_answer, rx_hk_answer) = mpsc::channel::<bool>();

        // Меню сниппетов: сохранённые команды отправляются в канал с Enter.
        // Строка меню появляется только если сниппеты есть.
        if !snippets.is_empty() {
            let bar = GtkBox::new(gtk4::Orientation::Horizontal, 6);
            bar.set_margin_top(4);
            bar.set_margin_bottom(4);
            bar.set_margin_start(6);
            bar.set_margin_end(6);

            let menu = MenuButton::builder().label("Сниппеты").build();
            menu.add_css_class("flat");
            let popover = Popover::new();
            let items = GtkBox::new(gtk4::Orientation::Vertical, 2);
            for snippet in snippets {
                let button = Button::with_label(&snippet.name);
                button.add_css_class("flat");
                button.set_halign(gtk4::Align::Fill);
                button.set_tooltip_text(Some(&snippet.command));
                let tx = tx_in.clone();
                let popover_ref = popover.clone();
                button.connect_clicked(move |_| {
                    // Команда вводится как в терминале: Enter в конце.
                    let mut command = snippet.command.trim_end_matches(['\r', '\n']).to_string();
                    command.push('\r');
                    let _ = tx.send(ToThread::Data(command.into_bytes()));
                    popover_ref.popdown();
                });
                items.append(&button);
            }
            popover.set_child(Some(&items));
            menu.set_popover(Some(&popover));
            bar.append(&menu);
            root.prepend(&bar);
        }

        // Пока сессия жива: по закрытии/ошибке гасим и таймер метрик.
        let alive = Rc::new(Cell::new(true));

        // Поток: подключение, shell/su → root, неблокирующий цикл обмена.
        std::thread::spawn(move || {
            use std::io::Write;

            let mut conn = conn;
            let verifier = move |prompt: &HostKeyPrompt| {
                tx_hk_prompt.send(prompt.clone()).is_ok()
                    && rx_hk_answer
                        .recv_timeout(Duration::from_secs(300))
                        .unwrap_or(false)
            };
            let host_key = HostKeyConfig {
                accept_new: false,
                verifier: Some(&verifier),
                ..Default::default()
            };
            if let Err(e) = conn.connect_with(&host_key) {
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
                ch.request_pty("xterm", None, None)
                    .map_err(|e| e.to_string())?;
                if su {
                    ch.exec("su -").map_err(|e| e.to_string())?;
                    wait_password(
                        &mut ch,
                        &mut session,
                        conn.profile
                            .root_password
                            .as_ref()
                            .map(|p| p.expose_secret())
                            .unwrap_or_default(),
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

            // Запись сессии (включается в настройках). Ошибки записи диска
            // не должны прерывать работу терминала — они фиксируются в
            // журнале, сессия продолжается.
            let command = match conn.profile.username.as_deref() {
                Some(u) if !u.trim().is_empty() => format!("ssh {u}@{}", conn.profile.host),
                _ => format!("ssh {}", conn.profile.host),
            };
            let mut recording = if recording_enabled {
                match crate::recording::Recording::start(
                    &crate::recording::recordings_dir(),
                    &command,
                ) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        crate::logging::warn(&format!("запись сессии не началась: {e}"));
                        None
                    }
                }
            } else {
                None
            };
            // Код выхода для итоговой строки записи (1 — сессия оборвалась
            // ошибкой, 0 — штатное закрытие).
            let mut failed = false;

            // Expect-правила: автоответы на промпты. Строки ответов живут
            // в SecretString и открываются только в момент отправки.
            let mut expect = crate::expect::ExpectEngine::new(expect_rules);

            session.set_blocking(false);
            let mut buf = [0u8; 8192];
            let mut last_keepalive = std::time::Instant::now();
            // Счётчики для дельт CPU/сети (см. protocols::metrics::sample).
            let mut prev_counters: Option<crate::protocols::metrics::Counters> = None;
            let mut last_counters_at: Option<std::time::Instant> = None;
            loop {
                // В неблокирующем режиме libssh2 не шлёт keepalive сам:
                // раз в 5 секунд проверяем, не пора ли отправить пустой пакет
                // (интервал задан в connect_with — 30 секунд).
                if last_keepalive.elapsed() >= Duration::from_secs(5) {
                    let _ = session.keepalive_send();
                    last_keepalive = std::time::Instant::now();
                }
                match ch.read(&mut buf) {
                    Ok(0) => {
                        let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Closed));
                        break;
                    }
                    Ok(n) => {
                        if let Some(r) = recording.as_mut() {
                            let _ = r.write_out(&buf[..n]);
                        }
                        for bytes in expect.on_output(&buf[..n]) {
                            let _ = ch.write_all(&bytes);
                        }
                        if tx_out.send(ToUi::Out(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        failed = true;
                        let _ = tx_out
                            .send(ToUi::State(crate::ui::SessionState::Failed(e.to_string())));
                        break;
                    }
                }
                match rx_in.recv_timeout(Duration::from_millis(PROMPT_MS)) {
                    Ok(ToThread::Data(d)) => {
                        let _ = ch.write_all(&d);
                    }
                    Ok(ToThread::Resize(c, r)) => {
                        let _ = ch.request_pty_size(c, r, None, None);
                    }
                    Ok(ToThread::Metrics) => {
                        // Второй exec-канал в той же сессии; чтение
                        // неблокирующее, с дедлайном — поток не замирает.
                        let elapsed = last_counters_at
                            .map(|t| t.elapsed())
                            .unwrap_or(Duration::ZERO);
                        match collect_metrics(&session, prev_counters, elapsed) {
                            Ok(s) => {
                                if tx_out.send(ToUi::Metrics(s.metrics)).is_err() {
                                    break;
                                }
                                prev_counters = Some(s.counters);
                                last_counters_at = Some(std::time::Instant::now());
                            }
                            Err(_) => {
                                let _ = tx_out.send(ToUi::MetricsFailed);
                            }
                        }
                    }
                    Err(_) => {}
                }
                if ch.eof() {
                    let _ = tx_out.send(ToUi::State(crate::ui::SessionState::Closed));
                    break;
                }
            }
            // Финализация записи (typescript + timing) до разрыва сессии.
            if let Some(r) = recording.take() {
                let _ = r.finish(if failed { 1 } else { 0 });
            }
            let _ = session.disconnect(None, "закрыто пользователем", None);
        });

        // Опрос вывода канала (главный поток) → кормим терминал.
        let term_out = term.clone();
        let tx_responses = tx_in.clone();
        let status = Label::new(None);
        status.set_halign(gtk4::Align::Start);
        let status_out = status.clone();
        let state_cb = on_state.clone();
        let metrics_bar_out = metrics_bar.clone();
        let metrics_label_out = metrics_label.clone();
        let metrics_box_out = metrics_box.clone();
        let alive_out = alive.clone();
        let metrics_ok = Rc::new(Cell::new(true));
        let metrics_ok_out = metrics_ok.clone();
        let mut metrics_fails: u32 = 0;
        glib::timeout_add_local(Duration::from_millis(PROMPT_MS), move || {
            loop {
                match rx_out.try_recv() {
                    Ok(ToUi::Out(data)) => {
                        let responses = term_out.feed(&data);
                        if !responses.is_empty() {
                            let _ = tx_responses.send(ToThread::Data(responses));
                        }
                    }
                    Ok(ToUi::Metrics(m)) => {
                        if let Some(cpu) = m.cpu_percent {
                            metrics_bar_out.set_value(cpu.clamp(0.0, 100.0));
                        }
                        metrics_label_out.set_text(&m.summary());
                        metrics_box_out.set_visible(true);
                        metrics_fails = 0;
                    }
                    Ok(ToUi::MetricsFailed) => {
                        // Три неудачи подряд → считаем метрики недоступными
                        // и гасим панель (таймер тоже остановится).
                        metrics_fails += 1;
                        if metrics_fails >= 3 {
                            metrics_box_out.set_visible(false);
                            metrics_ok_out.set(false);
                        }
                    }
                    Ok(ToUi::State(state)) => {
                        if matches!(
                            state,
                            crate::ui::SessionState::Closed | crate::ui::SessionState::Failed(_)
                        ) {
                            alive_out.set(false);
                        }
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

        // Неизвестный ключ хоста: поток подключения ждёт ответа, диалог
        // показываем в главном потоке GTK.
        {
            let tx_hk_answer = tx_hk_answer.clone();
            let parent_weak = root.downgrade();
            glib::timeout_add_local(Duration::from_millis(100), move || loop {
                match rx_hk_prompt.try_recv() {
                    Ok(prompt) => {
                        let tx_answer = tx_hk_answer.clone();
                        let parent = parent_weak
                            .upgrade()
                            .and_then(|widget| widget.root())
                            .and_then(|root| root.downcast::<gtk4::Window>().ok());
                        crate::ui::host_key::ask_unknown(
                            parent.as_ref(),
                            prompt,
                            move |accepted| {
                                let _ = tx_answer.send(accepted);
                            },
                        );
                    }
                    Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                    Err(mpsc::TryRecvError::Disconnected) => return glib::ControlFlow::Break,
                }
            });
        }

        // Таймер метрик: раз в 5 секунд просим поток снять показатели.
        // Останавливается при закрытии сессии и после трёх неудач опроса.
        if metrics_enabled {
            let tx_metrics = tx_in.clone();
            let alive_metrics = alive.clone();
            let metrics_ok_timer = metrics_ok.clone();
            glib::timeout_add_local(Duration::from_secs(5), move || {
                if !alive_metrics.get() || !metrics_ok_timer.get() {
                    return glib::ControlFlow::Break;
                }
                let _ = tx_metrics.send(ToThread::Metrics);
                glib::ControlFlow::Continue
            });
        }

        setup_input(&term, &scroll, tx_in);
        // Вкладка создаётся до показа в окне; фокус выдаём, когда виджет
        // уже прикреплён к окну, иначе клавиатура не работает до клика.
        let term_focus = term.clone();
        glib::idle_add_local_once(move || term_focus.focus());
        Ok(Self {
            root,
            title: title.to_string(),
        })
    }
}

/// Управляющий байт для Ctrl+символ.
fn ctrl_byte(ch: char) -> Option<u8> {
    let ch = ch.to_ascii_lowercase();
    match ch {
        'a'..='z' => Some(ch as u8 - b'a' + 1),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        '@' | ' ' => Some(0x00),
        '?' => Some(0x7f),
        _ => None,
    }
}

/// Кодирует клавишу в байты для удалённого PTY.
///
/// `name` — имя GDK (`Up`, `F5`, `Return`…), `unicode` — печатный символ.
/// Функция не зависит от GTK, поэтому покрыта обычными unit-тестами.
fn encode_key_parts(
    name: Option<&str>,
    unicode: Option<char>,
    ctrl: bool,
    alt: bool,
    shift: bool,
    modes: TerminalModes,
) -> Option<Vec<u8>> {
    // AltGr в X11 часто приходит как Ctrl+Alt. Если при этом есть печатный
    // символ, это не Ctrl+Alt+буква, а обычный ввод (например, «@»).
    let altgr_text = ctrl && alt && unicode.map(|ch| !ch.is_ascii_control()).unwrap_or(false);
    let (ctrl, alt) = if altgr_text {
        (false, false)
    } else {
        (ctrl, alt)
    };

    let modifier =
        1 + if shift { 1 } else { 0 } + if alt { 2 } else { 0 } + if ctrl { 4 } else { 0 };
    let modified = |base: &str, final_byte: char| -> Vec<u8> {
        if modifier == 1 {
            base.as_bytes().to_vec()
        } else {
            format!("\x1b[1;{modifier}{final_byte}").into_bytes()
        }
    };

    let special = match name {
        Some("Return") | Some("KP_Enter") => Some(if alt {
            b"\x1b\r".to_vec()
        } else {
            b"\r".to_vec()
        }),
        Some("BackSpace") => Some(if ctrl {
            b"\x08".to_vec()
        } else {
            b"\x7f".to_vec()
        }),
        Some("Tab") => Some(if shift {
            b"\x1b[Z".to_vec()
        } else if alt {
            b"\x1b\t".to_vec()
        } else {
            b"\t".to_vec()
        }),
        Some("ISO_Left_Tab") => Some(b"\x1b[Z".to_vec()),
        Some("Escape") => Some(if alt {
            b"\x1b\x1b".to_vec()
        } else {
            b"\x1b".to_vec()
        }),
        Some("Up") => Some(if modifier == 1 && modes.app_cursor {
            b"\x1bOA".to_vec()
        } else {
            modified("\x1b[A", 'A')
        }),
        Some("Down") => Some(if modifier == 1 && modes.app_cursor {
            b"\x1bOB".to_vec()
        } else {
            modified("\x1b[B", 'B')
        }),
        Some("Right") => Some(if modifier == 1 && modes.app_cursor {
            b"\x1bOC".to_vec()
        } else {
            modified("\x1b[C", 'C')
        }),
        Some("Left") => Some(if modifier == 1 && modes.app_cursor {
            b"\x1bOD".to_vec()
        } else {
            modified("\x1b[D", 'D')
        }),
        Some("Home") => Some(if modifier == 1 && modes.app_cursor {
            b"\x1bOH".to_vec()
        } else {
            modified("\x1b[H", 'H')
        }),
        Some("End") => Some(if modifier == 1 && modes.app_cursor {
            b"\x1bOF".to_vec()
        } else {
            modified("\x1b[F", 'F')
        }),
        Some("Insert") => Some(if modifier == 1 {
            b"\x1b[2~".to_vec()
        } else {
            format!("\x1b[2;{modifier}~").into_bytes()
        }),
        Some("Delete") => Some(if modifier == 1 {
            b"\x1b[3~".to_vec()
        } else {
            format!("\x1b[3;{modifier}~").into_bytes()
        }),
        Some("Prior") | Some("Page_Up") => Some(if modifier == 1 {
            b"\x1b[5~".to_vec()
        } else {
            format!("\x1b[5;{modifier}~").into_bytes()
        }),
        Some("Next") | Some("Page_Down") => Some(if modifier == 1 {
            b"\x1b[6~".to_vec()
        } else {
            format!("\x1b[6;{modifier}~").into_bytes()
        }),
        Some("F1") => Some(f_key(1, modifier)),
        Some("F2") => Some(f_key(2, modifier)),
        Some("F3") => Some(f_key(3, modifier)),
        Some("F4") => Some(f_key(4, modifier)),
        Some("F5") => Some(f_key(5, modifier)),
        Some("F6") => Some(f_key(6, modifier)),
        Some("F7") => Some(f_key(7, modifier)),
        Some("F8") => Some(f_key(8, modifier)),
        Some("F9") => Some(f_key(9, modifier)),
        Some("F10") => Some(f_key(10, modifier)),
        Some("F11") => Some(f_key(11, modifier)),
        Some("F12") => Some(f_key(12, modifier)),
        _ => None,
    };
    if special.is_some() {
        return special;
    }

    let ch = unicode?;
    if ctrl {
        if let Some(byte) = ctrl_byte(ch) {
            return Some(if alt { vec![0x1b, byte] } else { vec![byte] });
        }
    }
    let mut bytes = ch.to_string().into_bytes();
    if alt {
        bytes.insert(0, 0x1b);
    }
    Some(bytes)
}

/// Escape-последовательность функциональной клавиши F1..F12.
fn f_key(number: u8, modifier: u32) -> Vec<u8> {
    // F1..F4 — SS3 без модификаторов, F5..F12 — CSI.
    let code = match number {
        1..=4 => b"PQRS"[usize::from(number - 1)] as char,
        _ => {
            let code = match number {
                5 => 15,
                6 => 17,
                7 => 18,
                8 => 19,
                9 => 20,
                10 => 21,
                11 => 23,
                12 => 24,
                _ => return Vec::new(),
            };
            if modifier == 1 {
                return format!("\x1b[{code}~").into_bytes();
            }
            return format!("\x1b[{code};{modifier}~").into_bytes();
        }
    };
    if modifier == 1 {
        format!("\x1bO{code}").into_bytes()
    } else {
        format!("\x1b[1;{modifier}{code}").into_bytes()
    }
}

/// Кодирует xterm mouse-report. `button`: 0 — левая, 1 — средняя, 2 — правая,
/// 64/65 — колесо вверх/вниз (и 66/67 — горизонтальное).
fn mouse_sequence(
    button: u8,
    col: u32,
    row: u32,
    release: bool,
    motion: bool,
    modes: TerminalModes,
) -> Option<Vec<u8>> {
    if modes.mouse == MouseMode::Off {
        return None;
    }
    // X10 передаёт только нажатия.
    if modes.mouse == MouseMode::X10 && (release || motion) {
        return None;
    }
    // 1000 не передаёт движение; 1002 — только с зажатой кнопкой (это
    // проверяет вызывающая сторона), 1003 — любое.
    if motion && matches!(modes.mouse, MouseMode::Normal) {
        return None;
    }

    if modes.sgr_mouse {
        let mut code = u16::from(button);
        if motion {
            code += 32;
        }
        if release {
            Some(format!("\x1b[<{code};{};{}m", col + 1, row + 1).into_bytes())
        } else {
            Some(format!("\x1b[<{code};{};{}M", col + 1, row + 1).into_bytes())
        }
    } else {
        let code = if release { 3 } else { button } + 32;
        let x = (col + 33).min(255) as u8;
        let y = (row + 33).min(255) as u8;
        Some(vec![0x1b, b'[', b'M', code, x, y])
    }
}

/// Размер PTY при изменении размеров терминала: опрос по таймеру —
/// сигнала size-allocate в gtk4-rs 0.9 нет, а это работает на любых
/// версиях GTK (окно терминала меняется редко, 500 мс достаточно).
fn setup_resize_timer(term: &Rc<TerminalView>, scroll: &ScrolledWindow, tx_in: &Sender<ToThread>) {
    let term_resize = term.clone();
    let tx_resize = tx_in.clone();
    let last = Cell::new((0u32, 0u32));
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
            term_resize.resize(cols, rows);
            let _ = tx_resize.send(ToThread::Resize(cols.max(2), rows.max(2)));
        }
        glib::ControlFlow::Continue
    });
}

/// Ввод с клавиатуры/мыши: буквы и служебные клавиши → байты PTY,
/// xterm mouse reporting для полноэкранных приложений (`mc`, `vim`).
fn setup_input(term: &Rc<TerminalView>, scroll: &ScrolledWindow, tx_in: Sender<ToThread>) {
    use gtk4::gdk::ModifierType;

    let targets: Vec<gtk4::Widget> = match &term.kind {
        Kind::Vte(vte) => vec![vte.widget().clone()],
        Kind::Text { view, draw, .. } => vec![
            view.clone().upcast::<gtk4::Widget>(),
            draw.clone().upcast::<gtk4::Widget>(),
        ],
    };
    // Мышь подключаем только к VTE и к полноэкранной сетке: на обычном
    // TextView жесты не должны мешать выделению текста.
    let mouse_targets: Vec<gtk4::Widget> = match &term.kind {
        Kind::Vte(vte) => vec![vte.widget().clone()],
        Kind::Text { draw, .. } => vec![draw.clone().upcast::<gtk4::Widget>()],
    };

    for target in &targets {
        let controller = EventControllerKey::new();
        controller.set_propagation_phase(PropagationPhase::Capture);
        let term_key = term.clone();
        let tx_key = tx_in.clone();
        controller.connect_key_pressed(move |_, keyval, _code, state| {
            let ctrl = state.contains(ModifierType::CONTROL_MASK);
            let shift = state.contains(ModifierType::SHIFT_MASK);
            let alt = state.contains(ModifierType::ALT_MASK);
            let name = keyval.name();
            let name = name.as_deref();

            if ctrl && shift {
                match name.map(str::to_ascii_lowercase).as_deref() {
                    Some("c") => {
                        term_key.copy_clipboard();
                        return glib::Propagation::Stop;
                    }
                    Some("v") => {
                        term_key.paste_clipboard(tx_key.clone());
                        return glib::Propagation::Stop;
                    }
                    _ => {}
                }
            }
            if ctrl && !alt {
                match name {
                    Some("plus") | Some("equal") => {
                        term_key.zoom(1.1);
                        return glib::Propagation::Stop;
                    }
                    Some("minus") => {
                        term_key.zoom(1.0 / 1.1);
                        return glib::Propagation::Stop;
                    }
                    _ => {}
                }
            }

            let bytes = encode_key_parts(
                name,
                keyval.to_unicode(),
                ctrl,
                alt,
                shift,
                term_key.modes.get(),
            );
            match bytes {
                Some(bytes) if !bytes.is_empty() => {
                    let _ = tx_key.send(ToThread::Data(bytes));
                    glib::Propagation::Stop
                }
                _ => glib::Propagation::Proceed,
            }
        });
        target.add_controller(controller);
    }

    // Общее для всех страниц состояние мыши.
    let pressed = Rc::new(Cell::new(0u32));
    let pointer = Rc::new(Cell::new((0.0f64, 0.0f64)));

    let send_at = {
        let term = term.clone();
        let tx = tx_in.clone();
        move |x: f64, y: f64, button: u8, release: bool, motion: bool, pressed: &Rc<Cell<u32>>| {
            let modes = term.modes.get();
            if modes.mouse == MouseMode::Off {
                return false;
            }
            let (char_w, char_h) = term.char_size();
            let col = (x.max(0.0) / f64::from(char_w.max(1))).floor() as u32;
            let row = (y.max(0.0) / f64::from(char_h.max(1))).floor() as u32;
            // Для 1002/1003 движение несёт код зажатой кнопки (или 3, если
            // кнопок нет).
            let button = if motion && pressed.get() != 0 {
                match pressed.get() {
                    1 => 0,
                    2 => 1,
                    3 => 2,
                    _ => 3,
                }
            } else {
                button
            };
            if let Some(bytes) = mouse_sequence(button, col, row, release, motion, modes) {
                let _ = tx.send(ToThread::Data(bytes));
                true
            } else {
                false
            }
        }
    };

    for target in &mouse_targets {
        let term_click = term.clone();
        let send_click = send_at.clone();
        let pressed_click = pressed.clone();
        let pointer_click = pointer.clone();
        let click = GestureClick::new();
        click.set_button(0);
        click.set_propagation_phase(PropagationPhase::Capture);
        click.connect_pressed(move |_, button, x, y| {
            // Фокус нужен и без mouse-reporting: клавиатура должна работать.
            term_click.focus();
            if term_click.modes.get().mouse == MouseMode::Off {
                return;
            }
            pointer_click.set((x, y));
            let code = match button {
                1 => 0,
                2 => 1,
                3 => 2,
                _ => return,
            };
            pressed_click.set(button.max(0) as u32);
            if send_click(x, y, code, false, false, &pressed_click) {
                term_click.focus();
            }
        });
        let send_release = send_at.clone();
        let term_release = term.clone();
        let pressed_release = pressed.clone();
        let pointer_release = pointer.clone();
        click.connect_released(move |_, button, x, y| {
            if term_release.modes.get().mouse == MouseMode::Off {
                return;
            }
            pointer_release.set((x, y));
            let code = match button {
                1 => 0,
                2 => 1,
                3 => 2,
                _ => return,
            };
            let _ = send_release(x, y, code, true, false, &pressed_release);
            pressed_release.set(0);
        });
        target.add_controller(click);

        let term_motion = term.clone();
        let send_motion = send_at.clone();
        let pressed_motion = pressed.clone();
        let pointer_motion = pointer.clone();
        let motion = EventControllerMotion::new();
        motion.set_propagation_phase(PropagationPhase::Capture);
        motion.connect_motion(move |_, x, y| {
            pointer_motion.set((x, y));
            let modes = term_motion.modes.get();
            let dragging = pressed_motion.get() != 0;
            if matches!(modes.mouse, MouseMode::Button | MouseMode::Any)
                && (modes.mouse == MouseMode::Any || dragging)
            {
                let _ = send_motion(x, y, 3, false, true, &pressed_motion);
            }
        });
        target.add_controller(motion);

        let term_scroll = term.clone();
        let send_scroll = send_at.clone();
        let pressed_scroll = pressed.clone();
        let pointer_scroll = pointer.clone();
        let scroll = EventControllerScroll::new(
            EventControllerScrollFlags::VERTICAL
                | EventControllerScrollFlags::HORIZONTAL
                | EventControllerScrollFlags::DISCRETE,
        );
        scroll.set_propagation_phase(PropagationPhase::Capture);
        scroll.connect_scroll(move |_, dx, dy| {
            if term_scroll.modes.get().mouse == MouseMode::Off {
                return glib::Propagation::Proceed;
            }
            let (x, y) = pointer_scroll.get();
            let (button, delta) = if dy.abs() >= dx.abs() && dy != 0.0 {
                (if dy < 0.0 { 64 } else { 65 }, dy.abs())
            } else if dx != 0.0 {
                (if dx < 0.0 { 66 } else { 67 }, dx.abs())
            } else {
                return glib::Propagation::Proceed;
            };
            if delta > 0.0 && send_scroll(x, y, button, false, false, &pressed_scroll) {
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        target.add_controller(scroll);
    }

    setup_resize_timer(term, scroll, &tx_in);
}

/// Ожидание prompt "Password:" и ответ паролем root.
fn wait_password(
    ch: &mut ssh2::Channel,
    session: &mut ssh2::Session,
    password: &str,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn segments(data: &[u8]) -> (Vec<Segment>, AnsiState) {
        let mut state = AnsiState::default();
        let segs = parse_ansi(data, &mut state);
        (segs, state)
    }

    #[test]
    fn plain_text_without_escapes() {
        let (segs, state) = segments(b"hello\n");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].text, "hello\n");
        assert_eq!(segs[0].color, None);
        assert!(!state.bold);
    }

    #[test]
    fn color_and_bold_are_parsed() {
        // ESC[1;31m — жирный красный.
        let (segs, state) = segments(b"\x1b[1;31mRED\x1b[0mplain");
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].text, "RED");
        assert!(segs[0].bold);
        assert!(segs[0].color.is_some());
        assert_eq!(segs[1].text, "plain");
        assert!(!segs[1].bold);
        assert_eq!(segs[1].color, None);
        assert!(!state.bold);
    }

    #[test]
    fn xterm256_palette_is_supported() {
        // ESC[38;5;196m — 256-цветовая палитра.
        let (segs, _) = segments(b"\x1b[38;5;196mX");
        assert_eq!(segs.len(), 1);
        let (r, g, b) = segs[0].color.expect("цвет задан");
        assert_eq!(r, 0xffff, "красный канал");
        assert_eq!(g, 0x0000);
        assert_eq!(b, 0x0000);
    }

    #[test]
    fn ansi_color_uses_terminal_palette() {
        let mut state = AnsiState::default();
        let segs = parse_ansi_with_palette(b"\x1b[31mX", &mut state, &palette::SOLARIZED);
        let (r, g, b) = segs[0].color.expect("цвет задан");
        assert_eq!((r, g, b), (220 * 257, 50 * 257, 47 * 257));
    }

    #[test]
    fn true_color_is_supported() {
        // ESC[38;2;18;52;86m — 24-битный цвет.
        let (segs, _) = segments(b"\x1b[38;2;18;52;86mX");
        let (r, g, b) = segs[0].color.expect("цвет задан");
        assert_eq!((r, g, b), (18 * 257, 52 * 257, 86 * 257));
    }

    #[test]
    fn osc_sequences_are_skipped() {
        // OSC 0;title BEL — смена заголовка окна, текст не меняется.
        let (segs, _) = segments(b"\x1b]0;title\x07after");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].text, "after");
    }

    #[test]
    fn non_ascii_text_survives() {
        let (segs, _) = segments("Привет, мир!".as_bytes());
        assert_eq!(segs[0].text, "Привет, мир!");
    }

    #[test]
    fn backspace_removes_last_character() {
        let (segs, _) = segments(b"abc\x08");
        assert_eq!(segs[0].text, "ab");
    }

    #[test]
    fn carriage_return_does_not_duplicate_text() {
        let (segs, _) = segments(b"line\r\n");
        assert_eq!(segs[0].text, "line");
        assert_eq!(segs[1].text, "\n");
    }

    #[test]
    fn bare_carriage_return_marks_line_for_redraw() {
        let (segs, _) = segments(b"old prompt\rnew prompt");
        assert_eq!(segs[0].text, "old prompt");
        assert_eq!(segs[1].text, "new prompt");
        assert!(segs[1].clear_line);
    }

    #[test]
    fn crlf_split_between_chunks_is_not_redraw() {
        let mut state = AnsiState::default();
        let first = parse_ansi(b"line\r", &mut state);
        assert_eq!(first[0].text, "line");
        assert!(state.pending_cr);
        let second = parse_ansi(b"\n", &mut state);
        assert_eq!(second[0].text, "\n");
        assert!(!second[0].clear_line);
        assert!(!state.pending_cr);
    }

    #[test]
    fn charset_designator_does_not_print_final_byte() {
        // top/vi часто шлют ESC(B перед каждым цветовым сегментом.
        let (segs, _) = segments(b"\x1b(Bafter");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].text, "after");
    }

    #[test]
    fn ctrl_keys_are_control_bytes() {
        let modes = TerminalModes::default();
        assert_eq!(
            encode_key_parts(Some("c"), Some('c'), true, false, false, modes),
            Some(vec![0x03])
        );
        assert_eq!(
            encode_key_parts(None, Some('['), true, false, false, modes),
            Some(vec![0x1b])
        );
        assert_eq!(
            encode_key_parts(None, Some(' '), true, false, false, modes),
            Some(vec![0x00])
        );
    }

    #[test]
    fn arrows_respect_application_cursor_mode() {
        let normal = TerminalModes::default();
        let app = TerminalModes {
            app_cursor: true,
            ..TerminalModes::default()
        };
        assert_eq!(
            encode_key_parts(Some("Up"), None, false, false, false, normal),
            Some(b"\x1b[A".to_vec())
        );
        assert_eq!(
            encode_key_parts(Some("Up"), None, false, false, false, app),
            Some(b"\x1bOA".to_vec())
        );
        assert_eq!(
            encode_key_parts(Some("Left"), None, false, false, true, normal),
            Some(b"\x1b[1;2D".to_vec())
        );
    }

    #[test]
    fn function_keys_use_xterm_sequences() {
        let modes = TerminalModes::default();
        assert_eq!(
            encode_key_parts(Some("F1"), None, false, false, false, modes),
            Some(b"\x1bOP".to_vec())
        );
        assert_eq!(
            encode_key_parts(Some("F5"), None, false, false, false, modes),
            Some(b"\x1b[15~".to_vec())
        );
        assert_eq!(
            encode_key_parts(Some("F12"), None, false, false, false, modes),
            Some(b"\x1b[24~".to_vec())
        );
    }

    #[test]
    fn shift_tab_and_alt_text_are_encoded() {
        let modes = TerminalModes::default();
        assert_eq!(
            encode_key_parts(Some("ISO_Left_Tab"), None, false, false, true, modes),
            Some(b"\x1b[Z".to_vec())
        );
        assert_eq!(
            encode_key_parts(None, Some('x'), false, true, false, modes),
            Some(b"\x1bx".to_vec())
        );
    }

    #[test]
    fn sgr_mouse_reports_release_with_lowercase_m() {
        let modes = TerminalModes {
            mouse: MouseMode::Normal,
            sgr_mouse: true,
            ..TerminalModes::default()
        };
        let press = mouse_sequence(0, 4, 2, false, false, modes).unwrap();
        assert_eq!(press, b"\x1b[<0;5;3M");
        let release = mouse_sequence(0, 4, 2, true, false, modes).unwrap();
        assert_eq!(release, b"\x1b[<0;5;3m");
    }

    #[test]
    fn classic_mouse_release_uses_button_3() {
        let modes = TerminalModes {
            mouse: MouseMode::Normal,
            ..TerminalModes::default()
        };
        let release = mouse_sequence(0, 0, 0, true, false, modes).unwrap();
        assert_eq!(release, vec![0x1b, b'[', b'M', 35, 33, 33]);
    }

    #[test]
    fn output_router_splits_alternate_screen_across_chunks() {
        let mut router = alt_screen::OutputRouter::new();
        let chunks = router.route(b"before\x1b[?1049h");
        assert_eq!(chunks.len(), 1);
        assert!(!chunks[0].alt);
        assert!(router.alt());

        let chunks = router.route(b"fullscreen\x1b[?1049l");
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].alt);
        assert!(!router.alt());

        let chunks = router.route(b"after");
        assert_eq!(chunks.len(), 1);
        assert!(!chunks[0].alt);
        assert!(!router.alt());
        assert_eq!(chunks[0].data, b"after");
    }

    #[test]
    fn output_router_uses_hidden_cursor_as_fullscreen_for_top() {
        let mut router = alt_screen::OutputRouter::new();
        let chunks = router.route(b"\x1b[?1h\x1b[?25l\x1b[H\x1b[2J");
        assert!(router.alt());
        assert!(!chunks[0].alt);
        assert!(chunks.last().is_some_and(|chunk| chunk.alt));

        let chunks = router.route(b"\x1b[?25h");
        assert!(!router.alt());
        assert!(chunks.iter().all(|chunk| chunk.alt));
    }

    #[test]
    fn output_router_does_not_leave_explicit_alt_on_cursor_show() {
        let mut router = alt_screen::OutputRouter::new();
        let _ = router.route(b"\x1b[?1049h");
        assert!(router.alt());
        let chunks = router.route(b"\x1b[?25l\x1b[?25h");
        assert!(router.alt());
        assert!(chunks.iter().all(|chunk| chunk.alt));
        let _ = router.route(b"\x1b[?1049l");
        assert!(!router.alt());
    }

    #[test]
    fn output_router_tracks_mouse_and_paste_modes() {
        let mut router = alt_screen::OutputRouter::new();
        let _ = router.route(b"\x1b[?1h\x1b[?1002h\x1b[?1006h\x1b[?2004h");
        let modes = router.modes();
        assert!(modes.app_cursor);
        assert_eq!(modes.mouse, MouseMode::Button);
        assert!(modes.sgr_mouse);
        assert!(modes.bracketed_paste);

        let _ = router.route(b"\x1b[?1002l\x1b[?2004l");
        let modes = router.modes();
        assert_eq!(modes.mouse, MouseMode::Off);
        assert!(!modes.bracketed_paste);
    }

    #[test]
    fn alt_screen_handles_cursor_addressing_and_clear() {
        let mut screen = alt_screen::Screen::new(10, 3);
        screen.feed(b"hello\x1b[2;3HX");
        assert_eq!(screen.cell(0, 0).ch, 'h');
        assert_eq!(screen.cell(2, 1).ch, 'X');
        screen.feed(b"\x1b[2J");
        assert_eq!(screen.cell(2, 1).ch, ' ');
        assert_eq!(screen.cell(0, 0).ch, ' ');
    }

    #[test]
    fn alt_screen_handles_scroll_and_utf8() {
        let mut screen = alt_screen::Screen::new(8, 2);
        screen.feed("Привет".as_bytes());
        assert_eq!(screen.cell(0, 0).ch, 'П');
        assert_eq!(screen.cell(1, 0).ch, 'р');
    }

    /// Живой smoke-тест fallback-терминала: X11 + SSH на 127.0.0.1:2222.
    ///
    /// Запускается вручную (`--ignored`) под Xvfb. Окно висит 5 минут,
    /// чтобы можно было набрать `top`/`vi` через xdotool и снять скриншот.
    #[test]
    #[ignore = "требует X11 и SSH-сервер на 127.0.0.1:2222"]
    fn live_fallback_ui_smoke() {
        use crate::models::profile::{Profile, RdpOptions, SshOptions, VncOptions};
        use crate::models::Protocol;
        use secrecy::SecretString;

        if gtk4::init().is_err() {
            return;
        }

        let profile = Profile {
            id: 0,
            name: "live".to_string(),
            protocol: Protocol::Ssh,
            host: "127.0.0.1".to_string(),
            port: 2222,
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
            rdp_options: RdpOptions::default(),
            vnc_options: VncOptions::default(),
            ssh_options: SshOptions::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        };
        // Тот же known_hosts, что использует new_ssh(): предварительное
        // подключение добавит ключ тестового сервера, и вкладка не покажет
        // диалог подтверждения.
        let mut conn = SshConnection::new(profile.clone());
        conn.connect_with(&HostKeyConfig {
            known_hosts: crate::protocols::ssh::default_known_hosts_path(),
            accept_new: true,
            verifier: None,
        })
        .expect("SSH-подключение к тестовому серверу");

        let window = gtk4::Window::new();
        window.set_title(Some("remotix-live-terminal"));
        window.set_default_size(1000, 700);
        let tab = TerminalTab::new_ssh(
            "live",
            conn,
            Rc::new(|_| {}),
            14,
            false,
            false,
            TerminalExtras {
                expect_rules: vec![],
                snippets: vec![],
                palette: palette::DARK,
            },
        )
        .expect("создание вкладки терминала");
        window.set_child(Some(&tab.root));
        window.present();

        let main_loop = glib::MainLoop::new(None, false);
        let quit = main_loop.clone();
        glib::timeout_add_seconds_local(300, move || {
            quit.quit();
            glib::ControlFlow::Break
        });
        main_loop.run();
    }
}
