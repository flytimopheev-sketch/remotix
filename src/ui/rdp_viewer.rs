//! Просмотрщик удалённого рабочего стола (RDP).
//!
//! Сессия работает в отдельном потоке: там крутится цикл IronRDP, который
//! декодирует кадры сервера и принимает клавиатуру/мышь. В поток GTK кадры
//! приходят готовыми пикселями (RGBA32) и выводятся через `GdkMemoryTexture`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;

use gtk4::prelude::*;
use gtk4::{cairo, gdk, glib, Box as GtkBox, Button, DrawingArea, Label, Overlay, Spinner};

use crate::models::Profile;
use crate::protocols::rdp::{RdpConnection, RdpKey};
use crate::protocols::Connection;
use crate::ui::SessionState;

/// События от потока RDP в интерфейс.
enum ToUi {
    /// Готовый кадр удалённого рабочего стола (RGBA32, построчно).
    Frame { width: u32, height: u32, pixels: Vec<u8> },
    /// Изменилось состояние сессии.
    State(SessionState),
}

/// События от интерфейса в поток RDP.
enum ToRdp {
    Key { key: RdpKey, pressed: bool },
    Mouse { x: u32, y: u32, buttons: u8, is_move: bool },
    Wheel { x: u32, y: u32, delta: i32 },
    /// Синтетическая последовательность `Ctrl+Alt+Del`.
    CtrlAltDel,
}

/// Вкладка с просмотрщиком удалённого рабочего стола.
pub struct RdpViewer {
    root: GtkBox,
}

impl RdpViewer {
    /// Создаёт просмотрщик и запускает подключение в фоновом потоке.
    pub fn new(profile: Profile, on_state: Rc<dyn Fn(SessionState)>) -> Self {
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);

        // Экран рисуется в DrawingArea: у него нулевой минимальный размер,
        // поэтому окно приложения не «раздувается» до ширины удалённого
        // рабочего стола (и его можно сузить мышью). Картинка масштабируется
        // под размер окна с сохранением пропорций.
        let area = DrawingArea::new();
        area.set_hexpand(true);
        area.set_vexpand(true);
        area.add_css_class("remotix-remote-screen");

        // Размер удалённого экрана (нужен для пересчёта координат мыши).
        let remote_size = Rc::new(Cell::new((0u32, 0u32)));

        // Последний полученный кадр.
        let frame: Rc<RefCell<Option<cairo::ImageSurface>>> = Rc::new(RefCell::new(None));

        let spinner = Spinner::new();
        spinner.set_spinning(true);

        let hint = Label::new(Some("Подключение к удалённому рабочему столу…"));
        hint.add_css_class("remotix-empty");

        let (tx_ui, rx_ui) = mpsc::channel::<ToUi>();
        let (tx_rdp, rx_rdp) = mpsc::channel::<ToRdp>();

        // Панель управления сессией.
        let cad = Button::with_label("Ctrl+Alt+Del");
        cad.set_tooltip_text(Some("Отправить в удалённую сессию Ctrl+Alt+Del"));

        let panel = GtkBox::new(gtk4::Orientation::Horizontal, 6);
        panel.set_halign(gtk4::Align::End);
        panel.set_valign(gtk4::Align::Start);
        panel.set_margin_top(8);
        panel.set_margin_end(8);
        panel.append(&cad);

        let overlay = Overlay::new();
        overlay.set_child(Some(&area));
        overlay.add_overlay(&spinner);
        overlay.add_overlay(&hint);
        overlay.add_overlay(&panel);
        root.append(&overlay);

        // ---------------- Отрисовка кадра ----------------
        {
            let frame = frame.clone();
            let remote_size = remote_size.clone();
            area.set_draw_func(move |area, cr, _width, _height| {
                let surface = match frame.borrow().as_ref() {
                    Some(s) => s.clone(),
                    None => return,
                };
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return;
                }
                let w = area.width() as f64;
                let h = area.height() as f64;
                if w <= 0.0 || h <= 0.0 {
                    return;
                }
                // Масштаб с сохранением пропорций, кадр по центру.
                let scale = (w / rw as f64).min(h / rh as f64);
                let dw = rw as f64 * scale;
                let dh = rh as f64 * scale;
                let _ = cr.save();
                cr.translate((w - dw) / 2.0, (h - dh) / 2.0);
                cr.scale(scale, scale);
                let _ = cr.set_source_surface(&surface, 0.0, 0.0);
                let _ = cr.paint();
                let _ = cr.restore();
            });
        }

        {
            let tx = tx_rdp.clone();
            cad.connect_clicked(move |_| {
                let _ = tx.send(ToRdp::CtrlAltDel);
            });
        }

        // ---------------- Поток RDP ----------------
        {
            let tx_ui = tx_ui.clone();
            std::thread::spawn(move || {
                let mut conn = RdpConnection::new(profile);

                if let Err(e) = conn.connect() {
                    let _ = tx_ui.send(ToUi::State(SessionState::Failed(e)));
                    return;
                }
                let _ = tx_ui.send(ToUi::State(SessionState::Connected));

                // Неблокирующий сокет: иначе цикл просмотра не сможет
                // обрабатывать клавиатуру и мышь, пока сервер молчит.
                if let Err(e) = conn.set_nonblocking(true) {
                    let _ = tx_ui.send(ToUi::State(SessionState::Failed(e)));
                    return;
                }

                let mut last: Vec<u8> = Vec::new();
                loop {
                    // Ввод от пользователя.
                    while let Ok(ev) = rx_rdp.try_recv() {
                        match ev {
                            ToRdp::Key { key, pressed } => conn.send_key(key, pressed),
                            ToRdp::Mouse { x, y, buttons, is_move } => {
                                conn.send_mouse(x, y, buttons, is_move)
                            }
                            ToRdp::Wheel { x, y, delta } => conn.send_wheel(x, y, delta),
                            ToRdp::CtrlAltDel => conn.send_ctrl_alt_del(),
                        }
                    }

                    match conn.run() {
                        Ok(true) => {
                            if let Some((w, h)) = conn.image_size() {
                                let pixels = conn.image_pixels();
                                if !pixels.is_empty() && pixels != last.as_slice() {
                                    last.clear();
                                    last.extend_from_slice(pixels);
                                    let _ = tx_ui.send(ToUi::Frame {
                                        width: u32::from(w),
                                        height: u32::from(h),
                                        pixels: last.clone(),
                                    });
                                }
                            }
                        }
                        Ok(false) => {}
                        Err(e) => {
                            let _ = tx_ui.send(ToUi::State(SessionState::Failed(e)));
                            return;
                        }
                    }

                    std::thread::sleep(Duration::from_millis(12));
                }
            });
        }

        // ---------------- Вывод кадров в GTK ----------------
        {
            let area = area.clone();
            let frame = frame.clone();
            let spinner = spinner.clone();
            let hint = hint.clone();
            let remote_size = remote_size.clone();
            let on_state = on_state.clone();

            glib::timeout_add_local(Duration::from_millis(25), move || {
                loop {
                    match rx_ui.try_recv() {
                        Ok(ToUi::Frame { width, height, pixels }) => {
                            remote_size.set((width, height));
                            // Кадр приходит в формате RGBA32; для cairo это
                            // ARGB32 (альфа непрозрачная, так что разницы нет).
                            let surface = cairo::ImageSurface::create_for_data(
                                pixels,
                                cairo::Format::ARgb32,
                                width as i32,
                                height as i32,
                                width as i32 * 4,
                            );
                            match surface {
                                Ok(surface) => {
                                    *frame.borrow_mut() = Some(surface);
                                    area.queue_draw();
                                    spinner.set_spinning(false);
                                    hint.set_visible(false);
                                }
                                Err(e) => {
                                    eprintln!("Remotix: не удалось подготовить кадр RDP: {e}");
                                }
                            }
                        }
                        Ok(ToUi::State(state)) => {
                            match &state {
                                SessionState::Connected => {
                                    spinner.set_spinning(false);
                                }
                                SessionState::Failed(e) => {
                                    spinner.set_spinning(false);
                                    hint.set_text(&format!("Ошибка подключения: {e}"));
                                    hint.set_visible(true);
                                }
                                _ => {}
                            }
                            on_state(state);
                        }
                        Err(_) => return glib::ControlFlow::Continue,
                    }
                }
            });
        }

        // ---------------- Клавиатура ----------------
        {
            let tx = tx_rdp.clone();
            let controller = gtk4::EventControllerKey::new();
            controller.connect_key_pressed({
                let tx = tx.clone();
                move |_, key, keycode, _state| {
                    let _ = tx.send(ToRdp::Key { key: rdp_key(key, keycode), pressed: true });
                    glib::Propagation::Stop
                }
            });
            controller.connect_key_released(move |_, key, keycode, _state| {
                let _ = tx.send(ToRdp::Key { key: rdp_key(key, keycode), pressed: false });
            });
            area.add_controller(controller);
        }

        // ---------------- Мышь ----------------
        {
            let tx = tx_rdp.clone();
            let area_ref = area.clone();
            let remote_size = remote_size.clone();
            let controller = gtk4::EventControllerMotion::new();
            controller.connect_motion(move |_, x, y| {
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return;
                }
                let (rx, ry) = map_coordinates(&area_ref, x, y, rw, rh);
                let _ = tx.send(ToRdp::Mouse { x: rx, y: ry, buttons: 0, is_move: true });
            });
            area.add_controller(controller);
        }

        {
            let tx = tx_rdp.clone();
            let area_ref = area.clone();
            let remote_size = remote_size.clone();
            let controller = gtk4::GestureClick::new();
            controller.set_button(0); // любая кнопка мыши
            controller.connect_pressed(move |_, button, x, y| {
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return;
                }
                let (rx, ry) = map_coordinates(&area_ref, x, y, rw, rh);
                let buttons = match button {
                    1 => 1u8,
                    2 => 2,
                    3 => 3,
                    _ => 0,
                };
                let _ = tx.send(ToRdp::Mouse { x: rx, y: ry, buttons, is_move: false });
            });
            area.add_controller(controller);
        }

        {
            let tx = tx_rdp.clone();
            let area_ref = area.clone();
            let remote_size = remote_size.clone();
            let controller = gtk4::EventControllerScroll::new(
                gtk4::EventControllerScrollFlags::VERTICAL | gtk4::EventControllerScrollFlags::DISCRETE,
            );
            controller.connect_scroll(move |_, _dx, dy| {
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return glib::Propagation::Proceed;
                }
                let (rx, ry) = map_coordinates(&area_ref, 0.0, 0.0, rw, rh);
                let _ = tx.send(ToRdp::Wheel { x: rx, y: ry, delta: -(dy as i32) });
                glib::Propagation::Stop
            });
            area.add_controller(controller);
        }

        Self { root }
    }

    /// Корневой виджет вкладки.
    pub fn root(&self) -> &GtkBox {
        &self.root
    }
}

/// Переводит координаты виджета в координаты удалённого экрана.
///
/// Экран масштабируется под окно с сохранением пропорций и размещается по
/// центру — как при отрисовке кадра.
fn map_coordinates(area: &DrawingArea, x: f64, y: f64, remote_w: u32, remote_h: u32) -> (u32, u32) {
    let widget_w = area.width().max(1) as f64;
    let widget_h = area.height().max(1) as f64;
    let scale = (widget_w / remote_w as f64).min(widget_h / remote_h as f64);
    if scale <= 0.0 {
        return (0, 0);
    }
    let disp_w = remote_w as f64 * scale;
    let disp_h = remote_h as f64 * scale;
    let off_x = (widget_w - disp_w) / 2.0;
    let off_y = (widget_h - disp_h) / 2.0;

    let rx = (((x - off_x) / scale).round()).clamp(0.0, remote_w as f64 - 1.0) as u32;
    let ry = (((y - off_y) / scale).round()).clamp(0.0, remote_h as f64 - 1.0) as u32;
    (rx, ry)
}

/// Преобразует клавишу GDK в событие ввода RDP.
///
/// Основной путь — X11-сканкод (set 1): сервер сам учитывает состояние
/// Shift/Ctrl/Alt по таким событиям. Для редких клавиш используется таблица,
/// для остальных — аппаратный код клавиши.
fn rdp_key(key: gdk::Key, keycode: u32) -> RdpKey {
    if let Some((code, extended)) = scancode_for(key) {
        return RdpKey::Scancode { code, extended };
    }

    // Аппаратный код GDK на X11 — это X11-номер клавиши минус 8.
    let code = keycode.saturating_sub(8);
    if code > 0 && code < 0x80 {
        RdpKey::Scancode { code: code as u8, extended: false }
    } else {
        match key.to_unicode() {
            Some(c) => RdpKey::Char(c),
            None => RdpKey::Scancode { code: 0, extended: false },
        }
    }
}

/// Таблица соответствия «клавиша GDK → X11-сканкод (set 1)».
///
/// Основная часть клавиатуры (буквы, цифры, знаки) берётся из аппаратного
/// кода GDK: на X11 это X11-код клавиши минус 8. Для служебных клавиш
/// (стрелки, Home/End, F11/F12, клавиатура) X11-коды не совпадают с
/// set-1, поэтому для них используется таблица.
fn scancode_for(key: gdk::Key) -> Option<(u8, bool)> {
    let (code, extended) = match key {
        gdk::Key::Return | gdk::Key::KP_Enter => (0x1c, false),
        gdk::Key::Escape => (0x01, false),
        gdk::Key::BackSpace => (0x0e, false),
        gdk::Key::Tab | gdk::Key::ISO_Left_Tab => (0x0f, false),
        gdk::Key::space => (0x39, false),
        gdk::Key::Left => (0x4b, true),
        gdk::Key::Up => (0x48, true),
        gdk::Key::Right => (0x4d, true),
        gdk::Key::Down => (0x50, true),
        gdk::Key::Home => (0x47, true),
        gdk::Key::End => (0x4f, true),
        gdk::Key::Page_Up => (0x49, true),
        gdk::Key::Page_Down => (0x51, true),
        gdk::Key::Insert => (0x52, true),
        gdk::Key::Delete => (0x53, true),
        gdk::Key::KP_0 => (0x52, false),
        gdk::Key::KP_1 => (0x53, false),
        gdk::Key::KP_2 => (0x54, false),
        gdk::Key::KP_3 => (0x55, false),
        gdk::Key::KP_4 => (0x56, false),
        gdk::Key::KP_5 => (0x57, false),
        gdk::Key::KP_6 => (0x58, false),
        gdk::Key::KP_7 => (0x59, false),
        gdk::Key::KP_8 => (0x5a, false),
        gdk::Key::KP_9 => (0x5b, false),
        gdk::Key::KP_Divide => (0x35, true),
        gdk::Key::KP_Multiply => (0x37, false),
        gdk::Key::KP_Subtract => (0x4a, false),
        gdk::Key::KP_Add => (0x4e, false),
        gdk::Key::KP_Decimal => (0x53, false),
        gdk::Key::F1 => (0x3b, false),
        gdk::Key::F2 => (0x3c, false),
        gdk::Key::F3 => (0x3d, false),
        gdk::Key::F4 => (0x3e, false),
        gdk::Key::F5 => (0x3f, false),
        gdk::Key::F6 => (0x40, false),
        gdk::Key::F7 => (0x41, false),
        gdk::Key::F8 => (0x42, false),
        gdk::Key::F9 => (0x43, false),
        gdk::Key::F10 => (0x44, false),
        gdk::Key::F11 => (0x57, false),
        gdk::Key::F12 => (0x58, false),
        gdk::Key::Shift_R => (0x36, false),
        gdk::Key::Control_R => (0x1d, true),
        gdk::Key::Alt_R => (0x38, true),
        gdk::Key::Super_L => (0x5b, true),
        gdk::Key::Super_R => (0x5c, true),
        gdk::Key::Caps_Lock => (0x3a, false),
        gdk::Key::Num_Lock => (0x45, true),
        gdk::Key::Scroll_Lock => (0x46, true),
        _ => return None,
    };
    Some((code, extended))
}
