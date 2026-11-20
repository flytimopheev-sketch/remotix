//! Просмотрщик удалённого рабочего стола (RDP).
//!
//! Сессия работает в отдельном потоке: там крутится цикл IronRDP, который
//! декодирует кадры сервера и принимает клавиатуру/мышь. В поток GTK кадры
//! приходят готовыми пикселями (RGBA32) и выводятся через `GdkMemoryTexture`.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use gtk4::prelude::*;
use gtk4::{
    cairo, gdk, gio, glib, pango, Box as GtkBox, Button, DrawingArea, Label, Overlay, Spinner,
};

use crate::models::Profile;
use crate::protocols::rdp::{
    ClipboardConfig, MouseEvent, RdpConnection, RdpKey, MOUSE_LEFT, MOUSE_MIDDLE, MOUSE_RIGHT,
};
use crate::protocols::Connection;
use crate::ui::SessionState;

/// События от потока RDP в интерфейс.
enum ToUi {
    /// Готовый кадр удалённого рабочего стола (RGBA32, построчно).
    Frame {
        width: u32,
        height: u32,
        pixels: Vec<u8>,
    },
    /// Текст из удалённого буфера обмена (содержимое не логируется).
    ClipboardText(String),
    /// Снимок качества соединения для индикатора.
    Quality {
        summary: String,
        tooltip: String,
        /// CSS-класс: good / warn / bad.
        class: &'static str,
    },
    /// Изменилось состояние сессии.
    State(SessionState),
}

/// События от интерфейса в поток RDP.
enum ToRdp {
    Key {
        key: RdpKey,
        pressed: bool,
    },
    Mouse {
        x: u32,
        y: u32,
        /// Маска кнопок в порядке RDP (см. `protocols::rdp::MOUSE_*`).
        buttons: u8,
        event: MouseEvent,
    },
    Wheel {
        x: u32,
        y: u32,
        delta: i32,
    },
    /// Синтетическая последовательность `Ctrl+Alt+Del`.
    CtrlAltDel,
    /// Локальный текст, который нужно объявить удалённой стороне.
    ClipboardText(String),
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

        // Режим масштаба удалённого экрана: вписать / 1:1 / растянуть.
        let scale_mode = Rc::new(Cell::new(crate::rdp_screen::ScaleMode::default()));

        // Последний полученный кадр.
        let frame: Rc<RefCell<Option<cairo::ImageSurface>>> = Rc::new(RefCell::new(None));

        let spinner = Spinner::new();
        spinner.set_spinning(true);

        let hint = Label::new(Some("Подключение к удалённому рабочему столу…"));
        hint.add_css_class("remotix-empty");
        // Текст ошибки бывает длинным: переносим его по словам, чтобы он не
        // растягивал окно приложения.
        hint.set_wrap(true);
        hint.set_max_width_chars(60);
        hint.set_justify(gtk4::Justification::Center);

        let (tx_ui, rx_ui) = mpsc::channel::<ToUi>();
        let (tx_rdp, rx_rdp) = mpsc::channel::<ToRdp>();
        // Закрытие вкладки должно останавливать поток RDP, даже если
        // обработчики буфера обмена ещё держат отправитель канала.
        let cancelled = Arc::new(AtomicBool::new(false));

        // Буфер обмена: слушаем локальные изменения и отправляем текст в
        // поток RDP. Начальное содержимое читаем при появлении вкладки —
        // оно будет объявлено после Monitor Ready канала CLIPRDR.
        let clipboard_cfg = ClipboardConfig::from_profile(&profile);
        let last_remote_text: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
        let clipboard_active = Rc::new(Cell::new(false));
        let clipboard = if clipboard_cfg.enabled {
            Some(area.display().clipboard())
        } else {
            None
        };
        if clipboard_cfg.to_remote {
            if let Some(clipboard) = clipboard.clone() {
                let tx = tx_rdp.clone();
                let last_remote = last_remote_text.clone();
                let active = clipboard_active.clone();
                let handler_id =
                    Rc::new(RefCell::new(Some(clipboard.connect_changed(move |clip| {
                        if !active.get() {
                            return;
                        }
                        send_clipboard_text(clip, &tx, &last_remote);
                    }))));
                // GDK-буфер обмена общий для приложения: без явного
                // отключения обработчик переживёт закрытие вкладки и будет
                // держать канал RDP открытым.
                let clipboard_for_destroy = clipboard.clone();
                area.connect_destroy(move |_| {
                    if let Some(id) = handler_id.borrow_mut().take() {
                        clipboard_for_destroy.disconnect(id);
                    }
                });

                // Локальный буфер отправляем только когда вкладка видима:
                // иначе несколько RDP-сессий начнут пересылать изменения
                // друг другу и зациклят буфер между вкладками.
                {
                    let tx = tx_rdp.clone();
                    let last_remote = last_remote_text.clone();
                    let active = clipboard_active.clone();
                    let clipboard = clipboard.clone();
                    area.connect_map(move |_| {
                        active.set(true);
                        send_clipboard_text(&clipboard, &tx, &last_remote);
                    });
                }
                {
                    let active = clipboard_active.clone();
                    area.connect_unmap(move |_| active.set(false));
                }
            }
        }
        {
            let cancelled = cancelled.clone();
            area.connect_destroy(move |_| cancelled.store(true, Ordering::Relaxed));
        }

        // Панель управления сессией.
        let cad = Button::with_label("Ctrl+Alt+Del");
        cad.set_tooltip_text(Some("Отправить в удалённую сессию Ctrl+Alt+Del"));

        let quality = Label::new(Some("Подключение…"));
        quality.add_css_class("remotix-rdp-quality");
        quality.add_css_class("remotix-rdp-quality-warn");
        quality.set_tooltip_text(Some(
            "Качество RDP: протокол безопасности, отклик на ввод, кадры/с и ошибки декодирования",
        ));
        quality.set_ellipsize(pango::EllipsizeMode::End);
        quality.set_max_width_chars(56);

        let log_btn = Button::with_label("Лог");
        log_btn.set_tooltip_text(Some(
            "Открыть диагностический журнал RDP (без паролей и содержимого буфера)",
        ));
        {
            let hint = hint.clone();
            log_btn.connect_clicked(move |_| match crate::logging::ensure_rdp_log_file() {
                Ok(path) => {
                    crate::logging::rdp_info("диагностический журнал RDP открыт из просмотрщика");
                    let uri = gio::File::for_path(&path).uri();
                    if let Err(e) =
                        gio::AppInfo::launch_default_for_uri(&uri, None::<&gio::AppLaunchContext>)
                    {
                        crate::logging::rdp_warn(&format!("не удалось открыть журнал RDP: {e}"));
                        hint.set_text(&format!(
                            "Не удалось открыть журнал RDP: {e}\n{}",
                            path.display()
                        ));
                        hint.set_visible(true);
                    }
                }
                Err(e) => {
                    crate::logging::rdp_warn(&format!("не удалось создать журнал RDP: {e}"));
                    hint.set_text(&format!("Не удалось создать журнал RDP: {e}"));
                    hint.set_visible(true);
                }
            });
        }

        let panel = GtkBox::new(gtk4::Orientation::Horizontal, 6);
        panel.set_halign(gtk4::Align::End);
        panel.set_valign(gtk4::Align::Start);
        panel.set_margin_top(8);
        panel.set_margin_end(8);
        let scale_btn = Button::with_label(scale_mode.get().label());
        scale_btn.set_tooltip_text(Some("Масштаб экрана: вписать / 1:1 / растянуть"));
        {
            let mode = scale_mode.clone();
            let area_sc = area.clone();
            let btn = scale_btn.clone();
            scale_btn.connect_clicked(move |_| {
                let next = mode.get().next();
                mode.set(next);
                btn.set_label(next.label());
                area_sc.queue_draw();
            });
        }

        let fs_btn = Button::with_label("⛶");
        fs_btn.set_tooltip_text(Some("Полный экран (F11)"));
        {
            let area_fs = area.clone();
            fs_btn.connect_clicked(move |_| toggle_fullscreen(&area_fs));
        }

        panel.append(&quality);
        panel.append(&scale_btn);
        panel.append(&log_btn);
        panel.append(&fs_btn);
        panel.append(&cad);

        let overlay = Overlay::new();
        overlay.set_child(Some(&area));
        overlay.add_overlay(&spinner);
        overlay.add_overlay(&hint);
        overlay.add_overlay(&panel);
        root.append(&overlay);

        // F11 ловим на уровне корня вкладки: фокус может быть на кнопке
        // панели, а не на DrawingArea. Повторные press-события при
        // удержании клавиши не должны дёргать полноэкранный режим.
        {
            let area_f11 = area.clone();
            let f11_down = Rc::new(Cell::new(false));
            let controller = gtk4::EventControllerKey::new();
            controller.set_propagation_phase(gtk4::PropagationPhase::Capture);
            controller.connect_key_pressed({
                let f11_down = f11_down.clone();
                move |_, key, _, _| {
                    if key == gdk::Key::F11 {
                        if !f11_down.replace(true) {
                            toggle_fullscreen(&area_f11);
                        }
                        glib::Propagation::Stop
                    } else {
                        glib::Propagation::Proceed
                    }
                }
            });
            controller.connect_key_released(move |_, key, _, _| {
                if key == gdk::Key::F11 {
                    f11_down.set(false);
                }
            });
            root.add_controller(controller);
        }

        // ---------------- Отрисовка кадра ----------------
        {
            let frame = frame.clone();
            let remote_size = remote_size.clone();
            let mode = scale_mode.clone();
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
                // Геометрия зависит от выбранного режима масштаба.
                let g = crate::rdp_screen::geometry(rw, rh, w, h, mode.get());
                let _ = cr.save();
                cr.translate(g.off_x, g.off_y);
                cr.scale(g.scale_x, g.scale_y);
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
            let cancelled = cancelled.clone();
            std::thread::spawn(move || {
                let mut conn = RdpConnection::new(profile);
                if cancelled.load(Ordering::Relaxed) {
                    return;
                }

                if let Err(e) = conn.connect() {
                    let _ = tx_ui.send(ToUi::State(SessionState::Failed(e)));
                    return;
                }
                if cancelled.load(Ordering::Relaxed) {
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
                let mut frames_since: u32 = 0;
                let mut bytes_mark: u64 = 0;
                let mut errors_mark: u32 = 0;
                let mut stats_at = Instant::now();
                loop {
                    if cancelled.load(Ordering::Relaxed) {
                        return;
                    }

                    // Ввод от пользователя. Disconnected означает, что
                    // вкладку закрыли: поток RDP больше не нужен.
                    loop {
                        match rx_rdp.try_recv() {
                            Ok(ToRdp::Key { key, pressed }) => conn.send_key(key, pressed),
                            Ok(ToRdp::Mouse {
                                x,
                                y,
                                buttons,
                                event,
                            }) => conn.send_mouse(x, y, buttons, event),
                            Ok(ToRdp::Wheel { x, y, delta }) => conn.send_wheel(x, y, delta),
                            Ok(ToRdp::CtrlAltDel) => conn.send_ctrl_alt_del(),
                            Ok(ToRdp::ClipboardText(text)) => conn.set_clipboard(&text),
                            Err(mpsc::TryRecvError::Empty) => break,
                            Err(mpsc::TryRecvError::Disconnected) => return,
                        }
                    }

                    match conn.run() {
                        Ok(true) => {
                            if let Some((w, h)) = conn.image_size() {
                                let pixels = conn.image_pixels();
                                if !pixels.is_empty() && pixels != last.as_slice() {
                                    last.clear();
                                    last.extend_from_slice(pixels);
                                    frames_since = frames_since.saturating_add(1);
                                    let _ = tx_ui.send(ToUi::Frame {
                                        width: u32::from(w),
                                        height: u32::from(h),
                                        pixels: last.clone(),
                                    });
                                }
                            }
                        }
                        Ok(false) => {
                            if let Some(reason) = conn.close_reason() {
                                crate::logging::rdp_info(&format!(
                                    "RDP-сессия завершена: {reason}"
                                ));
                                let _ = tx_ui.send(ToUi::State(SessionState::Closed));
                                return;
                            }
                        }
                        Err(e) => {
                            crate::logging::rdp_error(&format!("RDP-сессия: {e}"));
                            let _ = tx_ui.send(ToUi::State(SessionState::Failed(e)));
                            return;
                        }
                    }

                    // Текст, который сервер положил в удалённый буфер.
                    for text in conn.take_clipboard_text() {
                        let _ = tx_ui.send(ToUi::ClipboardText(text));
                    }

                    // Раз в секунду обновляем индикатор качества. Задержка —
                    // время от последнего ввода до ответа сервера, ошибки —
                    // ошибки декодирования кадров за последнюю секунду.
                    if stats_at.elapsed() >= Duration::from_secs(1) {
                        let q = conn.quality();
                        let errors_since = q.decode_errors.saturating_sub(errors_mark);
                        let latency = q
                            .latency_ms
                            .map(|ms| format!("{ms} мс"))
                            .unwrap_or_else(|| "—".to_string());
                        let kbps =
                            ((q.bytes_received.saturating_sub(bytes_mark)) * 8 / 1000) as u32;
                        let summary = format!(
                            "{} · {} · {} к/с · ошибки {}",
                            q.security.label(),
                            latency,
                            frames_since,
                            errors_since
                        );
                        let tooltip = format!(
                            "Безопасность: {}\nОтклик на ввод: {}\nКадров в секунду: {}\nТрафик: {} кбит/с\nОшибки декодирования за секунду: {} (всего {})",
                            q.security.label(),
                            latency,
                            frames_since,
                            kbps,
                            errors_since,
                            q.decode_errors
                        );
                        let latency_ms = q.latency_ms.unwrap_or(0);
                        let class = if errors_since > 3 || latency_ms > 250 {
                            "remotix-rdp-quality-bad"
                        } else if errors_since > 0 || latency_ms > 100 {
                            "remotix-rdp-quality-warn"
                        } else {
                            "remotix-rdp-quality-good"
                        };
                        let _ = tx_ui.send(ToUi::Quality {
                            summary,
                            tooltip,
                            class,
                        });
                        stats_at = Instant::now();
                        frames_since = 0;
                        bytes_mark = q.bytes_received;
                        errors_mark = q.decode_errors;
                    }

                    std::thread::sleep(Duration::from_millis(12));
                }
            });
        }

        // ---------------- Вывод кадров в GTK ----------------
        {
            // Слабая ссылка: таймер не должен удерживать экран (и всю
            // вкладку) после её закрытия.
            let area = area.downgrade();
            let frame = frame.clone();
            let spinner = spinner.clone();
            let hint = hint.clone();
            let remote_size = remote_size.clone();
            let on_state = on_state.clone();
            let quality = quality.clone();
            let clipboard = clipboard.clone();
            let last_remote_text = last_remote_text.clone();
            let cancelled = cancelled.clone();

            let mut was_connected = false;
            glib::timeout_add_local(Duration::from_millis(25), move || {
                if cancelled.load(Ordering::Relaxed) || area.upgrade().is_none() {
                    return glib::ControlFlow::Break;
                }
                loop {
                    match rx_ui.try_recv() {
                        Ok(ToUi::Frame {
                            width,
                            height,
                            pixels,
                        }) => {
                            remote_size.set((width, height));
                            // Кадр приходит в формате BGRA32 (BgrA32) — это
                            // нативный порядок байтов cairo ARgb32, поэтому
                            // буфер отдаётся в ImageSurface без конвертации.
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
                                    if let Some(area) = area.upgrade() {
                                        area.queue_draw();
                                    }
                                    spinner.set_spinning(false);
                                    hint.set_visible(false);
                                }
                                Err(e) => {
                                    crate::logging::rdp_warn(&format!(
                                        "не удалось подготовить кадр RDP: {e}"
                                    ));
                                }
                            }
                        }
                        Ok(ToUi::ClipboardText(text)) => {
                            if !clipboard_cfg.from_remote {
                                continue;
                            }
                            if let Some(clipboard) = clipboard.as_ref() {
                                // Запоминаем текст, чтобы обработчик changed
                                // не отправил его обратно как локальное
                                // изменение (эхо удалённого буфера).
                                *last_remote_text.borrow_mut() = Some(text.clone());
                                clipboard.set_text(&text);
                            }
                        }
                        Ok(ToUi::Quality {
                            summary,
                            tooltip,
                            class,
                        }) => {
                            quality.set_text(&summary);
                            quality.set_tooltip_text(Some(&tooltip));
                            for old in [
                                "remotix-rdp-quality-good",
                                "remotix-rdp-quality-warn",
                                "remotix-rdp-quality-bad",
                            ] {
                                quality.remove_css_class(old);
                            }
                            quality.add_css_class(class);
                        }
                        Ok(ToUi::State(state)) => {
                            match &state {
                                SessionState::Connected => {
                                    was_connected = true;
                                    spinner.set_spinning(false);
                                    quality.set_text("Ожидание данных…");
                                    // После подключения сразу отдаём фокус
                                    // экрану, чтобы клавиатура работала без
                                    // обязательного первого клика.
                                    if let Some(area) = area.upgrade() {
                                        glib::idle_add_local_once(move || {
                                            area.grab_focus();
                                        });
                                    }
                                }
                                SessionState::Failed(e) => {
                                    spinner.set_spinning(false);
                                    quality.set_text("—");
                                    let prefix = if was_connected {
                                        "Сессия завершена с ошибкой"
                                    } else {
                                        "Ошибка подключения"
                                    };
                                    hint.set_text(&format!("{prefix}: {e}"));
                                    hint.set_visible(true);
                                }
                                SessionState::Closed => {
                                    spinner.set_spinning(false);
                                    quality.set_text("—");
                                    hint.set_text("Сессия завершена: сервер закрыл соединение.");
                                    hint.set_visible(true);
                                }
                                SessionState::Connecting => {}
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
                    let _ = tx.send(ToRdp::Key {
                        key: rdp_key(key, keycode),
                        pressed: true,
                    });
                    glib::Propagation::Stop
                }
            });
            controller.connect_key_released(move |_, key, keycode, _state| {
                // F11 переключает полный экран в capture-фазе корня;
                // release в удалённую сессию отправлять не нужно.
                if key == gdk::Key::F11 {
                    return;
                }
                let _ = tx.send(ToRdp::Key {
                    key: rdp_key(key, keycode),
                    pressed: false,
                });
            });
            area.add_controller(controller);
        }

        // ---------------- Мышь ----------------
        // DrawingArea по умолчанию не получает фокус клавиатуры; без этого
        // клавиши после клика уходили в никуда. Запоминаем и позицию курсора:
        // событие колеса не содержит координат, а раньше они всегда были (0,0).
        area.set_focusable(true);
        area.set_can_focus(true);
        let pressed = Rc::new(Cell::new(0u8));
        let pointer = Rc::new(Cell::new((0.0f64, 0.0f64)));

        {
            let tx = tx_rdp.clone();
            let area_ref = area.clone();
            let remote_size = remote_size.clone();
            let pressed = pressed.clone();
            let pointer = pointer.clone();
            let mode = scale_mode.clone();
            let controller = gtk4::EventControllerMotion::new();
            controller.connect_motion(move |_, x, y| {
                pointer.set((x, y));
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return;
                }
                let (rx, ry) = map_coordinates(&area_ref, x, y, rw, rh, mode.get());
                // Движение с зажатой кнопкой — это drag: маска кнопок должна
                // оставаться в событии, иначе сервер не тянет окно/выделение.
                let _ = tx.send(ToRdp::Mouse {
                    x: rx,
                    y: ry,
                    buttons: pressed.get(),
                    event: MouseEvent::Move,
                });
            });
            area.add_controller(controller);
        }

        {
            let tx = tx_rdp.clone();
            let area_ref = area.clone();
            let remote_size = remote_size.clone();
            let pressed = pressed.clone();
            let pointer = pointer.clone();
            let mode = scale_mode.clone();
            let controller = gtk4::GestureClick::new();
            controller.set_button(0); // любая кнопка мыши
            let tx_release = tx.clone();
            let area_release = area_ref.clone();
            let remote_release = remote_size.clone();
            let pressed_release = pressed.clone();
            controller.connect_pressed(move |_, button, x, y| {
                // Клик по удалённому экрану одновременно возвращает фокус
                // клавиатуре: иначе после переключения вкладки клавиши не шли.
                area_ref.grab_focus();
                pointer.set((x, y));
                let bit = match button {
                    1 => MOUSE_LEFT,
                    2 => MOUSE_MIDDLE,
                    3 => MOUSE_RIGHT,
                    _ => return,
                };
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return;
                }
                let (rx, ry) = map_coordinates(&area_ref, x, y, rw, rh, mode.get());
                pressed.set(pressed.get() | bit);
                let _ = tx.send(ToRdp::Mouse {
                    x: rx,
                    y: ry,
                    buttons: pressed.get(),
                    event: MouseEvent::ButtonDown,
                });
            });
            let mode_release = scale_mode.clone();
            controller.connect_released(move |_, button, x, y| {
                let bit = match button {
                    1 => MOUSE_LEFT,
                    2 => MOUSE_MIDDLE,
                    3 => MOUSE_RIGHT,
                    _ => return,
                };
                let (rw, rh) = remote_release.get();
                if rw == 0 || rh == 0 {
                    return;
                }
                let (rx, ry) = map_coordinates(&area_release, x, y, rw, rh, mode_release.get());
                // В событии отпускания кнопка должна остаться в маске, но без
                // DOWN — именно так RDP понимает button-up.
                let released = pressed_release.get() | bit;
                let _ = tx_release.send(ToRdp::Mouse {
                    x: rx,
                    y: ry,
                    buttons: released,
                    event: MouseEvent::ButtonUp,
                });
                pressed_release.set(pressed_release.get() & !bit);
            });
            area.add_controller(controller);
        }

        {
            let tx = tx_rdp.clone();
            let area_ref = area.clone();
            let remote_size = remote_size.clone();
            let pointer = pointer.clone();
            let mode = scale_mode.clone();
            let controller = gtk4::EventControllerScroll::new(
                gtk4::EventControllerScrollFlags::VERTICAL
                    | gtk4::EventControllerScrollFlags::DISCRETE,
            );
            controller.connect_scroll(move |_, _dx, dy| {
                let (rw, rh) = remote_size.get();
                if rw == 0 || rh == 0 {
                    return glib::Propagation::Proceed;
                }
                let (px, py) = pointer.get();
                let (rx, ry) = map_coordinates(&area_ref, px, py, rw, rh, mode.get());
                let _ = tx.send(ToRdp::Wheel {
                    x: rx,
                    y: ry,
                    delta: -(dy as i32),
                });
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

/// Переключает полноэкранный режим окна, в котором находится экран RDP.
fn toggle_fullscreen(area: &DrawingArea) {
    if let Some(root) = area.root() {
        if let Ok(win) = root.downcast::<gtk4::Window>() {
            if win.is_fullscreen() {
                win.unfullscreen();
            } else {
                win.fullscreen();
            }
        }
    }
}

/// Читает текст из GDK-буфера и отправляет его в поток RDP.
///
/// `last_remote` хранит текст, который мы только что записали в локальный
/// буфер из удалённой сессии: его нельзя отправлять обратно как «локальное
/// изменение», иначе получится эхо.
fn send_clipboard_text(
    clipboard: &gdk::Clipboard,
    tx: &mpsc::Sender<ToRdp>,
    last_remote: &Rc<RefCell<Option<String>>>,
) {
    let tx = tx.clone();
    let last_remote = last_remote.clone();
    clipboard.read_text_async(None::<&gio::Cancellable>, move |result| {
        // Пустой буфер или не текстовое содержимое (например, картинка)
        // означает, что удалённый текст больше не актуален.
        let text = match result {
            Ok(Some(text)) => text.to_string(),
            Ok(None) => String::new(),
            Err(e) => {
                crate::logging::rdp_warn(&format!(
                    "CLIPRDR: не удалось прочитать локальный буфер обмена: {e}"
                ));
                return;
            }
        };
        let is_echo = {
            let guard = last_remote.borrow();
            guard.as_deref() == Some(text.as_str())
        };
        if is_echo {
            return;
        }
        *last_remote.borrow_mut() = None;
        let _ = tx.send(ToRdp::ClipboardText(text));
    });
}

/// Переводит координаты виджета в координаты удалённого экрана.
///
/// Геометрия считается в `rdp_screen` — там же она проверяется unit-тестами
/// для всех режимов масштаба.
fn map_coordinates(
    area: &DrawingArea,
    x: f64,
    y: f64,
    remote_w: u32,
    remote_h: u32,
    mode: crate::rdp_screen::ScaleMode,
) -> (u32, u32) {
    crate::rdp_screen::map_point(
        x,
        y,
        remote_w,
        remote_h,
        area.width().max(1) as f64,
        area.height().max(1) as f64,
        mode,
    )
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
        RdpKey::Scancode {
            code: code as u8,
            extended: false,
        }
    } else {
        match key.to_unicode() {
            Some(c) => RdpKey::Char(c),
            None => RdpKey::Scancode {
                code: 0,
                extended: false,
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Живой smoke-тест RDP-просмотрщика: X11 + xrdp на 127.0.0.1:3389.
    ///
    /// Запускается вручную (`--ignored`) под Xvfb. Окно висит 5 минут,
    /// чтобы можно было проверить мышь/клавиатуру через xdotool и снять
    /// скриншоты.
    #[test]
    #[ignore = "требует X11 и xrdp на 127.0.0.1:3389"]
    fn live_rdp_ui_smoke() {
        use crate::models::profile::{Profile, RdpOptions, SshOptions, VncOptions};
        use crate::models::Protocol;
        use secrecy::SecretString;

        if gtk4::init().is_err() {
            return;
        }

        let profile = Profile {
            id: 0,
            name: "live-rdp".to_string(),
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
            rdp_options: RdpOptions::default(),
            vnc_options: VncOptions::default(),
            ssh_options: SshOptions::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        };

        let window = gtk4::Window::new();
        window.set_title(Some("remotix-live-rdp"));
        window.set_default_size(1000, 700);
        let on_state: Rc<dyn Fn(SessionState)> = Rc::new(|_| {});
        let viewer = RdpViewer::new(profile, on_state);
        window.set_child(Some(&viewer.root));
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
