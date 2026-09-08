use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Label, ScrolledWindow};

use crate::protocols::ssh::SshConnection;

#[cfg(target_os = "linux")]
use gtk4::EventControllerKey;
#[cfg(target_os = "linux")]
use vte4::Terminal as Vte;

const PROMPT_MS: u64 = 10;

/// Вкладка SSH-терминала. На Linux — полноценный VTE-эмулятор
/// (цвета, ANSI, vim/htop/mc), подключённый к SSH-сессии.
pub struct TerminalTab {
    pub root: GtkBox,
    pub title: String,
}

#[cfg(not(target_os = "linux"))]
impl TerminalTab {
    pub fn new_ssh(title: &str, _conn: SshConnection) -> Result<Self, String> {
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);
        let label = Label::new(Some(&format!(
            "Терминал «{title}» работает только на Linux (VTE)."
        )));
        root.append(&label);
        Ok(Self { root, title: title.to_string() })
    }
}

#[cfg(target_os = "linux")]
enum ToThread {
    Data(Vec<u8>),
    Resize(u32, u32),
}

#[cfg(target_os = "linux")]
enum ToUi {
    Out(Vec<u8>),
    Closed(Option<String>),
}

// PART2

#[cfg(target_os = "linux")]
impl TerminalTab {
    pub fn new_ssh(title: &str, conn: SshConnection) -> Result<Self, String> {
        use std::sync::mpsc;
        use std::time::Duration;

        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);
        let scroll = ScrolledWindow::new();
        let term = Vte::new();
        scroll.set_child(Some(&term));
        scroll.set_vexpand(true);
        root.append(&scroll);

        let (tx_in, rx_in) = mpsc::channel::<ToThread>();
        let (tx_out, rx_out) = mpsc::channel::<ToUi>();

        // Поток: подключение, shell/su → root, неблокирующий цикл обмена.
        std::thread::spawn(move || {
            let mut conn = conn;
            if let Err(e) = conn.connect() {
                let _ = tx_out.send(ToUi::Closed(Some(e)));
                return;
            }
            let Some(mut session) = conn.take_session() else {
                let _ = tx_out.send(ToUi::Closed(Some("сессия потеряна".into())));
                return;
            };
            session.set_blocking(true);
            let su = conn.profile.ssh_options.su_to_root && conn.profile.root_password.is_some();
            let open = (|| {
                let mut ch = session.channel_session()?;
                ch.request_pty("xterm", None, None)?;
                if su {
                    ch.exec("su -")?;
                    wait_password(&mut ch, &mut session, conn.profile.root_password.clone().unwrap_or_default())?;
                } else {
                    ch.shell()?;
                }
                Ok(ch)
            })();
            let mut ch = match open {
                Ok(c) => c,
                Err(e) => { let _ = tx_out.send(ToUi::Closed(Some(e))); return; }
            };

            session.set_blocking(false);
            let mut buf = [0u8; 8192];
            loop {
                match ch.read(&mut buf) {
                    Ok(0) => { let _ = tx_out.send(ToUi::Closed(None)); break; }
                    Ok(n) => { if tx_out.send(ToUi::Out(buf[..n].to_vec())).is_err() { break; } }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => { let _ = tx_out.send(ToUi::Closed(Some(e.to_string()))); break; }
                }
                match rx_in.recv_timeout(Duration::from_millis(PROMPT_MS)) {
                    Ok(ToThread::Data(d)) => {
                        use std::io::Write;
                        let _ = ch.write_all(&d);
                    }
                    Ok(ToThread::Resize(c, r)) => { let _ = ch.request_pty_size(c, r, None, None); }
                    Err(_) => {}
                }
                if ch.eof() { let _ = tx_out.send(ToUi::Closed(None)); break; }
            }
            let _ = session.disconnect(None, "закрыто пользователем", None);
        });

        // Опрос вывода канала (главный поток) → кормим VTE.
        let term_out = term.clone();
        let status = Label::new(None);
        status.set_halign(gtk4::Align::Start);
        glib::timeout_add_local(Duration::from_millis(PROMPT_MS), move || {
            loop {
                match rx_out.try_recv() {
                    Ok(ToUi::Out(data)) => term_out.feed(&data),
                    Ok(ToUi::Closed(err)) => {
                        status.set_text(&match err {
                            Some(e) => format!("● Сессия закрыта: {e}"),
                            None => "● Сессия закрыта".into(),
                        });
                        return glib::ControlFlow::Break;
                    }
                    Err(_) => return glib::ControlFlow::Continue,
                }
            }
        });
        root.append(&status);

        setup_input(&term, tx_in);
        Ok(Self { root, title: title.to_string() })
    }
}

// PART3

/// Ввод с клавиатуры: буквы/символы → UTF-8, служебные клавиши → escape-
/// последовательности, Ctrl+буква → управляющий байт. Плюс горячие клавиши
/// VTE: Ctrl+Shift+C/V (копия/вставка), Ctrl+± (масштаб шрифта).
#[cfg(target_os = "linux")]
fn setup_input(term: &Vte, tx_in: std::sync::mpsc::Sender<ToThread>) {
    use gtk4::gdk::ModifierType;

    let controller = EventControllerKey::new();
    let term_ref = term.clone();
    controller.connect_key_pressed(move |_, keyval, _code, state| {
        let ctrl = state.contains(ModifierType::CONTROL);
        let shift = state.contains(ModifierType::SHIFT_MASK);

        if ctrl && shift {
            match keyval.name().as_deref() {
                Some("c") => { term_ref.copy_clipboard_format(); return glib::Propagation::Stop; }
                Some("v") => {
                    let clipboard = term_ref.clipboard();
                    let tx = tx_in.clone();
                    glib::spawn_future_local(async move {
                        if let Ok(Some(text)) = clipboard.read_text_future().await {
                            let _ = tx.send(ToThread::Data(text.replace('\n', "\r").into_bytes()));
                        }
                    });
                    return glib::Propagation::Stop;
                }
                _ => {}
            }
        }
        if ctrl && !shift {
            match keyval.name().as_deref() {
                Some("plus") | Some("equal") => {
                    term_ref.set_font_scale((term_ref.font_scale() * 1.1).min(4.0));
                    return glib::Propagation::Stop;
                }
                Some("minus") => {
                    term_ref.set_font_scale((term_ref.font_scale() / 1.1).max(0.3));
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
        let _ = tx_in.send(ToThread::Data(bytes));
        glib::Propagation::Stop
    });
    term.add_controller(&controller);

    // Resize PTY при изменении размера виджета.
    let tx_resize = tx_in.clone();
    term.connect_resize(move |t, width, height| {
        let cw = t.char_width().max(1) as u32;
        let chh = t.char_height().max(1) as u32;
        let cols = (width as u32 / cw).max(2);
        let rows = (height as u32 / chh).max(2);
        let _ = tx_resize.send(ToThread::Resize(cols, rows));
    });
}

/// Ожидание prompt "Password:" и ответ паролем root.
#[cfg(target_os = "linux")]
fn wait_password(
    ch: &mut ssh2::Channel,
    session: &mut ssh2::Session,
    password: String,
) -> Result<(), String> {
    use std::io::{Read, Write};
    let mut buf = [0u8; 512];
    let mut seen = String::new();
    session.set_blocking(false);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
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
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    session.set_blocking(true);
    if !prompted {
        return Err("сервер не запросил пароль root".into());
    }
    ch.write_all(password.as_bytes())
        .and_then(|_| ch.write_all(b"\n"))
        .map_err(|e| e.to_string())
}



