//! Диалог предпросмотра импорта.
//!
//! Сначала пользователь видит «Импортируется N · пропущено M», причины
//! пропуска и список профилей. Только после нажатия «Импортировать» вызывающий
//! код пишет профили в базу.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, Label, Orientation, ScrolledWindow, TextView, Window};

use crate::import::normalize::{Candidate, ImportPreview};

thread_local! {
    /// Окно предпросмотра должно жить до закрытия: локальная переменная
    /// после `present()` уже не держит GTK-объект.
    static OPEN: RefCell<Vec<Window>> = const { RefCell::new(Vec::new()) };
}

/// Показывает предпросмотр и после подтверждения передаёт выбранные профили.
pub fn show<F>(parent: Option<&Window>, preview: ImportPreview, on_confirm: F)
where
    F: FnOnce(Vec<Candidate>) + 'static,
{
    let imported = preview.imported();
    let skipped = preview.skipped_count();

    let window = Window::builder()
        .title("Импорт подключений")
        .default_width(760)
        .default_height(560)
        .modal(true)
        .build();
    if let Some(parent) = parent {
        window.set_transient_for(Some(parent));
    }

    let root = GtkBox::new(Orientation::Vertical, 10);
    for margin in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
        root.set_property(margin, 14);
    }

    let heading = Label::new(Some(&preview.summary()));
    heading.set_xalign(0.0);
    heading.add_css_class("remotix-dialog-header");
    root.append(&heading);

    if !preview.skipped.is_empty() {
        let reasons = preview
            .skip_reasons()
            .into_iter()
            .map(|(reason, count)| format!("• {reason} — {count}"))
            .collect::<Vec<_>>()
            .join("\n");
        let label = Label::new(Some(&format!("Причины пропуска:\n{reasons}")));
        label.set_xalign(0.0);
        label.set_wrap(true);
        root.append(&label);
    }

    if !preview.notes.is_empty() {
        let note = Label::new(Some(&preview.notes.join("\n")));
        note.set_xalign(0.0);
        note.set_wrap(true);
        note.add_css_class("remotix-field-caption");
        root.append(&note);
    }

    let details = build_details(&preview);
    let text = TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk4::WrapMode::WordChar)
        .build();
    text.buffer().set_text(&details);
    let scroll = ScrolledWindow::new();
    scroll.set_vexpand(true);
    scroll.set_child(Some(&text));
    root.append(&scroll);

    let buttons = GtkBox::new(Orientation::Horizontal, 8);
    buttons.set_halign(gtk4::Align::End);
    let cancel = Button::with_label("Отмена");
    let import = Button::with_label(&if imported == 0 {
        "Нечего импортировать".to_string()
    } else {
        format!("Импортировать ({imported})")
    });
    import.add_css_class("suggested-action");
    import.set_sensitive(imported > 0);
    buttons.append(&cancel);
    buttons.append(&import);
    root.append(&buttons);
    window.set_child(Some(&root));

    {
        let window = window.clone();
        cancel.connect_clicked(move |_| window.close());
    }

    let callback: Rc<RefCell<Option<F>>> = Rc::new(RefCell::new(Some(on_confirm)));
    {
        let window = window.clone();
        let candidates = preview.candidates;
        import.connect_clicked(move |_| {
            let callback = callback.borrow_mut().take();
            window.close();
            if let Some(callback) = callback {
                callback(candidates.clone());
            }
        });
    }

    OPEN.with(|open| open.borrow_mut().push(window.clone()));
    {
        let addr = window.as_ptr() as usize;
        window.connect_destroy(move |_| {
            OPEN.with(|open| {
                open.borrow_mut()
                    .retain(|w| w.as_ptr() as usize != addr);
            });
        });
    }
    window.present();

    // Если кандидатов нет, кнопка «Импортировать» неактивна; окно остаётся
    // для просмотра причин пропуска. Явно помечаем это в заголовке.
    if imported == 0 && skipped == 0 {
        heading.set_text("Нечего импортировать: источник пуст");
    }
}

fn build_details(preview: &ImportPreview) -> String {
    let mut text = String::new();
    for candidate in &preview.candidates {
        let p = &candidate.profile;
        let protocol = p
            .protocol
            .map(|protocol| protocol.as_str())
            .unwrap_or("SSH");
        let login = p
            .username
            .as_deref()
            .map(|user| format!("{user}@"))
            .unwrap_or_default();
        text.push_str(&format!(
            "+ [{protocol}] {} — {login}{}:{}\n    {}\n",
            p.name, p.host, p.port, candidate.origin
        ));
    }
    if !preview.skipped.is_empty() {
        text.push_str("\nПропущено:\n");
        for item in &preview.skipped {
            text.push_str(&format!(
                "- [{}] {}: {}\n",
                item.source.label(),
                item.name,
                item.reason
            ));
        }
    }
    if text.is_empty() {
        text.push_str("Источник не содержит профилей для импорта.\n");
    }
    text
}
