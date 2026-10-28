//! Диалог подтверждения неизвестного ключа SSH-хоста.
//!
//! Ключ проверяется в фоновом потоке подключения. Поток отправляет сюда
//! отпечаток и ждёт ответа; диалог показывает главный поток GTK.

use std::cell::RefCell;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{MessageDialog, MessageType, ResponseType, Window};

use crate::protocols::ssh::HostKeyPrompt;

thread_local! {
    /// Диалоги должны жить до ответа пользователя: локальная переменная
    /// `MessageDialog` после `show()` больше не держит окно.
    static OPEN: RefCell<Vec<MessageDialog>> = const { RefCell::new(Vec::new()) };
}

/// Спрашивает пользователя, доверять ли неизвестному ключу.
///
/// `on_decision` вызывается в главном потоке GTK ровно один раз.
pub fn ask_unknown<F>(parent: Option<&Window>, prompt: HostKeyPrompt, on_decision: F)
where
    F: Fn(bool) + 'static,
{
    let text = format!("Неизвестный ключ SSH-хоста {}:{}", prompt.host, prompt.port);
    let details = format!(
        "Отпечаток: {}\nТип ключа: {}\n\n\
         Ключ будет добавлен в:\n{}\n\n\
         Доверять этому хосту и продолжить?",
        prompt.fingerprint,
        prompt.key_type,
        prompt.known_hosts.display()
    );

    let dialog = MessageDialog::builder()
        .message_type(MessageType::Question)
        .text(text)
        .secondary_text(details)
        .build();
    if let Some(parent) = parent {
        dialog.set_transient_for(Some(parent));
    }
    dialog.set_modal(true);
    dialog.set_default_response(ResponseType::Cancel);
    dialog.add_button("Отклонить", ResponseType::Cancel);
    dialog.add_button("Доверять и продолжить", ResponseType::Accept);

    type Decision = Box<dyn FnOnce(bool)>;

    let callback: Rc<RefCell<Option<Decision>>> =
        Rc::new(RefCell::new(Some(Box::new(on_decision))));
    {
        let callback = callback.clone();
        dialog.connect_response(move |dialog, response| {
            if let Some(cb) = callback.borrow_mut().take() {
                cb(response == ResponseType::Accept);
            }
            dialog.destroy();
        });
    }
    // Закрытие крестиком не должно оставлять поток подключения ждать
    // ответа до таймаута: считаем это отказом.
    {
        let callback = callback.clone();
        dialog.connect_destroy(move |_| {
            if let Some(cb) = callback.borrow_mut().take() {
                cb(false);
            }
        });
    }

    OPEN.with(|open| open.borrow_mut().push(dialog.clone()));
    {
        // Адрес объекта, а не его клон: иначе сигнал destroy создал бы
        // цикл «диалог → замыкание → диалог» и окно никогда не освободилось.
        let addr = dialog.as_ptr() as usize;
        dialog.connect_destroy(move |_| {
            OPEN.with(|open| {
                open.borrow_mut().retain(|w| w.as_ptr() as usize != addr);
            });
        });
    }
    dialog.show();
}
