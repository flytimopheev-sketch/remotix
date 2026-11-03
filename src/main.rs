//! Remotix — клиент удалённого доступа (RDP / VNC / SSH) для РЕД ОС.
//!
//! Точка входа. Здесь создаётся GTK4-приложение и подписываются обработчики
//! сигналов GApplication:
//!
//! * `activate` — обычный запуск (значок в меню, команда `remotix`);
//! * `open`    — запуск с URI (`ssh://`, `rdp://`, `vnc://`) или файлами;
//! * `--connect <ссылка>` — цель, которую нужно открыть после разблокировки.
//!
//! Флаг `G_APPLICATION_HANDLES_OPEN` обязателен: без него GApplication
//! завершает работу с критической ошибкой
//! «This application can not open files.» и графический интерфейс не
//! показывается вовсе.

// Модули RDP, VNC и SFTP пока не включены в интерфейс — их API используется
// не полностью, поэтому предупреждения о «мёртвом» коде отключаем.
#![allow(dead_code)]
// Небезопасный код разрешён только в одной зоне: динамическая загрузка VTE
// (src/ui/terminal.rs, mod vte_dynamic). Всё остальное приложение — safe Rust.
#![deny(unsafe_code)]

mod app;
mod config;
mod connect_target;
mod db;
mod expect;
mod host_check;
mod import;
mod logging;
mod models;
mod password;
mod profiles_io;
mod protocols;
mod recording;
mod settings;
mod ui;
mod wol;

use connect_target::ConnectTarget;
use gtk4::gio::ApplicationFlags;
use gtk4::prelude::*;

fn main() -> gtk4::glib::ExitCode {
    let mut args: Vec<String> = std::env::args().collect();

    // Поддержка `remotix --version`. Реализовано вручную: метод
    // gio::ApplicationExt::set_version появился только в GLib 2.80, а РЕД ОС
    // собирается с более старой версией.
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("remotix {}", env!("CARGO_PKG_VERSION"));
        return gtk4::glib::ExitCode::SUCCESS;
    }

    // `--connect` разбираем сами и убираем из argv: GApplication с
    // HANDLES_OPEN иначе принял бы значение за файл. Ошибку показываем
    // сразу, до открытия хранилища и запроса мастер-пароля.
    let launch_target = match take_connect_arg(&mut args) {
        Ok(target) => target,
        Err(message) => {
            eprintln!("remotix: {message}");
            return gtk4::glib::ExitCode::FAILURE;
        }
    };

    // Каталог данных (~/.local/share/remotix) должен существовать до
    // открытия базы данных.
    config::init_dirs();

    let app = gtk4::Application::builder()
        .application_id("ru.redos.Remotix")
        // Рабочее окружение (Cinnamon, файловый менеджер, «Открыть с помощью»)
        // умеет запускать приложение с URI/файлом. GApplication в этом случае
        // требует флаг HANDLES_OPEN, иначе он печатает
        // «This application can not open files.» и выходит с кодом 1 —
        // окно Remotix так и не появляется.
        .flags(ApplicationFlags::HANDLES_OPEN)
        .build();

    app.connect_activate(app::activate);
    app.connect_open(app::open);

    if let Some(target) = launch_target {
        // Передаём цель каноническим URI, а не через отдельную статическую
        // переменную: GApplication перешлёт аргумент уже запущенному
        // экземпляру, и ссылка откроется в его окне.
        args.push(target.to_uri());
    }

    // run() передаёт в GApplication все argv, включая уже разобранный
    // `--connect`. Запускаем с очищенным списком: URI в нём останутся и
    // придут в сигнал `open`.
    app.run_with_args(&args)
}

/// Извлекает `--connect <ссылка>` или `--connect=<ссылка>` из аргументов.
fn take_connect_arg(args: &mut Vec<String>) -> Result<Option<ConnectTarget>, String> {
    let mut target = None;
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--connect" {
            let value = args
                .get(index + 1)
                .cloned()
                .ok_or_else(|| "после --connect нужна ссылка (user@host, ssh://…)".to_string())?;
            target = Some(ConnectTarget::parse(&value)?);
            args.drain(index..=index + 1);
        } else if let Some(value) = args[index].strip_prefix("--connect=") {
            target = Some(ConnectTarget::parse(value)?);
            args.remove(index);
        } else {
            index += 1;
        }
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Protocol;

    #[test]
    fn connect_argument_is_removed_from_argv() {
        let mut args = vec![
            "remotix".to_string(),
            "--connect".to_string(),
            "ssh://user@host:2222".to_string(),
            "rdp://other".to_string(),
        ];
        let target = take_connect_arg(&mut args)
            .expect("разбор")
            .expect("цель найдена");
        assert_eq!(target.protocol, Protocol::Ssh);
        assert_eq!(target.host, "host");
        assert_eq!(target.port, 2222);
        assert_eq!(target.username.as_deref(), Some("user"));
        assert_eq!(args, vec!["remotix", "rdp://other"]);
    }

    #[test]
    fn connect_equals_form_is_supported() {
        let mut args = vec!["remotix".to_string(), "--connect=vnc://server".to_string()];
        let target = take_connect_arg(&mut args)
            .expect("разбор")
            .expect("цель найдена");
        assert_eq!(target.protocol, Protocol::Vnc);
        assert_eq!(args, vec!["remotix"]);
    }

    #[test]
    fn missing_or_invalid_connect_target_is_error() {
        let mut missing = vec!["remotix".to_string(), "--connect".to_string()];
        assert!(take_connect_arg(&mut missing).is_err());

        let mut invalid = vec!["remotix".to_string(), "--connect=file:///tmp/x".to_string()];
        assert!(take_connect_arg(&mut invalid).is_err());
    }
}
