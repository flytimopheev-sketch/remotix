//! Remotix — клиент удалённого доступа (RDP / VNC / SSH) для РЕД ОС.
//!
//! Точка входа. Здесь создаётся GTK4-приложение и подписываются обработчики
//! сигналов GApplication:
//!
//! * `activate` — обычный запуск (значок в меню, команда `remotix`);
//! * `open`    — запуск с файлами/URI (например, когда рабочее окружение
//!   передаёт приложению путь).
//!
//! Флаг `G_APPLICATION_HANDLES_OPEN` обязателен: без него GApplication
//! завершает работу с критической ошибкой
//! «This application can not open files.» и графический интерфейс не
//! показывается вовсе.

// Модули RDP, VNC и SFTP пока не включены в интерфейс — их API используется
// не полностью, поэтому предупреждения о «мёртвом» коде отключаем.
#![allow(dead_code)]

mod app;
mod config;
mod db;
mod host_check;
mod import;
mod models;
mod profiles_io;
mod protocols;
mod settings;
mod ui;
mod wol;

use gtk4::gio::ApplicationFlags;
use gtk4::prelude::*;

fn main() -> gtk4::glib::ExitCode {
    // Поддержка `remotix --version`. Реализовано вручную: метод
    // gio::ApplicationExt::set_version появился только в GLib 2.80, а РЕД ОС
    // собирается с более старой версией.
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("remotix {}", env!("CARGO_PKG_VERSION"));
        return gtk4::glib::ExitCode::SUCCESS;
    }

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

    app.run()
}
