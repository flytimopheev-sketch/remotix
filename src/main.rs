mod app;
mod config;
mod db;
mod models;
mod protocols;
mod ui;

use gtk4::prelude::*;

fn main() -> gtk4::glib::ExitCode {
    let app = gtk4::Application::builder()
        .application_id("ru.redos.Remotix")
        .build();

    config::init_dirs();

    app.connect_activate(app::activate);
    app.run()
}
