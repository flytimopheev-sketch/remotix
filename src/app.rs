use gtk4::prelude::*;
use gtk4::{Application, ApplicationWindow, Notebook};

use crate::db::repository::Database;
use crate::ui::main_window::MainWindow;
use crate::ui::master_password::MasterPasswordDialog;

/// Состояние приложения: база данных и ключ шифрования после разблокировки.
pub struct AppState {
    pub db: Database,
    pub key: Option<[u8; 32]>,
}

impl AppState {
    pub fn unlocked_key(&self) -> [u8; 32] {
        self.key.expect("приложение разблокировано")
    }
}

pub fn activate(app: &Application) {
    let db = crate::db::open_database();

    // Мастер-пароль: создание при первом запуске, иначе — запрос.
    let dialog = MasterPasswordDialog::new(&db);
    let key = dialog.run_and_get_key();
    let key = match key {
        Some(k) => k,
        None => {
            eprintln!("Remotix: не разблокировано, выход");
            return;
        }
    };

    let state = AppState { db, key: Some(key) };

    let window = ApplicationWindow::builder()
        .application(app)
        .title("Remotix — Клиент удалённого доступа")
        .default_width(1100)
        .default_height(700)
        .build();

    let notebook = Notebook::new();
    notebook.set_tab_pos(gtk4::PositionType::Top);
    window.set_child(Some(&notebook));

    let main = MainWindow::new(state);
    notebook.append_page(&main.root, Some(&gtk4::Label::new(Some("Подключения"))));

    // Горячие клавиши: Ctrl+N, Ctrl+F, Ctrl+Q, Ctrl+L
    let actions = gtk4::gio::SimpleActionGroup::new();
    window.insert_action_group("win", Some(&actions));

    let new_action = gtk4::gio::SimpleAction::new("new-profile", None);
    {
        let main = main.clone();
        new_action.connect_activate(move |_, _| main.open_profile_editor(None));
    }
    actions.add_action(&new_action);

    let lock_action = gtk4::gio::SimpleAction::new("lock", None);
    lock_action.connect_activate(|_, _| {
        // Блокировка интерфейса: повторный запрос мастер-пароля.
        // Полная реализация — затемняющий оверлей + диалог мастер-пароля.
    });
    actions.add_action(&lock_action);

    // О программе (Ctrl+I / меню приложения)
    let about_action = gtk4::gio::SimpleAction::new("about", None);
    {
        let window = window.clone();
        about_action.connect_activate(move |_, _| show_about(&window));
    }
    actions.add_action(&about_action);

    app.set_accelerators_for_action("win.about", Some(&["<Primary>I"]));

    window.present();
}

/// Красивый диалог «О программе».
fn show_about(parent: &ApplicationWindow) {
    let about = gtk4::AboutDialog::builder()
        .program_name("Remotix")
        .version("1.0.0")
        .title("О программе Remotix")
        .comments(
            "Единый клиент удалённого доступа для РЕД ОС.\n\
             RDP · VNC · SSH · SFTP — всё в одном окне.\n\
             Работает полностью офлайн: без облака, без телеметрии.",
        )
        .website("https://redos.example/remotix")
        .website_label("Сайт проекта")
        .license_type(gtk4::License::MitX11)
        .copyright("Copyright © 2026 flytimopheev")
        .authors(vec!["flytimopheev <flytimopheev@gmail.com>".to_string()])
        .logo_icon_name("preferences-system-remote")
        .transient_for(parent)
        .modal(true)
        .build();

    about.set_authors(&["flytimopheev <flytimopheev@gmail.com>"]);
    about.set_license(Some(concat!(
        "MIT License\n\n",
        "Copyright (c) 2026 flytimopheev <flytimopheev@gmail.com>\n\n",
        "Permission is hereby granted, free of charge, to any person obtaining a copy\n",
        "of this software and associated documentation files (the \"Software\"), to deal\n",
        "in the Software without restriction, including without limitation the rights\n",
        "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n",
        "copies of the Software, and to permit persons to whom the Software is\n",
        "furnished to do so, subject to the following conditions:\n\n",
        "The above copyright notice and this permission notice shall be included in all\n",
        "copies or substantial portions of the Software.\n\n",
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n",
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n",
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n",
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n",
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n",
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n",
        "SOFTWARE.\n\n",
        "Обратная связь и предложения: flytimopheev@gmail.com"
    )));

    about.present();
}
