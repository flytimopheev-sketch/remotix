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

    window.present();
}
