use gtk4::prelude::*;
use gtk4::Window;

use crate::app::AppState;

/// Диалог свойств/редактирования профиля подключения.
pub struct ProfileEditor {
    window: Window,
    #[allow(dead_code)]
    state: AppState,
    #[allow(dead_code)]
    profile_id: Option<i64>,
}

impl ProfileEditor {
    pub fn new(state: &AppState, profile_id: Option<i64>) -> Self {
        let window = Window::builder()
            .title(match profile_id {
                Some(_) => "Свойства подключения",
                None => "Новое подключение",
            })
            .default_width(520)
            .default_height(640)
            .modal(true)
            .hide_on_close(true)
            .build();

        Self { window, state: clone_state(state), profile_id }
    }

    /// Показывает диалог поверх родительского окна.
    pub fn present_transient_for(&self, parent: Option<&Window>) {
        self.window.set_transient_for(parent);
        self.window.present();
    }
}

fn clone_state(state: &AppState) -> AppState {
    // AppState содержит Database (Connection не Send/Sync-обёртка клонирования),
    // поэтому здесь создаётся лёгкая ссылочная семантика через повторное открытие БД.
    AppState {
        db: crate::db::open_database(),
        key: state.key,
    }
}
