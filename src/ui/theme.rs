//! Оформление интерфейса Remotix.
//!
//! Стили заданы в CSS GTK4 и используют системные цвета темы
//! (`@theme_bg_color`, `@accent_color` и т.д.), поэтому интерфейс одинаково
//! хорошо выглядит и в светлой, и в тёмной теме рабочего окружения.

use gtk4::CssProvider;

/// Основные стили интерфейса.
const STYLE: &str = r#"
/* --- Боковая панель со списком подключений --- */
.remotix-sidebar {
    background-color: alpha(@theme_base_color, 0.45);
}
.remotix-sidebar listbox {
    background-color: transparent;
}
.remotix-sidebar listbox row {
    border-radius: 9px;
    padding: 6px 10px;
    margin: 1px 6px;
    transition: background-color 120ms ease-out;
}
.remotix-sidebar listbox row:hover {
    background-color: alpha(currentColor, 0.07);
}
.remotix-sidebar listbox row.selected {
    background-color: @accent_bg_color;
}
.remotix-sidebar listbox row.selected label.remotix-profile-name,
.remotix-sidebar listbox row.selected label.remotix-profile-details {
    color: @accent_fg_color;
}
.remotix-group {
    font-weight: 700;
    font-size: 0.82em;
    opacity: 0.65;
    padding: 12px 16px 4px 16px;
}
.remotix-profile-name {
    font-weight: 600;
}
.remotix-profile-details {
    font-size: 0.82em;
    opacity: 0.62;
}
/* Метка протокола: цвет задаётся классами .success/.accent/.warning */
.remotix-tag {
    font-size: 0.72em;
    font-weight: 700;
}

/* --- Строка состояния --- */
.remotix-statusbar {
    padding: 5px 12px;
    font-size: 0.85em;
    opacity: 0.8;
    border-top: 1px solid alpha(currentColor, 0.12);
}
.remotix-status-ok {
    color: #3da35d;
    font-weight: 600;
}
.remotix-status-error {
    color: #e5534b;
    font-weight: 600;
}
.remotix-status-busy {
    color: #d99e2b;
    font-weight: 600;
}
.remotix-hint {
    opacity: 0.55;
}

/* --- Вкладки сессий --- */
.remotix-session {
    font-family: monospace;
}
.remotix-empty {
    font-size: 1.1em;
    opacity: 0.5;
}

/* --- Диалоги --- */
.remotix-dialog-header {
    font-weight: 700;
    font-size: 1.05em;
    padding-bottom: 6px;
}
.remotix-field-caption {
    font-size: 0.85em;
    opacity: 0.7;
}

/* --- Экран удалённого рабочего стола --- */
.remotix-remote-screen {
    background-color: #10161d;
}
"#;

/// Устанавливает стили приложения (один раз за сеанс).
///
/// Вызывать нужно **после** инициализации GTK (иначе создание
/// `GtkCssProvider` паникует) — то есть из обработчика окна.
pub fn install() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        let provider = CssProvider::new();
        provider.load_from_data(STYLE);

        if let Some(display) = gtk4::gdk::Display::default() {
            gtk4::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }
    });
}
