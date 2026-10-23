//! Оформление интерфейса Remotix.
//!
//! Стили заданы в CSS GTK4 и используют системные цвета темы
//! (`@theme_bg_color`, `@accent_color` и т.д.), поэтому интерфейс одинаково
//! хорошо выглядит и в светлой, и в тёмной теме рабочего окружения.
//! Дополнительно доступны несколько собственных палитр: «Cosmic», «Океан» и
//! «Уголь».

use gtk4::prelude::*;
use gtk4::CssProvider;

/// Описание темы оформления.
pub struct Theme {
    /// Идентификатор (сохраняется в настройках).
    pub id: &'static str,
    /// Название для интерфейса.
    pub name: &'static str,
    /// Тёмная ли палитра.
    pub dark: bool,
}

/// Доступные темы.
pub const THEMES: &[Theme] = &[
    Theme { id: "light", name: "Светлая", dark: false },
    Theme { id: "dark", name: "Тёмная", dark: true },
    Theme { id: "cosmic", name: "Cosmic", dark: true },
    Theme { id: "ocean", name: "Океан", dark: true },
    Theme { id: "carbon", name: "Уголь", dark: true },
];

/// Тема по умолчанию.
pub const DEFAULT_THEME: &str = "light";

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
    /* Отступ слева — чтобы название профиля не примыкало к краю окна. */
    padding: 7px 10px 7px 14px;
    margin: 1px 8px 1px 4px;
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
    opacity: 0.85;
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
.remotix-tab-close {
    padding: 0;
    min-width: 18px;
    min-height: 18px;
    opacity: 0.55;
}
.remotix-tab-close:hover {
    opacity: 1;
}

/* Пункты контекстного меню профиля */
.remotix-menu-item {
    padding: 6px 12px;
    border-radius: 6px;
}

/* Контекстное меню: убираем жёсткую рамку стандартного поповера. */
popover > contents {
    padding: 4px;
    border-radius: 12px;
    border-style: none;
}

/* --- Файловый менеджер SFTP --- */
.remotix-file-list {
    background-color: transparent;
}
.remotix-file-list row {
    border-radius: 6px;
    margin: 1px 4px;
    padding: 1px 4px;
}
.remotix-file-list row:hover {
    background-color: alpha(currentColor, 0.08);
}
.remotix-file-list row.selected,
.remotix-file-list row:selected,
.remotix-file-list row.selected:backdrop,
.remotix-file-list row:selected:backdrop {
    background-color: #3584e4;
}
.remotix-file-list row.selected label,
.remotix-file-list row:selected label,
.remotix-file-list row.selected:backdrop label,
.remotix-file-list row:selected:backdrop label {
    color: #ffffff;
}
.remotix-dir {
    color: #3584e4;
    font-weight: 700;
}
.remotix-file {
    color: @theme_fg_color;
}
.remotix-file-size {
    font-size: 0.8em;
    opacity: 0.55;
}
.remotix-dir-up {
    opacity: 0.6;
    font-style: italic;
}
.remotix-pane-local {
    background-color: alpha(@theme_base_color, 0.3);
}
.remotix-pane-remote {
    background-color: alpha(@theme_base_color, 0.6);
}
.remotix-pane-path {
    font-weight: 700;
    font-size: 0.9em;
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
.remotix-section-title {
    font-weight: 700;
    font-size: 0.95em;
    padding: 10px 0 4px 0;
}

/* --- Экран удалённого рабочего стола --- */
.remotix-remote-screen {
    background-color: #10161d;
}

/* --- Резервный терминал --- */
.remotix-terminal {
    background-color: #0d1b2a;
    color: #e6edf3;
}

/* ============ Собственные палитры ============ */

/* Cosmic: глубокий индиго */
.remotix-theme-cosmic { background-color: #12122b; color: #e7e4f7; }
.remotix-theme-cosmic .remotix-sidebar { background-color: #1a1a3c; }
.remotix-theme-cosmic .remotix-statusbar { background-color: #1a1a3c; color: #b6b1db; }
.remotix-theme-cosmic .remotix-profile-details { color: #9b96c4; }
.remotix-theme-cosmic .remotix-hint { color: #7a75a8; }
.remotix-theme-cosmic .remotix-empty { color: #8b86b8; }
.remotix-theme-cosmic entry,
.remotix-theme-cosmic searchentry { background-color: #232352; color: #e7e4f7; }
.remotix-theme-cosmic .remotix-remote-screen { background-color: #0b0b1c; }
.remotix-theme-cosmic .remotix-terminal { background-color: #17173a; color: #d9d5f5; }

/* Океан: холодные бирюзовые тона */
.remotix-theme-ocean { background-color: #0d1f26; color: #dff1f5; }
.remotix-theme-ocean .remotix-sidebar { background-color: #122a33; }
.remotix-theme-ocean .remotix-statusbar { background-color: #122a33; color: #a9cdd6; }
.remotix-theme-ocean .remotix-profile-details { color: #8fb4be; }
.remotix-theme-ocean .remotix-hint { color: #6d949e; }
.remotix-theme-ocean .remotix-empty { color: #7ea3ad; }
.remotix-theme-ocean entry,
.remotix-theme-ocean searchentry { background-color: #163742; color: #dff1f5; }
.remotix-theme-ocean .remotix-remote-screen { background-color: #08161b; }
.remotix-theme-ocean .remotix-terminal { background-color: #0f2b34; color: #cfeaf1; }

/* Уголь: нейтральный серый */
.remotix-theme-carbon { background-color: #17181a; color: #e3e4e6; }
.remotix-theme-carbon .remotix-sidebar { background-color: #1e2023; }
.remotix-theme-carbon .remotix-statusbar { background-color: #1e2023; color: #a8aaad; }
.remotix-theme-carbon .remotix-profile-details { color: #8f9296; }
.remotix-theme-carbon .remotix-hint { color: #6f7276; }
.remotix-theme-carbon .remotix-empty { color: #83868a; }
.remotix-theme-carbon entry,
.remotix-theme-carbon searchentry { background-color: #242629; color: #e3e4e6; }
.remotix-theme-carbon .remotix-remote-screen { background-color: #0d0e0f; }
.remotix-theme-carbon .remotix-terminal { background-color: #101112; color: #d8dade; }

/* Тёмная тема: приглушаем панели */
.remotix-theme-dark .remotix-sidebar { background-color: alpha(#000000, 0.25); }
.remotix-theme-dark .remotix-statusbar { background-color: alpha(#000000, 0.25); }
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

/// Применяет тему оформления: переключает тёмный вариант GTK и ставит
/// на корневой виджет класс темы (палитра задаётся в CSS).
pub fn apply(id: &str, root: &impl IsA<gtk4::Widget>) {
    let theme = THEMES.iter().find(|t| t.id == id).unwrap_or(&THEMES[0]);

    // Тёмный вариант адвайты.
    if let Some(settings) = gtk4::Settings::default() {
        settings.set_property("gtk-application-prefer-dark-theme", theme.dark);
    }

    for t in THEMES {
        root.remove_css_class(&format!("remotix-theme-{}", t.id));
    }
    root.add_css_class(&format!("remotix-theme-{}", theme.id));
}
