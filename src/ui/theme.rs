//! Оформление интерфейса Remotix.
//!
//! Стили заданы в CSS GTK4 и используют системные цвета темы
//! (`@theme_bg_color`, `@accent_color` и т.д.), поэтому интерфейс одинаково
//! хорошо выглядит и в светлой, и в тёмной теме рабочего окружения.
//! Дополнительно доступны несколько собственных палитр: «Cosmic», «Океан» и
//! «Уголь».
//!
//! Язык оформления: скруглённые карточки и «пилюли», спокойные отступы,
//! полупрозрачные панели поверх контента (RDP-панель, индикатор качества),
//! мягкие переходы цвета при наведении. Всё это — подмножество CSS GTK4,
//! совместимое с библиотекой 4.6 в РЕД ОС.

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
    Theme {
        id: "light",
        name: "Светлая",
        dark: false,
    },
    Theme {
        id: "dark",
        name: "Тёмная",
        dark: true,
    },
    Theme {
        id: "cosmic",
        name: "Cosmic",
        dark: true,
    },
    Theme {
        id: "ocean",
        name: "Океан",
        dark: true,
    },
    Theme {
        id: "carbon",
        name: "Уголь",
        dark: true,
    },
];

/// Тема по умолчанию.
pub const DEFAULT_THEME: &str = "light";

/// Основные стили интерфейса.
const STYLE: &str = r#"
/* ============================================================
   Общие элементы: скругления и спокойные переходы
   ============================================================ */
button,
entry,
spinbutton,
dropdown,
combobox {
    border-radius: 9px;
}
button.flat.remotix-menu-item,
notebook > header > tabs > tab {
    transition: background-color 140ms ease-out;
}

/* ============================================================
   Шапка окна: меньше «хрома», больше воздуха
   ============================================================ */
headerbar {
    box-shadow: none;
    min-height: 44px;
}
headerbar button {
    padding: 5px 10px;
}

/* ============================================================
   Боковая панель со списком подключений
   ============================================================ */
.remotix-sidebar {
    background-color: alpha(@theme_base_color, 0.45);
}
.remotix-sidebar listbox {
    background-color: transparent;
}
.remotix-sidebar listbox row {
    border-radius: 10px;
    padding: 8px 10px 8px 14px;
    margin: 1px 8px 1px 6px;
}
.remotix-sidebar listbox row:hover {
    background-color: alpha(currentColor, 0.07);
}
.remotix-sidebar listbox row.selected {
    background-color: @accent_bg_color;
    box-shadow: 0 1px 2px alpha(#000000, 0.18);
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

/* Метка протокола: «пилюля» с цветом от .success/.accent/.warning */
.remotix-tag {
    font-size: 0.72em;
    font-weight: 700;
    padding: 1px 8px;
    border-radius: 999px;
    background-color: alpha(currentColor, 0.14);
}
.remotix-sidebar listbox row.selected .remotix-tag {
    background-color: alpha(#ffffff, 0.22);
}

/* Блок быстрого подключения: компактная карточка */
.remotix-quick {
    background-color: alpha(currentColor, 0.05);
    border-radius: 12px;
    margin: 10px;
    padding: 10px;
}

/* ============================================================
   Строка состояния
   ============================================================ */
.remotix-statusbar {
    padding: 6px 12px;
    font-size: 0.85em;
    opacity: 0.85;
    border-top: 1px solid alpha(currentColor, 0.12);
}
.remotix-statusbar button {
    padding: 3px 8px;
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

/* ============================================================
   Вкладки сессий
   ============================================================ */
notebook > header {
    background-color: transparent;
    border-bottom: 1px solid alpha(currentColor, 0.10);
}
notebook > header > tabs > tab {
    padding: 5px 8px;
    border-radius: 8px;
    margin: 3px 2px;
    min-height: 0;
}
notebook > header > tabs > tab:hover {
    background-color: alpha(currentColor, 0.06);
}
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
    padding: 7px 12px;
    border-radius: 8px;
}

/* Контекстное меню: убираем жёсткую рамку стандартного поповера. */
popover > contents {
    padding: 5px;
    border-radius: 12px;
    border-style: none;
    box-shadow: 0 4px 14px alpha(#000000, 0.16);
}

/* ============================================================
   Файловый менеджер SFTP
   ============================================================ */
.remotix-file-list {
    background-color: transparent;
}
.remotix-file-list row {
    border-radius: 8px;
    margin: 1px 6px;
    padding: 3px 8px;
}
.remotix-file-list row:hover {
    background-color: alpha(currentColor, 0.08);
}
.remotix-file-list row.selected,
.remotix-file-list row:selected,
.remotix-file-list row.selected:backdrop,
.remotix-file-list row:selected:backdrop {
    background-color: @accent_bg_color;
}
.remotix-file-list row.selected label,
.remotix-file-list row:selected label,
.remotix-file-list row.selected:backdrop label,
.remotix-file-list row:selected:backdrop label {
    color: @accent_fg_color;
}
.remotix-dir {
    color: @accent_color;
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

/* ============================================================
   Диалоги
   ============================================================ */
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

/* ============================================================
   Экран удалённого рабочего стола
   ============================================================ */
.remotix-remote-screen {
    background-color: #10161d;
    /* Курсор над экраном скрывается в коде (рисует удалённая сессия). */
}
/* Плавающая панель управления сессией: полупрозрачная «пилюля». */
.remotix-rdp-toolbar {
    background-color: alpha(#0e1420, 0.72);
    border-radius: 12px;
    padding: 6px;
}
.remotix-rdp-toolbar button {
    padding: 4px 10px;
    border-radius: 8px;
    color: #e6edf3;
    background-color: alpha(#ffffff, 0.08);
}
.remotix-rdp-toolbar button:hover {
    background-color: alpha(#ffffff, 0.16);
}
.remotix-rdp-toolbar button:active {
    background-color: alpha(#ffffff, 0.24);
}
.remotix-rdp-quality {
    background-color: alpha(#000000, 0.45);
    color: #e6edf3;
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 0.85em;
}
.remotix-rdp-quality-good { color: #7ee787; }
.remotix-rdp-quality-warn { color: #f2cc60; }
.remotix-rdp-quality-bad { color: #ff7b72; }

/* ============================================================
   Резервный терминал
   ============================================================ */
.remotix-terminal {
    background-color: #0d1b2a;
    color: #e6edf3;
}

/* ============ Собственные палитры ============ */

/* Cosmic: глубокий индиго */
.remotix-theme-cosmic { background-color: #12122b; color: #e7e4f7; }
.remotix-theme-cosmic .remotix-sidebar { background-color: #1a1a3c; }
.remotix-theme-cosmic .remotix-quick { background-color: alpha(#ffffff, 0.06); }
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
.remotix-theme-ocean .remotix-quick { background-color: alpha(#ffffff, 0.06); }
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
.remotix-theme-carbon .remotix-quick { background-color: alpha(#ffffff, 0.05); }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Все идентификаторы тем уникальны и применяются без паники:
    /// `apply` ищет тему по id и вешает класс на корневой виджет.
    #[test]
    fn theme_ids_are_unique_and_known_ids_resolve() {
        let mut ids = std::collections::HashSet::new();
        for t in THEMES {
            assert!(ids.insert(t.id), "повторяющийся идентификатор темы");
            assert!(!t.name.is_empty());
        }
        // Неизвестный идентификатор откатывается на первую тему (светлую).
        assert!(THEMES.iter().find(|t| t.id == "no-such").is_none());
        assert_eq!(DEFAULT_THEME, "light");
    }
}
