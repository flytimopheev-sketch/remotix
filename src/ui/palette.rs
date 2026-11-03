//! Цветовые палитры терминала.
//!
//! Палитра применяется к VTE (`vte_terminal_set_colors`) и к резервному
//! `GtkTextView`: фон и основной текст задаются через CSS, а ANSI-цвета
//! подставляются при разборе SGR-последовательностей.

/// Цвет в формате RGB (8 бит на канал).
pub type Rgb = (u8, u8, u8);

/// Палитра терминала: фон, основной текст и 16 цветов ANSI.
#[derive(Clone, Copy)]
pub struct Palette {
    pub background: Rgb,
    pub foreground: Rgb,
    /// 0–7 — обычные цвета, 8–15 — яркие.
    pub ansi: [Rgb; 16],
}

/// Доступные схемы: (идентификатор в настройках, подпись в интерфейсе).
pub const SCHEMES: &[(&str, &str)] = &[
    ("dark", "Тёмная"),
    ("light", "Светлая"),
    ("solarized", "Solarized Dark"),
    ("dracula", "Dracula"),
    ("nord", "Nord"),
    ("gruvbox", "Gruvbox"),
    ("system", "Как в системе"),
];

/// Палитра по идентификатору. Неизвестный идентификатор — тёмная схема
/// (значение по умолчанию и совместимость со старыми настройками).
pub fn resolve(id: &str) -> Palette {
    match id {
        "light" => LIGHT,
        "solarized" => SOLARIZED,
        "dracula" => DRACULA,
        "nord" => NORD,
        "gruvbox" => GRUVBOX,
        "system" => {
            if system_prefers_dark() {
                DARK
            } else {
                LIGHT
            }
        }
        _ => DARK,
    }
}

/// Тёмная ли тема рабочего окружения. Если определить не удалось,
/// считаем тему тёмной — это прежнее поведение терминала.
fn system_prefers_dark() -> bool {
    gtk4::Settings::default()
        .map(|settings| {
            settings.is_gtk_application_prefer_dark_theme()
                || settings
                    .gtk_theme_name()
                    .map(|name| name.to_lowercase().contains("dark"))
                    .unwrap_or(false)
        })
        .unwrap_or(true)
}

/// Тёмная схема: прежние цвета Remotix.
pub const DARK: Palette = Palette {
    background: (13, 27, 42),
    foreground: (230, 237, 243),
    ansi: [
        (46, 46, 58),
        (232, 92, 92),
        (111, 208, 111),
        (224, 192, 96),
        (111, 168, 232),
        (200, 127, 224),
        (96, 208, 208),
        (208, 208, 208),
        (94, 94, 106),
        (255, 140, 140),
        (159, 255, 159),
        (255, 240, 144),
        (159, 216, 255),
        (248, 175, 255),
        (144, 255, 255),
        (255, 255, 255),
    ],
};

/// Светлая схема с тёмным текстом.
pub const LIGHT: Palette = Palette {
    background: (250, 250, 250),
    foreground: (31, 35, 40),
    ansi: [
        (60, 60, 60),
        (194, 54, 33),
        (37, 138, 50),
        (161, 116, 0),
        (30, 80, 190),
        (150, 60, 170),
        (0, 130, 140),
        (200, 200, 200),
        (110, 110, 110),
        (230, 80, 60),
        (60, 180, 75),
        (200, 160, 0),
        (60, 120, 230),
        (190, 90, 210),
        (40, 180, 190),
        (245, 245, 245),
    ],
};

/// Solarized Dark (Ethan Schoonover).
pub const SOLARIZED: Palette = Palette {
    background: (0, 43, 54),
    foreground: (147, 161, 161),
    ansi: [
        (7, 54, 66),
        (220, 50, 47),
        (133, 153, 0),
        (181, 137, 0),
        (38, 139, 210),
        (211, 54, 130),
        (42, 161, 152),
        (238, 232, 213),
        (0, 43, 54),
        (203, 75, 22),
        (88, 110, 117),
        (101, 123, 131),
        (131, 148, 150),
        (108, 113, 196),
        (147, 161, 161),
        (253, 246, 227),
    ],
};

/// Dracula.
pub const DRACULA: Palette = Palette {
    background: (40, 42, 54),
    foreground: (248, 248, 242),
    ansi: [
        (33, 34, 44),
        (255, 85, 85),
        (80, 250, 123),
        (241, 250, 140),
        (189, 147, 249),
        (255, 121, 198),
        (139, 233, 253),
        (248, 248, 242),
        (98, 114, 164),
        (255, 110, 110),
        (105, 255, 148),
        (255, 255, 165),
        (214, 172, 255),
        (255, 146, 223),
        (164, 255, 255),
        (255, 255, 255),
    ],
};

/// Nord.
pub const NORD: Palette = Palette {
    background: (46, 52, 64),
    foreground: (216, 222, 233),
    ansi: [
        (59, 66, 82),
        (191, 97, 106),
        (163, 190, 140),
        (235, 203, 139),
        (129, 161, 193),
        (180, 142, 173),
        (136, 192, 208),
        (229, 233, 240),
        (76, 86, 106),
        (191, 97, 106),
        (163, 190, 140),
        (235, 203, 139),
        (129, 161, 193),
        (180, 142, 173),
        (143, 188, 187),
        (236, 239, 244),
    ],
};

/// Gruvbox Dark.
pub const GRUVBOX: Palette = Palette {
    background: (40, 40, 40),
    foreground: (235, 219, 178),
    ansi: [
        (40, 40, 40),
        (204, 36, 29),
        (152, 151, 26),
        (215, 153, 33),
        (69, 133, 136),
        (177, 98, 134),
        (104, 157, 106),
        (168, 153, 132),
        (146, 131, 116),
        (251, 73, 52),
        (184, 187, 38),
        (250, 189, 47),
        (131, 165, 152),
        (211, 134, 155),
        (142, 192, 124),
        (235, 219, 178),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn schemes_are_unique_and_valid() {
        let mut ids = HashSet::new();
        for (id, label) in SCHEMES {
            assert!(ids.insert(*id), "повторяющийся идентификатор схемы");
            assert!(!label.is_empty());
            if *id == "system" {
                continue; // зависит от темы рабочего окружения
            }
            let palette = resolve(id);
            assert_eq!(palette.ansi.len(), 16);
            assert_ne!(palette.background, palette.foreground);
        }
    }

    #[test]
    fn unknown_scheme_falls_back_to_dark() {
        let palette = resolve("no-such-scheme");
        assert_eq!(palette.background, DARK.background);
        assert_eq!(palette.foreground, DARK.foreground);
    }
}
