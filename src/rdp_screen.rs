//! Геометрия просмотра RDP: режимы масштаба и пресеты разрешения.
//!
//! Модуль намеренно не зависит от GTK: расчёт геометрии и разбор пресетов
//! проверяются обычными unit-тестами, а просмотрщик только применяет результат.

/// Режим отображения удалённого экрана в окне.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScaleMode {
    /// Вписать в окно с сохранением пропорций (по умолчанию).
    #[default]
    Fit,
    /// Один пиксель удалённого экрана = один пиксель окна.
    OneToOne,
    /// Растянуть на всё окно (пропорции могут искажаться).
    Stretch,
}

impl ScaleMode {
    /// Следующий режим — для кнопки-переключателя.
    pub fn next(self) -> Self {
        match self {
            Self::Fit => Self::OneToOne,
            Self::OneToOne => Self::Stretch,
            Self::Stretch => Self::Fit,
        }
    }

    /// Подпись кнопки.
    pub fn label(self) -> &'static str {
        match self {
            Self::Fit => "Вписать",
            Self::OneToOne => "1:1",
            Self::Stretch => "Растянуть",
        }
    }

    /// Идентификатор для настроек.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fit => "fit",
            Self::OneToOne => "1:1",
            Self::Stretch => "stretch",
        }
    }

    /// Разбор идентификатора; неизвестное значение — режим по умолчанию.
    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "1:1" | "one-to-one" | "native" => Self::OneToOne,
            "stretch" | "fill" => Self::Stretch,
            _ => Self::Fit,
        }
    }
}

/// Пресеты разрешения — как в списке Remmina.
pub const PRESETS: &[(u32, u32)] = &[
    (1024, 768),
    (1280, 800),
    (1366, 768),
    (1600, 900),
    (1920, 1080),
    (2560, 1440),
];

/// Разбирает `ШИРИНАxВЫСОТА` (регистр `x` любой, пробелы допустимы).
/// Нулевые и слишком большие значения отклоняются.
pub fn parse_resolution(value: &str) -> Option<(u32, u32)> {
    let (w, h) = value.trim().split_once(['x', 'X'])?;
    let w: u32 = w.trim().parse().ok()?;
    let h: u32 = h.trim().parse().ok()?;
    if w == 0 || h == 0 || w > 8192 || h > 8192 {
        return None;
    }
    Some((w, h))
}

/// Размещение кадра в окне: смещение и масштабы по осям.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Geometry {
    pub off_x: f64,
    pub off_y: f64,
    pub scale_x: f64,
    pub scale_y: f64,
}

/// Считает геометрию кадра `remote` в окне `widget` для выбранного режима.
pub fn geometry(
    remote_w: u32,
    remote_h: u32,
    widget_w: f64,
    widget_h: f64,
    mode: ScaleMode,
) -> Geometry {
    let rw = remote_w.max(1) as f64;
    let rh = remote_h.max(1) as f64;
    let ww = widget_w.max(1.0);
    let wh = widget_h.max(1.0);
    match mode {
        ScaleMode::Stretch => Geometry {
            off_x: 0.0,
            off_y: 0.0,
            scale_x: ww / rw,
            scale_y: wh / rh,
        },
        ScaleMode::OneToOne => Geometry {
            off_x: (ww - rw) / 2.0,
            off_y: (wh - rh) / 2.0,
            scale_x: 1.0,
            scale_y: 1.0,
        },
        ScaleMode::Fit => {
            let scale = (ww / rw).min(wh / rh);
            Geometry {
                off_x: (ww - rw * scale) / 2.0,
                off_y: (wh - rh * scale) / 2.0,
                scale_x: scale,
                scale_y: scale,
            }
        }
    }
}

/// Переводит точку окна в координаты удалённого экрана (обратно к `geometry`).
pub fn map_point(
    x: f64,
    y: f64,
    remote_w: u32,
    remote_h: u32,
    widget_w: f64,
    widget_h: f64,
    mode: ScaleMode,
) -> (u32, u32) {
    let g = geometry(remote_w, remote_h, widget_w, widget_h, mode);
    let rx = ((x - g.off_x) / g.scale_x).round();
    let ry = ((y - g.off_y) / g.scale_y).round();
    let rx = rx.clamp(0.0, remote_w.saturating_sub(1) as f64) as u32;
    let ry = ry.clamp(0.0, remote_h.saturating_sub(1) as f64) as u32;
    (rx, ry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_mode_cycle_and_roundtrip() {
        let m = ScaleMode::default();
        assert_eq!(m, ScaleMode::Fit);
        assert_eq!(m.next(), ScaleMode::OneToOne);
        assert_eq!(m.next().next(), ScaleMode::Stretch);
        assert_eq!(m.next().next().next(), ScaleMode::Fit);
        for mode in [ScaleMode::Fit, ScaleMode::OneToOne, ScaleMode::Stretch] {
            assert_eq!(ScaleMode::parse(mode.as_str()), mode);
            assert!(!mode.label().is_empty());
        }
        assert_eq!(ScaleMode::parse("мусор"), ScaleMode::Fit);
    }

    #[test]
    fn resolution_presets_are_valid() {
        for (w, h) in PRESETS {
            assert!(*w > 0 && *h > 0);
            assert_eq!(parse_resolution(&format!("{w}x{h}")), Some((*w, *h)));
        }
    }

    #[test]
    fn resolution_parsing_rejects_junk() {
        assert_eq!(parse_resolution(" 1920 X 1080 "), Some((1920, 1080)));
        for bad in [
            "",
            "1920",
            "0x768",
            "1024x0",
            "axb",
            "99999x1080",
            "1024x99999",
        ] {
            assert_eq!(parse_resolution(bad), None, "должно отклоняться: {bad}");
        }
    }

    #[test]
    fn fit_keeps_aspect_and_centers() {
        let g = geometry(1000, 1000, 1000.0, 500.0, ScaleMode::Fit);
        assert_eq!(g.scale_x, 0.5);
        assert_eq!(g.scale_y, 0.5);
        assert_eq!(g.off_x, 250.0);
        assert_eq!(g.off_y, 0.0);
    }

    #[test]
    fn one_to_one_does_not_scale() {
        let g = geometry(800, 600, 1000.0, 800.0, ScaleMode::OneToOne);
        assert_eq!(g.scale_x, 1.0);
        assert_eq!(g.off_x, 100.0);
        assert_eq!(g.off_y, 100.0);
    }

    #[test]
    fn stretch_fills_window() {
        let g = geometry(800, 600, 1000.0, 900.0, ScaleMode::Stretch);
        assert_eq!(g.off_x, 0.0);
        assert_eq!(g.scale_x, 1.25);
        assert_eq!(g.scale_y, 1.5);
    }

    #[test]
    fn map_point_is_inverse_of_geometry() {
        for mode in [ScaleMode::Fit, ScaleMode::OneToOne, ScaleMode::Stretch] {
            let g = geometry(1920, 1080, 1000.0, 700.0, mode);
            let cx = g.off_x + 960.0 * g.scale_x;
            let cy = g.off_y + 540.0 * g.scale_y;
            let (rx, ry) = map_point(cx, cy, 1920, 1080, 1000.0, 700.0, mode);
            assert!((rx as i64 - 960).abs() <= 1, "mode={mode:?} rx={rx}");
            assert!((ry as i64 - 540).abs() <= 1, "mode={mode:?} ry={ry}");
        }
    }

    #[test]
    fn map_point_clamps_to_screen() {
        assert_eq!(
            map_point(-500.0, -500.0, 800, 600, 1000.0, 800.0, ScaleMode::Fit),
            (0, 0)
        );
        assert_eq!(
            map_point(99999.0, 99999.0, 800, 600, 1000.0, 800.0, ScaleMode::Fit),
            (799, 599)
        );
    }

    #[test]
    fn zero_sizes_do_not_panic() {
        let g = geometry(0, 0, 0.0, 0.0, ScaleMode::Fit);
        assert!(g.scale_x > 0.0 && g.scale_y > 0.0);
        assert_eq!(
            map_point(1.0, 1.0, 0, 0, 0.0, 0.0, ScaleMode::Stretch),
            (0, 0)
        );
    }
}
