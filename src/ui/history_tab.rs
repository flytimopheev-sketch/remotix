//! Вкладка журнала подключений: список сессий и экспорт в CSV.

use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{Box as GtkBox, Button, Label, ListBox, ListBoxRow, ScrolledWindow};

use crate::app::AppState;

/// Вкладка с журналом подключений.
pub struct HistoryTab {
    pub root: GtkBox,
}

impl HistoryTab {
    /// Создаёт вкладку журнала для приложения.
    pub fn new(state: Rc<AppState>) -> Self {
        let root = GtkBox::new(gtk4::Orientation::Vertical, 0);

        let toolbar = GtkBox::new(gtk4::Orientation::Horizontal, 8);
        for m in ["margin-top", "margin-bottom", "margin-start", "margin-end"] {
            toolbar.set_property(m, 8);
        }
        let refresh = Button::with_label("Обновить");
        let export = Button::with_label("Экспорт в CSV");
        let status = Label::new(Some(""));
        status.set_xalign(0.0);
        status.set_hexpand(true);
        status.add_css_class("remotix-field-caption");
        toolbar.append(&refresh);
        toolbar.append(&export);
        toolbar.append(&status);

        // Сводка по журналу: итоги, период и самые частые профили.
        let summary = GtkBox::new(gtk4::Orientation::Vertical, 2);
        summary.set_margin_start(12);
        summary.set_margin_end(12);
        summary.set_margin_top(2);
        summary.set_margin_bottom(6);

        let summary_counts = Label::new(None);
        summary_counts.set_xalign(0.0);
        summary_counts.add_css_class("remotix-profile-name");

        let summary_period = Label::new(None);
        summary_period.set_xalign(0.0);
        summary_period.add_css_class("remotix-field-caption");

        let summary_top = Label::new(None);
        summary_top.set_xalign(0.0);
        summary_top.set_wrap(true);
        summary_top.add_css_class("remotix-field-caption");

        summary.append(&summary_counts);
        summary.append(&summary_period);
        summary.append(&summary_top);

        let list = ListBox::new();
        list.set_selection_mode(gtk4::SelectionMode::Single);
        list.add_css_class("remotix-sidebar");
        let scroll = ScrolledWindow::new();
        scroll.set_child(Some(&list));
        scroll.set_vexpand(true);

        root.append(&toolbar);
        root.append(&summary);
        root.append(&scroll);

        // Перезагрузка списка и сводки.
        let reload = {
            let state = state.clone();
            let list = list.clone();
            let status = status.clone();
            let summary_counts = summary_counts.clone();
            let summary_period = summary_period.clone();
            let summary_top = summary_top.clone();
            move || {
                match state.db.history_stats() {
                    Ok(stats) => {
                        summary_counts.set_text(&format!(
                            "Всего подключений: {} · успешных: {} · с ошибкой: {}",
                            stats.total, stats.success, stats.failed
                        ));
                        let period = match (stats.first_at, stats.last_at) {
                            (Some(first), Some(last)) => {
                                format!("Период: {} — {}", format_time(first), format_time(last))
                            }
                            _ => "Период: —".to_string(),
                        };
                        summary_period.set_text(&period);
                        let top = if stats.top_profiles.is_empty() {
                            "—".to_string()
                        } else {
                            stats
                                .top_profiles
                                .iter()
                                .map(|(name, count)| format!("{name} ({count})"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        };
                        summary_top.set_text(&format!("Чаще всего: {top}"));
                    }
                    Err(e) => {
                        summary_counts.set_text(&format!("Сводка недоступна: {e}"));
                        summary_period.set_text("");
                        summary_top.set_text("");
                    }
                }

                match state.db.history(None, None) {
                    Ok(entries) if entries.is_empty() => {
                        crate::ui::clear_list(&list);
                        let empty = Label::new(Some("Подключений пока не было"));
                        empty.set_margin_top(18);
                        empty.add_css_class("remotix-empty");
                        list.append(&empty);
                        status.set_text("");
                    }
                    Ok(entries) => {
                        crate::ui::clear_list(&list);
                        let total = entries.len();
                        for entry in entries {
                            let when = format_time(entry.started_at);
                            let title = Label::new(Some(&format!(
                                "{} · {}",
                                entry.profile_name, entry.status
                            )));
                            title.set_xalign(0.0);
                            title.add_css_class("remotix-profile-name");

                            let details = Label::new(Some(&format!(
                                "{when}{}",
                                entry
                                    .error_message
                                    .as_ref()
                                    .map(|m| format!(" · {m}"))
                                    .unwrap_or_default()
                            )));
                            details.set_xalign(0.0);
                            details.add_css_class("remotix-profile-details");

                            let row = ListBoxRow::new();
                            let box_ = GtkBox::new(gtk4::Orientation::Vertical, 2);
                            box_.set_margin_start(8);
                            box_.set_margin_end(8);
                            box_.set_margin_top(4);
                            box_.set_margin_bottom(4);
                            box_.append(&title);
                            box_.append(&details);
                            row.set_child(Some(&box_));
                            list.append(&row);
                        }
                        status.set_text(&format!("Записей: {total}"));
                    }
                    Err(e) => status.set_text(&format!("Ошибка чтения журнала: {e}")),
                }
            }
        };

        {
            let reload = reload.clone();
            refresh.connect_clicked(move |_| reload());
        }

        {
            let state = state.clone();
            let status = status.clone();
            export.connect_clicked(move |_| {
                let path = crate::config::home_dir().join("remotix-history.csv");
                match state.db.export_history_csv(&path) {
                    Ok(n) => status
                        .set_text(&format!("Экспортировано записей: {n} → {}", path.display())),
                    Err(e) => status.set_text(&format!("Ошибка экспорта: {e}")),
                }
            });
        }

        reload();

        Self { root }
    }
}

/// Форматирует unix-время в «дд.мм.гггг чч:мм».
fn format_time(ts: i64) -> String {
    use chrono::Local;
    match chrono::DateTime::from_timestamp(ts, 0) {
        Some(dt) => dt
            .with_timezone(&Local)
            .format("%d.%m.%Y %H:%M")
            .to_string(),
        None => String::new(),
    }
}
