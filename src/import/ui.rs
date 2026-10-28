//! Кнопки импорта для раздела «Профили» в настройках.
//!
//! Любой источник сначала показывает предпросмотр. Запись в базу происходит
//! только в обработчике подтверждения, после проверки дублей.

use std::path::PathBuf;
use std::rc::Rc;

use gtk4::prelude::*;
use gtk4::{
    gio, Box as GtkBox, Button, FileChooserAction, FileChooserNative, FileFilter, Label, Window,
};

use crate::app::AppState;
use crate::import::normalize::ImportPreview;
use crate::import::{csv, json, preview, rdp, remmina, ssh_config};

/// Кнопки импорта из стандартных источников.
pub fn build(
    state: &Rc<AppState>,
    parent: &Window,
    status: &Label,
    refresh: Rc<dyn Fn()>,
) -> GtkBox {
    let box_ = GtkBox::new(gtk4::Orientation::Vertical, 6);

    let ssh = Button::with_label("Импортировать из ~/.ssh/config…");
    let remmina = Button::with_label("Импортировать из Remmina…");
    let rdp = Button::with_label("Импортировать из файлов .rdp…");
    let csv = Button::with_label("Импортировать из CSV…");
    let json = Button::with_label("Импортировать из JSON Remotix…");
    box_.append(&ssh);
    box_.append(&remmina);
    box_.append(&rdp);
    box_.append(&csv);
    box_.append(&json);

    {
        let state = state.clone();
        let parent = parent.clone();
        let status = status.clone();
        let refresh = refresh.clone();
        ssh.connect_clicked(move |_| {
            show_preview(
                ssh_config::scan_default(),
                &state,
                &parent,
                &status,
                refresh.clone(),
            );
        });
    }

    {
        let state = state.clone();
        let parent = parent.clone();
        let status = status.clone();
        let refresh = refresh.clone();
        remmina.connect_clicked(move |_| {
            show_preview(
                remmina::scan_default(),
                &state,
                &parent,
                &status,
                refresh.clone(),
            );
        });
    }

    {
        let state = state.clone();
        let parent = parent.clone();
        let status = status.clone();
        let refresh = refresh.clone();
        rdp.connect_clicked(move |_| {
            let chooser = FileChooserNative::new(
                Some("Импорт RDP-подключений"),
                Some(&parent),
                FileChooserAction::Open,
                Some("Импортировать"),
                Some("Отмена"),
            );
            chooser.set_select_multiple(true);
            let filter = FileFilter::new();
            filter.set_name(Some("Файлы .rdp"));
            filter.add_pattern("*.rdp");
            filter.add_pattern("*.RDP");
            chooser.set_filter(&filter);

            let state = state.clone();
            let parent = parent.clone();
            let status = status.clone();
            let refresh = refresh.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk4::ResponseType::Accept {
                    let paths: Vec<PathBuf> = chooser
                        .files()
                        .iter::<gio::File>()
                        .filter_map(Result::ok)
                        .filter_map(|file| file.path())
                        .collect();
                    let preview = rdp::scan_paths(&paths);
                    show_preview(preview, &state, &parent, &status, refresh.clone());
                }
                chooser.destroy();
            });
            chooser.show();
        });
    }

    {
        let state = state.clone();
        let parent = parent.clone();
        let status = status.clone();
        let refresh = refresh.clone();
        csv.connect_clicked(move |_| {
            let chooser = FileChooserNative::new(
                Some("Импорт подключений из CSV"),
                Some(&parent),
                FileChooserAction::Open,
                Some("Импортировать"),
                Some("Отмена"),
            );
            chooser.set_select_multiple(true);
            let filter = FileFilter::new();
            filter.set_name(Some("Файлы CSV"));
            filter.add_pattern("*.csv");
            filter.add_pattern("*.CSV");
            chooser.set_filter(&filter);

            let state = state.clone();
            let parent = parent.clone();
            let status = status.clone();
            let refresh = refresh.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk4::ResponseType::Accept {
                    let paths: Vec<PathBuf> = chooser
                        .files()
                        .iter::<gio::File>()
                        .filter_map(Result::ok)
                        .filter_map(|file| file.path())
                        .collect();
                    let preview = csv::scan_paths(&paths);
                    show_preview(preview, &state, &parent, &status, refresh.clone());
                }
                chooser.destroy();
            });
            chooser.show();
        });
    }

    {
        let state = state.clone();
        let parent = parent.clone();
        let status = status.clone();
        let refresh = refresh.clone();
        json.connect_clicked(move |_| {
            let chooser = FileChooserNative::new(
                Some("Импорт профилей Remotix"),
                Some(&parent),
                FileChooserAction::Open,
                Some("Импортировать"),
                Some("Отмена"),
            );
            let filter = FileFilter::new();
            filter.set_name(Some("JSON Remotix"));
            filter.add_pattern("*.json");
            chooser.set_filter(&filter);

            let state = state.clone();
            let parent = parent.clone();
            let status = status.clone();
            let refresh = refresh.clone();
            chooser.connect_response(move |chooser, response| {
                if response == gtk4::ResponseType::Accept {
                    if let Some(path) = chooser.file().and_then(|file| file.path()) {
                        let preview = json::scan_file(&path);
                        show_preview(preview, &state, &parent, &status, refresh.clone());
                    }
                }
                chooser.destroy();
            });
            chooser.show();
        });
    }

    box_
}

fn show_preview(
    result: Result<ImportPreview, String>,
    state: &Rc<AppState>,
    parent: &Window,
    status: &Label,
    refresh: Rc<dyn Fn()>,
) {
    let mut preview = match result {
        Ok(preview) => preview,
        Err(e) => {
            status.set_text(&e);
            return;
        }
    };

    if state.is_locked() {
        status.set_text("Хранилище заблокировано — разблокируйте Remotix");
        return;
    }
    let key = state.unlocked_key();
    match state.db.profile_identities(&key) {
        Ok(existing) => preview.dedupe_against(&existing),
        Err(e) => {
            status.set_text(&format!("Не удалось проверить дубли: {e}"));
            return;
        }
    }

    status.set_text(&format!("Предпросмотр импорта: {}", preview.summary()));
    let state = state.clone();
    let status = status.clone();
    preview::show(Some(parent), preview, move |candidates| {
        if state.is_locked() {
            status.set_text("Хранилище заблокировано — профили не добавлены");
            return;
        }
        let key = state.unlocked_key();
        let mut added = 0usize;
        let mut errors = Vec::new();
        for candidate in candidates {
            // Группы из источника (CSV «группа») создаются до записи профиля.
            let mut profile = candidate.profile;
            if !candidate.group_path.is_empty() {
                match state.db.ensure_group_path(&candidate.group_path) {
                    Ok(group_id) => profile.group_id = group_id,
                    Err(e) => {
                        errors.push(format!("{}: не удалось создать группу: {e}", profile.name))
                    }
                }
            }
            match state.db.add_profile(&key, &profile) {
                Ok(_) => added += 1,
                Err(e) => errors.push(format!("{}: {e}", profile.name)),
            }
        }

        if errors.is_empty() {
            status.set_text(&format!("Импортировано профилей: {added}"));
        } else {
            status.set_text(&format!(
                "Импортировано: {added} · ошибок: {}\n{}",
                errors.len(),
                errors.join("\n")
            ));
        }
        refresh();
    });
}
