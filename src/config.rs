use std::path::PathBuf;

/// Каталог данных приложения.
///
/// Используется `$XDG_DATA_HOME/remotix`, а при его отсутствии —
/// `~/.local/share/remotix`.
pub fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir).join("remotix");
        }
    }
    home_dir().join(".local").join("share").join("remotix")
}

/// Домашний каталог пользователя.
pub fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Путь к файлу базы данных.
pub fn db_path() -> PathBuf {
    data_dir().join("remotix.db")
}

/// Создаёт каталоги приложения при запуске.
pub fn init_dirs() {
    let dir = data_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        crate::logging::warn(&format!(
            "не удалось создать каталог данных {}: {e}",
            dir.display()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Меняет XDG_DATA_HOME и возвращает прежнее значение при drop.
    struct SavedXdg(Option<String>);
    impl SavedXdg {
        fn set(value: Option<&str>) -> Self {
            let saved = std::env::var("XDG_DATA_HOME").ok();
            match value {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
            Self(saved)
        }
    }
    impl Drop for SavedXdg {
        fn drop(&mut self) {
            match &self.0 {
                Some(v) => std::env::set_var("XDG_DATA_HOME", v),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }

    #[test]
    fn data_dir_uses_xdg_data_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _saved = SavedXdg::set(Some("/tmp/remotix-test-xdg"));
        assert_eq!(data_dir(), PathBuf::from("/tmp/remotix-test-xdg/remotix"));
        assert_eq!(
            db_path(),
            PathBuf::from("/tmp/remotix-test-xdg/remotix/remotix.db")
        );
    }

    #[test]
    fn blank_xdg_falls_back_to_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _saved = SavedXdg::set(Some("   "));
        assert_eq!(
            data_dir(),
            home_dir().join(".local").join("share").join("remotix")
        );
    }

    #[test]
    fn unset_xdg_falls_back_to_home() {
        let _guard = ENV_LOCK.lock().unwrap();
        let _saved = SavedXdg::set(None);
        assert!(data_dir().starts_with(home_dir()));
        assert!(data_dir().ends_with("remotix"));
    }
}
