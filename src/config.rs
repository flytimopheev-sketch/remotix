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
        eprintln!(
            "Remotix: не удалось создать каталог данных {}: {e}",
            dir.display()
        );
    }
}
