use std::path::PathBuf;

/// Возвращает базовый каталог данных приложения: ~/.local/share/remotix.
pub fn data_dir() -> PathBuf {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".local").join("share").join("remotix")
}

/// Путь к файлу базы данных.
pub fn db_path() -> PathBuf {
    data_dir().join("remotix.db")
}

/// Создаёт каталоги приложения при запуске.
pub fn init_dirs() {
    let _ = std::fs::create_dir_all(data_dir());
}
