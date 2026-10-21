pub mod crypto;
pub mod repository;
pub mod schema;

use repository::Database;

/// Открывает (и при необходимости инициализирует) базу данных приложения.
///
/// Каталог с базой создаётся автоматически: на «чистой» системе
/// `~/.local/share/remotix` может отсутствовать, и без него SQLite не смог
/// бы открыть файл.
pub fn open_database() -> Result<Database, String> {
    let path = crate::config::db_path();

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("не удалось создать каталог {}: {e}", parent.display()))?;
    }

    let path = path
        .to_str()
        .ok_or("некорректный путь к файлу базы данных")?
        .to_string();

    Database::open(&path).map_err(|e| format!("не удалось открыть базу данных: {e}"))
}
