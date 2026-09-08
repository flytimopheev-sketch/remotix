pub mod crypto;
pub mod repository;
pub mod schema;

use repository::Database;

/// Открывает (и при необходимости инициализирует) базу данных приложения.
pub fn open_database() -> Database {
    let path = crate::config::db_path();
    Database::open(path.to_str().expect("путь к БД")).expect("не удалось открыть базу данных")
}
