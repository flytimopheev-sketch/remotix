/// Схема базы данных Remotix (см. ТЗ, раздел «Схема базы данных»).
pub const SCHEMA_VERSION: i64 = 5;

pub const CREATE_META: &str = "CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);";

pub const CREATE_GROUPS: &str = "CREATE TABLE IF NOT EXISTS groups (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL,
    parent_id INTEGER,
    FOREIGN KEY (parent_id) REFERENCES groups(id)
);";

pub const CREATE_PROFILES: &str = "CREATE TABLE IF NOT EXISTS profiles (
    id                 INTEGER PRIMARY KEY,
    name               TEXT NOT NULL,
    protocol           TEXT NOT NULL, -- RDP, VNC, SSH
    host               TEXT NOT NULL,
    port               INTEGER NOT NULL,
    username           BLOB,          -- зашифровано
    password           BLOB,          -- зашифровано, опционально
    ssh_key_path       TEXT,          -- путь к ключу
    ssh_key_passphrase BLOB,          -- зашифровано, опционально
    root_password      BLOB,          -- зашифровано: пароль root для su (SSH, опционально)
    group_id           INTEGER,
    bastion_profile_id INTEGER,       -- профиль-бастион (SSH jump host)
    tags               TEXT,
    icon               TEXT,
    notes              TEXT,
    mac_address        TEXT,          -- MAC для Wake-on-LAN
    rdp_options        TEXT,          -- JSON
    vnc_options        TEXT,          -- JSON
    ssh_options        TEXT,          -- JSON
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    last_connected_at  INTEGER,
    FOREIGN KEY (group_id) REFERENCES groups(id),
    FOREIGN KEY (bastion_profile_id) REFERENCES profiles(id) ON DELETE SET NULL
);";

pub const CREATE_HISTORY: &str = "CREATE TABLE IF NOT EXISTS connection_history (
    id            INTEGER PRIMARY KEY,
    profile_id    INTEGER NOT NULL,
    started_at    INTEGER NOT NULL,
    ended_at      INTEGER,
    status        TEXT NOT NULL, -- success, error
    error_code    TEXT,
    error_message TEXT,
    FOREIGN KEY (profile_id) REFERENCES profiles(id)
);";

pub const CREATE_EXPECT_RULES: &str = "CREATE TABLE IF NOT EXISTS expect_rules (
    id       INTEGER PRIMARY KEY,
    pattern  TEXT NOT NULL,   -- шаблон вывода (*, ?, литералы)
    send     BLOB NOT NULL,   -- зашифровано: строка для отправки в канал
    once     INTEGER NOT NULL DEFAULT 0,
    enabled  INTEGER NOT NULL DEFAULT 1,
    position INTEGER NOT NULL DEFAULT 0
);";

pub const INDICES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_profiles_name  ON profiles(name);",
    "CREATE INDEX IF NOT EXISTS idx_profiles_host  ON profiles(host);",
    "CREATE INDEX IF NOT EXISTS idx_profiles_group ON profiles(group_id);",
    "CREATE INDEX IF NOT EXISTS idx_history_profile ON connection_history(profile_id);",
    "CREATE INDEX IF NOT EXISTS idx_history_started ON connection_history(started_at);",
];

/// Выполняет создание всех таблиц, индексов и миграции.
pub fn initialize(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(CREATE_META)?;
    conn.execute_batch(CREATE_GROUPS)?;
    conn.execute_batch(CREATE_PROFILES)?;
    conn.execute_batch(CREATE_HISTORY)?;
    conn.execute_batch(CREATE_EXPECT_RULES)?;
    for idx in INDICES {
        conn.execute_batch(idx)?;
    }
    migrate(conn)?;
    Ok(())
}

/// Миграции между версиями схемы.
fn migrate(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    // v1 -> v2: колонка root_password (двухступенчатый вход: admin -> su -> root).
    let has_root_password: bool = conn
        .prepare("SELECT COUNT(*) FROM pragma_table_info('profiles') WHERE name = 'root_password'")?
        .query_row([], |r| r.get::<_, i64>(0))
        .map(|n| n > 0)?;
    if !has_root_password {
        conn.execute_batch("ALTER TABLE profiles ADD COLUMN root_password BLOB;")?;
    }

    // v2 -> v3: MAC-адрес для Wake-on-LAN.
    let has_mac_address: bool = conn
        .prepare("SELECT COUNT(*) FROM pragma_table_info('profiles') WHERE name = 'mac_address'")?
        .query_row([], |r| r.get::<_, i64>(0))
        .map(|n| n > 0)?;
    if !has_mac_address {
        conn.execute_batch("ALTER TABLE profiles ADD COLUMN mac_address TEXT;")?;
    }

    // v4 -> v5: профиль-бастион (SSH jump host). Ссылка на другой профиль,
    // поэтому секреты бастиона не дублируются; при удалении бастиона
    // подключение просто становится прямым.
    let has_bastion: bool = conn
        .prepare(
            "SELECT COUNT(*) FROM pragma_table_info('profiles') WHERE name = 'bastion_profile_id'",
        )?
        .query_row([], |r| r.get::<_, i64>(0))
        .map(|n| n > 0)?;
    if !has_bastion {
        conn.execute_batch(
            "ALTER TABLE profiles ADD COLUMN bastion_profile_id INTEGER \
             REFERENCES profiles(id) ON DELETE SET NULL;",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает «старую» схему profiles: убирает внешние ключи и указанные
    /// колонки, а также висячую запятую перед закрывающей скобкой.
    fn old_profiles(columns: &[&str]) -> String {
        let mut lines: Vec<String> = CREATE_PROFILES
            .lines()
            .filter(|line| !line.contains("FOREIGN KEY"))
            .filter(|line| !columns.iter().any(|c| line.contains(c)))
            .map(str::to_string)
            .collect();
        if let Some(pos) = lines.iter().position(|line| line.trim() == ");") {
            if pos > 0 {
                lines[pos - 1] = lines[pos - 1].trim_end_matches(',').to_string();
            }
        }
        lines.join("\n")
    }

    #[test]
    fn migration_adds_mac_address_to_v2_database() {
        let conn = rusqlite::Connection::open_in_memory().expect("тестовая БД");
        let schema_v2 = old_profiles(&["mac_address", "bastion_profile_id"]);
        assert!(
            !schema_v2.contains("mac_address"),
            "тестовая схема должна быть без MAC"
        );
        conn.execute_batch(&schema_v2).expect("схема v2");

        initialize(&conn).expect("миграция схемы");

        let has_mac_address: bool = conn
            .prepare(
                "SELECT COUNT(*) FROM pragma_table_info('profiles') WHERE name = 'mac_address'",
            )
            .expect("pragma_table_info")
            .query_row([], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .expect("подсчёт колонок");
        assert!(has_mac_address, "колонка mac_address должна появиться");
    }

    #[test]
    fn migration_adds_bastion_to_v4_database() {
        let conn = rusqlite::Connection::open_in_memory().expect("тестовая БД");
        let schema_v4 = old_profiles(&["bastion_profile_id"]);
        assert!(
            !schema_v4.contains("bastion_profile_id"),
            "тестовая схема должна быть без бастиона"
        );
        conn.execute_batch(&schema_v4).expect("схема v4");

        initialize(&conn).expect("миграция схемы");

        let has_bastion: bool = conn
            .prepare(
                "SELECT COUNT(*) FROM pragma_table_info('profiles') \
                 WHERE name = 'bastion_profile_id'",
            )
            .expect("pragma_table_info")
            .query_row([], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .expect("подсчёт колонок");
        assert!(has_bastion, "колонка bastion_profile_id должна появиться");
    }
}
