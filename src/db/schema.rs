/// Схема базы данных Remotix (см. ТЗ, раздел «Схема базы данных»).
pub const SCHEMA_VERSION: i64 = 2;


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
    tags               TEXT,
    icon               TEXT,
    notes              TEXT,
    rdp_options        TEXT,          -- JSON
    vnc_options        TEXT,          -- JSON
    ssh_options        TEXT,          -- JSON
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    last_connected_at  INTEGER,
    FOREIGN KEY (group_id) REFERENCES groups(id)
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
    Ok(())
}

