use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::schema;
use super::crypto;
use crate::models::{HistoryEntry, Protocol};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Читает «зашифрованную» колонку, tolerая к типу значения.
///
/// SQLite хранит данные динамически, поэтому в BLOB-колонке может оказаться
/// текст (например, после переноса базы или ручного изменения). Такое значение
/// читаем как есть — расшифровка его не пройдёт, но профиль не потеряется.
fn blob_column(row: &rusqlite::Row, index: usize) -> rusqlite::Result<Option<Vec<u8>>> {
    use rusqlite::types::ValueRef;
    Ok(match row.get_ref(index)? {
        ValueRef::Null => None,
        ValueRef::Blob(b) => Some(b.to_vec()),
        ValueRef::Text(t) => Some(t.to_vec()),
        _ => None,
    })
}

/// Обёртка над SQLite: схема, таблица meta и CRUD профилей/истории.
/// Учётные данные шифруются AES-256-GCM ключом, выведенным из мастер-пароля.
pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        schema::initialize(&conn)?;
        Ok(Self { conn })
    }

    fn conn(&self) -> &Connection {
        &self.conn
    }

    // ---------- meta ----------

    pub fn meta_get(&self, key: &str) -> Option<Vec<u8>> {
        self.conn()
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()
            .ok()
            .flatten()
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Инициализирует хранилище при первом запуске (создание мастер-пароля).
    pub fn init_master(&self, master_password: &str) -> Result<(), String> {
        let salt = crypto::new_salt();
        let params_ = crypto::Argon2Params::default();
        let key = crypto::derive_key(master_password, &salt, &params_);
        let verifier = crypto::encrypt(&key, b"remotix-verifier");
        self.meta_set("argon2_salt", &salt).map_err(|e| e.to_string())?;
        self.meta_set("argon2_params", serde_json::to_vec(&params_).unwrap().as_slice())
            .map_err(|e| e.to_string())?;
        self.meta_set("verifier", &verifier).map_err(|e| e.to_string())?;
        self.meta_set("schema_version", &schema::SCHEMA_VERSION.to_le_bytes())
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Проверяет мастер-пароль и возвращает ключ шифрования.
    pub fn unlock(&self, master_password: &str) -> Result<[u8; 32], String> {
        let salt = self
            .meta_get("argon2_salt")
            .ok_or("хранилище не инициализировано")?;
        let params_: crypto::Argon2Params = self
            .meta_get("argon2_params")
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default();
        let key = crypto::derive_key(master_password, &salt, &params_);
        let verifier = self.meta_get("verifier").ok_or("хранилище повреждено")?;
        let ok = crypto::decrypt(&key, &verifier)? == b"remotix-verifier";
        if ok { Ok(key) } else { Err("неверный мастер-пароль".into()) }
    }

    // PART2

    /// Смена мастер-пароля: перешифровка всех учётных данных.
    pub fn change_master_password(&self, old: &str, new: &str) -> Result<(), String> {
        let old_key = self.unlock(old)?;
        let new_salt = crypto::new_salt();
        let new_params = crypto::Argon2Params::default();
        let new_key = crypto::derive_key(new, &new_salt, &new_params);
        let verifier = crypto::encrypt(&new_key, b"remotix-verifier");

        let mut stmt = self
            .conn()
            .prepare("SELECT id, username, password, ssh_key_passphrase, root_password FROM profiles")
            .map_err(|e| e.to_string())?;
        let rows: Vec<(i64, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> = stmt
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;

        for (id, username, password, passphrase, root_password) in rows {
            let enc = |blob: &Option<Vec<u8>>| -> Option<Vec<u8>> {
                blob.as_ref().map(|b| {
                    let plain = crypto::decrypt(&old_key, b).expect("перешифровка");
                    crypto::encrypt(&new_key, &plain)
                })
            };
            self.conn().execute(
                "UPDATE profiles SET username = ?1, password = ?2, ssh_key_passphrase = ?3, root_password = ?4 WHERE id = ?5",
                params![enc(&username), enc(&password), enc(&passphrase), enc(&root_password), id],
            )
            .map_err(|e| e.to_string())?;
        }

        self.meta_set("argon2_salt", &new_salt).map_err(|e| e.to_string())?;
        self.meta_set("argon2_params", serde_json::to_vec(&new_params).unwrap().as_slice())
            .map_err(|e| e.to_string())?;
        self.meta_set("verifier", &verifier).map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------- groups ----------

    pub fn add_group(&self, g: &crate::models::NewGroup) -> rusqlite::Result<()> {
        self.conn().execute(
            "INSERT INTO groups(id, name, parent_id) VALUES (?1, ?2, ?3)",
            params![g.id, g.name, g.parent_id],
        )?;
        Ok(())
    }

    pub fn delete_group(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn().execute("DELETE FROM groups WHERE id = ?1", params![id])
    }

    // PART3

    // ---------- profiles ----------

    pub fn add_profile(&self, key: &[u8; 32], p: &crate::models::NewProfile) -> Result<i64, String> {
        let enc = |s: &Option<String>| -> Option<Vec<u8>> {
            s.as_ref().map(|v| crypto::encrypt(key, v.as_bytes()))
        };
        let t = now();
        self.conn().execute(
            "INSERT INTO profiles(name, protocol, host, port, username, password,
                ssh_key_path, ssh_key_passphrase, root_password, group_id, tags, icon, notes,
                rdp_options, vnc_options, ssh_options, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?17)",
            params![
                p.name,
                p.protocol.unwrap_or(Protocol::Ssh).as_str(),
                p.host,
                p.port,
                enc(&p.username),
                enc(&p.password),
                p.ssh_key_path,
                enc(&p.ssh_key_passphrase),
                enc(&p.root_password),
                p.group_id,
                p.tags.join(","),
                p.icon,
                p.notes,
                serde_json::to_string(&p.rdp_options).unwrap_or_default(),
                serde_json::to_string(&p.vnc_options).unwrap_or_default(),
                serde_json::to_string(&p.ssh_options).unwrap_or_default(),
                t
            ],
        )
        .map_err(|e| e.to_string())?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Обновляет существующий профиль подключения.
    pub fn update_profile(
        &self,
        key: &[u8; 32],
        id: i64,
        p: &crate::models::NewProfile,
    ) -> Result<(), String> {
        let enc = |s: &Option<String>| -> Option<Vec<u8>> {
            s.as_ref().map(|v| crypto::encrypt(key, v.as_bytes()))
        };
        self.conn()
            .execute(
                "UPDATE profiles SET name = ?1, protocol = ?2, host = ?3, port = ?4,
                    username = ?5, password = ?6, ssh_key_path = ?7, ssh_key_passphrase = ?8,
                    root_password = ?9, group_id = ?10, tags = ?11, icon = ?12, notes = ?13,
                    rdp_options = ?14, vnc_options = ?15, ssh_options = ?16, updated_at = ?17
                 WHERE id = ?18",
                params![
                    p.name,
                    p.protocol.unwrap_or(Protocol::Ssh).as_str(),
                    p.host,
                    p.port,
                    enc(&p.username),
                    enc(&p.password),
                    p.ssh_key_path,
                    enc(&p.ssh_key_passphrase),
                    enc(&p.root_password),
                    p.group_id,
                    p.tags.join(","),
                    p.icon,
                    p.notes,
                    serde_json::to_string(&p.rdp_options).unwrap_or_default(),
                    serde_json::to_string(&p.vnc_options).unwrap_or_default(),
                    serde_json::to_string(&p.ssh_options).unwrap_or_default(),
                    now(),
                    id
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Загружает все профили, расшифровывая учётные данные.
    pub fn list_profiles(&self, key: &[u8; 32]) -> Result<Vec<crate::models::Profile>, String> {
        use crate::models::profile::{RdpOptions, SshOptions, VncOptions};
        let dec = |blob: &Option<Vec<u8>>| -> Option<String> {
            match blob {
                Some(b) => crypto::decrypt(key, b.as_slice()).ok()
                    .map(|v| String::from_utf8_lossy(&v).into_owned()),
                None => None,
            }
        };
        let mut stmt = self.conn().prepare(
            "SELECT id, name, protocol, host, port, username, password, ssh_key_path,
                    ssh_key_passphrase, root_password, group_id, tags, icon, notes, rdp_options,
                    vnc_options, ssh_options, created_at, updated_at, last_connected_at
             FROM profiles ORDER BY name",
        )
        .map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, String>(3)?, r.get::<_, u16>(4)?, blob_column(r, 5)?,
                blob_column(r, 6)?, r.get::<_, Option<String>>(7)?,
                blob_column(r, 8)?, blob_column(r, 9)?, r.get::<_, Option<i64>>(10)?,
                r.get::<_, Option<String>>(11)?, r.get::<_, Option<String>>(12)?,
                r.get::<_, Option<String>>(13)?, r.get::<_, Option<String>>(14)?,
                r.get::<_, Option<String>>(15)?, r.get::<_, Option<String>>(16)?,
                r.get::<_, i64>(17)?, r.get::<_, i64>(18)?, r.get::<_, Option<i64>>(19)?,
            ))
        })
        .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for row in rows {
            let (id, name, protocol, host, port, username, password, ssh_key_path,
                 ssh_key_passphrase, root_password, group_id, tags, icon, notes, rdp, vnc, ssh,
                 created_at, updated_at, last_connected_at) = row.map_err(|e| e.to_string())?;
            let protocol = match protocol.as_str() {
                "RDP" => Protocol::Rdp,
                "VNC" => Protocol::Vnc,
                _ => Protocol::Ssh,
            };
            out.push(crate::models::Profile {
                id,
                name,
                protocol,
                host,
                port,
                username: dec(&username),
                password: dec(&password),
                ssh_key_path,
                ssh_key_passphrase: dec(&ssh_key_passphrase),
                root_password: dec(&root_password),
                group_id,
                tags: tags.unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                icon,
                notes,
                rdp_options: rdp.and_then(|v| serde_json::from_str::<RdpOptions>(&v).ok()).unwrap_or_default(),
                vnc_options: vnc.and_then(|v| serde_json::from_str::<VncOptions>(&v).ok()).unwrap_or_default(),
                ssh_options: ssh.and_then(|v| serde_json::from_str::<SshOptions>(&v).ok()).unwrap_or_default(),
                created_at,
                updated_at,
                last_connected_at,
            });
        }
        Ok(out)
    }

    // PART4

    pub fn delete_profile(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn()
            .execute("DELETE FROM profiles WHERE id = ?1", params![id])
    }

    pub fn touch_profile(&self, id: i64) -> rusqlite::Result<()> {
        self.conn().execute(
            "UPDATE profiles SET last_connected_at = ?1 WHERE id = ?2",
            params![now(), id],
        )?;
        Ok(())
    }

    // ---------- settings ----------

    /// Читает настройку приложения (строка из таблицы meta).
    pub fn get_setting(&self, key: &str) -> Option<String> {
        self.meta_get(&format!("settings.{key}"))
            .and_then(|v| String::from_utf8(v).ok())
    }

    /// Сохраняет настройку приложения.
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.meta_set(&format!("settings.{key}"), value.as_bytes())
            .map_err(|e| e.to_string())
    }

    /// Удаляет настройку (возвращает значение по умолчанию).
    pub fn reset_setting(&self, key: &str) -> Result<(), String> {
        self.conn()
            .execute("DELETE FROM meta WHERE key = ?1", params![format!("settings.{key}")])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------- history ----------

    pub fn add_history(
        &self,
        profile_id: i64,
        started_at: i64,
        ended_at: Option<i64>,
        status: &str,
        error: Option<(String, String)>,
    ) -> rusqlite::Result<()> {
        let (code, msg) = match error {
            Some((c, m)) => (Some(c), Some(m)),
            None => (None, None),
        };
        self.conn().execute(
            "INSERT INTO connection_history(profile_id, started_at, ended_at, status, error_code, error_message)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![profile_id, started_at, ended_at, status, code, msg],
        )?;
        Ok(())
    }

    /// Журнал подключений с фильтрами (профиль, статус).
    pub fn history(&self, profile_id: Option<i64>, status: Option<&str>) -> Result<Vec<HistoryEntry>, String> {
        let mut stmt = self.conn().prepare(
            "SELECT h.id, h.profile_id, IFNULL(p.name, '?'), h.started_at, h.ended_at,
                    h.status, h.error_code, h.error_message
             FROM connection_history h LEFT JOIN profiles p ON p.id = h.profile_id
             WHERE (?1 IS NULL OR h.profile_id = ?1)
               AND (?2 IS NULL OR h.status = ?2)
             ORDER BY h.started_at DESC",
        )
        .map_err(|e| e.to_string())?;
        let rows = stmt.query_map(params![profile_id, status], |r| {
            Ok(HistoryEntry {
                id: r.get(0)?,
                profile_id: r.get(1)?,
                profile_name: r.get(2)?,
                started_at: r.get(3)?,
                ended_at: r.get(4)?,
                status: r.get(5)?,
                error_code: r.get(6)?,
                error_message: r.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    /// Экспорт журнала подключений в CSV.
    pub fn export_history_csv(&self, path: &Path) -> Result<usize, String> {
        let rows = self.history(None, None)?;
        let mut csv = String::from("id;profile;started_at;ended_at;status;error_code;error_message\n");
        for h in &rows {
            csv.push_str(&format!(
                "{};{};{};{};{};{};{}\n",
                h.id,
                h.profile_name,
                h.started_at,
                h.ended_at.map(|v| v.to_string()).unwrap_or_default(),
                h.status,
                h.error_code.clone().unwrap_or_default(),
                h.error_message.clone().unwrap_or_default()
            ));
        }
        std::fs::write(path, csv).map_err(|e| e.to_string())?;
        Ok(rows.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::NewProfile;

    fn opened() -> (Database, [u8; 32]) {
        let db = Database::open(":memory:").expect("открытие БД");
        db.init_master("master").expect("создание мастер-пароля");
        let key = db.unlock("master").expect("разблокировка");
        (db, key)
    }

    fn sample() -> NewProfile {
        NewProfile {
            name: "Сервер".to_string(),
            protocol: Some(Protocol::Ssh),
            host: "example.org".to_string(),
            port: 22,
            username: Some("user".to_string()),
            password: Some("secret".to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn profile_is_saved_and_read_back() {
        let (db, key) = opened();
        let id = db.add_profile(&key, &sample()).expect("сохранение профиля");

        let profiles = db.list_profiles(&key).expect("чтение профилей");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, id);
        assert_eq!(profiles[0].host, "example.org");
        assert_eq!(profiles[0].username.as_deref(), Some("user"));
        assert_eq!(profiles[0].password.as_deref(), Some("secret"));
    }

    #[test]
    fn profile_is_updated() {
        let (db, key) = opened();
        let id = db.add_profile(&key, &sample()).expect("сохранение профиля");

        let mut updated = sample();
        updated.host = "other.example.org".to_string();
        updated.port = 2222;
        db.update_profile(&key, id, &updated).expect("обновление профиля");

        let profiles = db.list_profiles(&key).expect("чтение профилей");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].host, "other.example.org");
        assert_eq!(profiles[0].port, 2222);
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let (db, _key) = opened();
        assert!(db.unlock("wrong").is_err(), "неверный мастер-пароль должен отклоняться");
    }
}

