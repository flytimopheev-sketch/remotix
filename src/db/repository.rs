use rusqlite::{params, Connection, OptionalExtension};
use secrecy::{ExposeSecret, SecretString};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

use super::crypto;
use super::schema;
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

/// Зашифрованные колонки профиля: id, пароль, пароль ключа, root-пароль.
type SecretRows = Vec<(
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
)>;

/// Идентичность профиля для проверки дублей: протокол, хост, порт, логин.
type ProfileIdentity = (Protocol, String, u16, Option<String>);

/// Expect-правило из БД: шаблон вывода и строка для отправки в канал.
/// `send` расшифрован (хранится в BLOB, как учётные данные профиля).
pub struct ExpectRuleRow {
    pub id: i64,
    pub pattern: String,
    pub send: SecretString,
    pub once: bool,
    pub enabled: bool,
}

/// Сниппет — сохранённая команда для терминала. Команда расшифрована при
/// чтении (в БД лежит BLOB-шифротекст), но не является `SecretString`:
/// её текст нужен интерфейсу для показа и редактирования.
#[derive(Clone)]
pub struct SnippetRow {
    pub id: i64,
    pub name: String,
    pub command: String,
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
        let key = Zeroizing::new(crypto::derive_key(master_password, &salt, &params_));
        let verifier = crypto::encrypt(&key, b"remotix-verifier");
        self.meta_set("argon2_salt", &salt)
            .map_err(|e| e.to_string())?;
        self.meta_set(
            "argon2_params",
            serde_json::to_vec(&params_).unwrap().as_slice(),
        )
        .map_err(|e| e.to_string())?;
        self.meta_set("verifier", &verifier)
            .map_err(|e| e.to_string())?;
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
        let key = Zeroizing::new(crypto::derive_key(master_password, &salt, &params_));
        let verifier = self.meta_get("verifier").ok_or("хранилище повреждено")?;
        let plain = crypto::decrypt(&key, &verifier)?;
        let ok = &*plain == b"remotix-verifier";
        if ok {
            Ok(*key)
        } else {
            Err("неверный мастер-пароль".into())
        }
    }

    // PART2

    /// Смена мастер-пароля: перешифровка всех учётных данных.
    pub fn change_master_password(&self, old: &str, new: &str) -> Result<(), String> {
        let old_key = Zeroizing::new(self.unlock(old)?);
        let new_salt = crypto::new_salt();
        let new_params = crypto::Argon2Params::default();
        let new_key = Zeroizing::new(crypto::derive_key(new, &new_salt, &new_params));
        let verifier = crypto::encrypt(&new_key, b"remotix-verifier");

        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, username, password, ssh_key_passphrase, root_password FROM profiles",
            )
            .map_err(|e| e.to_string())?;
        let rows: SecretRows = stmt
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

        self.meta_set("argon2_salt", &new_salt)
            .map_err(|e| e.to_string())?;
        self.meta_set(
            "argon2_params",
            serde_json::to_vec(&new_params).unwrap().as_slice(),
        )
        .map_err(|e| e.to_string())?;
        self.meta_set("verifier", &verifier)
            .map_err(|e| e.to_string())?;
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

    /// Создаёт группу с автогенерацией id. Возвращает id новой группы.
    pub fn create_group(&self, name: &str, parent_id: Option<i64>) -> Result<i64, String> {
        self.conn()
            .execute(
                "INSERT INTO groups(name, parent_id) VALUES (?1, ?2)",
                params![name, parent_id],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Все группы: (id, имя, родитель).
    pub fn list_groups(&self) -> Result<Vec<(i64, String, Option<i64>)>, String> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id, name, parent_id FROM groups ORDER BY name")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Находит группу по имени и родителю (или её отсутствие).
    fn find_group(&self, name: &str, parent_id: Option<i64>) -> Result<Option<i64>, String> {
        self.conn()
            .query_row(
                "SELECT id FROM groups WHERE name = ?1 AND parent_id IS ?2",
                params![name, parent_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Возвращает id листа по пути групп, создавая недостающие.
    ///
    /// Пустой путь — `None` (без группы). Циклы (группа внутри себя)
    /// отсекаются на глубине: путь длиной больше 32 считается некорректным.
    pub fn ensure_group_path(&self, path: &[String]) -> Result<Option<i64>, String> {
        if path.is_empty() {
            return Ok(None);
        }
        if path.len() > 32 {
            return Err("слишком глубокая вложенность групп".to_string());
        }
        let mut parent: Option<i64> = None;
        for name in path {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            match self.find_group(name, parent)? {
                Some(id) => parent = Some(id),
                None => {
                    parent = Some(self.create_group(name, parent)?);
                }
            }
        }
        Ok(parent)
    }

    /// Переименовывает группу.
    pub fn rename_group(&self, id: i64, name: &str) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE groups SET name = ?1 WHERE id = ?2",
                params![name, id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Переносит профиль в группу (`None` — без группы).
    pub fn set_profile_group(&self, id: i64, group_id: Option<i64>) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE profiles SET group_id = ?1 WHERE id = ?2",
                params![group_id, id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Удаляет группу: её профили остаются, но без группы, а дочерние
    /// группы поднимаются на уровень выше (внешние ключи в SQLite по
    /// умолчанию не включены, поэтому «висячие» ссылки надо чистить самим).
    pub fn delete_group(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn().execute(
            "UPDATE profiles SET group_id = NULL WHERE group_id = ?1",
            params![id],
        )?;
        self.conn().execute(
            "UPDATE groups SET parent_id = (SELECT parent_id FROM groups WHERE id = ?1)
             WHERE parent_id = ?1 AND id != ?1",
            params![id],
        )?;
        self.conn()
            .execute("DELETE FROM groups WHERE id = ?1", params![id])
    }

    // PART3

    // ---------- profiles ----------

    pub fn add_profile(
        &self,
        key: &[u8; 32],
        p: &crate::models::NewProfile,
    ) -> Result<i64, String> {
        let enc_text = |s: &Option<String>| -> Option<Vec<u8>> {
            s.as_ref().map(|v| crypto::encrypt(key, v.as_bytes()))
        };
        let enc_secret = |s: &Option<SecretString>| -> Option<Vec<u8>> {
            s.as_ref()
                .map(|v| crypto::encrypt(key, v.expose_secret().as_bytes()))
        };
        let t = now();
        self.conn()
            .execute(
                "INSERT INTO profiles(name, protocol, host, port, username, password,
                ssh_key_path, ssh_key_passphrase, root_password, group_id, bastion_profile_id,
                tags, icon, notes, mac_address, rdp_options, vnc_options, ssh_options,
                created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?19)",
                params![
                    p.name,
                    p.protocol.unwrap_or(Protocol::Ssh).as_str(),
                    p.host,
                    p.port,
                    enc_text(&p.username),
                    enc_secret(&p.password),
                    p.ssh_key_path,
                    enc_secret(&p.ssh_key_passphrase),
                    enc_secret(&p.root_password),
                    p.group_id,
                    p.bastion_profile_id,
                    p.tags.join(","),
                    p.icon,
                    p.notes,
                    p.mac_address,
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
        let enc_text = |s: &Option<String>| -> Option<Vec<u8>> {
            s.as_ref().map(|v| crypto::encrypt(key, v.as_bytes()))
        };
        let enc_secret = |s: &Option<SecretString>| -> Option<Vec<u8>> {
            s.as_ref()
                .map(|v| crypto::encrypt(key, v.expose_secret().as_bytes()))
        };
        self.conn()
            .execute(
                "UPDATE profiles SET name = ?1, protocol = ?2, host = ?3, port = ?4,
                    username = ?5, password = ?6, ssh_key_path = ?7, ssh_key_passphrase = ?8,
                    root_password = ?9, group_id = ?10, bastion_profile_id = ?11, tags = ?12,
                    icon = ?13, notes = ?14, mac_address = ?15, rdp_options = ?16,
                    vnc_options = ?17, ssh_options = ?18, updated_at = ?19
                 WHERE id = ?20",
                params![
                    p.name,
                    p.protocol.unwrap_or(Protocol::Ssh).as_str(),
                    p.host,
                    p.port,
                    enc_text(&p.username),
                    enc_secret(&p.password),
                    p.ssh_key_path,
                    enc_secret(&p.ssh_key_passphrase),
                    enc_secret(&p.root_password),
                    p.group_id,
                    p.bastion_profile_id,
                    p.tags.join(","),
                    p.icon,
                    p.notes,
                    p.mac_address,
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
        let dec_text = |blob: &Option<Vec<u8>>| -> Option<String> {
            match blob {
                Some(b) => crypto::decrypt(key, b.as_slice())
                    .ok()
                    .map(|v| String::from_utf8_lossy(&v).into_owned()),
                None => None,
            }
        };
        let dec_secret = |blob: &Option<Vec<u8>>| -> Option<SecretString> {
            dec_text(blob).map(SecretString::from)
        };
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, name, protocol, host, port, username, password, ssh_key_path,
                    ssh_key_passphrase, root_password, group_id, tags, icon, notes, mac_address,
                    rdp_options, vnc_options, ssh_options, created_at, updated_at, last_connected_at,
                    bastion_profile_id
             FROM profiles ORDER BY name",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, u16>(4)?,
                    blob_column(r, 5)?,
                    blob_column(r, 6)?,
                    r.get::<_, Option<String>>(7)?,
                    blob_column(r, 8)?,
                    blob_column(r, 9)?,
                    r.get::<_, Option<i64>>(10)?,
                    r.get::<_, Option<String>>(11)?,
                    r.get::<_, Option<String>>(12)?,
                    r.get::<_, Option<String>>(13)?,
                    r.get::<_, Option<String>>(14)?,
                    r.get::<_, Option<String>>(15)?,
                    r.get::<_, Option<String>>(16)?,
                    r.get::<_, Option<String>>(17)?,
                    r.get::<_, i64>(18)?,
                    r.get::<_, i64>(19)?,
                    r.get::<_, Option<i64>>(20)?,
                    r.get::<_, Option<i64>>(21)?,
                ))
            })
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for row in rows {
            let (
                id,
                name,
                protocol,
                host,
                port,
                username,
                password,
                ssh_key_path,
                ssh_key_passphrase,
                root_password,
                group_id,
                tags,
                icon,
                notes,
                mac_address,
                rdp,
                vnc,
                ssh,
                created_at,
                updated_at,
                last_connected_at,
                bastion_profile_id,
            ) = row.map_err(|e| e.to_string())?;
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
                username: dec_text(&username),
                password: dec_secret(&password),
                ssh_key_path,
                ssh_key_passphrase: dec_secret(&ssh_key_passphrase),
                root_password: dec_secret(&root_password),
                group_id,
                bastion_profile_id,
                tags: tags
                    .unwrap_or_default()
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect(),
                icon,
                notes,
                mac_address,
                rdp_options: rdp
                    .and_then(|v| serde_json::from_str::<RdpOptions>(&v).ok())
                    .unwrap_or_default(),
                vnc_options: vnc
                    .and_then(|v| serde_json::from_str::<VncOptions>(&v).ok())
                    .unwrap_or_default(),
                ssh_options: ssh
                    .and_then(|v| serde_json::from_str::<SshOptions>(&v).ok())
                    .unwrap_or_default(),
                created_at,
                updated_at,
                last_connected_at,
            });
        }
        Ok(out)
    }

    /// Возвращает только идентификаторы профилей для проверки дублей при
    /// импорте: протокол, хост, порт и логин. Пароли не расшифровываются.
    pub fn profile_identities(&self, key: &[u8; 32]) -> Result<Vec<ProfileIdentity>, String> {
        let mut stmt = self
            .conn()
            .prepare("SELECT protocol, host, port, username FROM profiles")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u16>(2)?,
                    blob_column(r, 3)?,
                ))
            })
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for row in rows {
            let (protocol, host, port, username) = row.map_err(|e| e.to_string())?;
            let protocol = match protocol.as_str() {
                "RDP" => Protocol::Rdp,
                "VNC" => Protocol::Vnc,
                "SSH" => Protocol::Ssh,
                _ => continue,
            };
            let username = username.and_then(|blob| {
                crypto::decrypt(key, &blob)
                    .ok()
                    .map(|v| String::from_utf8_lossy(&v).into_owned())
            });
            out.push((protocol, host, port, username));
        }
        Ok(out)
    }

    // PART4

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
            .execute(
                "DELETE FROM meta WHERE key = ?1",
                params![format!("settings.{key}")],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------- expect-правила ----------

    /// Список expect-правил в порядке следования, `send` расшифрован.
    ///
    /// Правило с испорченным шифротекстом пропускается целиком: шаблон
    /// без строки отправки не имеет смысла, а «полпустой» отправлять нельзя.
    pub fn list_expect_rules(&self, key: &[u8; 32]) -> Result<Vec<ExpectRuleRow>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT id, pattern, send, once, enabled FROM expect_rules ORDER BY position, id",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    blob_column(r, 2)?.unwrap_or_default(),
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows {
            let (id, pattern, send, once, enabled) = row.map_err(|e| e.to_string())?;
            let plain = match crypto::decrypt(key, &send) {
                Ok(v) => String::from_utf8_lossy(&v).into_owned(),
                Err(_) => continue,
            };
            out.push(ExpectRuleRow {
                id,
                pattern,
                send: SecretString::from(plain),
                once: once != 0,
                enabled: enabled != 0,
            });
        }
        Ok(out)
    }

    /// Добавляет expect-правило в конец списка.
    pub fn add_expect_rule(
        &self,
        key: &[u8; 32],
        pattern: &str,
        send: &SecretString,
        once: bool,
        enabled: bool,
    ) -> Result<i64, String> {
        let position: i64 = self
            .conn()
            .query_row(
                "SELECT COALESCE(MAX(position), 0) + 1 FROM expect_rules",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        self.conn()
            .execute(
                "INSERT INTO expect_rules(pattern, send, once, enabled, position)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    pattern,
                    crypto::encrypt(key, send.expose_secret().as_bytes()),
                    i64::from(once),
                    i64::from(enabled),
                    position
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Обновляет expect-правило (шаблон, отправка, флаги).
    pub fn update_expect_rule(
        &self,
        key: &[u8; 32],
        id: i64,
        pattern: &str,
        send: &SecretString,
        once: bool,
        enabled: bool,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE expect_rules
                 SET pattern = ?1, send = ?2, once = ?3, enabled = ?4
                 WHERE id = ?5",
                params![
                    pattern,
                    crypto::encrypt(key, send.expose_secret().as_bytes()),
                    i64::from(once),
                    i64::from(enabled),
                    id
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Удаляет expect-правило.
    pub fn delete_expect_rule(&self, id: i64) -> Result<(), String> {
        self.conn()
            .execute("DELETE FROM expect_rules WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------- snippets ----------

    /// Сохранённые команды терминала, по алфавиту.
    pub fn list_snippets(&self, key: &[u8; 32]) -> Result<Vec<SnippetRow>, String> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id, name, command FROM snippets ORDER BY name COLLATE NOCASE, id")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    blob_column(r, 2)?.unwrap_or_default(),
                ))
            })
            .map_err(|e| e.to_string())?;

        let mut out = Vec::new();
        for row in rows {
            let (id, name, encrypted) = row.map_err(|e| e.to_string())?;
            // Испорченный шифротекст (другой мастер-пароль) — команду
            // показать и отправить нельзя, поэтому сниппет пропускается.
            let plain = match crypto::decrypt(key, &encrypted) {
                Ok(v) => v,
                Err(_) => continue,
            };
            out.push(SnippetRow {
                id,
                name,
                command: String::from_utf8_lossy(&plain).into_owned(),
            });
        }
        Ok(out)
    }

    /// Добавляет сниппет; команда шифруется тем же ключом, что и пароли.
    pub fn add_snippet(&self, key: &[u8; 32], name: &str, command: &str) -> Result<i64, String> {
        let t = now();
        self.conn()
            .execute(
                "INSERT INTO snippets(name, command, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)",
                params![name, crypto::encrypt(key, command.as_bytes()), t],
            )
            .map_err(|e| e.to_string())?;
        Ok(self.conn().last_insert_rowid())
    }

    /// Обновляет имя и команду сниппета.
    pub fn update_snippet(
        &self,
        key: &[u8; 32],
        id: i64,
        name: &str,
        command: &str,
    ) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE snippets SET name = ?1, command = ?2, updated_at = ?3 WHERE id = ?4",
                params![name, crypto::encrypt(key, command.as_bytes()), now(), id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Удаляет сниппет.
    pub fn delete_snippet(&self, id: i64) -> Result<(), String> {
        self.conn()
            .execute("DELETE FROM snippets WHERE id = ?1", params![id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    // ---------- history ----------

    /// Удаляет профиль вместе с его историей подключений.
    ///
    /// На `profiles.id` ссылается внешний ключ из `connection_history`, поэтому
    /// записи журнала удаляются первыми — иначе SQLite отвечает
    /// «FOREIGN KEY constraint failed».
    pub fn delete_profile(&self, id: i64) -> rusqlite::Result<usize> {
        self.conn().execute(
            "DELETE FROM connection_history WHERE profile_id = ?1",
            params![id],
        )?;
        // Внешние ключи SQLite не форсятся, поэтому ссылку «профиль-бастион»
        // снимаем вручную: цель продолжает работать прямым подключением.
        self.conn().execute(
            "UPDATE profiles SET bastion_profile_id = NULL WHERE bastion_profile_id = ?1",
            params![id],
        )?;
        self.conn()
            .execute("DELETE FROM profiles WHERE id = ?1", params![id])
    }

    pub fn add_history(
        &self,
        profile_id: i64,
        started_at: i64,
        ended_at: Option<i64>,
        status: &str,
        error: Option<(String, String)>,
    ) -> rusqlite::Result<()> {
        let (code, msg) = match error {
            // Даже если вызывающий код забыл очистить текст, в журнал не
            // должно попасть значение пароля/токена.
            Some((c, m)) => (Some(c), Some(crate::logging::sanitize(&m))),
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
    pub fn history(
        &self,
        profile_id: Option<i64>,
        status: Option<&str>,
    ) -> Result<Vec<HistoryEntry>, String> {
        let mut stmt = self
            .conn()
            .prepare(
                "SELECT h.id, h.profile_id, IFNULL(p.name, '?'), h.started_at, h.ended_at,
                    h.status, h.error_code, h.error_message
             FROM connection_history h LEFT JOIN profiles p ON p.id = h.profile_id
             WHERE (?1 IS NULL OR h.profile_id = ?1)
               AND (?2 IS NULL OR h.status = ?2)
             ORDER BY h.started_at DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![profile_id, status], |r| {
                Ok(HistoryEntry {
                    id: r.get(0)?,
                    profile_id: r.get(1)?,
                    profile_name: r.get(2)?,
                    started_at: r.get(3)?,
                    ended_at: r.get(4)?,
                    status: r.get(5)?,
                    error_code: r.get(6)?,
                    error_message: r
                        .get::<_, Option<String>>(7)?
                        .map(|message| crate::logging::sanitize(&message)),
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    /// Экспорт журнала подключений в CSV.
    pub fn export_history_csv(&self, path: &Path) -> Result<usize, String> {
        let rows = self.history(None, None)?;
        let mut csv =
            String::from("id;profile;started_at;ended_at;status;error_code;error_message\n");
        for h in &rows {
            csv.push_str(&format!(
                "{};{};{};{};{};{};{}\n",
                h.id,
                h.profile_name,
                h.started_at,
                h.ended_at.map(|v| v.to_string()).unwrap_or_default(),
                h.status,
                h.error_code.clone().unwrap_or_default(),
                crate::logging::sanitize(h.error_message.as_deref().unwrap_or_default())
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
    use secrecy::{ExposeSecret, SecretString};

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
            password: Some(SecretString::from("secret".to_string())),
            mac_address: Some("AA:BB:CC:DD:EE:FF".to_string()),
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
        assert_eq!(
            profiles[0].password.as_ref().map(|p| p.expose_secret()),
            Some("secret")
        );
        assert_eq!(
            profiles[0].mac_address.as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    #[test]
    fn profile_is_updated() {
        let (db, key) = opened();
        let id = db.add_profile(&key, &sample()).expect("сохранение профиля");

        let mut updated = sample();
        updated.host = "other.example.org".to_string();
        updated.port = 2222;
        db.update_profile(&key, id, &updated)
            .expect("обновление профиля");

        let profiles = db.list_profiles(&key).expect("чтение профилей");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].host, "other.example.org");
        assert_eq!(profiles[0].port, 2222);
    }

    #[test]
    fn profile_bastion_roundtrip_and_cleared_on_delete() {
        let (db, key) = opened();
        let bastion_id = db
            .add_profile(&key, &sample())
            .expect("сохранение профиля-бастиона");

        let mut target = sample();
        target.name = "Цель".to_string();
        target.host = "inner.example.org".to_string();
        target.bastion_profile_id = Some(bastion_id);
        let target_id = db.add_profile(&key, &target).expect("сохранение цели");

        let profiles = db.list_profiles(&key).expect("чтение профилей");
        let saved = profiles
            .iter()
            .find(|p| p.id == target_id)
            .expect("целевой профиль");
        assert_eq!(saved.bastion_profile_id, Some(bastion_id));

        // Удаление бастиона не удаляет цель и не ломает внешний ключ:
        // ON DELETE SET NULL делает подключение прямым.
        db.delete_profile(bastion_id).expect("удаление бастиона");
        let profiles = db.list_profiles(&key).expect("чтение после удаления");
        let saved = profiles
            .iter()
            .find(|p| p.id == target_id)
            .expect("цель должна остаться");
        assert_eq!(saved.bastion_profile_id, None);
    }

    #[test]
    fn wrong_master_password_is_rejected() {
        let (db, _key) = opened();
        assert!(
            db.unlock("wrong").is_err(),
            "неверный мастер-пароль должен отклоняться"
        );
    }

    #[test]
    fn history_sanitizes_secrets() {
        let (db, key) = opened();
        let id = db.add_profile(&key, &sample()).expect("сохранение профиля");
        db.add_history(
            id,
            100,
            Some(200),
            "error",
            Some((
                "E_CONNECT".to_string(),
                "login failed: password=hunter2".to_string(),
            )),
        )
        .expect("запись в журнал");

        let rows = db.history(None, None).expect("чтение журнала");
        let message = rows[0].error_message.as_deref().unwrap_or_default();
        assert!(!message.contains("hunter2"));
        assert!(message.contains("[REDACTED]"));
    }

    /// Профиль с историей подключений должен удаляться без ошибки
    /// «FOREIGN KEY constraint failed».
    #[test]
    fn profile_is_deleted_with_its_history() {
        let (db, key) = opened();
        let id = db.add_profile(&key, &sample()).expect("сохранение профиля");
        db.add_history(id, 100, Some(200), "success", None)
            .expect("запись в журнал");

        let removed = db.delete_profile(id).expect("удаление профиля");
        assert_eq!(removed, 1, "профиль должен быть удалён");
        assert!(
            db.history(None, None).expect("журнал").is_empty(),
            "история подключений должна удаляться вместе с профилем"
        );
    }

    // ---------- группы ----------

    #[test]
    fn ensure_group_path_creates_nested_groups_once() {
        let (db, _key) = opened();

        let leaf = db
            .ensure_group_path(&["Прод".to_string(), "Сервера".to_string()])
            .expect("создание пути групп");
        assert!(leaf.is_some());

        // Повторный вызов должен найти существующие группы, а не дублировать.
        let again = db
            .ensure_group_path(&["Прод".to_string(), "Сервера".to_string()])
            .expect("повторное создание пути");
        assert_eq!(leaf, again);

        let groups = db.list_groups().expect("список групп");
        assert_eq!(groups.len(), 2, "группы не должны дублироваться");
    }

    #[test]
    fn ensure_group_path_empty_is_none() {
        let (db, _key) = opened();
        assert_eq!(
            db.ensure_group_path(&[]).expect("пустой путь"),
            None,
            "пустой путь — профиль без группы"
        );
    }

    #[test]
    fn delete_group_detaches_profiles_and_reparents_children() {
        let (db, key) = opened();

        let root = db
            .ensure_group_path(&["Корень".to_string()])
            .expect("корневая группа")
            .expect("есть id");
        let child = db
            .ensure_group_path(&["Корень".to_string(), "Ребёнок".to_string()])
            .expect("дочерняя группа")
            .expect("есть id");

        // Один профиль в удаляемой группе, другой — в дочерней.
        let mut in_root = sample();
        in_root.name = "В корне".to_string();
        in_root.group_id = Some(root);
        let in_root_id = db.add_profile(&key, &in_root).expect("профиль");

        let mut in_child = sample();
        in_child.name = "В ребёнке".to_string();
        in_child.group_id = Some(child);
        let in_child_id = db.add_profile(&key, &in_child).expect("профиль");

        db.delete_group(root).expect("удаление группы");

        let profiles = db.list_profiles(&key).expect("чтение профилей");
        assert_eq!(profiles.len(), 2, "профили должны остаться в списке");
        let by_id = |id: i64| profiles.iter().find(|p| p.id == id).cloned().unwrap();
        assert_eq!(
            by_id(in_root_id).group_id,
            None,
            "профиль из удалённой группы — без группы"
        );
        assert_eq!(
            by_id(in_child_id).group_id,
            Some(child),
            "профиль дочерней группы не трогаем"
        );

        // Дочерняя группа поднялась на верхний уровень.
        let groups = db.list_groups().expect("группы");
        assert_eq!(groups.len(), 1, "осталась только «Ребёнок»");
        assert_eq!(groups[0].0, child);
        assert_eq!(groups[0].2, None);
    }

    #[test]
    fn set_profile_group_moves_profile() {
        let (db, key) = opened();
        let id = db.add_profile(&key, &sample()).expect("профиль");

        let group = db
            .ensure_group_path(&["Инфраструктура".to_string()])
            .expect("группа")
            .expect("есть id");
        db.set_profile_group(id, Some(group)).expect("перенос");

        let profiles = db.list_profiles(&key).expect("чтение");
        assert_eq!(profiles[0].group_id, Some(group));

        db.set_profile_group(id, None).expect("возврат");
        let profiles = db.list_profiles(&key).expect("чтение");
        assert_eq!(profiles[0].group_id, None);
    }

    #[test]
    fn rename_group_updates_name() {
        let (db, _key) = opened();
        let id = db
            .ensure_group_path(&["Старое".to_string()])
            .expect("группа")
            .expect("есть id");

        db.rename_group(id, "Новое").expect("переименование");

        let groups = db.list_groups().expect("группы");
        assert_eq!(groups[0].1, "Новое");
    }

    // ---------- expect-правила ----------

    #[test]
    fn expect_rules_roundtrip() {
        let (db, key) = opened();

        let id1 = db
            .add_expect_rule(
                &key,
                "Password:",
                &SecretString::from("hunter2".to_string()),
                true,
                true,
            )
            .expect("первое правило");
        let id2 = db
            .add_expect_rule(
                &key,
                "[yes/no]*:",
                &SecretString::from("yes".to_string()),
                false,
                true,
            )
            .expect("второе правило");

        let rules = db.list_expect_rules(&key).expect("чтение правил");
        assert_eq!(rules.len(), 2, "порядок — по позиции");
        assert_eq!(rules[0].id, id1);
        assert_eq!(rules[0].pattern, "Password:");
        assert_eq!(rules[0].send.expose_secret(), "hunter2");
        assert!(rules[0].once);
        assert!(rules[0].enabled);
        assert_eq!(rules[1].id, id2);
        assert!(!rules[1].once);
    }

    #[test]
    fn expect_rule_update_and_delete() {
        let (db, key) = opened();
        let id = db
            .add_expect_rule(
                &key,
                "old",
                &SecretString::from("a".to_string()),
                false,
                true,
            )
            .expect("правило");

        db.update_expect_rule(
            &key,
            id,
            "new",
            &SecretString::from("b".to_string()),
            true,
            false,
        )
        .expect("обновление");

        let rules = db.list_expect_rules(&key).expect("чтение");
        assert_eq!(rules[0].pattern, "new");
        assert_eq!(rules[0].send.expose_secret(), "b");
        assert!(rules[0].once);
        assert!(!rules[0].enabled);

        db.delete_expect_rule(id).expect("удаление");
        assert!(db.list_expect_rules(&key).expect("чтение").is_empty());
    }

    /// Правило с шифротекстом под другим ключом пропускается: отправлять
    /// непонятно что нельзя.
    #[test]
    fn expect_rules_skip_corrupted_secrets() {
        let (db, key) = opened();
        db.add_expect_rule(
            &key,
            "Password:",
            &SecretString::from("hunter2".to_string()),
            true,
            true,
        )
        .expect("правило");

        let wrong = [0u8; 32]; // не тот ключ
        let rules = db.list_expect_rules(&wrong).expect("чтение");
        assert!(
            rules.is_empty(),
            "испорченная отправка не должна попадать в список"
        );
    }

    /// В файле БД не должно остаться расшифрованной строки отправки.
    #[test]
    fn expect_rule_send_is_stored_encrypted() {
        let dir = std::env::temp_dir().join(format!(
            "remotix-expect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("временный каталог");
        let path = dir.join("test.db");
        {
            let db = Database::open(path.to_str().expect("путь")).expect("открытие БД");
            db.init_master("master").expect("создание мастер-пароля");
            let key = db.unlock("master").expect("разблокировка");

            db.add_expect_rule(
                &key,
                "Password:",
                &SecretString::from("hunter2".to_string()),
                true,
                true,
            )
            .expect("правило");
        }

        let raw = std::fs::read(&path).expect("файл БД");
        let text = String::from_utf8_lossy(&raw);
        assert!(
            !text.contains("hunter2"),
            "секрет не должен храниться в БД открыто"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn snippet_crud_and_encryption() {
        let (db, key) = opened();
        let id = db
            .add_snippet(&key, "Диск", "df -h")
            .expect("сохранение сниппета");

        let snippets = db.list_snippets(&key).expect("чтение сниппетов");
        assert_eq!(snippets.len(), 1);
        assert_eq!(snippets[0].name, "Диск");
        assert_eq!(snippets[0].command, "df -h");

        // Команда лежит в БД зашифрованной: открытого текста нет.
        let raw: Vec<u8> = db
            .conn()
            .query_row(
                "SELECT command FROM snippets WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .expect("шифротекст");
        assert!(
            !raw.windows(5).any(|w| w == b"df -h"),
            "команда не должна храниться открытым текстом"
        );

        db.update_snippet(&key, id, "Диск", "df -i")
            .expect("обновление сниппета");
        let snippets = db.list_snippets(&key).expect("чтение после обновления");
        assert_eq!(snippets[0].command, "df -i");

        // Чужой ключ не должен показывать испорченную команду.
        assert!(db
            .list_snippets(&[0u8; 32])
            .expect("чтение чужим ключом")
            .is_empty());

        db.delete_snippet(id).expect("удаление сниппета");
        assert!(db.list_snippets(&key).expect("чтение").is_empty());
    }
}
