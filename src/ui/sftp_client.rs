use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::models::Profile;

/// Запись каталога (файл или подкаталог).
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    /// Имя объекта.
    pub name: String,
    /// Это каталог.
    pub is_dir: bool,
    /// Размер в байтах.
    pub size: u64,
    /// Время изменения (unix-время).
    pub modified: i64,
}

/// Двухпанельный SFTP-клиент (данные для отображения в GTK4-окне).
pub struct SftpPanel {
    pub local_dir: PathBuf,
    pub remote_dir: String,
    session: Option<ssh2::Session>,
    /// Кэш «объект является каталогом» для серверов, которые не присылают
    /// тип объекта в атрибутах (`S_IFDIR`). Сбрасывается при смене каталога.
    dir_cache: HashMap<String, bool>,
}

impl SftpPanel {
    pub fn new(profile: &Profile) -> Result<Self, String> {
        Self::new_with_host_key(profile, &crate::protocols::ssh::HostKeyConfig::default())
    }

    /// Подключение с явной проверкой ключа хоста (терминал/SFTP используют
    /// диалог подтверждения, тесты — временный known_hosts).
    pub fn new_with_host_key(
        profile: &Profile,
        host_key: &crate::protocols::ssh::HostKeyConfig<'_>,
    ) -> Result<Self, String> {
        // Способы входа (пароль, ключ, ssh-agent) те же, что у терминала.
        let username = profile.username.as_deref().unwrap_or("root");
        let session =
            crate::protocols::ssh::connect_session_with(profile, username, host_key)?;

        // Начальный каталог — абсолютный путь домашнего каталога пользователя.
        // Относительные пути сервер SFTP разрешает от своего рабочего
        // каталога, который не обязательно совпадает с домашним, поэтому
        // дальше работаем только с абсолютными путями.
        let remote_dir = {
            let sftp = session.sftp().map_err(|e| e.to_string())?;
            sftp.realpath(Path::new("."))
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "/".to_string())
        };

        Ok(Self {
            local_dir: crate::config::home_dir(),
            remote_dir,
            session: Some(session),
            dir_cache: HashMap::new(),
        })
    }

    /// Отправляет keepalive, если libssh2 считает, что пора.
    ///
    /// SFTP-поток работает в блокирующем режиме, но между операциями может
    /// простаивать; явный вызов не даёт NAT забыть сессию.
    pub fn keepalive(&self) {
        if let Some(session) = self.session.as_ref() {
            let _ = session.keepalive_send();
        }
    }

    /// Текущий каталог сервера (абсолютный путь).
    pub fn remote_path(&self) -> String {
        let dir = self.remote_dir.trim_end_matches('/');
        if dir.is_empty() {
            "/".to_string()
        } else {
            dir.to_string()
        }
    }

    /// Признак каталога по битам режима (S_IFDIR).
    fn is_dir_mode(perm: Option<u32>) -> bool {
        perm.map(|mode| (mode & 0o170000) == 0o040000).unwrap_or(false)
    }

    /// Тип объекта в атрибутах неизвестен: сервер прислал только права
    /// доступа (`0o755`), без битов `S_IF*`.
    fn type_unknown(perm: Option<u32>) -> bool {
        perm.map(|mode| (mode & 0o170000) == 0).unwrap_or(true)
    }

    /// Абсолютный ли путь на сервере: Unix (`/…`) или Windows (`C:/…`,
    /// `C:\…`, `\\сервер\…`). SFTP-сервер под Windows отдаёт путь с буквой
    /// диска, и без этой проверки переход в родительский каталог склеивал
    /// его с текущим.
    fn is_absolute(path: &str) -> bool {
        if path.starts_with('/') || path.starts_with('\\') {
            return true;
        }
        let bytes = path.as_bytes();
        bytes.len() >= 3 && bytes[1] == b':' && (bytes[2] == b'/' || bytes[2] == b'\\')
    }

    /// Получает абсолютный путь: относительный — относительно текущего
    /// каталога сервера.
    fn resolve(&self, path: &str) -> String {
        if Self::is_absolute(path) {
            let trimmed = path.trim_end_matches('/');
            return if trimmed.is_empty() {
                "/".to_string()
            } else if trimmed.len() == 2 && trimmed.as_bytes()[1] == b':' {
                // Корень диска Windows: «C:» → «C:/».
                format!("{trimmed}/")
            } else {
                trimmed.to_string()
            };
        }
        let current = self.remote_dir.trim_end_matches('/');
        if current.is_empty() {
            path.to_string()
        } else {
            format!("{current}/{path}")
        }
    }

    /// Перейти в каталог на сервере.
    ///
    /// Путь строится от текущего каталога (см. `resolve`). Надёжный признак
    /// каталога — возможность его открыть (`opendir`): часть SFTP-серверов
    /// не присылает тип объекта (`S_IFDIR`) в атрибутах, и проверка по
    /// режиму ошибочно объявляла каталог файлом.
    pub fn cd(&mut self, path: &str) -> Result<(), String> {
        let full = self.resolve(path);
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;

        let mut target = full.clone();
        let mut opened = sftp.opendir(Path::new(&target)).is_ok();
        if !opened && full != path {
            // Запасной вариант: сервер мог разрешить путь относительно
            // своего рабочего каталога.
            if sftp.opendir(Path::new(path)).is_ok() {
                target = path.to_string();
                opened = true;
            }
        }
        if !opened {
            // Различаем «это файл» и «каталог недоступен», чтобы сообщение
            // было понятным.
            if let Ok(stat) = sftp.stat(Path::new(&full)) {
                let is_file = stat
                    .perm
                    .map(|mode| {
                        let kind = mode & 0o170000;
                        kind != 0 && kind != 0o040000
                    })
                    .unwrap_or(false);
                if is_file {
                    return Err(format!("{full} — не каталог"));
                }
            }
            return Err(format!("не удалось открыть каталог {full}"));
        }

        // Канонический путь: корректно обрабатываем «..» и символические
        // ссылки, чтобы дальнейшие переходы строились от реального каталога.
        if let Ok(real) = sftp.realpath(Path::new(&target)) {
            let real = real.to_string_lossy().into_owned();
            if !real.is_empty() {
                target = real;
            }
        }

        drop(sftp);
        self.remote_dir = target;
        self.dir_cache.clear();
        Ok(())
    }

    /// Подняться на уровень выше.
    pub fn cd_up(&mut self) -> Result<(), String> {
        let current = self.remote_path();
        let parent = match current.rfind('/') {
            Some(0) => "/".to_string(),
            Some(i) => current[..i].to_string(),
            None => "/".to_string(),
        };
        self.cd(&parent)
    }

    /// Список файлов удалённого каталога.
    pub fn remote_list(&mut self) -> Result<Vec<Entry>, String> {
        let mut out: Vec<Entry> = Vec::new();
        // Объекты, тип которых сервер не сообщил: проверим их отдельно.
        let mut unknown: Vec<(usize, String)> = Vec::new();

        {
            let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
            for entry in sftp
                .readdir(Path::new(&self.remote_dir))
                .map_err(|e| e.to_string())?
            {
                let (path, stat) = entry;
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if name.is_empty() || name == "." || name == ".." {
                    continue;
                }
                if Self::type_unknown(stat.perm) {
                    let full = Path::new(&self.remote_dir)
                        .join(&name)
                        .to_string_lossy()
                        .into_owned();
                    unknown.push((out.len(), full));
                }
                out.push(Entry {
                    name,
                    is_dir: Self::is_dir_mode(stat.perm),
                    size: stat.size.unwrap_or(0),
                    modified: stat.mtime.unwrap_or(0) as i64,
                });
            }
        }

        // Сервер не присылает тип объекта — определяем каталог по
        // возможности его открыть. Результат кэшируем, чтобы не делать
        // лишних запросов при каждом обновлении списка.
        if !unknown.is_empty() {
            let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
            for (idx, full) in unknown {
                let is_dir = match self.dir_cache.get(&full) {
                    Some(cached) => *cached,
                    None => {
                        let probe = sftp.opendir(Path::new(&full)).is_ok();
                        self.dir_cache.insert(full, probe);
                        probe
                    }
                };
                if let Some(entry) = out.get_mut(idx) {
                    entry.is_dir = is_dir;
                }
            }
        }

        // Сначала каталоги, затем файлы — как в файловом менеджере.
        out.sort_by(|a, b| {
            b.is_dir
                .cmp(&a.is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        Ok(out)
    }

    /// Загрузка файла на сервер.
    pub fn upload(&mut self, local: &Path, remote_name: &str) -> Result<(), String> {
        let data = std::fs::read(local).map_err(|e| e.to_string())?;
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        let remote = Path::new(&self.remote_dir).join(remote_name);
        let mut file = sftp.create(&remote).map_err(|e| e.to_string())?;
        use std::io::Write;
        file.write_all(&data).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Скачивание файла с сервера.
    pub fn download(&mut self, remote_name: &str, local: &Path) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        let remote = Path::new(&self.remote_dir).join(remote_name);
        let mut file = sftp.open(&remote).map_err(|e| e.to_string())?;
        use std::io::Read;
        let mut data = Vec::new();
        file.read_to_end(&mut data).map_err(|e| e.to_string())?;
        std::fs::write(local, data).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Создание папки на сервере.
    pub fn mkdir(&mut self, name: &str) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        sftp.mkdir(&Path::new(&self.remote_dir).join(name), 0o755).map_err(|e| e.to_string())
    }

    /// Переименование объекта на сервере.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        sftp.rename(
            &Path::new(&self.remote_dir).join(from),
            &Path::new(&self.remote_dir).join(to),
            None,
        )
        .map_err(|e| e.to_string())
    }

    /// Удаление объекта на сервере.
    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        sftp.unlink(&Path::new(&self.remote_dir).join(name)).map_err(|e| e.to_string())
    }

    /// Копирование файла на сервере (в пределах текущего каталога).
    pub fn copy(&mut self, from: &str, to: &str) -> Result<(), String> {
        use std::io::{Read, Write};

        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        let src = Path::new(&self.remote_dir).join(from);
        let dst = Path::new(&self.remote_dir).join(to);
        let mut data = Vec::new();
        sftp.open(&src)
            .map_err(|e| format!("не удалось прочитать {from}: {e}"))?
            .read_to_end(&mut data)
            .map_err(|e| format!("не удалось прочитать {from}: {e}"))?;
        let mut file = sftp
            .create(&dst)
            .map_err(|e| format!("не удалось создать {to}: {e}"))?;
        file.write_all(&data)
            .map_err(|e| format!("не удалось записать {to}: {e}"))?;
        Ok(())
    }
}

/// Содержимое локального каталога.
pub fn local_list(dir: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = entry.metadata().ok();
            out.push(Entry {
                name,
                is_dir: meta.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                size: meta.as_ref().map(|m| m.len()).unwrap_or(0),
                modified: meta
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            });
        }
    }
    out.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::profile::{RdpOptions, SshOptions, VncOptions};
    use crate::models::Protocol;
    use crate::protocols::ssh::HostKeyConfig;

    /// Временный known_hosts: тест не должен трогать файл пользователя.
    struct TempKnownHosts(PathBuf);

    impl Drop for TempKnownHosts {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Профиль тестового SFTP-сервера.
    fn test_profile() -> Profile {
        Profile {
            id: 0,
            name: "test".to_string(),
            protocol: Protocol::Ssh,
            host: "127.0.0.1".to_string(),
            port: 2222,
            username: Some("tester".to_string()),
            password: Some("secret".to_string()),
            ssh_key_path: None,
            ssh_key_passphrase: None,
            root_password: None,
            group_id: None,
            tags: vec![],
            icon: None,
            notes: None,
            rdp_options: RdpOptions::default(),
            vnc_options: VncOptions::default(),
            ssh_options: SshOptions::default(),
            created_at: 0,
            updated_at: 0,
            last_connected_at: None,
        }
    }

    /// SFTP: в каталог можно войти по имени — путь строится от текущего
    /// каталога сервера, а не от его рабочего каталога.
    ///
    /// Требует SSH-сервера на `127.0.0.1:2222`; без него тест пропускается.
    #[test]
    fn enters_remote_directory() {
        if std::net::TcpStream::connect("127.0.0.1:2222").is_err() {
            eprintln!("SSH-сервер на 127.0.0.1:2222 недоступен — тест пропущен");
            return;
        }

        let known_hosts = TempKnownHosts(std::env::temp_dir().join(format!(
            "remotix-sftp-known-hosts-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        )));
        let host_key = HostKeyConfig {
            known_hosts: known_hosts.0.clone(),
            accept_new: true,
            verifier: None,
        };
        let profile = test_profile();
        let mut panel = SftpPanel::new_with_host_key(&profile, &host_key)
            .expect("подключение к SFTP-серверу");

        // Начальный каталог — абсолютный путь.
        let start = panel.remote_path();
        assert!(start.starts_with('/'), "начальный путь должен быть абсолютным: {start}");

        // Ищем каталог, в который можно войти.
        let listing = panel.remote_list().expect("список удалённого каталога");
        let Some(dir) = listing.iter().find(|e| e.is_dir) else {
            eprintln!("в домашнем каталоге нет подкаталогов — тест пропущен");
            return;
        };

        panel.cd(&dir.name).expect("вход в каталог на сервере");
        let current = panel.remote_path();
        assert!(
            current.starts_with('/'),
            "после входа путь должен остаться абсолютным: {current}"
        );
        assert!(
            current != start,
            "после входа путь должен измениться: {current} == {start}"
        );
        assert!(
            current.ends_with(&dir.name),
            "в пути должно быть имя каталога: {current}"
        );

        // На уровень выше — снова абсолютный путь.
        panel.cd_up().expect("переход в родительский каталог");
        assert_eq!(panel.remote_path(), start);
    }

    /// SFTP под Windows отдаёт абсолютные пути с буквой диска — такие пути
    /// не должны склеиваться с текущим каталогом.
    #[test]
    fn resolves_windows_and_unix_absolute_paths() {
        let panel = SftpPanel {
            local_dir: PathBuf::from("/tmp"),
            remote_dir: "C:/Users/tester".to_string(),
            session: None,
            dir_cache: HashMap::new(),
        };
        assert_eq!(panel.resolve("C:/"), "C:/");
        assert_eq!(panel.resolve("C:\\Windows"), "C:\\Windows");
        assert_eq!(panel.resolve("Documents"), "C:/Users/tester/Documents");
        assert_eq!(panel.resolve("C:/Users"), "C:/Users");

        let unix = SftpPanel {
            local_dir: PathBuf::from("/tmp"),
            remote_dir: "/home/tester".to_string(),
            session: None,
            dir_cache: HashMap::new(),
        };
        assert_eq!(unix.resolve("/"), "/");
        assert_eq!(unix.resolve("/etc"), "/etc");
        assert_eq!(unix.resolve("docs"), "/home/tester/docs");
    }
}
