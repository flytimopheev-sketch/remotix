use std::net::TcpStream;
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
}

impl SftpPanel {
    pub fn new(profile: &Profile) -> Result<Self, String> {
        let addr = format!("{}:{}", profile.host, profile.port);
        let tcp = TcpStream::connect(&addr)
            .map_err(|e| format!("не удалось подключиться к {addr}: {e}"))?;
        let mut session = ssh2::Session::new().map_err(|e| e.to_string())?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| e.to_string())?;
        let username = profile.username.clone().unwrap_or_else(|| "root".into());
        session
            .userauth_password(&username, profile.password.as_deref().unwrap_or(""))
            .map_err(|e| format!("аутентификация не удалась: {e}"))?;

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
        })
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

    /// Получает абсолютный путь: относительный — относительно текущего
    /// каталога сервера.
    fn resolve(&self, path: &str) -> String {
        if path.starts_with('/') {
            return path.trim_end_matches('/').to_string();
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
    /// Путь строится от текущего каталога (см. `resolve`). Права объекта
    /// у некоторых SFTP-серверов не приходят, поэтому каталогом считается
    /// любой объект, который удалось простатировать.
    pub fn cd(&mut self, path: &str) -> Result<(), String> {
        let full = self.resolve(path);
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;

        let stat = match sftp.stat(Path::new(&full)) {
            Ok(stat) => stat,
            Err(e) => {
                // Запасной вариант: сервер мог разрешить путь относительно
                // своего рабочего каталога.
                if full != path {
                    if let Ok(stat) = sftp.stat(Path::new(path)) {
                        let is_dir = stat.perm.map(|m| (m & 0o170000) == 0o040000).unwrap_or(true);
                        if is_dir {
                            self.remote_dir = path.to_string();
                            return Ok(());
                        }
                    }
                }
                return Err(format!("не удалось открыть каталог {full}: {e}"));
            }
        };

        if let Some(perm) = stat.perm {
            if (perm & 0o170000) != 0o040000 {
                return Err(format!("{full} — не каталог"));
            }
        }
        self.remote_dir = full;
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
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for entry in sftp.readdir(Path::new(&self.remote_dir)).map_err(|e| e.to_string())? {
            let (path, stat) = entry;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            out.push(Entry {
                name,
                is_dir: Self::is_dir_mode(stat.perm),
                size: stat.size.unwrap_or(0),
                modified: stat.mtime.unwrap_or(0) as i64,
            });
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

        let mut panel = SftpPanel::new(&test_profile()).expect("подключение к SFTP-серверу");

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
}
