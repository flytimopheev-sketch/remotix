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

        Ok(Self {
            local_dir: crate::config::home_dir(),
            remote_dir: ".".into(),
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

    /// Перейти в каталог на сервере.
    pub fn cd(&mut self, path: &str) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        let stat = sftp
            .stat(Path::new(path))
            .map_err(|e| format!("не удалось открыть каталог {path}: {e}"))?;
        if !Self::is_dir_mode(stat.perm) {
            return Err(format!("{path} — не каталог"));
        }
        self.remote_dir = path.to_string();
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
