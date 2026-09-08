use std::net::TcpStream;
use std::path::{Path, PathBuf};

use crate::models::Profile;

/// Двухпанельный SFTP-клиент (данные для отображения в GTK4-окне).
pub struct SftpPanel {
    pub local_dir: PathBuf,
    pub remote_dir: String,
    session: Option<ssh2::Session>,
}

impl SftpPanel {
    pub fn new(profile: &Profile) -> Result<Self, String> {
        let addr = format!("{}:{}", profile.host, profile.port);
        let tcp = TcpStream::connect(&addr).map_err(|e| e.to_string())?;
        let mut session = ssh2::Session::new().map_err(|e| e.to_string())?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| e.to_string())?;
        let username = profile.username.clone().unwrap_or_else(|| "root".into());
        session
            .userauth_password(&username, profile.password.as_deref().unwrap_or(""))
            .map_err(|e| format!("аутентификация не удалась: {e}"))?;

        Ok(Self {
            local_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/")),
            remote_dir: ".".into(),
            session: Some(session),
        })
    }

    /// Список файлов удалённой директории (имя, размер, mtime).
    pub fn remote_list(&mut self) -> Result<Vec<(String, u64, i64)>, String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for entry in sftp.readdir(Path::new(&self.remote_dir)).map_err(|e| e.to_string())? {
            let (path, stat) = entry;
            out.push((
                path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                stat.size.unwrap_or(0),
                stat.mtime.unwrap_or(0) as i64,
            ));
        }
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
        sftp.mkdir(Path::new(&self.remote_dir).join(name), 0o755).map_err(|e| e.to_string())
    }

    /// Переименование/удаление на сервере.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        sftp.rename(
            Path::new(&self.remote_dir).join(from),
            Path::new(&self.remote_dir).join(to),
            None,
        )
        .map_err(|e| e.to_string())
    }

    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        let sftp = self.session.as_mut().unwrap().sftp().map_err(|e| e.to_string())?;
        sftp.unlink(Path::new(&self.remote_dir).join(name)).map_err(|e| e.to_string())
    }
}
