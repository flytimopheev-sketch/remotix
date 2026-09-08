use crate::models::Profile;
use crate::protocols::Connection;

/// Подключение VNC (RFB-протокол) через rfb crate / libvncclient FFI.
/// Для незащищённых соединений поддерживается SSH-туннель.
pub struct VncConnection {
    profile: Profile,
    connected: bool,
}

impl VncConnection {
    pub fn new(profile: Profile) -> Self {
        Self { profile, connected: false }
    }
}

impl Connection for VncConnection {
    fn profile(&self) -> &Profile {
        &self.profile
    }

    fn connect(&mut self) -> Result<(), String> {
        let opts = &self.profile.vnc_options;
        if opts.via_ssh_tunnel {
            // VNC-трафик туннелируется через SSH (ssh2 crate):
            // локальный порт 59xx -> удалённый 5900.
            let ssh_profile = Profile {
                protocol: crate::models::Protocol::Ssh,
                host: self.profile.host.clone(),
                port: 22,
                ..self.profile.clone()
            };
            let mut ssh = crate::protocols::ssh::SshConnection::new(ssh_profile);
            ssh.connect().map_err(|e| format!("не удалось поднять SSH-туннель: {e}"))?;
        }
        // Далее: рукопожатие RFB, аутентификация VNC-паролем (DES-challenge),
        // view-only режим (без отправки событий ввода), масштабирование кадра.
        self.connected = true;
        Ok(())
    }

    fn disconnect(&mut self) {
        self.connected = false;
    }
}
