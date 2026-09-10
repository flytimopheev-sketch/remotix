pub mod ssh;
// RDP через IronRDP — чистый Rust, кроссплатформенный (не требует FreeRDP).
pub mod rdp;
// VNC через libvncclient (FFI) — только на Linux.
#[cfg(target_os = "linux")]
pub mod vnc;

use crate::models::Profile;

/// Интерфейс активного подключения к удалённому хосту.
pub trait Connection {
    fn profile(&self) -> &Profile;

    /// Устанавливает соединение. Возвращает текст ошибки при неудаче.
    fn connect(&mut self) -> Result<(), String>;

    /// Завершает соединение.
    fn disconnect(&mut self);
}
