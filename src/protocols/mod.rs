pub mod ssh;
// Модули rdp и vnc активируются на Linux-сборке (FFI к FreeRDP / libvncclient).
#[cfg(target_os = "linux")]
pub mod rdp;
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
