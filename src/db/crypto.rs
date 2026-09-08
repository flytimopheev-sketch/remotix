use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;

/// Размер соли Argon2id (байты).
pub const SALT_LEN: usize = 16;
/// Размер nonce AES-256-GCM (байты).
pub const NONCE_LEN: usize = 12;

/// Параметры Argon2id, хранятся в таблице meta.
#[derive(serde::Serialize, serde::Deserialize, Clone, Copy)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 4 }
    }
}

/// Выводит 32-байтный ключ шифрования из мастер-пароля (Argon2id).
pub fn derive_key(master_password: &str, salt: &[u8], params: &Argon2Params) -> [u8; 32] {
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32))
            .expect("параметры Argon2id"),
    );
    let mut key = [0u8; 32];
    argon
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .expect("не удалось вывести ключ из мастер-пароля");
    key
}

/// Шифрует данные AES-256-GCM. Возвращает nonce || ciphertext.
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .expect("ошибка шифрования AES-256-GCM");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Расшифровывает данные AES-256-GCM (nonce || ciphertext).
pub fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < NONCE_LEN {
        return Err("повреждённый шифротекст".into());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| "неверный мастер-пароль или повреждённые данные".to_string())
}

/// Генерирует новую случайную соль.
pub fn new_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}
