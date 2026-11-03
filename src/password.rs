//! Генератор паролей для профилей подключений.
//!
//! Источник случайности — `OsRng` (криптостойкий ГПСЧ ОС). В пароле
//! гарантированно есть строчная и заглавная буква, цифра и символ, а
//! распределение не смещено делением по модулю.

use rand::rngs::OsRng;
use rand::RngCore;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
// Символы без кавычек, обратной косой черты и обратного апострофа: такой
// пароль проще вводить в конфигурацию сервера и в шелл.
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

const ALL: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.?/";

/// Длина пароля по умолчанию (20 символов).
pub const DEFAULT_LENGTH: usize = 20;
/// Минимальная длина: короче не имеет смысла для реальных паролей.
pub const MIN_LENGTH: usize = 8;
/// Максимальная длина: защита от случайного `generate(usize::MAX)`.
pub const MAX_LENGTH: usize = 128;

/// Генерирует пароль заданной длины (зажатую в [`MIN_LENGTH`]..=[`MAX_LENGTH`]).
pub fn generate(length: usize) -> String {
    let length = length.clamp(MIN_LENGTH, MAX_LENGTH);
    let mut rng = OsRng;
    let mut chars = Vec::with_capacity(length);

    // По одному символу каждого класса — дальше добиваем случайными.
    for class in [LOWER, UPPER, DIGITS, SYMBOLS] {
        chars.push(class[pick_index(class.len(), &mut rng)]);
    }
    while chars.len() < length {
        chars.push(ALL[pick_index(ALL.len(), &mut rng)]);
    }

    // Перемешивание Фишера — Йетса: обязательные символы не должны стоять
    // в предсказуемых позициях.
    for i in (1..chars.len()).rev() {
        let j = pick_index(i + 1, &mut rng);
        chars.swap(i, j);
    }

    String::from_utf8(chars).expect("пароль состоит только из ASCII")
}

/// Равномерный индекс `0..bound` без смещения по модулю.
fn pick_index(bound: usize, rng: &mut impl RngCore) -> usize {
    debug_assert!(bound > 0 && bound <= u32::MAX as usize);
    let bound = bound as u32;
    // Отбрасываем хвост, который не делится на bound нацело.
    let limit = u32::MAX - (u32::MAX % bound);
    loop {
        let value = rng.next_u32();
        if value < limit {
            return (value % bound) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_class(password: &str, class: &[u8]) -> bool {
        password.bytes().any(|b| class.contains(&b))
    }

    #[test]
    fn generated_password_has_all_character_classes() {
        for _ in 0..20 {
            let password = generate(DEFAULT_LENGTH);
            assert_eq!(password.len(), DEFAULT_LENGTH);
            assert!(has_class(&password, LOWER), "нет строчной буквы");
            assert!(has_class(&password, UPPER), "нет заглавной буквы");
            assert!(has_class(&password, DIGITS), "нет цифры");
            assert!(has_class(&password, SYMBOLS), "нет символа");
            assert!(
                password.bytes().all(|b| ALL.contains(&b)),
                "посторонний символ в пароле"
            );
        }
    }

    #[test]
    fn length_is_clamped() {
        assert_eq!(generate(1).len(), MIN_LENGTH);
        assert_eq!(generate(usize::MAX).len(), MAX_LENGTH);
        assert_eq!(generate(33).len(), 33);
    }
}
