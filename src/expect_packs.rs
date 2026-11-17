//! Готовые наборы expect-правил («паки») для типовых промптов.
//!
//! Пак — это подсказка, а не готовый автоответ с паролем: правила, которым
//! нужен секрет, помечены `needs_secret` и не содержат текста отправки.
//! Значение для них вводит пользователь, и хранится оно зашифрованным, как
//! остальные учётные данные. Готовые ответы в паках — только не секретные
//! («yes» для отпечатка хоста, «Y» для подтверждения пакетного менеджера).

/// Одно правило пака.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackRule {
    /// Шаблон вывода (`*`, `?`, литералы) — как в `expect`.
    pub pattern: &'static str,
    /// Готовый ответ; пустой, если правило требует секрета от пользователя.
    pub send: &'static str,
    /// Сработать один раз за сессию.
    pub once: bool,
    /// Ответ — секрет: значение задаёт пользователь, в паке его нет.
    pub needs_secret: bool,
}

/// Набор правил под конкретную задачу.
#[derive(Clone, Copy, Debug)]
pub struct Pack {
    /// Идентификатор для настроек и импорта.
    pub id: &'static str,
    /// Название для интерфейса.
    pub title: &'static str,
    /// Правила набора.
    pub rules: &'static [PackRule],
}

// Шаблон начинается со «re you sure», а не с «Are»: матчер чувствителен к
// регистру, а OpenSSH пишет «Are you sure…». Пропуск первой буквы делает
// правило устойчивым к регистру без дублирования вариантов.
const SSH_HOSTKEY: &[PackRule] = &[PackRule {
    pattern: "*re you sure you want to continue connecting*",
    send: "yes",
    once: true,
    needs_secret: false,
}];

const SUDO: &[PackRule] = &[PackRule {
    pattern: "*[sudo] password*",
    send: "",
    once: true,
    needs_secret: true,
}];

const SSH_PASSPHRASE: &[PackRule] = &[PackRule {
    pattern: "*Enter passphrase for key*",
    send: "",
    once: true,
    needs_secret: true,
}];

const APT_CONFIRM: &[PackRule] = &[PackRule {
    pattern: "*Do you want to continue*",
    send: "Y",
    once: false,
    needs_secret: false,
}];

/// Все встроенные наборы.
pub const PACKS: &[Pack] = &[
    Pack {
        id: "ssh-hostkey",
        title: "SSH: подтверждение отпечатка хоста",
        rules: SSH_HOSTKEY,
    },
    Pack {
        id: "sudo",
        title: "sudo: запрос пароля",
        rules: SUDO,
    },
    Pack {
        id: "ssh-passphrase",
        title: "SSH: парольная фраза ключа",
        rules: SSH_PASSPHRASE,
    },
    Pack {
        id: "apt-confirm",
        title: "APT: подтверждение установки",
        rules: APT_CONFIRM,
    },
];

/// Набор по идентификатору.
pub fn by_id(id: &str) -> Option<&'static Pack> {
    PACKS.iter().find(|p| p.id == id)
}

/// Сколько правил во всех наборах.
pub fn rule_count() -> usize {
    PACKS.iter().map(|p| p.rules.len()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_are_well_formed() {
        assert!(!PACKS.is_empty());
        for p in PACKS {
            assert!(!p.id.is_empty() && !p.title.is_empty());
            assert!(!p.rules.is_empty(), "пустой пак: {}", p.id);
            for r in p.rules {
                assert!(!r.pattern.is_empty(), "пустой шаблон в {}", p.id);
            }
        }
    }

    #[test]
    fn ids_are_unique() {
        for (i, a) in PACKS.iter().enumerate() {
            for b in &PACKS[i + 1..] {
                assert_ne!(a.id, b.id, "повтор id: {}", a.id);
            }
        }
    }

    /// Пак не должен содержать готовый пароль: секрет вводит пользователь.
    #[test]
    fn secret_rules_carry_no_payload() {
        for p in PACKS {
            for r in p.rules {
                if r.needs_secret {
                    assert!(
                        r.send.is_empty(),
                        "секретное правило с готовым ответом: {}",
                        p.id
                    );
                } else {
                    assert!(
                        !r.send.is_empty(),
                        "пустой ответ у не-секретного правила: {}",
                        p.id
                    );
                }
            }
        }
    }

    #[test]
    fn lookup_by_id() {
        assert!(by_id("sudo").is_some());
        assert!(by_id("нет-такого").is_none());
        assert_eq!(by_id("ssh-hostkey").unwrap().rules[0].send, "yes");
    }

    #[test]
    fn rule_count_matches() {
        assert_eq!(
            rule_count(),
            PACKS.iter().flat_map(|p| p.rules.iter()).count()
        );
        assert!(rule_count() >= 4);
    }

    /// Шаблоны паков должны срабатывать на реальных промптах.
    #[test]
    fn patterns_match_real_prompts() {
        use crate::expect::wildcard_contains;
        let cases = [
            (
                "ssh-hostkey",
                "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            ),
            ("sudo", "[sudo] password for admin: "),
            (
                "ssh-passphrase",
                "Enter passphrase for key '/home/admin/.ssh/id_ed25519': ",
            ),
            ("apt-confirm", "Do you want to continue? [Y/n] "),
        ];
        for (id, text) in cases {
            let pack = by_id(id).expect(id);
            assert!(
                pack.rules
                    .iter()
                    .any(|r| wildcard_contains(r.pattern, text)),
                "пак {id} не сработал на: {text}"
            );
        }
    }
}
