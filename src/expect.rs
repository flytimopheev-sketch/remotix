//! Expect-правила: автоматический ответ на вывод терминала.
//!
//! Правило — это шаблон вывода (например, `Password:`) и строка, которую
//! нужно отправить в канал при совпадении (например, пароль). Движок
//! накапливает скользящее окно вывода и проверяет правила на каждой порции.
//!
//! Сопоставление — собственный вайлдкард-матчер, семантика expect(1):
//! шаблон ищется в любом месте окна (`Password:` срабатывает на
//! «Password: » и на «Enter Password:»). В шаблоне `*` — любая
//! последовательность символов (в том числе пустая), `?` — ровно один
//! символ, остальное — литералы. Регулярные выражения сознательно не
//! используются: ни новой зависимости, ни обработки пользовательских
//! шаблонов как кода.

use secrecy::{ExposeSecret, SecretString};

/// Правило expect: при совпадении `pattern` с окном вывода отправить `send`.
#[derive(Clone)]
pub struct Rule {
    /// Шаблон вывода (`*`, `?`, литералы).
    pub pattern: String,
    /// Строка для отправки в канал (хранится зашифрованной в БД).
    pub send: SecretString,
    /// Сработать только один раз за сессию.
    pub once: bool,
}

/// Размер скользящего окна вывода для сопоставления (байт).
///
/// Промпты и короткие вопросы помещаются с запасом; больший размер означал
/// бы заметные накладные расходы на каждую порцию вывода.
pub const WINDOW_BYTES: usize = 4096;

/// Проверяет шаблон против текста целиком: `*` — любая последовательность,
/// `?` — один символ, остальное — литералы.
///
/// Жадный алгоритм с возвратом к последней `*` (классика fnmatch), без
/// рекурсии — линейная память.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    wildcard_match_prefix(&p, &t, true)
}

/// Совпадение шаблона В ЛЮБОМ месте текста — семантика expect(1):
/// `Password:` срабатывает и на «Password: », и на «Enter Password:».
///
/// Поиск якорится по первому литеральному символу шаблона; префикс из
/// `*`/`?` совпадает с любым началом (звёздочка поглощает лишнее), а
/// концом совпадения может быть любая позиция — текст после шаблона
/// не учитывается.
pub fn wildcard_contains(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    // Префикс шаблона без литералов.
    let prefix = p.iter().take_while(|c| **c == '*' || **c == '?').count();
    if prefix == p.len() {
        // Шаблон целиком из wildcards: каждый `?` требует один символ.
        let needed = p.iter().filter(|c| **c == '?').count();
        return t.len() >= needed;
    }
    let first = p[prefix];
    // Минимальная длина префикса: `?` — ровно по символу, `*` — ноль и больше.
    let min_prefix = p[..prefix].iter().filter(|c| **c == '?').count();
    for (i, c) in t.iter().enumerate() {
        if *c == first && i >= min_prefix && wildcard_match_prefix(&p[prefix..], &t[i..], false) {
            return true;
        }
    }
    false
}

/// Ядро сопоставления. `full` — текст должен совпасть целиком (якорное
/// совпадение fnmatch); иначе достаточно полного потребления шаблона
/// (шаблон совпадает с префиксом текста — остаток текста игнорируется).
fn wildcard_match_prefix(p: &[char], t: &[char], full: bool) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    // Позиция последней `*` в шаблоне и позиция текста, с которой она
    // уже «съела» символы (точка возврата).
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
            if !full && pi == p.len() {
                return true;
            }
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
            if !full && pi == p.len() {
                return true;
            }
        } else if let Some(s) = star {
            // Возврат: `*` съедает ещё один символ текста.
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Движок expect-правил сессии. Живёт в потоке сессии, получает порции
/// вывода и возвращает байты для отправки в канал.
pub struct ExpectEngine {
    rules: Vec<Rule>,
    /// Срабатывания правил `once`.
    fired: Vec<bool>,
    window: Vec<u8>,
}

impl ExpectEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        let fired = vec![false; rules.len()];
        Self {
            rules,
            fired,
            window: Vec::new(),
        }
    }

    /// Правил нет — движок не нужен (вызова можно не делать вовсе).
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Порция вывода сессии. Возвращает байты для отправки в канал
    /// (по одной порции на сработавшее правило, в порядке списка).
    ///
    /// После любой отправки окно очищается: промпт «съеден», повторное
    /// срабатывание на тех же байтах невозможно (защита от циклов
    /// resend). Правила `once` не срабатывают второй раз за сессию.
    pub fn on_output(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        if self.rules.is_empty() || chunk.is_empty() {
            return Vec::new();
        }
        self.window.extend_from_slice(chunk);
        if self.window.len() > WINDOW_BYTES {
            let drop = self.window.len() - WINDOW_BYTES;
            self.window.drain(..drop);
        }
        let text = String::from_utf8_lossy(&self.window).into_owned();

        let mut sends: Vec<Vec<u8>> = Vec::new();
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.once && self.fired[i] {
                continue;
            }
            if wildcard_contains(&rule.pattern, &text) {
                self.fired[i] = true;
                sends.push(send_bytes(&rule.send));
            }
        }
        if !sends.is_empty() {
            self.window.clear();
        }
        sends
    }
}

/// Байты для отправки: строка правила + Enter (`\r`), если строка ещё не
/// заканчивается переводом строки. Терминальные промпты (`Password:`,
/// `yes/no`) и команды всегда ждут Enter, а ввести его в однострочном
/// поле нельзя — поэтому он добавляется здесь, в одном месте.
fn send_bytes(send: &SecretString) -> Vec<u8> {
    let mut bytes = send.expose_secret().as_bytes().to_vec();
    if !bytes.ends_with(b"\r") && !bytes.ends_with(b"\n") {
        bytes.push(b'\r');
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, send: &str, once: bool) -> Rule {
        Rule {
            pattern: pattern.to_string(),
            send: SecretString::from(send.to_string()),
            once,
        }
    }

    // ---------- wildcard_match (якорное совпадение) ----------

    #[test]
    fn anchored_match() {
        assert!(wildcard_match("Password:", "Password:"));
        assert!(
            !wildcard_match("Password:", "Password: "),
            "хвост не входит"
        );
        assert!(!wildcard_match("Password:", "password: "));
        assert!(wildcard_match("", ""));
        assert!(!wildcard_match("x", "abcx"), "якорное совпадение целиком");
        assert!(!wildcard_match("x", "abc"));
    }

    #[test]
    fn question_mark_matches_exactly_one() {
        assert!(wildcard_match("a?c", "abc"));
        assert!(!wildcard_match("a?c", "ac"));
        assert!(!wildcard_match("a?c", "abbc"));
        assert!(wildcard_match("???", "abc"));
        assert!(!wildcard_match("???", "ab"));
    }

    #[test]
    fn star_matches_any_sequence() {
        assert!(wildcard_match("*", "любой текст"));
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("a*", "abc"));
        assert!(wildcard_match("*c", "abc"));
        assert!(wildcard_match("a*c", "ac"));
        assert!(wildcard_match("a*c", "abXXc"));
        assert!(!wildcard_match("a*c", "abcX"));
        assert!(
            wildcard_match("*assword*", "Password: "),
            "хвостовая * съедает хвост"
        );
    }

    // ---------- wildcard_contains (семантика expect) ----------

    #[test]
    fn contains_is_substring_semantics() {
        assert!(wildcard_contains("Password:", "Password: "));
        assert!(wildcard_contains("Password:", "Enter Password:"));
        assert!(wildcard_contains("x", "abcx"));
        assert!(!wildcard_contains("x", "abc"));
        assert!(wildcard_contains("*assword*", "Password: "));
        assert!(
            wildcard_contains("[yes/no*]:", "[yes/no/ALL]: "),
            "`*` внутри скобок"
        );
        assert!(
            wildcard_contains("[yes/no]*:", "[yes/no]: "),
            "скобки — литералы"
        );
        assert!(wildcard_contains("", ""), "пустой шаблон — пустой текст");
        assert!(
            !wildcard_contains("a", ""),
            "пустой текст не содержит литералов"
        );
        assert!(!wildcard_contains("?a", "a"), "`?` требует символ перед a");
        assert!(wildcard_contains("?a", "ba"), "префикс `?` съедает b");
        assert!(
            wildcard_contains("****", "abc"),
            "только звёздочки — всегда да"
        );
        assert!(wildcard_contains("?", "abc"));
        assert!(
            !wildcard_contains("??", "a"),
            "двум `?` нужен хотя бы 2 символа"
        );
    }

    #[test]
    fn star_backtracking() {
        // Жадная `*` съедает слишком много — нужен возврат к ней.
        assert!(wildcard_match("a*a*b", "aaaab"));
        assert!(wildcard_match("*a*b", "xxaayb"));
        assert!(!wildcard_match("a*ab", "aaXb"));
        assert!(wildcard_match("*abc*", "zzabczzabczz"));
        assert!(!wildcard_match("a*bc", "abcbcX"));
    }

    #[test]
    fn unicode_in_pattern_and_text() {
        assert!(wildcard_match("пароль?", "пароль:"));
        assert!(wildcard_match("сер*вер", "сер111вер"));
        assert!(!wildcard_match("сер?вер", "сер11вер"));
    }

    // ---------- ExpectEngine ----------

    #[test]
    fn fires_on_substring_in_window() {
        let mut e = ExpectEngine::new(vec![rule("Password:", "secret", false)]);
        assert!(e.on_output(b"login succeeded\n").is_empty());
        let sends = e.on_output(b"\nWelcome\nPassword: ");
        assert_eq!(sends, vec![b"secret\r".to_vec()]);
    }

    #[test]
    fn once_rule_fires_only_first_time() {
        let mut e = ExpectEngine::new(vec![rule("Password:", "secret", true)]);
        assert!(!e.on_output(b"Password: ").is_empty());
        assert!(e.on_output(b"Password: again").is_empty());
    }

    #[test]
    fn non_once_rule_does_not_refire_same_window() {
        let mut e = ExpectEngine::new(vec![rule("Password:", "secret", false)]);
        assert!(!e.on_output(b"Password: ").is_empty());
        // Окно очищено после отправки: тех же байтов больше нет — правила
        // не срабатывают повторно без нового вывода.
        assert!(e.on_output(b"\n").is_empty());
    }

    #[test]
    fn non_once_rule_refires_on_new_match() {
        let mut e = ExpectEngine::new(vec![rule("$ ", "ls", false)]);
        assert!(!e.on_output(b"user@host $ ").is_empty());
        assert!(e.on_output(b"\n").is_empty());
        // Промпт появился снова — правило срабатывает снова.
        assert!(!e.on_output(b"output\nuser@host $ ").is_empty());
    }

    #[test]
    fn window_is_bounded() {
        // Шаблон, разорванный окном: «L» вытесняется шумом до прихода «ATE».
        let mut e = ExpectEngine::new(vec![rule("LATE", "x", false)]);
        assert!(e.on_output(b"L").is_empty());
        let noise = vec![b'n'; WINDOW_BYTES];
        assert!(e.on_output(&noise).is_empty(), "«L» вытеснен из окна");
        assert!(
            e.on_output(b"ATE").is_empty(),
            "шаблон частично за окном — совпадения нет"
        );

        // Целый шаблон внутри окна срабатывает как обычно.
        let mut e2 = ExpectEngine::new(vec![rule("ALPHA", "x", false)]);
        assert!(!e2.on_output(b"ALPHA").is_empty());
    }

    #[test]
    fn rules_fire_in_list_order() {
        let mut e = ExpectEngine::new(vec![
            rule("Password:", "first", false),
            rule("*assword*", "second", false),
        ]);
        let sends = e.on_output(b"Password: ");
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0], b"first\r".to_vec());
        assert_eq!(sends[1], b"second\r".to_vec());
    }

    #[test]
    fn enter_is_appended_once() {
        let mut e = ExpectEngine::new(vec![rule("x", "with\n", false)]);
        let sends = e.on_output(b"x");
        assert_eq!(sends, vec![b"with\n".to_vec()]);
    }

    #[test]
    fn non_utf8_output_does_not_panic() {
        let mut e = ExpectEngine::new(vec![rule("ok", "y", false)]);
        // Обрезанный многобайтовый символ в середине потока.
        let sends = e.on_output(&[0xD0, 0x9F, 0xD0, b'o', b'k']);
        assert_eq!(sends, vec![b"y\r".to_vec()]);
    }

    #[test]
    fn empty_engine_and_chunks() {
        let mut e = ExpectEngine::new(Vec::new());
        assert!(e.is_empty());
        assert!(e.on_output(b"anything").is_empty());
        let mut e2 = ExpectEngine::new(vec![rule("x", "y", false)]);
        assert!(e2.on_output(b"").is_empty());
    }
}
