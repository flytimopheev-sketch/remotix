//! Сниппеты с параметрами: `{{имя}}` и `{{имя:значение_по_умолчанию}}`.
//!
//! Перед отправкой в терминал значения подставляются (интерфейс спрашивает
//! недостающие). Модуль не зависит от GTK и проверяется unit-тестами.

/// Параметр сниппета, найденный в тексте команды.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    /// Имя параметра без скобок.
    pub name: String,
    /// Значение по умолчанию из `{{имя:значение}}`.
    pub default: Option<String>,
}

/// Есть ли в команде хотя бы один параметр.
pub fn has_params(command: &str) -> bool {
    !params(command).is_empty()
}

/// Список параметров в порядке первого появления, без повторов.
///
/// Незакрытая `{{` параметром не считается: такой текст уходит в терминал
/// как есть, чтобы опечатка не превращалась в молчаливую подстановку.
pub fn params(command: &str) -> Vec<Param> {
    let mut out: Vec<Param> = Vec::new();
    let bytes = command.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = command[i + 2..].find("}}") {
                let inner = &command[i + 2..i + 2 + end];
                if !inner.is_empty() && !inner.contains('{') && !inner.contains('}') {
                    let (name, default) = match inner.split_once(':') {
                        Some((n, d)) => (n.trim(), Some(d.to_string())),
                        None => (inner.trim(), None),
                    };
                    if !name.is_empty() && !out.iter().any(|p| p.name == name) {
                        out.push(Param {
                            name: name.to_string(),
                            default,
                        });
                    }
                    i += 2 + end + 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// Подставляет значения параметров.
///
/// Значения ищутся по имени; при отсутствии берётся значение по умолчанию.
/// Если ни того, ни другого нет — ошибка со списком недостающих имён:
/// отправлять команду с незаполненным плейсхолдером нельзя.
pub fn render(command: &str, values: &[(String, String)]) -> Result<String, String> {
    let needed = params(command);
    let mut missing: Vec<&str> = Vec::new();
    for p in &needed {
        let provided = values.iter().find(|(k, _)| k == &p.name);
        if provided.is_none() && p.default.is_none() {
            missing.push(&p.name);
        }
    }
    if !missing.is_empty() {
        return Err(format!("не заполнены параметры: {}", missing.join(", ")));
    }

    let mut out = String::with_capacity(command.len());
    let bytes = command.as_bytes();
    let mut i = 0;
    while i < command.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = command[i + 2..].find("}}") {
                let inner = &command[i + 2..i + 2 + end];
                if !inner.is_empty() && !inner.contains('{') && !inner.contains('}') {
                    let name = inner.split(':').next().unwrap_or("").trim();
                    if let Some(p) = needed.iter().find(|p| p.name == name) {
                        let value = values
                            .iter()
                            .find(|(k, _)| k == name)
                            .map(|(_, v)| v.clone())
                            .or_else(|| p.default.clone())
                            .unwrap_or_default();
                        out.push_str(&value);
                        i += 2 + end + 2;
                        continue;
                    }
                }
            }
        }
        let ch = command[i..].chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn plain_command_has_no_params() {
        assert!(!has_params("df -h"));
        assert!(params("df -h").is_empty());
        assert_eq!(render("df -h", &[]).unwrap(), "df -h");
    }

    #[test]
    fn params_are_unique_and_ordered() {
        let p = params("systemctl restart {{svc}} && systemctl status {{svc}} {{extra}}");
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "svc");
        assert_eq!(p[1].name, "extra");
    }

    #[test]
    fn defaults_are_parsed() {
        let p = params("ping -c {{count:4}} {{host}}");
        assert_eq!(p[0].name, "count");
        assert_eq!(p[0].default.as_deref(), Some("4"));
        assert_eq!(p[1].default, None);
    }

    #[test]
    fn render_uses_values_then_defaults() {
        let cmd = "ping -c {{count:4}} {{host}}";
        assert_eq!(
            render(cmd, &vals(&[("host", "example.org")])).unwrap(),
            "ping -c 4 example.org"
        );
        assert_eq!(
            render(cmd, &vals(&[("host", "example.org"), ("count", "10")])).unwrap(),
            "ping -c 10 example.org"
        );
    }

    #[test]
    fn missing_param_is_an_error() {
        let err = render("echo {{a}} {{b}}", &vals(&[("a", "1")])).unwrap_err();
        assert!(err.contains('b'), "{err}");
        assert!(
            !err.contains('a'),
            "заполненный параметр не должен попасть в ошибку: {err}"
        );
    }

    #[test]
    fn empty_value_is_allowed() {
        assert_eq!(render("echo {{a}}", &vals(&[("a", "")])).unwrap(), "echo ");
    }

    #[test]
    fn unclosed_brace_is_left_as_is() {
        assert!(params("echo {{oops").is_empty());
        assert_eq!(render("echo {{oops", &[]).unwrap(), "echo {{oops");
    }

    #[test]
    fn unicode_and_repeated_params() {
        let cmd = "logger \"{{текст}}\"; logger \"{{текст}}\"";
        assert_eq!(params(cmd).len(), 1);
        assert_eq!(
            render(cmd, &vals(&[("текст", "привет")])).unwrap(),
            "logger \"привет\"; logger \"привет\""
        );
    }

    #[test]
    fn adjacent_params() {
        assert_eq!(
            render("{{a}}{{b}}", &vals(&[("a", "x"), ("b", "y")])).unwrap(),
            "xy"
        );
    }
}
