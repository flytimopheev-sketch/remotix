//! Импорт инвентаря Ansible (INI-формат).
//!
//! Поддерживаются секции `[группа]`, `[группа:vars]` и `[группа:children]`,
//! переменные `ansible_host`, `ansible_user`, `ansible_port`,
//! `ansible_ssh_private_key_file`. Как и остальные источники, инвентарь
//! разбирается в предпросмотр: пароли не читаются, дубли отсеиваются.
//!
//! YAML-инвентарь пока не разбирается — для него нужен отдельный парсер.

use std::collections::HashMap;

use crate::import::normalize::{ImportPreview, Source};
use crate::models::{NewProfile, Protocol};

/// Хост из секции группы: имя-алиас и переменные из строки.
struct Entry {
    alias: String,
    vars: Vec<(String, String)>,
}

/// Разбирает текст инвентаря.
pub fn parse_text(text: &str, origin: &str) -> ImportPreview {
    let mut preview = ImportPreview::default();
    preview.note("Пароли из инвентаря Ansible не импортируются");

    let mut order: Vec<String> = Vec::new();
    let mut hosts: HashMap<String, Vec<Entry>> = HashMap::new();
    let mut gvars: HashMap<String, Vec<(String, String)>> = HashMap::new();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();

    let mut group = String::new();
    let mut kind = "hosts";

    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let inner = line[1..line.len() - 1].trim();
            let (g, k) = match inner.split_once(':') {
                Some((g, k)) => (g.trim(), k.trim()),
                None => (inner, "hosts"),
            };
            if g.is_empty() {
                continue;
            }
            group = g.to_string();
            kind = k;
            if k == "hosts" && !order.iter().any(|x| x == &group) {
                order.push(group.clone());
            }
            continue;
        }
        if group.is_empty() {
            continue;
        }
        match kind {
            "vars" => {
                if let Some(kv) = key_value(line) {
                    gvars.entry(group.clone()).or_default().push(kv);
                }
            }
            "children" => {
                for token in line.split_whitespace() {
                    children
                        .entry(group.clone())
                        .or_default()
                        .push(token.to_string());
                }
            }
            _ => {
                let mut it = line.split_whitespace();
                let Some(alias) = it.next() else { continue };
                let vars = it.filter_map(key_value).collect();
                hosts.entry(group.clone()).or_default().push(Entry {
                    alias: alias.to_string(),
                    vars,
                });
            }
        }
    }

    if order.is_empty() {
        preview.skip(
            Source::Ansible,
            origin.to_string(),
            "в инвентаре не найдено ни одной группы с хостами",
        );
        return preview;
    }

    for g in &order {
        let Some(list) = hosts.get(g) else { continue };
        // Родительская группа из :children — путь «родитель/группа».
        let parent = children
            .iter()
            .find(|(_, kids)| kids.iter().any(|k| k == g))
            .map(|(p, _)| p.clone());
        for e in list {
            let mut merged: Vec<(String, String)> = Vec::new();
            for v in [gvars.get("all"), gvars.get(g), Some(&e.vars)]
                .into_iter()
                .flatten()
            {
                merged.extend(v.iter().cloned());
            }
            let get = |key: &str| -> Option<String> {
                merged
                    .iter()
                    .rev()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.clone())
            };
            let host = get("ansible_host").unwrap_or_else(|| e.alias.clone());
            let port = get("ansible_port")
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|p| *p > 0)
                .unwrap_or(22);
            let path = if g == "all" {
                Vec::new()
            } else if let Some(p) = &parent {
                vec![p.clone(), g.clone()]
            } else {
                vec![g.clone()]
            };
            let profile = NewProfile {
                name: e.alias.clone(),
                protocol: Some(Protocol::Ssh),
                host,
                port,
                username: get("ansible_user"),
                ssh_key_path: get("ansible_ssh_private_key_file"),
                ..Default::default()
            };
            preview.push_grouped(Source::Ansible, origin.to_string(), profile, path);
        }
    }
    preview
}

/// Убирает комментарий `#` или `;` вне кавычек.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' | '"' => {
                if quote == Some(ch) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(ch);
                }
            }
            '#' | ';' if quote.is_none() => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Разбирает `ключ=значение`, снимая обрамляющие кавычки.
fn key_value(token: &str) -> Option<(String, String)> {
    let (k, v) = token.split_once('=')?;
    let k = k.trim();
    if k.is_empty() {
        return None;
    }
    let v = v.trim();
    let v = if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        &v[1..v.len() - 1]
    } else {
        v
    };
    Some((k.to_string(), v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_group_hosts() {
        let text = "[web]\nweb1.example.org\nweb2.example.org\n";
        let p = parse_text(text, "hosts");
        assert_eq!(p.imported(), 2);
        assert_eq!(p.candidates[0].profile.host, "web1.example.org");
        assert_eq!(p.candidates[0].profile.port, 22);
        assert_eq!(p.candidates[0].group_path, vec!["web".to_string()]);
    }

    #[test]
    fn inline_vars_override_alias() {
        let text = "[web]\napp ansible_host=10.0.0.5 ansible_user=admin ansible_port=2222\n";
        let p = parse_text(text, "hosts");
        let c = &p.candidates[0];
        assert_eq!(c.profile.name, "app");
        assert_eq!(c.profile.host, "10.0.0.5");
        assert_eq!(c.profile.port, 2222);
        assert_eq!(c.profile.username.as_deref(), Some("admin"));
    }

    #[test]
    fn group_vars_and_all_vars() {
        let text =
            "[all:vars]\nansible_user=root\n\n[db]\ndb1\n\n[db:vars]\nansible_user=postgres\n";
        let p = parse_text(text, "hosts");
        assert_eq!(
            p.candidates[0].profile.username.as_deref(),
            Some("postgres")
        );
    }

    #[test]
    fn inline_beats_group_vars() {
        let text = "[db:vars]\nansible_user=postgres\n\n[db]\ndb1 ansible_user=alice\n";
        let p = parse_text(text, "hosts");
        assert_eq!(p.candidates[0].profile.username.as_deref(), Some("alice"));
    }

    #[test]
    fn children_build_nested_path() {
        let text = "[web]\nw1\n\n[prod:children]\nweb\n";
        let p = parse_text(text, "hosts");
        assert_eq!(
            p.candidates[0].group_path,
            vec!["prod".to_string(), "web".to_string()]
        );
    }

    #[test]
    fn key_path_and_quotes() {
        let text = "[web]\nw1 ansible_ssh_private_key_file=\"~/.ssh/id_ed25519\"\n";
        let p = parse_text(text, "hosts");
        assert!(p.candidates[0].profile.ssh_key_path.is_some());
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let text = "# инвентарь\n\n[web]\nw1 ; прод\n; строка-комментарий\nw2\n";
        let p = parse_text(text, "hosts");
        assert_eq!(p.imported(), 2);
    }

    #[test]
    fn bad_port_falls_back_to_22() {
        let text = "[web]\nw1 ansible_port=abc\nw2 ansible_port=0\n";
        let p = parse_text(text, "hosts");
        assert!(p.candidates.iter().all(|c| c.profile.port == 22));
    }

    #[test]
    fn empty_inventory_reports_reason() {
        let p = parse_text("# пусто\n", "hosts");
        assert_eq!(p.imported(), 0);
        assert!(p.skipped[0].reason.contains("группы"));
    }

    #[test]
    fn no_secrets_are_imported() {
        let text = "[web]\nw1 ansible_password=hunter2 ansible_user=admin\n";
        let p = parse_text(text, "hosts");
        assert!(p.candidates[0].profile.password.is_none());
        assert!(p.notes.iter().any(|n| n.contains("не импортируются")));
    }
}
