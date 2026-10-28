# Архитектура Remotix

Документ для преемника и будущих контрибьюторов. Задача — чтобы человек,
открывший репозиторий впервые, за полчаса понял, что где лежит, как
связано и почему сделано именно так. Дополняйте его вместе с кодом.

## Обзор

Remotix — GTK4-приложение на Rust: единое окно для SSH-терминалов,
RDP-рабочих столов (IronRDP), SFTP-панелей и журнала подключений.
Профили и история — в локальной SQLite; секреты шифруются AES-256-GCM
ключом из мастер-пароля (Argon2id). Сеть приложение покидает только ради
подключений к серверам, которые создал пользователь.

Целевая платформа — РЕД ОС 7/8 и совместимые (EL7/EL9): GTK4 ≥ 4.4,
glibc 2.34, OpenSSL 3. Поэтому привязки ограничены фичей `v4_4`, а
VTE-терминал грузится динамически (см. ниже).

## Слои и модули

```
src/
├── main.rs            # GApplication: activate/open, crate-атрибуты (deny(unsafe_code))
├── app.rs             # сборка окна, меню «О программе», refresh_main_profiles
├── config.rs          # XDG-пути (данные, конфиг, home_dir)
├── settings.rs        # key-value настройки в meta-таблице (тема, терминал, RDP…)
├── logging.rs         # лог с санитайзером секретов
├── host_check.rs      # TCP-проба узла перед подключением
├── wol/               # Wake-on-LAN (magic packet, UDP broadcast)
├── profiles_io.rs     # JSON-экспорт/импорт профилей
├── db/
│   ├── schema.rs      # DDL: meta, groups, profiles, connection_history
│   ├── repository.rs  # CRUD профилей/групп/истории + шифрование полей
│   └── crypto.rs      # Argon2id (ключ), AES-256-GCM (данные), verifier
├── models/profile.rs  # Profile, NewProfile, SshOptions/RdpOptions/VncOptions
├── protocols/
│   ├── ssh.rs         # SshConnection: TCP → баннер → kex → auth, known_hosts
│   ├── rdp.rs         # IronRDP: TLS/NLA/RC4, входной поток, NetworkClient для CredSSP
│   ├── vnc.rs         # заглушка (VNC 🚧, не подключён к UI)
│   └── metrics.rs     # разбор /proc + df для панели метрик (чистые функции)
├── import/
│   ├── mod.rs         # split_host_port (host:port, [IPv6]:port)
│   ├── normalize.rs   # ImportPreview, Candidate, Skipped, источники (Source)
│   ├── preview.rs     # диалог предпросмотра «импортируется N, пропущено M»
│   ├── ssh_config.rs  # ~/.ssh/config (+Include, рекурсия ≤8, циклы)
│   ├── remmina.rs     # *.remmina (INI + сжатые группы)
│   ├── rdp.rs         # .rdp (UTF-8/UTF-16, BOM)
│   ├── csv.rs         # CSV (RFC 4180-подмножество, сниффер разделителя)
│   ├── json.rs        # экспорт Remotix
│   └── ui.rs          # кнопки источников, диалог выбора файлов
└── ui/
    ├── main_window.rs # окно: сайдбар (дерево групп+теги), вкладки, статус
    ├── terminal.rs    # SSH-вкладка: VTE-динамика/TextView, поток сессии, метрики
    ├── rdp_viewer.rs  # RDP-вкладка: поток IronRDP, surface → GTK drawing
    ├── sftp_tab.rs    # двухпанельный SFTP
    ├── history_tab.rs # журнал + экспорт CSV
    ├── profile_editor.rs, connection_dialog.rs, master_password.rs,
    ├── settings_window.rs, host_key.rs, theme.rs
```

Правило слоёв: `ui` знает про `db`/`models`/`protocols`, но `protocols` и
`db` ничего не знают про GTK. Разбор форматов в `import/*` — чистые
функции без I/O там, где это возможно (parse_text принимает текст),
тестируются без файловой системы.

## Потоки и каналы

GTK и SSH/RDP живут в разных потоках и общаются каналами `mpsc`:

```
UI-поток (GTK, glib::timeout_add_local)          Фоновый поток сессии
─────────────────────────────────────            ──────────────────────
terminal.rs:  tx_in (Data/Resize/Metrics)  ──▶   recv_timeout → write/resize/
                                                 collect_metrics (exec в той же сессии)
              rx_out (Out/State/Metrics…) ◀──    ch.read (неблокирующе) → tx_out
```

- **Всё, что трогает libssh2, живёт в одном потоке** вкладки. Сессия
  не Shareable — вместо отдельных потоков «читателя» и «писателя» один
  поток крутит неблокирующий цикл (read → recv_timeout(PROMPT_MS)).
  Это осознанное решение: libssh2 в разных потоках по одной сессии
  небезопасно без внешней синхронизации.
- UI-поток не блокируется: `try_recv`/`recv_timeout` в таймерах glib.
- RDP-вкладка устроена так же: поток рендерит в буфер, шлёт кадры в UI.
- Таймеры «живости» (восстановление состояния, метрики) гасятся по
  `SessionState::Closed/Failed` через флаг `alive: Rc<Cell<bool>>` —
  тот же паттерн использовать для новых таймеров.

## Безопасность

- **Мастер-пароль** не хранится нигде; хранится соль, параметры Argon2
  и verifier-шифротекст константы. Неверный пароль отсекается verifier'ом.
- **Поля-секреты** (password, ssh_key_passphrase, root_password) в БД —
  AES-256-GCM от ключа мастер-пароля; в памяти — `SecretString`
  (zeroize при drop); в логи секреты не попадают (санитайзер logging.rs).
- **known_hosts**: неизвестный ключ → диалог с SHA256-отпечатком
  (поток подключения ждёт ответ через канал ≤300 с); изменение ключа →
  блокировка подключения. TOFU — только для неинтерактивных сценариев.
- **RDP**: TLS с NLA по умолчанию; Standard RDP Security (RC4) — только
  при явной галке профиля + подтверждении. Известный компромисс:
  верификатор серверных сертификатов RDP пока `NoCertificateVerification`
  (см. «Известные компромиссы»).
- **`#![deny(unsafe_code)]`** на весь крейт; единственное исключение —
  `mod vte_dynamic` в `ui/terminal.rs` (динамическая загрузка VTE через
  libloading, потому что в EL9 нет пакета VTE для GTK4).

## База данных

SQLite (`rusqlite`, bundled). Таблицы:

- `meta(key, value)` — соль/параметры Argon2, verifier, версия схемы,
  настройки приложения (settings.rs пишет туда же `ключ = Value`).
- `groups(id, name, parent_id)` — дерево групп, ограничение глубины 32.
- `profiles(...)` — профили; секретные поля — BLOB-шифротексты.
- `connection_history(profile_id, started_at, ...)` — журнал.

Внешние ключи SQLite не форсятся: `delete_group` вручную репарентит
детей и отвязывает профили. Миграции — только добавлением DDL в
`schema::initialize` (идемпотентные `CREATE IF NOT EXISTS`).

## VTE: динамическая загрузка

`libvte-2.91-gtk4.so.0` ищется через `libloading` в рантайме. Есть —
полноценная эмуляция (через минимальный набор C-функций: new/feed/
copy_clipboard/set_font_scale/get_char_*). Нет — запасной `GtkTextView`
с тем же вводом/выводом (escape-последовательности не эмулируются).
Обе ветки имеют общий интерфейс `TerminalView`, поэтому остальной код
о режиме не знает.

## Сборка и CI

- Сборка полностью офлайн: `.cargo/config.toml` заменяет crates.io на
  `vendor/`, который поставляется архивом `vendor.tar.zst`
  (распаковка — `packaging/ci/unpack-vendor.sh`; 22 тыс. файлов в git
  не хранятся).
- CI (`build-rpm.yml`): job **quality** (fmt, clippy `-D warnings`,
  cargo-deny) и job **build-rpm** — окружение AlmaLinux 9 через chroot
  (`packaging/ci/el9-chroot.sh`, без Docker): сборка релиза, тесты против
  локального sshd (127.0.0.1:2222, tester/secret — `el9-chroot.sh sshd start`),
  smoke-тесты GUI в Xvfb, сборка RPM/SRPM.
- Локальная проверка (Docker, Fedora 37 = платформа-близнец EL9):
  `cargo check --all-targets`, `cargo test`. fmt по всему проекту не
  гонять — историческое форматирование расходится с rustfmt.

## Известные компромиссы

- **RDP: `NoCertificateVerification`** — серверные сертификаты RDP не
  проверяются (rustls-dangerous). Нужен UI-проверщик отпечатков, как у
  SSH known_hosts. Кандидат №1 в безопасности.
- **VNC** (`protocols/vnc.rs`) — заглушка, в UI не подключена. Решение:
  минимальный RFB 3.8 (DES + raw/copyrect) или удаление из описания.
- **gettext** нет — строки в коде русские; локализация задумана до
  разрастания UI, дороже потом.
- **`regex` не используется** — в Cargo.lock его нет, добавлять ради
  мелких задач (expect-правила и т.п.) не планируется: пишем маленькие
  ручные матчеры.
