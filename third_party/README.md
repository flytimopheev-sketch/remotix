# Патченные зависимости IronRDP

Здесь лежат копии трёх крейтов IronRDP с локальными правками, которых ещё нет
в опубликованных версиях:

| Каталог            | Крейт               | Версия во `vendor/` |
| ------------------ | ------------------- | ------------------- |
| `ironrdp-pdu`      | `ironrdp-pdu`       | 0.9.0               |
| `ironrdp-connector`| `ironrdp-connector` | 0.10.0              |
| `ironrdp-session`  | `ironrdp-session`   | 0.11.0              |

Корневой `Cargo.toml` подключает их через `[patch.crates-io]`.

## Что добавлено

Поддержка Standard RDP Security (`PROTOCOL_RDP`, шифр RC4) — порт открытого
апстримного PR IronRDP #2105 «feat(rdpsec): add Standard RDP Security client
support»:

- `ironrdp-pdu/src/rdpsec.rs` — криптодвижок: RC4, MAC, ключи из client/server
  random, Security Exchange PDU;
- `ironrdp-connector` — согласование `PROTOCOL_RDP`, обмен Security Exchange,
  шифрование Client Info и лицензирования;
- `ironrdp-session` — шифрование и дешифрование fast-path/slow-path PDU,
  включая ввод с клавиатуры и мыши.

## Почему не `vendor/`

`vendor/` пересоздаётся командой `cargo vendor` в CI
(`.github/workflows/build-rpm.yml`), поэтому правки там теряются, а изменённые
файлы ломают контрольные суммы (`cargo` отказывается собирать такой каталог).
Патченные крейты поэтому вынесены в `third_party/` и подключаются через
`[patch.crates-io]`.

## Обновление

1. При выходе новой версии IronRDP скопировать свежие `vendor/ironrdp-*` в этот
   каталог.
2. Перенести правки — либо удалить каталог и `[patch.crates-io]`, если апстрим
   уже умеет Standard RDP Security.
3. Проверить сборку и тест `tests/rdpsec.rs`.
